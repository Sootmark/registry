//! Windows registry hives (`regf`): SYSTEM, SOFTWARE, SAM, SECURITY,
//! NTUSER.DAT, UsrClass.dat, Amcache.hve, BCD.
//!
//! Written from the public format documentation (libyal's "Windows NT
//! Registry File (REGF) format"). A hive is a 4,096-byte base block, then
//! hive bins of cells; keys (`nk`) point at lists of subkeys (`lf`, `lh`,
//! `li`, `ri`) and of values (`vk`), whose data is inline, in a cell, or in
//! segments (`db`).
//!
//! Every read is bounds-checked and every walk guarded against cycles:
//! damaged or hostile hives give errors, never panics or endless loops.
//! What a damaged hive still holds is kept: a key's unreadable value is an
//! error for that value, not for the key.
//!
//! Not yet: replaying transaction logs (`.LOG1`/`.LOG2`) into a dirty hive
//! ([`Hive::is_dirty`] says when it matters), and recovering deleted keys
//! and values from free cells.

pub mod shellbags;
pub mod shellitem;
pub mod shimcache;
pub mod userassist;
mod value;

use core::fmt;
use std::collections::HashSet;

pub use value::{Data, Kind, Value};

/// This crate's version, for provenance.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const BASE_BLOCK: usize = 4096;
/// Nesting of index lists (`ri` → `lf`/`lh`/`li`) beyond this is damage.
const MAX_LIST_DEPTH: u32 = 8;
/// `KEY_COMP_NAME`: the key's name is Latin-1, not UTF-16.
const KEY_COMP_NAME: u16 = 0x0020;

/// Why something couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Byte offset in the hive file where it went wrong.
    pub offset: usize,
    /// What went wrong.
    pub reason: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at byte {})", self.reason, self.offset)
    }
}

impl std::error::Error for Error {}

pub(crate) fn error(offset: usize, reason: impl Into<String>) -> Error {
    Error {
        offset,
        reason: reason.into(),
    }
}

pub(crate) fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

pub(crate) fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

pub(crate) fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

/// Latin-1 or UTF-16LE text.
pub(crate) fn name(bytes: &[u8], latin1: bool) -> String {
    if latin1 {
        bytes.iter().map(|&b| char::from(b)).collect()
    } else {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }
}

/// The base block's header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Incremented when a write starts.
    pub primary_sequence: u32,
    /// Set equal to the primary when the write completes.
    pub secondary_sequence: u32,
    /// When the hive was last written (FILETIME).
    pub last_written: u64,
    /// Format version, major (1).
    pub major: u32,
    /// Format version, minor (3 to 6).
    pub minor: u32,
    /// The root key's cell, relative to the first hive bin.
    pub root: u32,
    /// Size of the hive bins, in bytes.
    pub bins_size: u32,
    /// The last characters of the hive's path when it was loaded.
    pub file_name: String,
    /// Whether the base block's checksum is right.
    pub checksum_ok: bool,
}

/// A hive.
#[derive(Debug, Clone)]
pub struct Hive<'a> {
    data: &'a [u8],
    /// The header.
    pub header: Header,
    /// Where the hive bins end in `data` (the header's claim, within the file).
    bins_end: usize,
}

impl<'a> Hive<'a> {
    /// Read a hive's base block.
    ///
    /// # Errors
    /// When it isn't a hive (no `regf` signature, or too short).
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < BASE_BLOCK || &data[..4] != b"regf" {
            return Err(error(0, "not a registry hive (no regf signature)"));
        }
        let at = |offset| u32_at(data, offset).unwrap_or(0);
        let mut checksum = (0..127).fold(0_u32, |x, i| x ^ at(4 * i));
        checksum = match checksum {
            0 => 1,
            u32::MAX => u32::MAX - 1,
            other => other,
        };
        let header = Header {
            primary_sequence: at(4),
            secondary_sequence: at(8),
            last_written: u64_at(data, 12).unwrap_or(0),
            major: at(20),
            minor: at(24),
            root: at(36),
            bins_size: at(40),
            file_name: name(&data[48..112], false)
                .trim_end_matches('\0')
                .to_owned(),
            checksum_ok: checksum == at(508),
        };
        let claimed = BASE_BLOCK.saturating_add(header.bins_size as usize);
        Ok(Self {
            data,
            bins_end: claimed.min(data.len()),
            header,
        })
    }

    /// Whether a write was interrupted (the sequence numbers differ): the
    /// hive's latest changes may be in its transaction logs.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.header.primary_sequence != self.header.secondary_sequence
    }

    /// The root key.
    ///
    /// # Errors
    /// When the root cell isn't a readable key.
    pub fn root(&self) -> Result<Key<'_>, Error> {
        self.key_at(self.header.root)
    }

    /// The key at `path` (`Software\Microsoft\Windows`, case-insensitive,
    /// relative to the root), if it exists.
    ///
    /// # Errors
    /// When a key on the way can't be read.
    pub fn open(&self, path: &str) -> Result<Option<Key<'_>>, Error> {
        let mut key = self.root()?;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            match key.subkey(part)? {
                Some(next) => key = next,
                None => return Ok(None),
            }
        }
        Ok(Some(key))
    }

    /// Every key, depth first with subkeys in the hive's order, and its
    /// path from the root (`""` for the root, `\Software\…` below).
    /// Damage never loops: a key reached twice is visited once, and a key
    /// whose subkeys can't be read is passed to `problem` with the reason.
    ///
    /// # Errors
    /// When the root can't be read.
    pub fn walk(
        &self,
        mut visit: impl FnMut(&str, &Key<'_>),
        mut problem: impl FnMut(&str, Error),
    ) -> Result<(), Error> {
        let mut seen = HashSet::new();
        let mut stack = vec![(String::new(), self.root()?)];
        while let Some((path, key)) = stack.pop() {
            if !seen.insert(key.offset) {
                continue;
            }
            visit(&path, &key);
            match key.subkeys() {
                Ok(subkeys) => {
                    for sub in subkeys.into_iter().rev() {
                        stack.push((format!("{path}\\{}", sub.name), sub));
                    }
                }
                Err(e) => problem(&path, e),
            }
        }
        Ok(())
    }

    /// A cell's data (after its size), given its offset in the bins.
    pub(crate) fn cell(&self, offset: u32) -> Result<&'a [u8], Error> {
        let at = BASE_BLOCK
            .checked_add(offset as usize)
            .filter(|&at| at + 4 <= self.bins_end)
            .ok_or_else(|| error(BASE_BLOCK + offset as usize, "cell outside the hive bins"))?;
        let size = i32::from_le_bytes(self.data[at..at + 4].try_into().unwrap_or([0; 4]));
        // Allocated cells have a negative size; free ones are still read
        // (a key pointing at one is damage the caller may want to see
        // through), but a size smaller than its own header isn't a cell.
        let len = size.unsigned_abs() as usize;
        if len < 8 {
            return Err(error(at, format!("cell of size {size}")));
        }
        self.data
            .get(at + 4..at + len)
            .filter(|_| at + len <= self.bins_end)
            .ok_or_else(|| error(at, "cell runs past the hive bins"))
    }

    fn key_at(&self, offset: u32) -> Result<Key<'_>, Error> {
        let cell = self.cell(offset)?;
        let at = BASE_BLOCK + offset as usize + 4;
        if cell.get(..2) != Some(b"nk") {
            return Err(error(at, "not a key (no nk signature)"));
        }
        let field = |o| u32_at(cell, o).ok_or_else(|| error(at + o, "key cell too short"));
        let flags = u16_at(cell, 2).unwrap_or(0);
        let name_len = u16_at(cell, 72).unwrap_or(0) as usize;
        let class_len = u16_at(cell, 74).unwrap_or(0);
        let name_bytes = cell
            .get(76..76 + name_len)
            .ok_or_else(|| error(at + 76, "key name runs past its cell"))?;
        Ok(Key {
            hive: self,
            offset,
            name: name(name_bytes, flags & KEY_COMP_NAME != 0),
            flags,
            last_written: u64_at(cell, 4).unwrap_or(0),
            parent: field(16)?,
            subkey_count: field(20)?,
            subkeys: field(28)?,
            value_count: field(36)?,
            values: field(40)?,
            class: field(48)?,
            class_len,
        })
    }
}

/// A key.
#[derive(Debug, Clone)]
pub struct Key<'h> {
    hive: &'h Hive<'h>,
    /// Its cell's offset in the bins: a stable locator.
    pub offset: u32,
    /// Its name.
    pub name: String,
    /// Its flags (`KEY_HIVE_ENTRY` 0x4, `KEY_COMP_NAME` 0x20, …).
    pub flags: u16,
    /// When it was last written (FILETIME).
    pub last_written: u64,
    /// Its parent's cell offset.
    pub parent: u32,
    /// How many subkeys it says it has.
    pub subkey_count: u32,
    subkeys: u32,
    /// How many values it says it has.
    pub value_count: u32,
    values: u32,
    class: u32,
    class_len: u16,
}

impl<'h> Key<'h> {
    /// Its class name, if it has one.
    ///
    /// # Errors
    /// When the class name's cell can't be read.
    pub fn class_name(&self) -> Result<Option<String>, Error> {
        if self.class_len == 0 || self.class == u32::MAX {
            return Ok(None);
        }
        let cell = self.hive.cell(self.class)?;
        let bytes = cell.get(..usize::from(self.class_len)).ok_or_else(|| {
            error(
                BASE_BLOCK + self.class as usize,
                "class name runs past its cell",
            )
        })?;
        Ok(Some(name(bytes, false)))
    }

    /// Its subkeys, in the hive's order.
    ///
    /// # Errors
    /// When a subkey list or a subkey can't be read.
    pub fn subkeys(&self) -> Result<Vec<Key<'h>>, Error> {
        if self.subkey_count == 0 || self.subkeys == u32::MAX {
            return Ok(Vec::new());
        }
        let mut offsets = Vec::new();
        let mut seen = HashSet::new();
        self.collect(self.subkeys, 0, &mut offsets, &mut seen)?;
        offsets.iter().map(|&o| self.hive.key_at(o)).collect()
    }

    /// Follow a subkey list (and index roots) to key offsets.
    fn collect(
        &self,
        list: u32,
        depth: u32,
        out: &mut Vec<u32>,
        seen: &mut HashSet<u32>,
    ) -> Result<(), Error> {
        let at = BASE_BLOCK + list as usize + 4;
        if depth > MAX_LIST_DEPTH || !seen.insert(list) {
            return Err(error(at, "subkey lists loop or nest too deep"));
        }
        let cell = self.hive.cell(list)?;
        let count = usize::from(u16_at(cell, 2).ok_or_else(|| error(at, "subkey list too short"))?);
        let (step, index) = match cell.get(..2) {
            Some(b"lf" | b"lh") => (8, false),
            Some(b"li") => (4, false),
            Some(b"ri") => (4, true),
            _ => return Err(error(at, "not a subkey list")),
        };
        for i in 0..count {
            let entry = u32_at(cell, 4 + i * step)
                .ok_or_else(|| error(at, "subkey list runs past its cell"))?;
            if index {
                self.collect(entry, depth + 1, out, seen)?;
            } else {
                out.push(entry);
            }
        }
        Ok(())
    }

    /// The subkey named `name` (case-insensitive), if any.
    ///
    /// # Errors
    /// When the subkeys can't be read.
    pub fn subkey(&self, name: &str) -> Result<Option<Key<'h>>, Error> {
        Ok(self
            .subkeys()?
            .into_iter()
            .find(|k| k.name.to_uppercase() == name.to_uppercase()))
    }

    /// Its values, each readable or the reason it isn't.
    ///
    /// # Errors
    /// When the value list itself can't be read.
    pub fn values(&self) -> Result<Vec<Result<Value<'h>, Error>>, Error> {
        if self.value_count == 0 || self.values == u32::MAX {
            return Ok(Vec::new());
        }
        let list = self.hive.cell(self.values)?;
        let count = self.value_count as usize;
        if list.len() < count * 4 {
            return Err(error(
                BASE_BLOCK + self.values as usize,
                "value list runs past its cell",
            ));
        }
        Ok((0..count)
            .map(|i| {
                let offset = u32_at(list, 4 * i).unwrap_or(u32::MAX);
                Value::read(self.hive, offset)
            })
            .collect())
    }

    /// The value named `name` (case-insensitive; `""` is the default
    /// value), if any is readable.
    ///
    /// # Errors
    /// When the value list can't be read.
    pub fn value(&self, name: &str) -> Result<Option<Value<'h>>, Error> {
        Ok(self
            .values()?
            .into_iter()
            .flatten()
            .find(|v| v.name.eq_ignore_ascii_case(name)))
    }

    /// Its parent, unless it's the root.
    ///
    /// # Errors
    /// When the parent can't be read.
    pub fn parent(&self) -> Result<Option<Key<'h>>, Error> {
        if self.offset == self.hive.header.root {
            return Ok(None);
        }
        self.hive.key_at(self.parent).map(Some)
    }
}
