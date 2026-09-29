//! The Application Compatibility Cache ("ShimCache"): the
//! `AppCompatCache` value of `ControlSet00N\Control\Session Manager\AppCompatCache`
//! in SYSTEM. Files Windows checked for compatibility shims, most recent
//! first, each with the file's last modification time (not when it ran)
//! and, before Windows 10, whether it was executed.
//!
//! Layouts from the public documentation (Mandiant's "Leveraging the
//! Application Compatibility Cache in Forensic Investigations", libyal's
//! notes): Windows 7 / 2008 R2 (x86 and x64), 8.0, 8.1 / 2012 R2, and 10 /
//! 11. XP and Vista layouts are refused with the reason.

use crate::{error, u16_at, u32_at, u64_at, Error};

/// The layout a cache was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Windows 7 / Server 2008 R2, 32-bit.
    Windows7X86,
    /// Windows 7 / Server 2008 R2, 64-bit.
    Windows7X64,
    /// Windows 8.0 / Server 2012.
    Windows8,
    /// Windows 8.1 / Server 2012 R2.
    Windows81,
    /// Windows 10 / 11 / Server 2016 and later.
    Windows10,
}

/// One cached file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its position in the cache (0: most recently added or updated).
    pub position: usize,
    /// Its path, as Windows recorded it (`SYSVOL\…`, `\??\C:\…`).
    pub path: String,
    /// The file's last modification time (FILETIME; 0 when none).
    pub last_modified: u64,
    /// Whether the insertion flags say it was executed; `None` where the
    /// layout doesn't record it (Windows 10 and later).
    pub executed: Option<bool>,
}

/// `CSRSS_INSERT_FLAG`-style bit marking an executed file.
const EXECUTED_FLAG: u32 = 0x0000_0002;
const WINDOWS7: u32 = 0xbadc_0fee;
const XP: u32 = 0xdead_beef;
const VISTA: u32 = 0xbadc_0ffe;

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Read a cache.
///
/// # Errors
/// When the layout is unknown or unsupported, or an entry is damaged
/// (entries before it are lost too: the cache is read in one pass).
pub fn parse(value: &[u8]) -> Result<(Format, Vec<Entry>), Error> {
    let first = u32_at(value, 0).ok_or_else(|| error(0, "AppCompatCache too short"))?;
    match first {
        WINDOWS7 => windows7(value),
        XP => Err(error(0, "Windows XP AppCompatCache (not supported yet)")),
        VISTA => Err(error(
            0,
            "Windows Vista / 2008 AppCompatCache (not supported yet)",
        )),
        0x80 => match value.get(0x80..0x84) {
            Some(b"00ts") => signed(value, 0x80, Format::Windows8),
            Some(b"10ts") => signed(value, 0x80, Format::Windows81),
            _ => Err(error(0x80, "unknown AppCompatCache entry signature")),
        },
        0x30 | 0x34 => signed(value, first as usize, Format::Windows10),
        other => Err(error(
            0,
            format!("unknown AppCompatCache layout (header {other:#x})"),
        )),
    }
}

/// Windows 8 and later: a header, then signed entries of declared size.
fn signed(value: &[u8], start: usize, format: Format) -> Result<(Format, Vec<Entry>), Error> {
    let mut entries = Vec::new();
    let mut at = start;
    while at + 12 <= value.len() {
        let signature = &value[at..at + 4];
        if signature != b"10ts" && signature != b"00ts" {
            return Err(error(at, "AppCompatCache entry without signature"));
        }
        let size = u32_at(value, at + 8).unwrap_or(0) as usize;
        let data = value
            .get(at + 12..at + 12 + size)
            .ok_or_else(|| error(at, "AppCompatCache entry runs past the value"))?;
        let short = || error(at, "AppCompatCache entry too short");
        let path_len = usize::from(u16_at(data, 0).ok_or_else(short)?);
        let path = utf16(data.get(2..2 + path_len).ok_or_else(short)?);
        let mut o = 2 + path_len;
        let (last_modified, executed) = match format {
            Format::Windows10 => (u64_at(data, o).ok_or_else(short)?, None),
            Format::Windows81 | Format::Windows8 => {
                if format == Format::Windows81 {
                    let package = usize::from(u16_at(data, o).ok_or_else(short)?);
                    o += 2 + package;
                }
                let insertion = u32_at(data, o).ok_or_else(short)?;
                (
                    u64_at(data, o + 8).ok_or_else(short)?,
                    Some(insertion & EXECUTED_FLAG != 0),
                )
            }
            Format::Windows7X86 | Format::Windows7X64 => unreachable!("not a signed layout"),
        };
        entries.push(Entry {
            position: entries.len(),
            path,
            last_modified,
            executed,
        });
        at += 12 + size;
    }
    Ok((format, entries))
}

/// Windows 7: a 128-byte header with the count, then fixed-size entries
/// pointing at their paths.
fn windows7(value: &[u8]) -> Result<(Format, Vec<Entry>), Error> {
    let count = u32_at(value, 4).unwrap_or(0) as usize;
    // x64 entries are 48 bytes, x86 32: the x64 path offset (a u64 at +8)
    // points inside the value; read as x86 it's two small u32s.
    let x64 = u64_at(value, 128 + 8).is_some_and(|o| o > 0 && (o as usize) < value.len())
        && u32_at(value, 128 + 12) == Some(0);
    let (format, size) = if x64 {
        (Format::Windows7X64, 48)
    } else {
        (Format::Windows7X86, 32)
    };
    let mut entries = Vec::with_capacity(count.min(4096));
    for i in 0..count {
        let at = 128 + i * size;
        let short = || error(at, "AppCompatCache entry runs past the value");
        let len = usize::from(u16_at(value, at).ok_or_else(short)?);
        let (path_at, modified, flags) = if x64 {
            (
                u64_at(value, at + 8).ok_or_else(short)? as usize,
                u64_at(value, at + 16).ok_or_else(short)?,
                u32_at(value, at + 24).ok_or_else(short)?,
            )
        } else {
            (
                u32_at(value, at + 4).ok_or_else(short)? as usize,
                u64_at(value, at + 8).ok_or_else(short)?,
                u32_at(value, at + 16).ok_or_else(short)?,
            )
        };
        let path = value
            .get(path_at..path_at + len)
            .ok_or_else(|| error(at, "AppCompatCache path outside the value"))?;
        entries.push(Entry {
            position: i,
            path: utf16(path),
            last_modified: modified,
            executed: Some(flags & EXECUTED_FLAG != 0),
        });
    }
    Ok((format, entries))
}
