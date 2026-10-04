//! Values (`vk` cells) and their data.

use std::borrow::Cow;

use crate::{error, name, u16_at, u32_at, Error, Hive, BASE_BLOCK};

/// Data stored in the offset field itself: the high bit of the size.
const DATA_INLINE: u32 = 0x8000_0000;
/// Larger data is split into `db` segments (hive format 1.4 and later).
const BIG_DATA_SEGMENT: usize = 16_344;
/// `VALUE_COMP_NAME`: the value's name is Latin-1, not UTF-16.
const VALUE_COMP_NAME: u16 = 0x0001;

/// A value's declared type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `REG_NONE` (0).
    None,
    /// `REG_SZ` (1).
    String,
    /// `REG_EXPAND_SZ` (2).
    ExpandString,
    /// `REG_BINARY` (3).
    Binary,
    /// `REG_DWORD` (4).
    Dword,
    /// `REG_DWORD_BIG_ENDIAN` (5).
    DwordBigEndian,
    /// `REG_LINK` (6).
    Link,
    /// `REG_MULTI_SZ` (7).
    MultiString,
    /// `REG_RESOURCE_LIST` (8).
    ResourceList,
    /// `REG_FULL_RESOURCE_DESCRIPTOR` (9).
    FullResourceDescriptor,
    /// `REG_RESOURCE_REQUIREMENTS_LIST` (10).
    ResourceRequirementsList,
    /// `REG_QWORD` (11).
    Qword,
    /// Anything else (applications store their own types).
    Other(u32),
}

impl Kind {
    /// The type for its number.
    #[must_use]
    pub const fn from_u32(n: u32) -> Self {
        match n {
            0 => Self::None,
            1 => Self::String,
            2 => Self::ExpandString,
            3 => Self::Binary,
            4 => Self::Dword,
            5 => Self::DwordBigEndian,
            6 => Self::Link,
            7 => Self::MultiString,
            8 => Self::ResourceList,
            9 => Self::FullResourceDescriptor,
            10 => Self::ResourceRequirementsList,
            11 => Self::Qword,
            other => Self::Other(other),
        }
    }

    /// Its number, as stored.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::None => 0,
            Self::String => 1,
            Self::ExpandString => 2,
            Self::Binary => 3,
            Self::Dword => 4,
            Self::DwordBigEndian => 5,
            Self::Link => 6,
            Self::MultiString => 7,
            Self::ResourceList => 8,
            Self::FullResourceDescriptor => 9,
            Self::ResourceRequirementsList => 10,
            Self::Qword => 11,
            Self::Other(n) => n,
        }
    }

    /// Its Windows name, `REG_SZ` and so on.
    #[must_use]
    pub fn name(self) -> Cow<'static, str> {
        Cow::Borrowed(match self {
            Self::None => "REG_NONE",
            Self::String => "REG_SZ",
            Self::ExpandString => "REG_EXPAND_SZ",
            Self::Binary => "REG_BINARY",
            Self::Dword => "REG_DWORD",
            Self::DwordBigEndian => "REG_DWORD_BIG_ENDIAN",
            Self::Link => "REG_LINK",
            Self::MultiString => "REG_MULTI_SZ",
            Self::ResourceList => "REG_RESOURCE_LIST",
            Self::FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
            Self::ResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST",
            Self::Qword => "REG_QWORD",
            Self::Other(n) => return Cow::Owned(format!("0x{n:08X}")),
        })
    }
}

/// A value's data, read as its type says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    /// `REG_SZ`, `REG_EXPAND_SZ`, `REG_LINK`: text up to the first NUL.
    String(String),
    /// `REG_MULTI_SZ`: the strings, empty ones dropped.
    MultiString(Vec<String>),
    /// `REG_DWORD`, `REG_DWORD_BIG_ENDIAN`.
    Dword(u32),
    /// `REG_QWORD`.
    Qword(u64),
    /// Anything else, or data too short for its type.
    Bytes(Vec<u8>),
}

/// A value.
#[derive(Debug, Clone)]
pub struct Value<'h> {
    /// Its cell's offset in the bins: a stable locator.
    pub offset: u32,
    /// Its name; `""` for the key's default value.
    pub name: String,
    /// Its declared type.
    pub kind: Kind,
    /// Its raw data.
    pub bytes: Cow<'h, [u8]>,
}

/// UTF-16LE text up to the first NUL.
pub(crate) fn utf16_until_nul(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

impl<'h> Value<'h> {
    pub(crate) fn read(hive: &'h Hive<'h>, offset: u32) -> Result<Self, Error> {
        let cell = hive.cell(offset)?;
        let at = BASE_BLOCK + offset as usize + 4;
        if cell.get(..2) != Some(b"vk") {
            return Err(error(at, "not a value (no vk signature)"));
        }
        let too_short = || error(at, "value cell too short");
        let name_len = usize::from(u16_at(cell, 2).ok_or_else(too_short)?);
        let size = u32_at(cell, 4).ok_or_else(too_short)?;
        let data_at = u32_at(cell, 8).ok_or_else(too_short)?;
        let kind = Kind::from_u32(u32_at(cell, 12).ok_or_else(too_short)?);
        let flags = u16_at(cell, 16).ok_or_else(too_short)?;
        let name_bytes = cell
            .get(20..20 + name_len)
            .ok_or_else(|| error(at + 20, "value name runs past its cell"))?;
        let name = name(name_bytes, flags & VALUE_COMP_NAME != 0);
        let bytes = if size & DATA_INLINE != 0 {
            let len = ((size & !DATA_INLINE) as usize).min(4);
            Cow::Owned(data_at.to_le_bytes()[..len].to_vec())
        } else {
            data(hive, data_at, size as usize)?
        };
        Ok(Self {
            offset,
            name,
            kind,
            bytes,
        })
    }

    /// The data read as its type says.
    #[must_use]
    pub fn data(&self) -> Data {
        let b = &*self.bytes;
        match self.kind {
            Kind::String | Kind::ExpandString | Kind::Link => Data::String(utf16_until_nul(b)),
            Kind::MultiString => {
                let units: Vec<u16> = b
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                Data::MultiString(
                    units
                        .split(|&u| u == 0)
                        .filter(|s| !s.is_empty())
                        .map(String::from_utf16_lossy)
                        .collect(),
                )
            }
            Kind::Dword if b.len() >= 4 => {
                Data::Dword(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            }
            Kind::DwordBigEndian if b.len() >= 4 => {
                Data::Dword(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            }
            Kind::Qword if b.len() >= 8 => {
                Data::Qword(u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8])))
            }
            _ => Data::Bytes(b.to_vec()),
        }
    }
}

/// A value's data of `size` bytes at cell `offset`: one cell, or `db`
/// segments.
fn data<'h>(hive: &'h Hive<'h>, offset: u32, size: usize) -> Result<Cow<'h, [u8]>, Error> {
    if size == 0 {
        return Ok(Cow::Borrowed(&[]));
    }
    let cell = hive.cell(offset)?;
    let at = BASE_BLOCK + offset as usize + 4;
    let big = size > BIG_DATA_SEGMENT && hive.header.minor >= 4 && cell.get(..2) == Some(b"db");
    if !big {
        return cell
            .get(..size)
            .map(Cow::Borrowed)
            .ok_or_else(|| error(at, format!("value data of {size} bytes runs past its cell")));
    }
    let segments =
        usize::from(u16_at(cell, 2).ok_or_else(|| error(at, "big data cell too short"))?);
    let list = hive.cell(u32_at(cell, 4).ok_or_else(|| error(at, "big data cell too short"))?)?;
    let mut out = Vec::with_capacity(size);
    for i in 0..segments {
        let segment =
            u32_at(list, 4 * i).ok_or_else(|| error(at, "big data list runs past its cell"))?;
        let bytes = hive.cell(segment)?;
        let take = (size - out.len()).min(BIG_DATA_SEGMENT).min(bytes.len());
        out.extend_from_slice(&bytes[..take]);
        if out.len() == size {
            break;
        }
    }
    if out.len() < size {
        return Err(error(
            at,
            format!("big data holds {} of its {size} bytes", out.len()),
        ));
    }
    Ok(Cow::Owned(out))
}
