//! `MountedDevices` (SYSTEM): what each drive letter (`\DosDevices\E:`)
//! and volume (`\??\Volume{GUID}`) was last bound to. Names with the same
//! data are the same volume, so a letter finds its volume GUID (and the
//! shortcuts and jump lists that recorded that GUID) through it.
//!
//! The data says how Windows recognised the volume (libyal's "Mounted
//! devices" notes): an MBR partition as its disk's signature and the
//! partition's byte offset (12 bytes); a GPT partition as `DMIO:ID:` and the
//! partition's GUID (24 bytes); anything else, removable media included, as
//! the device's path in UTF-16 (`\??\USBSTOR#Disk&Ven_…#<instance>#{class}`,
//! `_??_` in some versions). The key's last write is the only time: it
//! dates the latest change to any of its values, not each one.

use crate::artifact::Found;
use crate::shellitem;
use crate::Hive;

/// What a name stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A drive letter (`\DosDevices\E:`).
    DriveLetter(char),
    /// A volume, by its GUID (`\??\Volume{…}`), braces kept.
    Volume(String),
    /// Anything else (`#{GUID}` names, …).
    Other,
}

/// How the volume was recognised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// An MBR partition: its disk's signature and the partition's offset in
    /// bytes.
    Mbr {
        /// The disk signature, from the MBR at byte 440.
        disk_signature: u32,
        /// The partition's start, in bytes from the disk's start.
        offset: u64,
    },
    /// A GPT partition, by its GUID.
    Gpt(String),
    /// A device, by its path (`\??\USBSTOR#…`, `\??\SCSI#…`).
    Device(String),
    /// Anything else, as stored.
    Other(Vec<u8>),
}

impl Binding {
    fn read(bytes: &[u8]) -> Self {
        if bytes.len() == 12 {
            return Self::Mbr {
                disk_signature: crate::u32_at(bytes, 0).unwrap_or(0),
                offset: crate::u64_at(bytes, 4).unwrap_or(0),
            };
        }
        if let Some(guid) = bytes
            .strip_prefix(b"DMIO:ID:")
            .and_then(shellitem::guid)
            .filter(|_| bytes.len() == 24)
        {
            return Self::Gpt(guid);
        }
        let text = crate::value::utf16_until_nul(bytes);
        if bytes.len() % 2 == 0 && (text.starts_with(r"\??\") || text.starts_with("_??_")) {
            return Self::Device(text);
        }
        Self::Other(bytes.to_vec())
    }

    /// A device path's parts: bus (`USBSTOR`), device (`Disk&Ven_…`) and
    /// instance (the serial number, `…&0`).
    #[must_use]
    pub fn device_parts(&self) -> Option<(&str, &str, &str)> {
        let Self::Device(path) = self else {
            return None;
        };
        let mut parts = path.get(4..)?.split('#');
        Some((parts.next()?, parts.next()?, parts.next()?))
    }
}

/// One name and what it was bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// The value's name: `\DosDevices\E:`, `\??\Volume{…}`.
    pub name: String,
    /// What the name stands for.
    pub target: Target,
    /// What it was bound to.
    pub binding: Binding,
    /// The other names with the same data (a letter's volumes, a volume's
    /// letters), in the hive's order.
    pub same_binding: Vec<String>,
    /// When the key was last written (FILETIME): any value's latest change.
    pub key_last_written: u64,
}

fn target(name: &str) -> Target {
    if let Some(letter) = name
        .strip_prefix(r"\DosDevices\")
        .and_then(|rest| rest.strip_suffix(':'))
        .and_then(|l| l.chars().next().filter(|_| l.len() == 1))
    {
        return Target::DriveLetter(letter);
    }
    match name.strip_prefix(r"\??\Volume") {
        Some(guid) if guid.starts_with('{') => Target::Volume(guid.to_owned()),
        _ => Target::Other,
    }
}

/// Every name in `MountedDevices`.
#[must_use]
pub fn read(hive: &Hive<'_>) -> Found<Mount> {
    let mut found = Found::default();
    let Some(key) = found.open(hive, "MountedDevices") else {
        return found;
    };
    let values = found.values(&key, "MountedDevices");
    for value in &values {
        let same_binding = values
            .iter()
            .filter(|other| other.name != value.name && other.bytes == value.bytes)
            .map(|other| other.name.clone())
            .collect();
        found.entries.push(Mount {
            name: value.name.clone(),
            target: target(&value.name),
            binding: Binding::read(&value.bytes),
            same_binding,
            key_last_written: key.last_written,
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bindings_and_targets_read() {
        let mbr = [0xbd, 0xc3, 0xff, 0xa5, 0, 0, 0x10, 0, 0, 0, 0, 0];
        assert_eq!(
            Binding::read(&mbr),
            Binding::Mbr {
                disk_signature: 0xa5ff_c3bd,
                offset: 1_048_576
            }
        );
        let mut gpt = b"DMIO:ID:".to_vec();
        gpt.extend_from_slice(&[0x11; 16]);
        assert!(matches!(Binding::read(&gpt), Binding::Gpt(g) if g.starts_with("{11111111-")));
        let path: Vec<u8> =
            r"_??_USBSTOR#Disk&Ven_X&Prod_Y&Rev_1#ABC&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
        let device = Binding::read(&path);
        assert_eq!(
            device.device_parts(),
            Some(("USBSTOR", "Disk&Ven_X&Prod_Y&Rev_1", "ABC&0"))
        );
        assert_eq!(
            Binding::read(b"TrueCryptVolumeZ"),
            Binding::Other(b"TrueCryptVolumeZ".to_vec())
        );
        assert_eq!(target(r"\DosDevices\E:"), Target::DriveLetter('E'));
        assert_eq!(
            target(r"\??\Volume{10feca75-e030-11e3-8250-806e6f6e6963}"),
            Target::Volume("{10feca75-e030-11e3-8250-806e6f6e6963}".to_owned())
        );
        assert_eq!(
            target("#{422b05dd-2c99-11e4-8260-ac220b2a5a56}"),
            Target::Other
        );
    }
}
