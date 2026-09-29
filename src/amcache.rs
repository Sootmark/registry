//! Amcache.hve: what Windows inventoried about the programs and files on a
//! machine (with each executable's SHA-1), its drivers and its devices.
//! A file entry means the file was present and inventoried, often because
//! it ran; it isn't by itself proof of execution.
//!
//! Two layouts, and a hive may hold both:
//! - Windows 10 1607 and later: `Root\Inventory*`, one key per entry, its
//!   values named (`LowerCaseLongPath`, `FileId`, `LinkDate`, …).
//! - Windows 8 to early Windows 10: `Root\File\<volume>\<id>` and
//!   `Root\Programs\<id>`, values numbered; the numbers are given names
//!   here (`15` is `FullPath`, `101` is `SHA1`, …).
//!
//! Every value is kept, as text; the accessors read the ones investigations
//! pivot on.

use std::fmt::Write as _;

use crate::{Data, Error, Hive, Key};

/// What an entry describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// A file (`InventoryApplicationFile`, or `File` in the older layout).
    File,
    /// An installed program (`InventoryApplication`, or `Programs`).
    Program,
    /// A Start menu shortcut (`InventoryApplicationShortcut`).
    Shortcut,
    /// A driver binary (`InventoryDriverBinary`).
    DriverBinary,
    /// A driver package (`InventoryDriverPackage`).
    DriverPackage,
    /// A Plug and Play device (`InventoryDevicePnp`).
    DevicePnp,
    /// A device container (`InventoryDeviceContainer`).
    DeviceContainer,
}

impl Class {
    /// Its short name: `file`, `program`, `shortcut`, `driver_binary`,
    /// `driver_package`, `device_pnp`, `device_container`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Program => "program",
            Self::Shortcut => "shortcut",
            Self::DriverBinary => "driver_binary",
            Self::DriverPackage => "driver_package",
            Self::DevicePnp => "device_pnp",
            Self::DeviceContainer => "device_container",
        }
    }
}

/// The newer layout's keys under `Root`, and what their subkeys describe.
const INVENTORY: [(&str, Class); 7] = [
    ("InventoryApplicationFile", Class::File),
    ("InventoryApplication", Class::Program),
    ("InventoryApplicationShortcut", Class::Shortcut),
    ("InventoryDriverBinary", Class::DriverBinary),
    ("InventoryDriverPackage", Class::DriverPackage),
    ("InventoryDevicePnp", Class::DevicePnp),
    ("InventoryDeviceContainer", Class::DeviceContainer),
];

/// The older layout's numbered values of a file entry, named.
const LEGACY_FILE_VALUES: [(&str, &str); 19] = [
    ("0", "ProductName"),
    ("1", "CompanyName"),
    ("2", "FileVersionNumber"),
    ("3", "LanguageCode"),
    ("4", "SwitchBackContext"),
    ("5", "FileVersion"),
    ("6", "Size"),
    ("7", "SizeOfImage"),
    ("8", "PeHeaderHash"),
    ("9", "PeChecksum"),
    ("c", "FileDescription"),
    ("d", "PeSubsystem"),
    ("f", "LinkDate"),
    ("11", "FileModified"),
    ("12", "FileCreated"),
    ("15", "FullPath"),
    ("17", "EntryWritten"),
    ("100", "ProgramId"),
    ("101", "SHA1"),
];

/// The older layout's numbered values of a program entry, named.
const LEGACY_PROGRAM_VALUES: [(&str, &str); 12] = [
    ("0", "Name"),
    ("1", "Version"),
    ("2", "Publisher"),
    ("3", "LanguageCode"),
    ("6", "EntryType"),
    ("7", "UninstallKey"),
    ("a", "InstallDate"),
    ("d", "FilePaths"),
    ("f", "ProductCode"),
    ("10", "PackageCode"),
    ("11", "MsiProductCode"),
    ("12", "MsiPackageCode"),
];

/// One inventoried item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// What it describes.
    pub class: Class,
    /// Its key's name; `<volume>@<id>` for the older layout's files (as
    /// program entries and `Orphan` refer to them).
    pub key: String,
    /// Its key's path under the hive's root (`Root\InventoryApplicationFile\…`).
    pub path: String,
    /// When its key was last written (FILETIME).
    pub last_written: u64,
    /// Whether it comes from the older layout.
    pub legacy: bool,
    /// Its values, as text (numbers in decimal, lists joined with `, `,
    /// other data in hexadecimal), older values under their names.
    pub values: Vec<(String, String)>,
}

impl Entry {
    /// A value's text, if it's there and not empty.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }

    /// The file's path (lower case, as Windows recorded it).
    #[must_use]
    pub fn file_path(&self) -> Option<&str> {
        self.get("LowerCaseLongPath")
            .or_else(|| self.get("FullPath"))
    }

    /// The file's SHA-1 in hexadecimal: its file identifier without the
    /// leading `0000`.
    #[must_use]
    pub fn sha1(&self) -> Option<&str> {
        let id = self.get("FileId").or_else(|| self.get("SHA1"))?;
        let hash = id.strip_prefix("0000").unwrap_or(id);
        (hash.len() == 40 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hash)
    }

    /// The file's size in bytes (`0x`-prefixed hexadecimal in the newer
    /// layout, a number in the older).
    #[must_use]
    pub fn size(&self) -> Option<u64> {
        let size = self.get("Size")?;
        match size.strip_prefix("0x").or_else(|| size.strip_prefix("0X")) {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => size.parse().ok(),
        }
    }

    /// The program an entry belongs to (`ProgramId`).
    #[must_use]
    pub fn program_id(&self) -> Option<&str> {
        self.get("ProgramId")
    }

    /// The PE header's link time (FILETIME): `MM/DD/YYYY HH:MM:SS` in the
    /// newer layout, seconds since 1970 in the older.
    #[must_use]
    pub fn link_date(&self) -> Option<u64> {
        let text = self.get("LinkDate")?;
        if self.legacy {
            unix_seconds(text.parse().ok()?)
        } else {
            date(text)
        }
    }

    /// When a program was installed (FILETIME): `MM/DD/YYYY HH:MM:SS` in
    /// the newer layout, seconds since 1970 in the older.
    #[must_use]
    pub fn install_date(&self) -> Option<u64> {
        let text = self.get("InstallDate")?;
        if self.legacy {
            unix_seconds(text.parse().ok()?)
        } else {
            date(text)
        }
    }

    /// A value in seconds since 1970, as a FILETIME (`DriverTimeStamp`,
    /// the driver's link time).
    #[must_use]
    pub fn unix_time(&self, name: &str) -> Option<u64> {
        unix_seconds(self.get(name)?.parse().ok()?)
    }

    /// An older-layout FILETIME value (`FileModified`, `FileCreated`,
    /// `EntryWritten`).
    #[must_use]
    pub fn filetime(&self, name: &str) -> Option<u64> {
        self.get(name)?.parse().ok().filter(|&t| t != 0)
    }
}

/// An Amcache hive's entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Amcache {
    /// Every entry, newer layout first.
    pub entries: Vec<Entry>,
    /// Keys and values that couldn't be read, and why.
    pub problems: Vec<String>,
}

/// The entries of an Amcache hive; `None` when the hive isn't one (no
/// `Root` with inventory, `File` or `Programs` keys).
///
/// # Errors
/// When the root can't be read.
pub fn read(hive: &Hive<'_>) -> Result<Option<Amcache>, Error> {
    let Some(root) = hive.root()?.subkey("Root")? else {
        return Ok(None);
    };
    let mut amcache = Amcache::default();
    let mut found = false;
    for (name, class) in INVENTORY {
        if let Some(key) = root.subkey(name)? {
            found = true;
            for entry in subkeys(&key, &mut amcache.problems) {
                let path = format!(r"Root\{name}\{}", entry.name);
                let entry = to_entry(
                    &entry,
                    class,
                    entry.name.clone(),
                    path,
                    false,
                    &[],
                    &mut amcache.problems,
                );
                amcache.entries.push(entry);
            }
        }
    }
    if let Some(files) = root.subkey("File")? {
        found = true;
        for volume in subkeys(&files, &mut amcache.problems) {
            for file in subkeys(&volume, &mut amcache.problems) {
                let name = format!("{}@{}", volume.name, file.name);
                let path = format!(r"Root\File\{}\{}", volume.name, file.name);
                let entry = to_entry(
                    &file,
                    Class::File,
                    name,
                    path,
                    true,
                    &LEGACY_FILE_VALUES,
                    &mut amcache.problems,
                );
                amcache.entries.push(entry);
            }
        }
    }
    if let Some(programs) = root.subkey("Programs")? {
        found = true;
        for program in subkeys(&programs, &mut amcache.problems) {
            let entry = to_entry(
                &program,
                Class::Program,
                program.name.clone(),
                format!(r"Root\Programs\{}", program.name),
                true,
                &LEGACY_PROGRAM_VALUES,
                &mut amcache.problems,
            );
            amcache.entries.push(entry);
        }
    }
    Ok(found.then_some(amcache))
}

fn subkeys<'h>(key: &Key<'h>, problems: &mut Vec<String>) -> Vec<Key<'h>> {
    key.subkeys().unwrap_or_else(|e| {
        problems.push(format!("{}: {e}", key.name));
        Vec::new()
    })
}

fn to_entry(
    key: &Key<'_>,
    class: Class,
    name: String,
    path: String,
    legacy: bool,
    numbered: &[(&str, &str)],
    problems: &mut Vec<String>,
) -> Entry {
    let mut values = Vec::new();
    match key.values() {
        Ok(read) => {
            for value in read {
                match value {
                    Ok(value) => {
                        let label = numbered
                            .iter()
                            .find(|(number, _)| value.name.eq_ignore_ascii_case(number))
                            .map_or(value.name.as_str(), |(_, label)| label);
                        values.push((label.to_owned(), text(&value.data())));
                    }
                    Err(e) => problems.push(format!("{name}: {e}")),
                }
            }
        }
        Err(e) => problems.push(format!("{name}: {e}")),
    }
    Entry {
        class,
        key: name,
        path,
        last_written: key.last_written,
        legacy,
        values,
    }
}

fn text(data: &Data) -> String {
    match data {
        Data::String(s) => s.clone(),
        Data::MultiString(list) => list.join(", "),
        Data::Dword(n) => n.to_string(),
        Data::Qword(n) => n.to_string(),
        Data::Bytes(bytes) => bytes.iter().fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        }),
    }
}

/// `MM/DD/YYYY HH:MM:SS` (UTC) as a FILETIME.
fn date(text: &str) -> Option<u64> {
    let (day, time) = text.split_once(' ')?;
    let mut date = day.split('/').map(str::parse::<i64>);
    let (month, mday, year) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let mut clock = time.split(':').map(str::parse::<i64>);
    let (hour, minute, second) = (
        clock.next()?.ok()?,
        clock.next()?.ok()?,
        clock.next()?.ok()?,
    );
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&mday)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(year, month, mday);
    unix_seconds(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Seconds since 1970 as a FILETIME.
fn unix_seconds(seconds: i64) -> Option<u64> {
    let ticks = (seconds.checked_add(11_644_473_600)?).checked_mul(10_000_000)?;
    u64::try_from(ticks).ok().filter(|&t| t != 0)
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_read_as_windows_writes_them() {
        // 2016-07-16 22:55:48 UTC.
        assert_eq!(date("07/16/2016 22:55:48"), unix_seconds(1_468_709_748));
        assert_eq!(date("13/01/2016 00:00:00"), None);
        assert_eq!(date("not a date"), None);
    }
}
