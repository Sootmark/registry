//! Explorer's Start menu cache, in NTUSER.DAT
//! (`Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage` and
//! `StartPage2`): the shortcuts the Start menu and taskbar showed, values
//! `ProgramsCache`, `ProgramsCacheSMP` (Start menu pins) and
//! `ProgramsCacheTBP` (taskbar pins).
//!
//! A value starts with a format version (1, 9, 12 or 19; 12 and 19 then
//! hold a known folder identifier), then a sentinel byte and entries, each
//! a 32-bit size, a shell item list (the shortcut's path, folder by
//! folder) and a sentinel byte: `0` or `1` another entry follows, `2` the
//! list ends.

use crate::artifact::Found;
use crate::shellitem;
use crate::{Data, Hive};

const EXPLORER: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer";
const KEYS: [&str; 2] = ["StartPage", "StartPage2"];
const VALUES: [&str; 3] = ["ProgramsCache", "ProgramsCacheSMP", "ProgramsCacheTBP"];
/// The most entries read from one value, against a damaged chain.
const MAX_ENTRIES: usize = 4096;

/// One value's cached shortcuts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramsCache {
    /// The value's name (`ProgramsCache`, `ProgramsCacheSMP`,
    /// `ProgramsCacheTBP`).
    pub value: String,
    /// The format version.
    pub version: u32,
    /// The known folder the entries are in (versions 12 and 19).
    pub known_folder: Option<String>,
    /// The shortcuts, each its path's names in order.
    pub entries: Vec<Vec<String>>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// Every cache value of both keys.
#[must_use]
pub fn caches(hive: &Hive<'_>) -> Found<ProgramsCache> {
    let mut found = Found::default();
    for name in KEYS {
        let path = format!(r"{EXPLORER}\{name}");
        let Some(key) = found.open(hive, &path) else {
            continue;
        };
        for value in found.values(&key, &path) {
            if !VALUES.iter().any(|v| v.eq_ignore_ascii_case(&value.name)) {
                continue;
            }
            let Data::Bytes(data) = value.data() else {
                continue;
            };
            match parse(&data) {
                Some((version, known_folder, entries)) => found.entries.push(ProgramsCache {
                    value: value.name.clone(),
                    version,
                    known_folder,
                    entries,
                    key: path.clone(),
                    key_last_written: key.last_written,
                }),
                None => found.problem(&path, Some(&value.name), "not a ProgramsCache value"),
            }
        }
    }
    found
}

type Parsed = (u32, Option<String>, Vec<Vec<String>>);

/// A value's version, known folder and entries; `None` when its version
/// isn't one this reads.
fn parse(data: &[u8]) -> Option<Parsed> {
    let version = u32::from_le_bytes(data.get(..4)?.try_into().ok()?);
    let (mut at, known_folder) = match version {
        1 => (8, None),
        9 => (6, None),
        12 | 19 => (20, data.get(4..20).and_then(shellitem::guid)),
        _ => return None,
    };
    let mut sentinel = 0;
    if version != 9 {
        sentinel = *data.get(at)?;
        at += 1;
    }
    let mut entries = Vec::new();
    while matches!(sentinel, 0 | 1) && at < data.len() && entries.len() < MAX_ENTRIES {
        let Some(size) = data
            .get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
        else {
            break;
        };
        at += 4;
        let end = at.saturating_add(size as usize).min(data.len());
        let names: Vec<String> = shellitem::items(&data[at..end])
            .into_iter()
            .map(|item| shellitem::decode(item).name)
            .collect();
        if !names.is_empty() {
            entries.push(names);
        }
        at = end;
        let Some(&next) = data.get(at) else {
            break;
        };
        sentinel = next;
        at += 1;
    }
    Some((version, known_folder, entries))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_versions_and_cut_values() {
        assert_eq!(parse(&[7, 0, 0, 0]), None);
        assert_eq!(parse(&[1, 0]), None);
        let empty = parse(&[1, 0, 0, 0, 0, 0, 0, 0, 2]).unwrap();
        assert_eq!(empty, (1, None, Vec::new()));
    }
}
