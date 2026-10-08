//! A user's most-recently-used lists (NTUSER.DAT, under
//! `Software\Microsoft\Windows\CurrentVersion\Explorer`):
//!
//! - `RecentDocs`: files and folders opened from Explorer, all of them in
//!   the key itself and by extension in its subkeys (`.pdf`, `Folder`).
//!   Each numbered value holds the name in UTF-16, then the shell item of
//!   the shortcut Windows made for it in `Recent`; `MRUListEx` orders them.
//! - `RunMRU`: commands typed in the Run dialog, values `a` to `z` ending in
//!   `\1`; `MRUList` orders them as a string of value names.
//! - `TypedPaths`: paths typed in Explorer's address bar, `url1` the most
//!   recent.
//! - `WordWheelQuery`: searches typed in Explorer (Windows 7 and later), in
//!   the key and per search location in its subkeys; numbered UTF-16
//!   values ordered by `MRUListEx`.
//! - Internet Explorer's `TypedURLs` (`Software\Microsoft\Internet
//!   Explorer`): addresses typed in its address bar (or Explorer's, which
//!   shares it), `url1` the most recent; Windows 8 and later date each in
//!   `TypedURLsTime` (a FILETIME per `url<n>`).
//! - WinRAR (`Software\WinRAR`): `ArcHistory`, the archives it opened, and
//!   `DialogEditHistory\ArcName` and `ExtrPath`, the archive names and
//!   extraction folders typed in its dialogs; values `0` (the most recent),
//!   `1`, …: how data was staged for theft.
//!
//! Each key's last write dates its most recent entry (position 0); the
//! others' times aren't recorded.

use crate::artifact::{mru_list_ex, Found};
use crate::shellitem;
use crate::value::utf16_until_nul;
use crate::{Data, Hive, Key, Value};

const EXPLORER: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer";
const TYPED_URLS: &str = r"Software\Microsoft\Internet Explorer\TypedURLs";
const TYPED_URLS_TIME: &str = r"Software\Microsoft\Internet Explorer\TypedURLsTime";

/// Which list an entry is from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum List {
    /// `RecentDocs`: files and folders opened.
    RecentDocs,
    /// `RunMRU`: Run dialog commands.
    RunMru,
    /// `TypedPaths`: paths typed in Explorer.
    TypedPaths,
    /// `WordWheelQuery`: Explorer searches.
    WordWheelQuery,
    /// `TypedURLs`: addresses typed in Internet Explorer.
    TypedUrls,
    /// WinRAR's `ArcHistory`: archives opened.
    WinRarArchives,
    /// WinRAR's `DialogEditHistory\ArcName`: archive names typed.
    WinRarArchiveNames,
    /// WinRAR's `DialogEditHistory\ExtrPath`: extraction folders typed.
    WinRarExtractPaths,
}

impl List {
    /// Its key's name: `RecentDocs`, `RunMRU`, `TypedPaths`,
    /// `WordWheelQuery`, `TypedURLs`, `ArcHistory`, `ArcName`, `ExtrPath`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::RecentDocs => "RecentDocs",
            Self::RunMru => "RunMRU",
            Self::TypedPaths => "TypedPaths",
            Self::WordWheelQuery => "WordWheelQuery",
            Self::TypedUrls => "TypedURLs",
            Self::WinRarArchives => "ArcHistory",
            Self::WinRarArchiveNames => "ArcName",
            Self::WinRarExtractPaths => "ExtrPath",
        }
    }

    /// Its key's path in the hive.
    #[must_use]
    pub fn path(self) -> String {
        match self {
            Self::TypedUrls => TYPED_URLS.to_owned(),
            Self::WinRarArchives => r"Software\WinRAR\ArcHistory".to_owned(),
            Self::WinRarArchiveNames => r"Software\WinRAR\DialogEditHistory\ArcName".to_owned(),
            Self::WinRarExtractPaths => r"Software\WinRAR\DialogEditHistory\ExtrPath".to_owned(),
            explorer => format!(r"{EXPLORER}\{}", explorer.name()),
        }
    }
}

/// One entry of a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The list.
    pub list: List,
    /// The subkey it's in (`.pdf`, `Folder`, a search location), if not the
    /// list's own key.
    pub sublist: Option<String>,
    /// The value's name.
    pub value: String,
    /// Its position (0: most recent), when the list orders it.
    pub position: Option<usize>,
    /// What was opened, typed or searched (RunMRU's `\1` dropped).
    pub text: String,
    /// `RecentDocs`: the shortcut's name in `Recent` (`report.lnk`).
    pub lnk_name: Option<String>,
    /// `TypedURLs`: when it was typed (FILETIME), from `TypedURLsTime`.
    pub time: Option<u64>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME): when its position 0 entry
    /// was added.
    pub key_last_written: u64,
}

/// Every entry of the lists, each list in order of position.
#[must_use]
pub fn entries(hive: &Hive<'_>) -> Found<Entry> {
    let mut found = Found::default();
    for list in [
        List::RecentDocs,
        List::RunMru,
        List::TypedPaths,
        List::WordWheelQuery,
        List::TypedUrls,
        List::WinRarArchives,
        List::WinRarArchiveNames,
        List::WinRarExtractPaths,
    ] {
        let path = list.path();
        let Some(key) = found.open(hive, &path) else {
            continue;
        };
        read_list(list, None, &key, &path, &mut found);
        if matches!(list, List::RecentDocs | List::WordWheelQuery) {
            for sub in found.subkeys(&key, &path) {
                let sub_path = format!(r"{path}\{}", sub.name);
                read_list(list, Some(&sub.name), &sub, &sub_path, &mut found);
            }
        }
    }
    date_typed_urls(hive, &mut found);
    found
}

/// `TypedURLsTime`'s FILETIME for each `url<n>` of `TypedURLs`.
fn date_typed_urls(hive: &Hive<'_>, found: &mut Found<Entry>) {
    let Some(times) = found.open(hive, TYPED_URLS_TIME) else {
        return;
    };
    let values = found.values(&times, TYPED_URLS_TIME);
    for entry in found
        .entries
        .iter_mut()
        .filter(|e| e.list == List::TypedUrls)
    {
        entry.time = values
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case(&entry.value))
            .and_then(|v| v.bytes.get(..8))
            .map(|b| u64::from_le_bytes(b.try_into().unwrap_or_default()))
            .filter(|&t| t != 0);
    }
}

fn read_list(
    list: List,
    sublist: Option<&str>,
    key: &Key<'_>,
    path: &str,
    found: &mut Found<Entry>,
) {
    let values = found.values(key, path);
    let order = Order::of(list, key, &values);
    let mut entries: Vec<Entry> = values
        .iter()
        .filter_map(|value| {
            let (text, lnk_name) = read_value(list, value)?;
            Some(Entry {
                list,
                sublist: sublist.map(str::to_owned),
                value: value.name.clone(),
                position: order.position(&value.name),
                text,
                lnk_name,
                time: None,
                key: path.to_owned(),
                key_last_written: key.last_written,
            })
        })
        .collect();
    entries.sort_by_key(|e| e.position.unwrap_or(usize::MAX));
    found.entries.extend(entries);
}

/// How a list orders its values.
enum Order {
    /// `MRUListEx`: value numbers, most recent first.
    Numbers(Vec<u32>),
    /// `MRUList`: value names (one letter each), most recent first.
    Letters(String),
    /// `url<n>`: position `n - 1`.
    Urls,
    /// `<n>`: position `n`.
    Index,
}

impl Order {
    fn of(list: List, key: &Key<'_>, values: &[Value<'_>]) -> Self {
        match list {
            List::RecentDocs | List::WordWheelQuery => Self::Numbers(mru_list_ex(key)),
            List::RunMru => Self::Letters(
                values
                    .iter()
                    .find(|v| v.name.eq_ignore_ascii_case("MRUList"))
                    .and_then(|v| match v.data() {
                        Data::String(s) => Some(s),
                        _ => None,
                    })
                    .unwrap_or_default(),
            ),
            List::TypedPaths | List::TypedUrls => Self::Urls,
            List::WinRarArchives | List::WinRarArchiveNames | List::WinRarExtractPaths => {
                Self::Index
            }
        }
    }

    /// A value's position, by its name.
    fn position(&self, name: &str) -> Option<usize> {
        match self {
            Self::Numbers(mru) => {
                let n: u32 = name.parse().ok()?;
                mru.iter().position(|&m| m == n)
            }
            Self::Letters(mru) => {
                let mut chars = name.chars();
                let (Some(c), None) = (chars.next(), chars.next()) else {
                    return None;
                };
                mru.chars().position(|m| m == c)
            }
            Self::Urls => name
                .strip_prefix("url")?
                .parse::<usize>()
                .ok()?
                .checked_sub(1),
            Self::Index => name.parse().ok(),
        }
    }
}

/// A value's text (and, for `RecentDocs`, its shortcut's name), when it's
/// an entry of the list rather than bookkeeping (`MRUListEx`, `MRUList`).
fn read_value(list: List, value: &Value<'_>) -> Option<(String, Option<String>)> {
    match list {
        List::RecentDocs => {
            value.name.parse::<u32>().ok()?;
            Some(recent_doc(&value.bytes))
        }
        List::WordWheelQuery => {
            value.name.parse::<u32>().ok()?;
            Some((utf16_until_nul(&value.bytes), None))
        }
        List::RunMru => {
            let name = value.name.as_str();
            if name.len() != 1 || !name.chars().all(|c| c.is_ascii_lowercase()) {
                return None;
            }
            let Data::String(command) = value.data() else {
                return None;
            };
            let command = command.strip_suffix(r"\1").unwrap_or(&command);
            Some((command.to_owned(), None))
        }
        List::TypedPaths | List::TypedUrls => {
            value.name.strip_prefix("url")?.parse::<u32>().ok()?;
            match value.data() {
                Data::String(path) => Some((path, None)),
                _ => None,
            }
        }
        List::WinRarArchives | List::WinRarArchiveNames | List::WinRarExtractPaths => {
            value.name.parse::<u32>().ok()?;
            match value.data() {
                Data::String(path) => Some((path, None)),
                _ => None,
            }
        }
    }
}

/// A `RecentDocs` value: the name in UTF-16 up to its NUL, then the
/// shortcut's shell item.
fn recent_doc(bytes: &[u8]) -> (String, Option<String>) {
    let name = utf16_until_nul(bytes);
    let item_at = (name.encode_utf16().count() + 1) * 2;
    let lnk_name = bytes
        .get(item_at..)
        .and_then(|rest| shellitem::items(rest).first().copied())
        .map(|item| shellitem::decode(item).name)
        .filter(|n| !n.is_empty());
    (name, lnk_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_docs_read_name_then_shortcut() {
        // A RecentDocs value of plaso's NTUSER-WIN7.DAT, shortened: the
        // name, then a file entry shell item with its long name.
        let mut bytes: Vec<u8> = "Downloads\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        bytes.extend_from_slice(&[0, 0]);
        let (name, lnk) = recent_doc(&bytes);
        assert_eq!(name, "Downloads");
        assert_eq!(lnk, None);
        assert_eq!(recent_doc(&[]), (String::new(), None));
    }
}
