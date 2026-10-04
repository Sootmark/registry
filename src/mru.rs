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
//!
//! Each key's last write dates its most recent entry (position 0); the
//! others' times aren't recorded.

use crate::artifact::{mru_list_ex, Found};
use crate::shellitem;
use crate::value::utf16_until_nul;
use crate::{Data, Hive, Key, Value};

const EXPLORER: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer";

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
}

impl List {
    /// Its key's name: `RecentDocs`, `RunMRU`, `TypedPaths`,
    /// `WordWheelQuery`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::RecentDocs => "RecentDocs",
            Self::RunMru => "RunMRU",
            Self::TypedPaths => "TypedPaths",
            Self::WordWheelQuery => "WordWheelQuery",
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
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME): when its position 0 entry
    /// was added.
    pub key_last_written: u64,
}

/// Every entry of the four lists, each list in order of position.
#[must_use]
pub fn entries(hive: &Hive<'_>) -> Found<Entry> {
    let mut found = Found::default();
    for list in [
        List::RecentDocs,
        List::RunMru,
        List::TypedPaths,
        List::WordWheelQuery,
    ] {
        let path = format!(r"{EXPLORER}\{}", list.name());
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
    found
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
            List::TypedPaths => Self::Urls,
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
        List::TypedPaths => {
            value.name.strip_prefix("url")?.parse::<u32>().ok()?;
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
