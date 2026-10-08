//! Microsoft Office, in a user's NTUSER.DAT (under
//! `Software\Microsoft\Office\<version>\<application>`):
//!
//! - `File MRU` and `Place MRU`: the documents and folders each
//!   application opened, values `Item <n>` holding
//!   `[F00000000][T<FILETIME in hex>][O00000000]*<path>`: the time is when
//!   the item was last opened. Microsoft 365 keeps them per account under
//!   `User MRU\<account>\`.
//! - `Security\Trusted Documents\TrustRecords`: the documents the user
//!   trusted, by path; the data's first 8 bytes are when (FILETIME), and
//!   its last four `FF FF FF 7F` when the user enabled macros, not only
//!   editing: how a malicious attachment's macros came to run.
//! - `Outlook\Search`: the mail stores Outlook's search indexed, values
//!   named by each store's path (`.pst`, `.ost`): the user's mailboxes and
//!   archives, local copies included.

use crate::artifact::Found;
use crate::{Data, Hive, Key};

const OFFICE: &str = r"Software\Microsoft\Office";
/// The last four bytes of a trust record whose macros were enabled.
const MACROS_ENABLED: [u8; 4] = [0xFF, 0xFF, 0xFF, 0x7F];

/// A document or folder an Office application opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MruItem {
    /// Office's version (`14.0` for 2010, `16.0` for 2016 and later).
    pub version: String,
    /// The application (`Word`, `Excel`, `PowerPoint`, …).
    pub application: String,
    /// `File MRU` or `Place MRU`.
    pub list: String,
    /// The account, for Microsoft 365's per-account lists.
    pub account: Option<String>,
    /// The value's name (`Item 1`).
    pub value: String,
    /// Its position (0: most recent), from the value's number.
    pub position: Option<usize>,
    /// The document or folder.
    pub path: String,
    /// When it was last opened (FILETIME), from the item's `[T…]`.
    pub opened: Option<u64>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// A document the user trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRecord {
    /// Office's version.
    pub version: String,
    /// The application.
    pub application: String,
    /// The document, as Office wrote it (`%USERPROFILE%` kept).
    pub path: String,
    /// When it was trusted (FILETIME).
    pub trusted: Option<u64>,
    /// Whether the user enabled its macros, not only editing.
    pub macros_enabled: bool,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// The mail stores one Outlook version's search indexed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutlookSearch {
    /// Office's version.
    pub version: String,
    /// Each store's path and the number its value holds, in the key's
    /// order.
    pub stores: Vec<(String, u32)>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// Every Outlook version's `Search` key.
#[must_use]
pub fn outlook_search(hive: &Hive<'_>) -> Found<OutlookSearch> {
    let mut found = Found::default();
    for (version, application, app_path) in applications(hive, &mut found) {
        if !application.eq_ignore_ascii_case("Outlook") {
            continue;
        }
        let path = format!(r"{app_path}\Search");
        let Some(key) = found.open(hive, &path) else {
            continue;
        };
        let stores = found
            .values(&key, &path)
            .into_iter()
            .filter(|v| !v.name.is_empty())
            .filter_map(|v| match v.data() {
                Data::Dword(n) => Some((v.name.clone(), n)),
                _ => None,
            })
            .collect();
        found.entries.push(OutlookSearch {
            version,
            stores,
            key: path,
            key_last_written: key.last_written,
        });
    }
    found
}

/// Every item of every Office application's lists.
#[must_use]
pub fn mru(hive: &Hive<'_>) -> Found<MruItem> {
    let mut found = Found::default();
    for (version, application, app_path) in applications(hive, &mut found) {
        for list in ["File MRU", "Place MRU"] {
            let path = format!(r"{app_path}\{list}");
            if let Some(key) = found.open(hive, &path) {
                read_list(&version, &application, list, None, &key, &path, &mut found);
            }
        }
        let users_path = format!(r"{app_path}\User MRU");
        let Some(users) = found.open(hive, &users_path) else {
            continue;
        };
        for account in found.subkeys(&users, &users_path) {
            for list in ["File MRU", "Place MRU"] {
                let path = format!(r"{users_path}\{}\{list}", account.name);
                if let Some(key) = found.open(hive, &path) {
                    let name = Some(account.name.as_str());
                    read_list(&version, &application, list, name, &key, &path, &mut found);
                }
            }
        }
    }
    found
}

/// Every trust record of every Office application.
#[must_use]
pub fn trust_records(hive: &Hive<'_>) -> Found<TrustRecord> {
    let mut found = Found::default();
    for (version, application, app_path) in applications(hive, &mut found) {
        let path = format!(r"{app_path}\Security\Trusted Documents\TrustRecords");
        let Some(key) = found.open(hive, &path) else {
            continue;
        };
        for value in found.values(&key, &path) {
            let (trusted, macros_enabled) = trust(&value.bytes);
            found.entries.push(TrustRecord {
                version: version.clone(),
                application: application.clone(),
                path: value.name.clone(),
                trusted,
                macros_enabled,
                key: path.clone(),
                key_last_written: key.last_written,
            });
        }
    }
    found
}

/// A trust record's data: when (its first 8 bytes, FILETIME) and whether
/// macros were enabled (its last four `FF FF FF 7F`).
fn trust(data: &[u8]) -> (Option<u64>, bool) {
    let trusted = data
        .get(..8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap_or_default()))
        .filter(|&t| t != 0);
    let macros = data.len() >= 12 && data[data.len() - 4..] == MACROS_ENABLED;
    (trusted, macros)
}

/// Each Office version's applications: version, name and key path.
fn applications<T>(hive: &Hive<'_>, found: &mut Found<T>) -> Vec<(String, String, String)> {
    let Some(office) = found.open(hive, OFFICE) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for version in found.subkeys(&office, OFFICE) {
        if !version
            .name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
        {
            continue;
        }
        let version_path = format!(r"{OFFICE}\{}", version.name);
        for app in found.subkeys(&version, &version_path) {
            let app_path = format!(r"{version_path}\{}", app.name);
            out.push((version.name.clone(), app.name.clone(), app_path));
        }
    }
    out
}

fn read_list(
    version: &str,
    application: &str,
    list: &str,
    account: Option<&str>,
    key: &Key<'_>,
    path: &str,
    found: &mut Found<MruItem>,
) {
    let mut items: Vec<MruItem> = found
        .values(key, path)
        .iter()
        .filter_map(|value| {
            let number: usize = value.name.strip_prefix("Item ")?.parse().ok()?;
            let Data::String(text) = value.data() else {
                return None;
            };
            let (opened, item_path) = item(&text);
            Some(MruItem {
                version: version.to_owned(),
                application: application.to_owned(),
                list: list.to_owned(),
                account: account.map(str::to_owned),
                value: value.name.clone(),
                position: number.checked_sub(1),
                path: item_path.to_owned(),
                opened,
                key: path.to_owned(),
                key_last_written: key.last_written,
            })
        })
        .collect();
    items.sort_by_key(|i| i.position.unwrap_or(usize::MAX));
    found.entries.extend(items);
}

/// `[F00000000][T01CCFCBA595DFC30][O00000000]*C:\x.docx`: the time and the
/// path; text without the brackets is all path.
fn item(text: &str) -> (Option<u64>, &str) {
    let Some((tags, path)) = text.split_once('*') else {
        return (None, text);
    };
    let time = tags
        .split('[')
        .filter_map(|tag| tag.strip_suffix(']'))
        .find_map(|tag| tag.strip_prefix('T'))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .filter(|&t| t != 0);
    (time, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_records() {
        let mut data = 0x01D4_0000_0000_0000u64.to_le_bytes().to_vec();
        data.extend([0; 12]);
        data.extend(MACROS_ENABLED);
        assert_eq!(trust(&data), (Some(0x01D4_0000_0000_0000), true));
        let editing = [&data[..20], &[1, 0, 0, 0]].concat();
        assert!(!trust(&editing).1);
        assert_eq!(trust(&[]), (None, false));
    }

    #[test]
    fn items() {
        assert_eq!(
            item(r"[F00000000][T01CCFCBA595DFC30][O00000000]*C:\Users\nfury\x.docx"),
            (Some(0x01CC_FCBA_595D_FC30), r"C:\Users\nfury\x.docx")
        );
        assert_eq!(item(r"C:\plain.docx"), (None, r"C:\plain.docx"));
    }
}
