//! The SAM hive's local accounts and groups (`SAM\Domains\Account` and
//! `SAM\Domains\Builtin`), as libyal's winreg-kb documents them.
//!
//! - `Users\<RID>`'s `F` value: last logon, password last set, account
//!   expiry and last failed logon (FILETIMEs), the RID, the account control
//!   flags (disabled, password not required, …), failed logons and logons
//!   counted. Its `V` value: 17 descriptors (offset from byte 0xCC, size),
//!   the account's name, full name and comment among them; the password
//!   hashes it also holds are never read here.
//! - `Users\Names\<name>`: one key per account, written when it was
//!   created (the key's time is the account's creation, as far as nothing
//!   rewrote it).
//! - `Aliases\<RID>`'s `C` value: a local group's name, description and
//!   members (their SIDs): `Builtin\Aliases\00000220` is Administrators.

use common::win::sid_to_string;

use crate::artifact::{bytes, Found};
use crate::{u64_at, Hive, Key};

/// Where accounts are.
const USERS: &str = r"SAM\Domains\Account\Users";
/// Where the built-in and the machine's local groups are.
const ALIASES: [&str; 2] = [
    r"SAM\Domains\Builtin\Aliases",
    r"SAM\Domains\Account\Aliases",
];
/// Where a `V` value's data starts: after its 17 descriptors.
const V_DATA: usize = 0xCC;
/// Where a `C` value's data starts.
const C_DATA: usize = 52;
/// A FILETIME meaning never.
const NEVER: u64 = 0x7FFF_FFFF_FFFF_FFFF;

/// A local account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Its relative identifier (`500`: Administrator, `501`: Guest, 1000
    /// and up: accounts created).
    pub rid: u32,
    /// Its name.
    pub name: Option<String>,
    /// Its full name.
    pub full_name: Option<String>,
    /// Its comment.
    pub comment: Option<String>,
    /// Last logon (FILETIME), `None` when never.
    pub last_logon: Option<u64>,
    /// Password last set (FILETIME).
    pub password_last_set: Option<u64>,
    /// When the account expires (FILETIME), `None` when never.
    pub account_expires: Option<u64>,
    /// Last failed logon (FILETIME).
    pub last_failed_logon: Option<u64>,
    /// The account control flags (`USER_ACCOUNT_DISABLED` = 0x1, …).
    pub flags: u32,
    /// Failed logons counted since the last success.
    pub failed_logons: u16,
    /// Logons counted.
    pub logons: u16,
    /// When its `Names` key was written: its creation, unless rewritten
    /// (FILETIME).
    pub created: Option<u64>,
    /// The account's key in the hive.
    pub key: String,
    /// When that key was last written (FILETIME).
    pub key_last_written: u64,
}

impl User {
    /// The account is disabled (`USER_ACCOUNT_DISABLED`).
    #[must_use]
    pub const fn disabled(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// The account may have no password (`USER_PASSWORD_NOT_REQUIRED`).
    #[must_use]
    pub const fn password_not_required(&self) -> bool {
        self.flags & 0x0004 != 0
    }

    /// Its password never expires (`USER_DONT_EXPIRE_PASSWORD`).
    #[must_use]
    pub const fn password_never_expires(&self) -> bool {
        self.flags & 0x0200 != 0
    }

    /// The account is locked out (`USER_ACCOUNT_AUTO_LOCKED`).
    #[must_use]
    pub const fn locked(&self) -> bool {
        self.flags & 0x0400 != 0
    }
}

/// A local group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Its relative identifier (`544`: Administrators, `555`: Remote Desktop
    /// Users).
    pub rid: u32,
    /// Its name.
    pub name: Option<String>,
    /// Its description.
    pub description: Option<String>,
    /// Its members' SIDs.
    pub members: Vec<String>,
    /// The group's key in the hive.
    pub key: String,
    /// When that key was last written: the last change of members, as far
    /// as nothing else rewrote it (FILETIME).
    pub key_last_written: u64,
}

/// Every account of a SAM hive.
#[must_use]
pub fn users(hive: &Hive<'_>) -> Found<User> {
    let mut found = Found::default();
    let Some(users) = found.open(hive, USERS) else {
        return found;
    };
    let names_path = format!(r"{USERS}\Names");
    let created: Vec<(String, u64)> = found
        .open(hive, &names_path)
        .map(|names| {
            found
                .subkeys(&names, &names_path)
                .iter()
                .map(|name| (name.name.to_lowercase(), name.last_written))
                .collect()
        })
        .unwrap_or_default();
    for account in found.subkeys(&users, USERS) {
        if account.name.eq_ignore_ascii_case("Names") {
            continue;
        }
        let path = format!(r"{USERS}\{}", account.name);
        match user(&account, &path, &created) {
            Ok(user) => found.entries.push(user),
            Err(reason) => found.problem(&path, Some("F"), reason),
        }
    }
    found
}

fn user(account: &Key<'_>, path: &str, created: &[(String, u64)]) -> Result<User, String> {
    let f = bytes(account, "F").ok_or("no F value")?;
    if f.len() < 68 {
        return Err(format!("an F value of {} bytes", f.len()));
    }
    let time = |at: usize| u64_at(&f, at).filter(|&t| t != 0 && t != NEVER);
    let u32_at = |at: usize| u32::from_le_bytes([f[at], f[at + 1], f[at + 2], f[at + 3]]);
    let u16_at = |at: usize| u16::from_le_bytes([f[at], f[at + 1]]);
    let v = bytes(account, "V").unwrap_or_default();
    let name = v_string(&v, 1);
    Ok(User {
        rid: u32_at(48),
        created: name.as_ref().and_then(|name| {
            let lower = name.to_lowercase();
            created.iter().find(|(n, _)| *n == lower).map(|(_, t)| *t)
        }),
        name,
        full_name: v_string(&v, 2),
        comment: v_string(&v, 3),
        last_logon: time(8),
        password_last_set: time(24),
        account_expires: time(32),
        last_failed_logon: time(40),
        flags: u32_at(56),
        failed_logons: u16_at(64),
        logons: u16_at(66),
        key: path.to_owned(),
        key_last_written: account.last_written,
    })
}

/// Descriptor `index` of a `V` value as text (UTF-16LE).
fn v_string(v: &[u8], index: usize) -> Option<String> {
    let at = index * 12;
    let offset = u32::from_le_bytes(v.get(at..at + 4)?.try_into().ok()?) as usize;
    let size = u32::from_le_bytes(v.get(at + 4..at + 8)?.try_into().ok()?) as usize;
    let start = V_DATA.checked_add(offset)?;
    utf16(v.get(start..start.checked_add(size)?)?)
}

/// Every local group of a SAM hive: the built-in ones, then the machine's.
#[must_use]
pub fn groups(hive: &Hive<'_>) -> Found<Group> {
    let mut found = Found::default();
    for parent in ALIASES {
        let Some(aliases) = found.open(hive, parent) else {
            continue;
        };
        for alias in found.subkeys(&aliases, parent) {
            if !alias.name.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let path = format!(r"{parent}\{}", alias.name);
            match bytes(&alias, "C")
                .ok_or_else(|| "no C value".to_owned())
                .and_then(|c| group(&c))
            {
                Ok((rid, name, description, members)) => found.entries.push(Group {
                    rid,
                    name,
                    description,
                    members,
                    key: path,
                    key_last_written: alias.last_written,
                }),
                Err(reason) => found.problem(&path, Some("C"), reason),
            }
        }
    }
    found
}

type GroupParts = (u32, Option<String>, Option<String>, Vec<String>);

/// A `C` value: RID, name, description, members.
fn group(c: &[u8]) -> Result<GroupParts, String> {
    let word = |at: usize| -> Result<usize, String> {
        c.get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
            .ok_or_else(|| format!("a C value of {} bytes", c.len()))
    };
    let rid = word(0)? as u32;
    let text = |offset: usize, size: usize| {
        let start = C_DATA.checked_add(offset)?;
        utf16(c.get(start..start.checked_add(size)?)?)
    };
    let name = text(word(16)?, word(20)?);
    let description = text(word(28)?, word(32)?);
    let (offset, size, count) = (word(40)?, word(44)?, word(48)?);
    let mut members = Vec::new();
    let start = C_DATA.saturating_add(offset);
    let mut array = c
        .get(start..start.saturating_add(size).min(c.len()))
        .unwrap_or_default();
    while members.len() < count && !array.is_empty() {
        let (sid, used) =
            sid_to_string(array).map_err(|e| format!("member {}: {e}", members.len() + 1))?;
        members.push(sid);
        array = &array[used..];
    }
    Ok((rid, name, description, members))
}

/// UTF-16LE text, `None` when empty.
fn utf16(bytes: &[u8]) -> Option<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .take_while(|&u| u != 0)
        .collect();
    Some(String::from_utf16_lossy(&units)).filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `V` value holding `name` as its username.
    fn v_with_name(name: &str) -> Vec<u8> {
        let mut v = vec![0u8; V_DATA];
        let text: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        v[12..16].copy_from_slice(&0u32.to_le_bytes());
        v[16..20].copy_from_slice(&(text.len() as u32).to_le_bytes());
        v.extend(text);
        v
    }

    #[test]
    fn v_strings() {
        let v = v_with_name("backup");
        assert_eq!(v_string(&v, 1).as_deref(), Some("backup"));
        assert_eq!(v_string(&v, 2), None);
        assert_eq!(v_string(&v[..10], 1), None);
    }

    #[test]
    fn group_members() {
        let name: Vec<u8> = "Administrators"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        // S-1-5-21-1-2-3-500.
        let mut sid = vec![1, 5, 0, 0, 0, 0, 0, 5];
        for part in [21u32, 1, 2, 3, 500] {
            sid.extend(part.to_le_bytes());
        }
        let mut c = vec![0u8; C_DATA];
        c[0..4].copy_from_slice(&544u32.to_le_bytes());
        c[16..20].copy_from_slice(&0u32.to_le_bytes());
        c[20..24].copy_from_slice(&(name.len() as u32).to_le_bytes());
        c[40..44].copy_from_slice(&(name.len() as u32).to_le_bytes());
        c[44..48].copy_from_slice(&(sid.len() as u32).to_le_bytes());
        c[48..52].copy_from_slice(&1u32.to_le_bytes());
        c.extend(&name);
        c.extend(&sid);
        let (rid, group_name, _, members) = group(&c).unwrap();
        assert_eq!((rid, group_name.as_deref()), (544, Some("Administrators")));
        assert_eq!(members, ["S-1-5-21-1-2-3-500"]);
        assert!(group(&c[..20]).is_err());
    }
}
