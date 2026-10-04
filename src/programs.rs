//! Installed programs, as Programs and Features lists them: the
//! `Uninstall` keys of SOFTWARE (`Microsoft\Windows\CurrentVersion\
//! Uninstall`, and `Wow6432Node\…` for 32-bit programs on 64-bit Windows)
//! and of NTUSER.DAT (`Software\Microsoft\…`, programs installed for one
//! user). One subkey per program, named by its product code or its own
//! name; installers write the values, so any may be missing.
//!
//! `InstallDate` is a local date, `YYYYMMDD`, when an installer wrote one.
//! The key's last write dates the install or the program's last update.

use crate::artifact::{non_empty, Found, SystemTime};
use crate::{Data, Hive, Key};

/// Where the keys are, and whether each is the 32-bit view.
const ROOTS: [(&str, bool, bool); 4] = [
    (r"Microsoft\Windows\CurrentVersion\Uninstall", false, false),
    (
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        true,
        false,
    ),
    (
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        false,
        true,
    ),
    (
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        true,
        true,
    ),
];

/// One installed program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// Its key's name: a product code (`{…}`) or a name.
    pub key_name: String,
    /// Whether it's from `Wow6432Node` (a 32-bit program).
    pub wow64: bool,
    /// Whether it's a user's (NTUSER.DAT).
    pub user: bool,
    /// `DisplayName`.
    pub display_name: Option<String>,
    /// `DisplayVersion`.
    pub display_version: Option<String>,
    /// `Publisher`.
    pub publisher: Option<String>,
    /// `InstallDate`, as written (`20141208`).
    pub install_date_text: Option<String>,
    /// `InstallLocation`.
    pub install_location: Option<String>,
    /// `InstallSource`.
    pub install_source: Option<String>,
    /// `UninstallString`.
    pub uninstall_string: Option<String>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

impl Program {
    /// `InstallDate` as a date (local, at midnight), when it's `YYYYMMDD`.
    #[must_use]
    pub fn install_date(&self) -> Option<SystemTime> {
        let text = self.install_date_text.as_deref()?.trim();
        if text.len() != 8 || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let date = SystemTime::date(
            text[..4].parse().ok()?,
            text[4..6].parse().ok()?,
            text[6..].parse().ok()?,
        );
        date.wall_clock_filetime().map(|_| date)
    }
}

/// Every program of every `Uninstall` key in the hive.
#[must_use]
pub fn programs(hive: &Hive<'_>) -> Found<Program> {
    let mut found = Found::default();
    for (root_path, wow64, user) in ROOTS {
        let Some(root) = found.open(hive, root_path) else {
            continue;
        };
        for key in found.subkeys(&root, root_path) {
            let path = format!(r"{root_path}\{}", key.name);
            found.entries.push(program(&key, path, wow64, user));
        }
    }
    found
}

fn program(key: &Key<'_>, path: String, wow64: bool, user: bool) -> Program {
    let install_date_text = match key.value("InstallDate").ok().flatten().map(|v| v.data()) {
        Some(Data::String(s)) => Some(s).filter(|s| !s.trim().is_empty()),
        Some(Data::Dword(n)) => Some(n.to_string()),
        _ => None,
    };
    Program {
        key_name: key.name.clone(),
        wow64,
        user,
        display_name: non_empty(key, "DisplayName"),
        display_version: non_empty(key, "DisplayVersion"),
        publisher: non_empty(key, "Publisher"),
        install_date_text,
        install_location: non_empty(key, "InstallLocation"),
        install_source: non_empty(key, "InstallSource"),
        uninstall_string: non_empty(key, "UninstallString"),
        key: path,
        key_last_written: key.last_written,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_dates_read_when_well_formed() {
        let mut program = Program {
            key_name: String::new(),
            wow64: false,
            user: false,
            display_name: None,
            display_version: None,
            publisher: None,
            install_date_text: Some("20141208".to_owned()),
            install_location: None,
            install_source: None,
            uninstall_string: None,
            key: String::new(),
            key_last_written: 0,
        };
        let date = program.install_date().unwrap();
        assert_eq!((date.year, date.month, date.day), (2014, 12, 8));
        for bad in ["2014128", "20141308", "12/08/2014"] {
            program.install_date_text = Some(bad.to_owned());
            assert_eq!(program.install_date(), None, "{bad}");
        }
    }
}
