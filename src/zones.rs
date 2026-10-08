//! Internet Explorer's (and Windows') security zones, in NTUSER.DAT
//! (`Software\Microsoft\Windows\CurrentVersion\Internet Settings`) and
//! SOFTWARE (the same path without `Software\`, and its `Wow6432Node`
//! view for 32-bit programs): for each zone (0 My
//! Computer, 1 Local intranet, 2 Trusted sites, 3 Internet, 4 Restricted
//! sites), what it lets pages and files do, under `Zones\<n>` and, for the
//! locked-down local machine zone, `Lockdown_Zones\<n>`.
//!
//! Each setting is a value named by its action number (`1201`: run
//! unsigned ActiveX controls, `1400`: scripting, `1806`: launch programs
//! and unsafe files, `2500`: protected mode) holding `0` allowed, `1`
//! prompt, `3` disallowed. A zone opened up is how some payloads ran
//! without a prompt.

use crate::artifact::Found;
use crate::{Data, Hive};

const SETTINGS: &str = r"Microsoft\Windows\CurrentVersion\Internet Settings";

/// The cookie settings' values, which aren't zone settings.
const COOKIES: [&str; 2] = [
    "{A8A88C49-5EB2-4990-A1A2-0876022C854F}",
    "{AEBA21FA-782A-4A90-978D-B72164C80120}",
];

/// A zone's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// Whether it's a user's (NTUSER.DAT) rather than the machine's.
    pub user: bool,
    /// Whether it's in `Wow6432Node`, for 32-bit programs.
    pub wow64: bool,
    /// Whether it's under `Lockdown_Zones`.
    pub lockdown: bool,
    /// The zone's number, its key's name.
    pub zone: String,
    /// Its name, for the five standard zones.
    pub name: Option<&'static str>,
    /// Its settings: value name and data (numbers as decimal), sorted by
    /// name.
    pub settings: Vec<(String, String)>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// The standard zone named by a key.
fn zone_name(zone: &str) -> Option<&'static str> {
    Some(match zone {
        "0" => "My Computer",
        "1" => "Local Intranet Zone",
        "2" => "Trusted sites Zone",
        "3" => "Internet Zone",
        "4" => "Restricted Sites Zone",
        "5" => "Custom",
        _ => return None,
    })
}

/// Every zone, the machine's first (native, then 32-bit).
#[must_use]
pub fn zones(hive: &Hive<'_>) -> Found<Zone> {
    let mut found = Found::default();
    for (prefix, user, wow64) in [
        ("", false, false),
        (r"Wow6432Node\", false, true),
        (r"Software\", true, false),
    ] {
        for (folder, lockdown) in [("Lockdown_Zones", true), ("Zones", false)] {
            let root_path = format!(r"{prefix}{SETTINGS}\{folder}");
            let Some(root) = found.open(hive, &root_path) else {
                continue;
            };
            for zone in found.subkeys(&root, &root_path) {
                let path = format!(r"{root_path}\{}", zone.name);
                let mut settings: Vec<(String, String)> = found
                    .values(&zone, &path)
                    .into_iter()
                    .filter(|v| !v.name.is_empty() && !COOKIES.contains(&v.name.as_str()))
                    .filter_map(|v| {
                        let data = match v.data() {
                            Data::Dword(n) => n.to_string(),
                            Data::Qword(n) => n.to_string(),
                            Data::String(s) => s,
                            _ => return None,
                        };
                        Some((v.name.clone(), data))
                    })
                    .collect();
                settings.sort();
                found.entries.push(Zone {
                    user,
                    wow64,
                    lockdown,
                    name: zone_name(&zone.name),
                    zone: zone.name.clone(),
                    settings,
                    key: path,
                    key_last_written: zone.last_written,
                });
            }
        }
    }
    found
}
