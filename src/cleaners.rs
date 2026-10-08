//! Anti-forensic and diagnostic traces of programs:
//!
//! - CCleaner's settings, in NTUSER.DAT (`Software\Piriform\CCleaner`):
//!   what it was set to wipe (`(App)Cookies`, `(App)Recent Documents`, …)
//!   and when it last checked for an update (`UpdateKey`, a local date and
//!   time as text). A sign that traces were cleaned on purpose.
//! - Diagnosed applications, in SOFTWARE
//!   (`Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications\<program>`):
//!   programs Windows' memory leak diagnosis watched, with
//!   `LastDetectionTime` (a FILETIME): evidence that the program ran.

use crate::artifact::{text, Found};
use crate::{u64_at, Data, Hive};

const CCLEANER: &str = r"Software\Piriform\CCleaner";
const RADAR: &str = r"Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications";

/// CCleaner's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CCleaner {
    /// Every setting but `UpdateKey`, as name and data (numbers as
    /// decimal), sorted by name.
    pub settings: Vec<(String, String)>,
    /// `UpdateKey`: when it last checked for an update, as written
    /// (`07/13/2013 10:03:14 AM`, local time).
    pub update_key: Option<String>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// CCleaner's settings, if the hive has them.
#[must_use]
pub fn ccleaner(hive: &Hive<'_>) -> Found<CCleaner> {
    let mut found = Found::default();
    let Some(key) = found.open(hive, CCLEANER) else {
        return found;
    };
    let mut settings: Vec<(String, String)> = found
        .values(&key, CCLEANER)
        .into_iter()
        .filter(|v| !v.name.is_empty() && !v.name.eq_ignore_ascii_case("UpdateKey"))
        .filter_map(|v| {
            let data = match v.data() {
                Data::String(s) => s,
                Data::Dword(n) => n.to_string(),
                Data::Qword(n) => n.to_string(),
                _ => return None,
            };
            Some((v.name.clone(), data))
        })
        .collect();
    settings.sort();
    found.entries.push(CCleaner {
        settings,
        update_key: text(&key, "UpdateKey"),
        key: CCLEANER.to_owned(),
        key_last_written: key.last_written,
    });
    found
}

/// A program the memory leak diagnosis watched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosedApplication {
    /// The program's file name (its key's name).
    pub program: String,
    /// `LastDetectionTime` (FILETIME).
    pub last_detection: Option<u64>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// Every diagnosed application.
#[must_use]
pub fn diagnosed_applications(hive: &Hive<'_>) -> Found<DiagnosedApplication> {
    let mut found = Found::default();
    let Some(root) = found.open(hive, RADAR) else {
        return found;
    };
    for program in found.subkeys(&root, RADAR) {
        let path = format!(r"{RADAR}\{}", program.name);
        let last_detection = program
            .value("LastDetectionTime")
            .ok()
            .flatten()
            .and_then(|v| match v.data() {
                Data::Qword(n) => Some(n),
                Data::Bytes(b) => u64_at(&b, 0),
                _ => None,
            })
            .filter(|&t| t != 0);
        found.entries.push(DiagnosedApplication {
            program: program.name.clone(),
            last_detection,
            key: path,
            key_last_written: program.last_written,
        });
    }
    found
}
