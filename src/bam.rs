//! BAM and DAM (the Background and Desktop Activity Moderators, Windows 10
//! 1709 and later): per user, which programs ran and when last.
//!
//! SYSTEM holds them under `<control set>\Services\bam\State\UserSettings\
//! <SID>` (`dam` for the Desktop Activity Moderator; builds before 1809
//! without `State`). Each value is named by a program (a device path such
//! as `\Device\HarddiskVolume2\Windows\explorer.exe`, or an app's package
//! family name) and starts with a FILETIME: its last run. `Version` and
//! `SequenceNumber` are bookkeeping, not programs.

use crate::{Data, Error, Hive};

/// One program a user ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `bam` or `dam`.
    pub service: &'static str,
    /// The user's SID (the key's name).
    pub sid: String,
    /// The program, as the value's name records it.
    pub program: String,
    /// When it last ran (FILETIME, UTC).
    pub last_run: u64,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// Where each service keeps its per-user keys, newest layout first.
const LAYOUTS: [(&str, &str); 4] = [
    ("bam", r"Services\bam\State\UserSettings"),
    ("bam", r"Services\bam\UserSettings"),
    ("dam", r"Services\dam\State\UserSettings"),
    ("dam", r"Services\dam\UserSettings"),
];

/// Every BAM and DAM entry of `control_set` (`ControlSet001`, …).
///
/// # Errors
/// When a key can't be read; values that can't are left out.
pub fn entries(hive: &Hive<'_>, control_set: &str) -> Result<Vec<Entry>, Error> {
    let mut out = Vec::new();
    for (service, layout) in LAYOUTS {
        let path = format!(r"{control_set}\{layout}");
        let Some(settings) = hive.open(&path)? else {
            continue;
        };
        for user in settings.subkeys()? {
            let key = format!(r"{path}\{}", user.name);
            for value in user.values()?.into_iter().flatten() {
                let Data::Bytes(bytes) = value.data() else {
                    continue;
                };
                let Some(last_run) = bytes
                    .get(..8)
                    .and_then(|b| b.try_into().ok())
                    .map(u64::from_le_bytes)
                else {
                    continue;
                };
                out.push(Entry {
                    service,
                    sid: user.name.clone(),
                    program: value.name.clone(),
                    last_run,
                    key: key.clone(),
                    key_last_written: user.last_written,
                });
            }
        }
    }
    Ok(out)
}
