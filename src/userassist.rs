//! UserAssist: what a user started from Explorer, the Start menu or the
//! taskbar, with how often and when. Values of NTUSER.DAT's
//! `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`,
//! named in ROT13, holding counters and a last-run time.
//!
//! Windows 7 and later write 72-byte records; XP wrote 16 bytes, its run
//! count starting at 5. Paths may start with a known folder's GUID; [`path`]
//! names the ones checked against Eric Zimmerman's RECmd.

/// One UserAssist entry's counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counts {
    /// Times run.
    pub run_count: u32,
    /// Times it got the focus (Windows 7 and later).
    pub focus_count: Option<u32>,
    /// Total focus time, milliseconds (Windows 7 and later).
    pub focus_ms: Option<u32>,
    /// When it last ran (FILETIME; 0 when never recorded).
    pub last_run: u64,
}

/// A ROT13-encoded name, decoded (letters only; everything else as is).
#[must_use]
pub fn decode(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            'a'..='z' => char::from(b'a' + (c as u8 - b'a' + 13) % 26),
            'A'..='Z' => char::from(b'A' + (c as u8 - b'A' + 13) % 26),
            c => c,
        })
        .collect()
}

/// A value's counters, when its data has a known size.
#[must_use]
pub fn counts(data: &[u8]) -> Option<Counts> {
    let u32_at = |at: usize| Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?));
    let u64_at = |at: usize| Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?));
    match data.len() {
        72 => Some(Counts {
            run_count: u32_at(4)?,
            focus_count: Some(u32_at(8)?),
            focus_ms: Some(u32_at(12)?),
            last_run: u64_at(60)?,
        }),
        16 => Some(Counts {
            run_count: u32_at(4)?.saturating_sub(5),
            focus_count: None,
            focus_ms: None,
            last_run: u64_at(8)?,
        }),
        _ => None,
    }
}

/// Known folders a decoded name may start with, and their names
/// (Microsoft's `KNOWNFOLDERID`).
const KNOWN_FOLDERS: &[(&str, &str)] = &[
    ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "System"),
    ("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", "SystemX86"),
    ("{905E63B6-C1BF-494E-B29C-65B732D3D21A}", "ProgramFiles"),
    ("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", "ProgramFilesX86"),
    ("{6D809377-6AF0-444B-8957-A3773F02200E}", "ProgramFilesX64"),
    ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "Windows"),
    ("{9E3995AB-1F9C-4F13-B827-48B24B6C7174}", "User Pinned"),
    ("{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", "Common Programs"),
    ("{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}", "Programs"),
];

/// A decoded name with a leading known folder GUID named: `{System}\cmd.exe`.
#[must_use]
pub fn path(decoded: &str) -> String {
    for (guid, name) in KNOWN_FOLDERS {
        if let Some(rest) = decoded
            .get(..guid.len())
            .filter(|g| g.eq_ignore_ascii_case(guid))
            .map(|_| &decoded[guid.len()..])
        {
            return format!("{{{name}}}{rest}");
        }
    }
    decoded.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_names_and_folders() {
        assert_eq!(decode("HRZR_PGYFRFFVBA"), "UEME_CTLSESSION");
        assert_eq!(
            decode(r"{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\pzq.rkr"),
            r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe"
        );
        assert_eq!(
            path(r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe"),
            r"{System}\cmd.exe"
        );
        assert_eq!(path(r"C:\Tools\x.exe"), r"C:\Tools\x.exe");
        assert!(counts(&[0; 20]).is_none());
        let mut xp = [0_u8; 16];
        xp[4] = 7;
        assert_eq!(counts(&xp).unwrap().run_count, 2);
    }
}
