//! The drives a user mounted, in NTUSER.DAT:
//!
//! - `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`:
//!   one subkey per drive letter, volume (`{GUID}`, matching the SYSTEM
//!   hive's `MountedDevices`) or network share (`##server#share#…`) the
//!   user's Explorer saw, with the label it gave it (`_LabelFromReg`); the
//!   subkey's last write is about when it was last connected.
//! - `Network\<letter>`: the network drives mapped to a letter for good,
//!   with the share (`RemotePath`), the account used (`UserName`, when not
//!   the user's own) and the provider.

use crate::artifact::{non_empty, text, Found};
use crate::Hive;

const MOUNT_POINTS: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2";
const NETWORK: &str = "Network";

/// What a mount point is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountKind {
    /// A drive letter (`C`, `CPC`).
    Drive,
    /// A volume, by its GUID.
    Volume,
    /// A network share.
    Remote {
        /// The server.
        server: String,
        /// The share and the path below it (`\home\nfury`).
        share: String,
    },
}

/// A drive, volume or share the user's Explorer saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountPoint {
    /// The subkey's name.
    pub name: String,
    /// What it is.
    pub kind: MountKind,
    /// The label Explorer showed (`_LabelFromReg`, `_LabelFromDesktopINI`).
    pub label: Option<String>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// A network drive mapped to a letter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDrive {
    /// The drive letter.
    pub letter: String,
    /// The share (`\\controller\public`).
    pub remote_path: Option<String>,
    /// Its server.
    pub server: Option<String>,
    /// Its share, from the backslash after the server.
    pub share: Option<String>,
    /// The account it was mapped with, when not the user's own.
    pub user_name: Option<String>,
    /// The network provider (`Microsoft Windows Network`).
    pub provider: Option<String>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME): when it was mapped.
    pub key_last_written: u64,
}

/// Every mount point the user's Explorer saw.
#[must_use]
pub fn mount_points(hive: &Hive<'_>) -> Found<MountPoint> {
    let mut found = Found::default();
    let Some(points) = found.open(hive, MOUNT_POINTS) else {
        return found;
    };
    for point in found.subkeys(&points, MOUNT_POINTS) {
        let kind = if let Some(remote) = point.name.strip_prefix("##") {
            let mut parts = remote.split('#');
            let server = parts.next().unwrap_or_default().to_owned();
            let share = parts.fold(String::new(), |mut share, part| {
                share.push('\\');
                share.push_str(part);
                share
            });
            MountKind::Remote { server, share }
        } else if point.name.starts_with('{') {
            MountKind::Volume
        } else {
            MountKind::Drive
        };
        let label = non_empty(&point, "_LabelFromReg")
            .or_else(|| non_empty(&point, "_LabelFromDesktopINI"));
        found.entries.push(MountPoint {
            key: format!(r"{MOUNT_POINTS}\{}", point.name),
            name: point.name.clone(),
            kind,
            label,
            key_last_written: point.last_written,
        });
    }
    found
}

/// Every network drive mapped to a letter.
#[must_use]
pub fn network_drives(hive: &Hive<'_>) -> Found<NetworkDrive> {
    let mut found = Found::default();
    let Some(network) = found.open(hive, NETWORK) else {
        return found;
    };
    for drive in found.subkeys(&network, NETWORK) {
        let remote_path = text(&drive, "RemotePath").filter(|p| !p.is_empty());
        let (server, share) = remote_path
            .as_deref()
            .and_then(|p| p.trim_start_matches('\\').split_once('\\'))
            .map_or((None, None), |(server, share)| {
                (Some(server.to_owned()), Some(format!("\\{share}")))
            });
        found.entries.push(NetworkDrive {
            key: format!(r"{NETWORK}\{}", drive.name),
            letter: drive.name.clone(),
            server,
            share,
            remote_path,
            user_name: non_empty(&drive, "UserName"),
            provider: non_empty(&drive, "ProviderName"),
            key_last_written: drive.last_written,
        });
    }
    found
}
