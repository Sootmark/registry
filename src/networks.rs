//! Networks a machine joined (SOFTWARE, Windows Vista and later), from the
//! Network List Service's keys under `Microsoft\Windows NT\CurrentVersion\
//! NetworkList` (libyal's notes, plaso's networks plugin).
//!
//! `Profiles\{GUID}` holds each network's name (the SSID of a wireless
//! one), its type and category, and when it was first and last connected
//! to. Those two are `SYSTEMTIME`s in the machine's local time, not UTC,
//! and nothing in the key says which zone: they are kept as wall-clock
//! times. `Signatures\Managed` and `Signatures\Unmanaged` (domain networks
//! and the others) tie each profile to what identified the network: the
//! default gateway's MAC address and the DNS suffix.

use crate::artifact::{bytes, dword, non_empty, text, Found, SystemTime};
use crate::{Hive, Key};

const ROOT: &str = r"Microsoft\Windows NT\CurrentVersion\NetworkList";

/// What identified a network: one `Signatures` subkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Whether it's under `Managed` (a domain network) or `Unmanaged`.
    pub managed: bool,
    /// The default gateway's MAC address (`00-18-F8-EA-2E-A2`).
    pub gateway_mac: Option<String>,
    /// `DnsSuffix` (`<none>` when there was none).
    pub dns_suffix: Option<String>,
    /// `FirstNetwork`: the network's name when first seen.
    pub first_network: Option<String>,
    /// `Description`.
    pub description: Option<String>,
    /// The subkey's path in the hive.
    pub key: String,
    /// When the subkey was last written (FILETIME).
    pub key_last_written: u64,
}

/// One network profile, with its signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The profile's GUID (its key's name), braces kept.
    pub guid: String,
    /// `ProfileName`: the network's name, a wireless network's SSID.
    pub name: Option<String>,
    /// `Description`.
    pub description: Option<String>,
    /// `NameType`: 6 wired, 23 VPN, 71 wireless, 243 mobile broadband.
    pub name_type: Option<u32>,
    /// `Category`: 0 public, 1 private, 2 domain.
    pub category: Option<u32>,
    /// `Managed`: whether it's a domain network.
    pub managed: Option<bool>,
    /// `DateCreated`: when first connected to, local time.
    pub created: Option<SystemTime>,
    /// `DateLastConnected`: when last connected to, local time.
    pub last_connected: Option<SystemTime>,
    /// The signatures naming this profile.
    pub signatures: Vec<Signature>,
    /// The profile key's path in the hive (`None` for signatures whose
    /// profile is gone).
    pub key: Option<String>,
    /// When the profile key was last written (FILETIME).
    pub key_last_written: Option<u64>,
}

impl Profile {
    /// What `NameType` says the network is: `wired`, `vpn`, `wireless`,
    /// `mobile broadband`.
    #[must_use]
    pub fn kind(&self) -> Option<&'static str> {
        match self.name_type? {
            6 => Some("wired"),
            23 => Some("vpn"),
            71 => Some("wireless"),
            243 => Some("mobile broadband"),
            _ => None,
        }
    }

    /// What `Category` says: `public`, `private`, `domain`.
    #[must_use]
    pub fn category_name(&self) -> Option<&'static str> {
        match self.category? {
            0 => Some("public"),
            1 => Some("private"),
            2 => Some("domain"),
            _ => None,
        }
    }

    fn orphan(guid: String) -> Self {
        Self {
            guid,
            name: None,
            description: None,
            name_type: None,
            category: None,
            managed: None,
            created: None,
            last_connected: None,
            signatures: Vec::new(),
            key: None,
            key_last_written: None,
        }
    }
}

/// Every profile, each with its signatures; signatures naming a profile
/// that's gone come last, as profiles of their own.
#[must_use]
pub fn profiles(hive: &Hive<'_>) -> Found<Profile> {
    let mut found = Found::default();
    let profiles_path = format!(r"{ROOT}\Profiles");
    if let Some(profiles) = found.open(hive, &profiles_path) {
        for key in found.subkeys(&profiles, &profiles_path) {
            let path = format!(r"{profiles_path}\{}", key.name);
            found.entries.push(profile(&key, path));
        }
    }
    for (managed, group) in [(true, "Managed"), (false, "Unmanaged")] {
        let path = format!(r"{ROOT}\Signatures\{group}");
        let Some(signatures) = found.open(hive, &path) else {
            continue;
        };
        for key in found.subkeys(&signatures, &path) {
            let guid = text(&key, "ProfileGuid").unwrap_or_default();
            let signature = signature(&key, format!(r"{path}\{}", key.name), managed);
            attach(&mut found.entries, guid, signature);
        }
    }
    found
}

fn profile(key: &Key<'_>, path: String) -> Profile {
    let time = |name| bytes(key, name).as_deref().and_then(SystemTime::parse);
    Profile {
        name: text(key, "ProfileName"),
        description: text(key, "Description"),
        name_type: dword(key, "NameType"),
        category: dword(key, "Category"),
        managed: dword(key, "Managed").map(|m| m != 0),
        created: time("DateCreated"),
        last_connected: time("DateLastConnected"),
        key: Some(path),
        key_last_written: Some(key.last_written),
        ..Profile::orphan(key.name.clone())
    }
}

fn signature(key: &Key<'_>, path: String, managed: bool) -> Signature {
    Signature {
        managed,
        gateway_mac: bytes(key, "DefaultGatewayMac")
            .filter(|mac| !mac.is_empty())
            .map(|mac| mac_address(&mac)),
        dns_suffix: non_empty(key, "DnsSuffix"),
        first_network: non_empty(key, "FirstNetwork"),
        description: non_empty(key, "Description"),
        key: path,
        key_last_written: key.last_written,
    }
}

fn attach(profiles: &mut Vec<Profile>, guid: String, signature: Signature) {
    if let Some(profile) = profiles
        .iter_mut()
        .find(|p| p.guid.eq_ignore_ascii_case(&guid))
    {
        profile.signatures.push(signature);
        return;
    }
    let mut orphan = Profile::orphan(guid);
    orphan.signatures.push(signature);
    profiles.push(orphan);
}

/// A MAC address as Windows prints it: `00-18-F8-EA-2E-A2`.
fn mac_address(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_and_names() {
        assert_eq!(
            mac_address(&[0x00, 0x50, 0x56, 0xea, 0x6c, 0xec]),
            "00-50-56-EA-6C-EC"
        );
        let mut profile = Profile::orphan("{X}".to_owned());
        profile.name_type = Some(71);
        profile.category = Some(2);
        assert_eq!(profile.kind(), Some("wireless"));
        assert_eq!(profile.category_name(), Some("domain"));
    }
}
