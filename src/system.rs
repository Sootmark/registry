//! What a machine is: from SYSTEM (of the current control set), its name,
//! time zone and last shutdown; from SOFTWARE, its Windows version,
//! install time and registered owner, and the user profiles on it.
//!
//! - `<control set>\Control\ComputerName\ComputerName`'s `ComputerName`.
//! - `<control set>\Control\TimeZoneInformation`: the zone's key name
//!   (`Eastern Standard Time`), and its offsets from UTC in minutes, UTC
//!   being local time plus the bias (`ActiveTimeBias` is the one in force
//!   when the hive was written).
//! - `<control set>\Control\Windows`'s `ShutdownTime`: a FILETIME, the last
//!   clean shutdown.
//! - `<control set>\Control\SystemInformation`, or where it isn't kept,
//!   `HardwareConfig\<LastConfig>` (the hardware profile last used): the
//!   machine's maker and model, and its BIOS version and release date, as
//!   the firmware gave them.
//! - `Microsoft\Windows NT\CurrentVersion`: product name, edition, version
//!   and build, `InstallDate` (seconds since 1970, rewritten by feature
//!   updates) and `InstallTime` (a FILETIME, Windows 10 and later), the
//!   registered owner and organisation.
//! - `Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>`: each profile's
//!   folder and, where Windows keeps them (`LocalProfileLoadTimeHigh`/`Low`,
//!   `LocalProfileUnloadTimeHigh`/`Low`, Windows 7 and later), when it was
//!   last loaded and unloaded: a logon and a logoff.

use crate::artifact::{bytes, dword, non_empty, qword, text, Found};
use crate::{u64_at, Hive, Key};

const NT: &str = r"Microsoft\Windows NT\CurrentVersion";

/// The machine's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputerName {
    /// `ComputerName`.
    pub name: String,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// The machine's time zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeZone {
    /// `TimeZoneKeyName` (Windows Vista and later): `Eastern Standard Time`.
    pub key_name: Option<String>,
    /// `StandardName`, as written (`@tzres.dll,-112`).
    pub standard_name: Option<String>,
    /// `DaylightName`, as written.
    pub daylight_name: Option<String>,
    /// `Bias`: minutes to add to local standard time to get UTC.
    pub bias: Option<i32>,
    /// `ActiveTimeBias`: the bias in force when the hive was written.
    pub active_time_bias: Option<i32>,
    /// `StandardBias`: added to `Bias` in standard time (usually 0).
    pub standard_bias: Option<i32>,
    /// `DaylightBias`: added to `Bias` in daylight saving time (usually
    /// -60).
    pub daylight_bias: Option<i32>,
    /// `DynamicDaylightTimeDisabled`: whether daylight saving is off.
    pub dynamic_daylight_disabled: Option<bool>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// The last clean shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shutdown {
    /// `ShutdownTime` (FILETIME).
    pub time: u64,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// The Windows version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// `ProductName`: `Windows 10 Pro`.
    pub product_name: Option<String>,
    /// `EditionID`: `Professional`.
    pub edition_id: Option<String>,
    /// `DisplayVersion` (`21H1`) or, before it, `ReleaseId` (`2009`).
    pub display_version: Option<String>,
    /// `CurrentVersion`: `6.1` (stuck at `6.3` since Windows 8.1).
    pub current_version: Option<String>,
    /// `CurrentBuild` (or `CurrentBuildNumber`): `19043`.
    pub current_build: Option<String>,
    /// `CSDVersion`: the service pack.
    pub service_pack: Option<String>,
    /// `InstallDate`: seconds since 1970, UTC.
    pub install_date: Option<u32>,
    /// `InstallTime` (FILETIME; Windows 10 and later).
    pub install_time: Option<u64>,
    /// `RegisteredOwner`.
    pub registered_owner: Option<String>,
    /// `RegisteredOrganization`.
    pub registered_organization: Option<String>,
    /// `SystemRoot`: `C:\Windows`.
    pub system_root: Option<String>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// One user profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The account's SID (the key's name).
    pub sid: String,
    /// `ProfileImagePath`: the profile's folder, as written.
    pub image_path: Option<String>,
    /// When it was last loaded (FILETIME): a logon.
    pub loaded: Option<u64>,
    /// When it was last unloaded (FILETIME): a logoff.
    pub unloaded: Option<u64>,
    /// `State` (bit flags; 0 for a normal local profile).
    pub state: Option<u32>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// The machine's hardware, as its firmware describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardware {
    /// `SystemManufacturer`.
    pub manufacturer: Option<String>,
    /// `SystemProductName`: the model.
    pub model: Option<String>,
    /// `BIOSVersion`.
    pub bios_version: Option<String>,
    /// `BIOSReleaseDate`, as written (`05/20/2020`).
    pub bios_release_date: Option<String>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

/// What a hive says of its machine: SYSTEM gives the first four, SOFTWARE
/// the last two.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// The machine's name.
    pub computer_name: Option<ComputerName>,
    /// Its time zone.
    pub time_zone: Option<TimeZone>,
    /// Its last clean shutdown.
    pub shutdown: Option<Shutdown>,
    /// Its hardware.
    pub hardware: Option<Hardware>,
    /// Its Windows version.
    pub version: Option<Version>,
    /// Its user profiles.
    pub profiles: Vec<Profile>,
}

/// What the hive says of its machine, in a [`Found`] of one.
#[must_use]
pub fn identity(hive: &Hive<'_>) -> Found<Identity> {
    let mut found = Found::default();
    let mut identity = Identity::default();
    match hive.current_control_set() {
        Ok(Some(set)) => {
            identity.computer_name = computer_name(hive, &set, &mut found);
            identity.time_zone = time_zone(hive, &set, &mut found);
            identity.shutdown = shutdown(hive, &set, &mut found);
            identity.hardware = hardware(hive, &set, &mut found);
        }
        Ok(None) => {}
        Err(e) => found.problem("Select", Some("Current"), e.to_string()),
    }
    identity.version = version(hive, &mut found);
    identity.profiles = profiles(hive, &mut found);
    found.entries.push(identity);
    found
}

fn computer_name(hive: &Hive<'_>, set: &str, found: &mut Found<Identity>) -> Option<ComputerName> {
    let path = format!(r"{set}\Control\ComputerName\ComputerName");
    let key = found.open(hive, &path)?;
    Some(ComputerName {
        name: non_empty(&key, "ComputerName")?,
        key: path,
        key_last_written: key.last_written,
    })
}

fn signed(key: &Key<'_>, name: &str) -> Option<i32> {
    dword(key, name).map(|n| n as i32)
}

fn time_zone(hive: &Hive<'_>, set: &str, found: &mut Found<Identity>) -> Option<TimeZone> {
    let path = format!(r"{set}\Control\TimeZoneInformation");
    let key = found.open(hive, &path)?;
    Some(TimeZone {
        key_name: non_empty(&key, "TimeZoneKeyName"),
        standard_name: non_empty(&key, "StandardName"),
        daylight_name: non_empty(&key, "DaylightName"),
        bias: signed(&key, "Bias"),
        active_time_bias: signed(&key, "ActiveTimeBias"),
        standard_bias: signed(&key, "StandardBias"),
        daylight_bias: signed(&key, "DaylightBias"),
        dynamic_daylight_disabled: dword(&key, "DynamicDaylightTimeDisabled").map(|n| n != 0),
        key: path,
        key_last_written: key.last_written,
    })
}

fn hardware(hive: &Hive<'_>, set: &str, found: &mut Found<Identity>) -> Option<Hardware> {
    let system_information = format!(r"{set}\Control\SystemInformation");
    hardware_at(hive, &system_information, found).or_else(|| {
        let profiles = found.open(hive, "HardwareConfig")?;
        let last = text(&profiles, "LastConfig")?;
        hardware_at(hive, &format!(r"HardwareConfig\{last}"), found)
    })
}

/// The firmware's description at `path`, when it holds any of it.
fn hardware_at(hive: &Hive<'_>, path: &str, found: &mut Found<Identity>) -> Option<Hardware> {
    let key = found.open(hive, path)?;
    let hardware = Hardware {
        manufacturer: non_empty(&key, "SystemManufacturer"),
        model: non_empty(&key, "SystemProductName"),
        bios_version: non_empty(&key, "BIOSVersion"),
        bios_release_date: non_empty(&key, "BIOSReleaseDate"),
        key: path.to_owned(),
        key_last_written: key.last_written,
    };
    let any = hardware.manufacturer.is_some()
        || hardware.model.is_some()
        || hardware.bios_version.is_some()
        || hardware.bios_release_date.is_some();
    any.then_some(hardware)
}

fn shutdown(hive: &Hive<'_>, set: &str, found: &mut Found<Identity>) -> Option<Shutdown> {
    let path = format!(r"{set}\Control\Windows");
    let key = found.open(hive, &path)?;
    let time = bytes(&key, "ShutdownTime").and_then(|b| u64_at(&b, 0))?;
    Some(Shutdown {
        time,
        key: path,
        key_last_written: key.last_written,
    })
}

fn version(hive: &Hive<'_>, found: &mut Found<Identity>) -> Option<Version> {
    let key = found.open(hive, NT)?;
    let version = Version {
        product_name: non_empty(&key, "ProductName"),
        edition_id: non_empty(&key, "EditionID"),
        display_version: non_empty(&key, "DisplayVersion").or_else(|| non_empty(&key, "ReleaseId")),
        current_version: non_empty(&key, "CurrentVersion"),
        current_build: non_empty(&key, "CurrentBuild")
            .or_else(|| non_empty(&key, "CurrentBuildNumber")),
        service_pack: non_empty(&key, "CSDVersion"),
        install_date: dword(&key, "InstallDate").filter(|&d| d != 0),
        install_time: qword(&key, "InstallTime").filter(|&t| t != 0),
        registered_owner: non_empty(&key, "RegisteredOwner"),
        registered_organization: non_empty(&key, "RegisteredOrganization"),
        system_root: non_empty(&key, "SystemRoot"),
        key: NT.to_owned(),
        key_last_written: key.last_written,
    };
    // Every hive has a root; only SOFTWARE names a product.
    (version.product_name.is_some() || version.current_build.is_some()).then_some(version)
}

/// A FILETIME split in two DWORD values, `<name>High` and `<name>Low`.
fn split_filetime(key: &Key<'_>, name: &str) -> Option<u64> {
    let high = dword(key, &format!("{name}High"))?;
    let low = dword(key, &format!("{name}Low"))?;
    Some((u64::from(high) << 32) | u64::from(low)).filter(|&t| t != 0)
}

fn profiles(hive: &Hive<'_>, found: &mut Found<Identity>) -> Vec<Profile> {
    let root_path = format!(r"{NT}\ProfileList");
    let Some(root) = found.open(hive, &root_path) else {
        return Vec::new();
    };
    found
        .subkeys(&root, &root_path)
        .into_iter()
        .map(|key| Profile {
            sid: key.name.clone(),
            image_path: text(&key, "ProfileImagePath"),
            loaded: split_filetime(&key, "LocalProfileLoadTime"),
            unloaded: split_filetime(&key, "LocalProfileUnloadTime"),
            state: dword(&key, "State"),
            key: format!(r"{root_path}\{}", key.name),
            key_last_written: key.last_written,
        })
        .collect()
}
