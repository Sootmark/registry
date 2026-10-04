//! USB devices (SYSTEM): mass storage under `<control set>\Enum\USBSTOR`
//! (`<type>&Ven_<vendor>&Prod_<product>&Rev_<revision>\<instance>`), every
//! USB device under `Enum\USB` (`VID_<vendor id>&PID_<product id>\
//! <instance>`), the drive letters and volumes `MountedDevices` last bound
//! to each storage device, and the times Windows keeps per device.
//!
//! The instance is the device's serial number, or an id Windows made up
//! when it has none (its second character is then `&`, and it is unique to
//! this machine only).
//!
//! The times are device properties under `<instance>\Properties\
//! {83da6326-97a6-4088-9453-a1923f573b29}` (`DEVPKEY_Device_InstallDate`
//! and the next ones): `0064` when its driver was last installed, `0065`
//! when first installed, `0066` its last arrival, `0067` its last removal.
//! Windows 8 and later store each as the default value of `…\0064`, typed
//! `0xFFFF0010` (a FILETIME property); Windows 7 as `…\00000064\00000000`'s
//! `Data`, and only the first two. Where a hive has no last arrival, the
//! instance key's last write stands in for it, marked as such: Windows
//! writes that key when the device arrives, but other changes write it too.

use crate::artifact::{text, Found};
use crate::mounted::{self, Mount};
use crate::value::utf16_until_nul;
use crate::{u64_at, Hive, Key};

/// The device property set holding the install and arrival times.
const TIMES: &str = "{83da6326-97a6-4088-9453-a1923f573b29}";
/// The property set holding `DEVPKEY_Device_BusReportedDeviceDesc` (4).
const BUS_REPORTED: &str = "{540b947e-8b40-45bc-a8a2-6a0b894cbda2}";

/// Which enumerator a device was found under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bus {
    /// `Enum\USBSTOR`: mass storage.
    UsbStor,
    /// `Enum\USB`: every USB device (hubs, keyboards, the storage devices'
    /// USB side).
    Usb,
}

impl Bus {
    /// Its key's name: `USBSTOR`, `USB`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::UsbStor => "USBSTOR",
            Self::Usb => "USB",
        }
    }
}

/// Where a device time comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSource {
    /// The device property itself.
    Property,
    /// The instance key's last write, standing in for a missing property.
    KeyLastWritten,
}

/// A device time (FILETIME, UTC) and where it comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceTime {
    /// The time.
    pub filetime: u64,
    /// Where it comes from.
    pub source: TimeSource,
}

/// One device instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The enumerator it was found under.
    pub bus: Bus,
    /// The device key's name: `Disk&Ven_HP&Prod_v100w&Rev_1024`,
    /// `VID_0E0F&PID_0002`.
    pub device: String,
    /// USBSTOR's device type: `Disk`, `CdRom`.
    pub kind: Option<String>,
    /// The vendor: `HP` (USBSTOR, without `Ven_`), `0E0F` (USB, without
    /// `VID_`).
    pub vendor: Option<String>,
    /// The product: `v100w` (without `Prod_`), `0002` (without `PID_`).
    pub product: Option<String>,
    /// USBSTOR's revision, without `Rev_`.
    pub revision: Option<String>,
    /// The instance key's name: the serial number, or Windows' own id.
    pub instance: String,
    /// `FriendlyName`: `HP v100w USB Device`.
    pub friendly_name: Option<String>,
    /// The description the bus reported (`DEVPKEY_Device_BusReportedDeviceDesc`,
    /// Windows 8 and later): the name the device gave itself, present
    /// where `FriendlyName` isn't.
    pub bus_reported_description: Option<String>,
    /// `DeviceDesc`, as stored (`@disk.inf,%disk_devdesc%;Disk drive`).
    pub description: Option<String>,
    /// `Service`: the driver (`disk`, `usbhub`).
    pub service: Option<String>,
    /// `ParentIdPrefix` (Windows XP to 7): ties a USB device to its volumes.
    pub parent_id_prefix: Option<String>,
    /// `LocationInformation`: the port, or the device's own name.
    pub location: Option<String>,
    /// `ContainerID`: the same physical device across enumerators.
    pub container_id: Option<String>,
    /// `Device Parameters\Partmgr\DiskId`: the disk's GUID, as volume
    /// records may name it.
    pub disk_id: Option<String>,
    /// When its driver was last installed (`0064`).
    pub installed: Option<DeviceTime>,
    /// When its driver was first installed (`0065`).
    pub first_installed: Option<DeviceTime>,
    /// When it last arrived (`0066`, or the instance key's last write).
    pub last_arrival: Option<DeviceTime>,
    /// When it was last removed (`0067`).
    pub last_removal: Option<DeviceTime>,
    /// The `MountedDevices` names last bound to it: drive letters and
    /// volumes.
    pub mounts: Vec<String>,
    /// The instance key's path in the hive.
    pub key: String,
    /// When the instance key was last written (FILETIME).
    pub key_last_written: u64,
}

impl Device {
    /// Whether the instance is the device's own serial number (its second
    /// character isn't `&`), so the same device can be recognised on other
    /// machines.
    #[must_use]
    pub fn serial_is_unique(&self) -> bool {
        self.instance.chars().nth(1).is_some_and(|c| c != '&')
    }
}

/// A resource string's readable part: `Disk drive` for
/// `@disk.inf,%disk_devdesc%;Disk drive`; other text as it is.
#[must_use]
pub fn readable(text: &str) -> &str {
    match text.rsplit_once(';') {
        Some((_, rest)) if text.starts_with('@') => rest,
        _ => text,
    }
}

/// Every USBSTOR and USB device instance of `control_set`
/// (`ControlSet001`, …).
#[must_use]
pub fn devices(hive: &Hive<'_>, control_set: &str) -> Found<Device> {
    let mut found = Found::default();
    let mounts = mounted::read(hive).entries;
    for bus in [Bus::UsbStor, Bus::Usb] {
        let path = format!(r"{control_set}\Enum\{}", bus.name());
        let Some(root) = found.open(hive, &path) else {
            continue;
        };
        for device in found.subkeys(&root, &path) {
            let device_path = format!(r"{path}\{}", device.name);
            for instance in found.subkeys(&device, &device_path) {
                let key = format!(r"{device_path}\{}", instance.name);
                let entry = read_device(bus, &device.name, &instance, key, &mounts);
                found.entries.push(entry);
            }
        }
    }
    found
}

fn read_device(
    bus: Bus,
    device: &str,
    instance: &Key<'_>,
    key: String,
    mounts: &[Mount],
) -> Device {
    let names = Names::of(bus, device);
    let time = |id: u32| {
        let filetime = property(instance, TIMES, id).and_then(|data| u64_at(&data, 0))?;
        (filetime != 0).then_some(DeviceTime {
            filetime,
            source: TimeSource::Property,
        })
    };
    let last_arrival = time(0x66).or(Some(DeviceTime {
        filetime: instance.last_written,
        source: TimeSource::KeyLastWritten,
    }));
    Device {
        bus,
        device: device.to_owned(),
        kind: names.kind,
        vendor: names.vendor,
        product: names.product,
        revision: names.revision,
        instance: instance.name.clone(),
        friendly_name: text(instance, "FriendlyName"),
        bus_reported_description: property(instance, BUS_REPORTED, 4)
            .map(|data| utf16_until_nul(&data))
            .filter(|d| !d.is_empty()),
        description: text(instance, "DeviceDesc"),
        service: text(instance, "Service"),
        parent_id_prefix: text(instance, "ParentIdPrefix"),
        location: text(instance, "LocationInformation"),
        container_id: text(instance, "ContainerID"),
        disk_id: disk_id(instance),
        installed: time(0x64),
        first_installed: time(0x65),
        last_arrival,
        last_removal: time(0x67),
        mounts: mounts_of(bus, device, &instance.name, mounts),
        key,
        key_last_written: instance.last_written,
    }
}

/// The device key's name taken apart.
#[derive(Debug, PartialEq, Eq)]
struct Names {
    kind: Option<String>,
    vendor: Option<String>,
    product: Option<String>,
    revision: Option<String>,
}

impl Names {
    fn of(bus: Bus, device: &str) -> Self {
        let field = |prefix: &str| {
            device
                .split('&')
                .find_map(|p| p.strip_prefix(prefix))
                .map(str::to_owned)
        };
        match bus {
            Bus::UsbStor => Self {
                kind: device.split('&').next().map(str::to_owned),
                vendor: field("Ven_"),
                product: field("Prod_"),
                revision: field("Rev_"),
            },
            Bus::Usb => Self {
                kind: None,
                vendor: field("VID_"),
                product: field("PID_"),
                revision: None,
            },
        }
    }
}

fn disk_id(instance: &Key<'_>) -> Option<String> {
    let parameters = instance.subkey("Device Parameters").ok()??;
    text(&parameters.subkey("Partmgr").ok()??, "DiskId")
}

/// A device property's data, in either layout: the default value of
/// `Properties\<set>\<id>` (Windows 8 and later), or `Data` of
/// `Properties\<set>\<id>\00000000` (Windows 7), ids in hexadecimal.
fn property(instance: &Key<'_>, set: &str, id: u32) -> Option<Vec<u8>> {
    let set = instance.subkey("Properties").ok()??.subkey(set).ok()??;
    let key = set
        .subkeys()
        .ok()?
        .into_iter()
        .find(|k| u32::from_str_radix(&k.name, 16).ok() == Some(id))?;
    let value = match key.value("").ok()? {
        Some(value) => value,
        None => key.subkey("00000000").ok()??.value("Data").ok()??,
    };
    Some(value.bytes.into_owned())
}

/// The mounts whose device path names this USBSTOR instance.
fn mounts_of(bus: Bus, device: &str, instance: &str, mounts: &[Mount]) -> Vec<String> {
    if bus != Bus::UsbStor {
        return Vec::new();
    }
    mounts
        .iter()
        .filter(|m| {
            m.binding.device_parts().is_some_and(|(b, d, i)| {
                b.eq_ignore_ascii_case("USBSTOR")
                    && d.eq_ignore_ascii_case(device)
                    && i.eq_ignore_ascii_case(instance)
            })
        })
        .map(|m| m.name.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_names_taken_apart() {
        let names = Names::of(Bus::UsbStor, "Disk&Ven_HP&Prod_v100w&Rev_1024");
        assert_eq!(names.kind.as_deref(), Some("Disk"));
        assert_eq!(names.vendor.as_deref(), Some("HP"));
        assert_eq!(names.product.as_deref(), Some("v100w"));
        assert_eq!(names.revision.as_deref(), Some("1024"));
        let names = Names::of(Bus::Usb, "VID_0E0F&PID_0002&MI_00");
        assert_eq!(names.vendor.as_deref(), Some("0E0F"));
        assert_eq!(names.product.as_deref(), Some("0002"));
        assert_eq!(names.kind, None);
        assert_eq!(Names::of(Bus::Usb, "ROOT_HUB20").vendor, None);
        assert_eq!(
            readable("@disk.inf,%disk_devdesc%;Disk drive"),
            "Disk drive"
        );
        assert_eq!(readable("HP v100w USB Device"), "HP v100w USB Device");
    }
}
