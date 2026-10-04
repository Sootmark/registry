//! The incident-response artifacts (`usb`, `mounted`, `rdp`, `mru`,
//! `networks`, `tasks`, `persistence`, `programs`, `system`) on openly
//! licensed hives, fetched by `tests/fetch-hives.sh` and skipped when they
//! aren't there:
//!
//! - Eric Zimmerman's test SYSTEM, SOFTWARE and NTUSER.DAT (MIT,
//!   `ez-large/`), and `NTUSER slack.DAT` for the Run dialog list;
//! - plaso's SYSTEM, SOFTWARE-RunTests and NTUSER-WIN7.DAT (Apache-2.0,
//!   `plaso-large/`), with the values plaso's own Windows Registry plugin
//!   tests expect of them (`tests/parsers/winreg_plugins/*.py` at the
//!   pinned commit), quoted where they're checked;
//! - Andrew Rathbun's Windows 10 VM: SYSTEM, SOFTWARE and NTUSER.DAT (MIT,
//!   `rathbun-large/win10/`).
//!
//! Each is compared with Eric Zimmerman's RECmd (2026.5.0, its
//! `Kroll_Batch.reb` 1.22, run with `--nl` on the hive alone): its plugin
//! files and the batch rows these artifacts need are in
//! `tests/oracle/recmd/`, named by hive. Where RECmd chooses a display form
//! or this crate reads more than it does, the test says so.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;

use registry::{mounted, mru, networks, persistence, programs, rdp, system, tasks, usb};
use registry::{Hive, SystemTime};

fn hive(path: &str) -> Option<Vec<u8>> {
    let full = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path);
    let data = fs::read(&full).ok();
    if data.is_none() {
        eprintln!("{path} not checked (run tests/fetch-hives.sh)");
    }
    data
}

/// RECmd's rows in `tests/oracle/recmd/<name>.csv`, by column name.
fn recmd(name: &str) -> Vec<HashMap<String, String>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/oracle/recmd")
        .join(format!("{name}.csv"));
    let text = fs::read_to_string(path).unwrap();
    let (mut rows, mut row, mut field, mut quoted) = (Vec::new(), Vec::new(), String::new(), false);
    let mut chars = text.trim_start_matches('\u{feff}').chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => row.push(std::mem::take(&mut field)),
            '\r' if !quoted => {}
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            c => field.push(c),
        }
    }
    let header = rows.remove(0);
    rows.into_iter()
        .map(|r| header.iter().cloned().zip(r).collect())
        .collect()
}

/// A batch row's `ValueData` for a value name and description.
fn batch_value(rows: &[HashMap<String, String>], description: &str, value: &str) -> String {
    rows.iter()
        .find(|r| r["Description"] == description && r["ValueName"] == value)
        .map_or_else(
            || panic!("{description} {value}"),
            |r| r["ValueData"].clone(),
        )
}

/// Days since 1970 as a calendar date.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// A FILETIME as RECmd prints it: `2015-02-24 03:22:21.7296539`.
fn when(filetime: u64) -> String {
    let secs = (filetime / 10_000_000) as i64 - 11_644_473_600;
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (year, month, day) = civil(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}.{:07}",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60,
        filetime % 10_000_000
    )
}

/// An optional FILETIME as RECmd prints it, empty when absent.
fn maybe(filetime: Option<u64>) -> String {
    filetime.map(when).unwrap_or_default()
}

/// A wall-clock `SYSTEMTIME` as RECmd prints it.
fn wall(time: Option<SystemTime>) -> String {
    maybe(time.and_then(|t| t.wall_clock_filetime()))
}

fn text(value: Option<&String>) -> String {
    value.cloned().unwrap_or_default()
}

mod usb_devices {
    use super::*;

    fn device_time(time: Option<usb::DeviceTime>) -> String {
        maybe(
            time.filter(|t| t.source == usb::TimeSource::Property)
                .map(|t| t.filetime),
        )
    }

    /// USBSTOR: every device of the test SYSTEM hive, every column RECmd
    /// prints (it adds `Ven_`, `Prod_` and `Rev_` back, and keeps the bus
    /// reported description's NUL).
    #[test]
    fn usbstor_matches_recmd() {
        let Some(data) = hive("ez-large/SYSTEM") else {
            return;
        };
        let hive = Hive::parse(&data).unwrap();
        let found = usb::devices(&hive, "ControlSet001");
        assert!(found.problems.is_empty(), "{:?}", found.problems);
        let ours: BTreeSet<Vec<String>> = found
            .entries
            .iter()
            .filter(|d| d.bus == usb::Bus::UsbStor)
            .map(|d| {
                vec![
                    format!("Ven_{}", text(d.vendor.as_ref())),
                    format!("Prod_{}", text(d.product.as_ref())),
                    format!("Rev_{}", text(d.revision.as_ref())),
                    d.instance.clone(),
                    text(d.bus_reported_description.as_ref()),
                    text(d.disk_id.as_ref()),
                    device_time(d.installed),
                    device_time(d.first_installed),
                    device_time(d.last_arrival),
                    device_time(d.last_removal),
                ]
            })
            .collect();
        let theirs: BTreeSet<Vec<String>> = recmd("ez-SYSTEM_USBSTOR")
            .iter()
            .map(|r| {
                [
                    "Manufacturer",
                    "Title",
                    "Version",
                    "SerialNumber",
                    "DeviceName",
                    "DiskId",
                    "Installed",
                    "FirstInstalled",
                    "LastConnected",
                    "LastRemoved",
                ]
                .iter()
                .map(|c| r[*c].trim_end_matches('\0').to_owned())
                .collect()
            })
            .collect();
        assert_eq!(ours.len(), 9);
        assert_eq!(ours, theirs);
    }

    /// USB: every device of three SYSTEM hives against RECmd (its
    /// `DeviceDesc` is the resource string's readable part). RECmd leaves
    /// a time out where the property is missing; the instance key's last
    /// write, kept here for a missing arrival, isn't compared. RECmd doesn't
    /// read Windows 7's layout of the properties (plaso's SYSTEM): there its
    /// times are empty, and only the other columns are compared (plaso's
    /// test checks one of those times, above).
    #[test]
    fn usb_matches_recmd() {
        for (path, oracle, count, times) in [
            ("ez-large/SYSTEM", "ez-SYSTEM_USB", 26, true),
            ("plaso-large/SYSTEM", "plaso-SYSTEM_USB", 7, false),
            (
                "rathbun-large/win10/SYSTEM",
                "rathbun-win10-SYSTEM_USB",
                8,
                true,
            ),
        ] {
            let Some(data) = hive(path) else { continue };
            let hive = Hive::parse(&data).unwrap();
            let set = hive.current_control_set().unwrap().unwrap();
            let found = usb::devices(&hive, &set);
            assert!(found.problems.is_empty(), "{path}: {:?}", found.problems);
            let ours: BTreeSet<Vec<String>> = found
                .entries
                .iter()
                .filter(|d| d.bus == usb::Bus::Usb)
                .map(|d| {
                    let time = |t| if times { device_time(t) } else { String::new() };
                    vec![
                        d.device.clone(),
                        d.instance.clone(),
                        text(d.parent_id_prefix.as_ref()),
                        text(d.service.as_ref()),
                        d.description
                            .as_deref()
                            .map(usb::readable)
                            .unwrap_or_default()
                            .to_owned(),
                        text(d.location.as_ref()),
                        time(d.installed),
                        time(d.first_installed),
                        time(d.last_arrival),
                        time(d.last_removal),
                    ]
                })
                .collect();
            let theirs: BTreeSet<Vec<String>> = recmd(oracle)
                .iter()
                .map(|r| {
                    [
                        "KeyName",
                        "SerialNumber",
                        "ParentidPrefix",
                        "Service",
                        "DeviceDesc",
                        "LocationInformation",
                        "Installed",
                        "FirstInstalled",
                        "LastConnected",
                        "LastRemoved",
                    ]
                    .iter()
                    .map(|c| r[*c].clone())
                    .collect()
                })
                .collect();
            assert_eq!(ours.len(), count, "{path}");
            assert_eq!(ours, theirs, "{path}");
        }
    }

    /// plaso's USBSTOR and USB plugin tests on its SYSTEM hive (Windows 7:
    /// install times only, so the last arrival is the key's last write).
    #[test]
    fn plaso_system_as_plaso_reads_it() {
        let Some(data) = hive("plaso-large/SYSTEM") else {
            return;
        };
        let hive = Hive::parse(&data).unwrap();
        let found = usb::devices(&hive, "ControlSet001");
        let storage: Vec<&usb::Device> = found
            .entries
            .iter()
            .filter(|d| d.bus == usb::Bus::UsbStor)
            .collect();
        // usbstor.py: "HP v100w USB Device", Ven_HP, Prod_v100w, Rev_1024,
        // driver first and last installation 2011-04-01T04:52:38.686.
        assert_eq!(storage.len(), 1);
        let hp = storage[0];
        assert_eq!(hp.friendly_name.as_deref(), Some("HP v100w USB Device"));
        assert_eq!(hp.kind.as_deref(), Some("Disk"));
        assert_eq!(
            (
                hp.vendor.as_deref(),
                hp.product.as_deref(),
                hp.revision.as_deref()
            ),
            (Some("HP"), Some("v100w"), Some("1024"))
        );
        assert_eq!(hp.instance, "AA951D0000007252&0");
        assert!(hp.serial_is_unique());
        assert_eq!(
            when(hp.installed.unwrap().filetime),
            "2011-04-01 04:52:38.6860000"
        );
        assert_eq!(
            when(hp.first_installed.unwrap().filetime),
            "2011-04-01 04:52:38.6860000"
        );
        let arrival = hp.last_arrival.unwrap();
        assert_eq!(arrival.source, usb::TimeSource::KeyLastWritten);
        assert_eq!(arrival.filetime, hp.key_last_written);
        assert_eq!(hp.last_removal, None);
        // MountedDevices binds it to E: and one volume.
        assert_eq!(hp.mounts.len(), 2);
        assert!(hp.mounts.contains(&r"\DosDevices\E:".to_owned()));
        // usb.py: 7 devices, the fourth VID_0E0F&PID_0002, serial
        // 6&2ab01149&0&2, last written 2012-04-07T10:31:37.6252465.
        let usb: Vec<&usb::Device> = found
            .entries
            .iter()
            .filter(|d| d.bus == usb::Bus::Usb)
            .collect();
        assert_eq!(usb.len(), 7);
        assert_eq!(usb[3].device, "VID_0E0F&PID_0002");
        assert_eq!(
            (usb[3].vendor.as_deref(), usb[3].product.as_deref()),
            (Some("0E0F"), Some("0002"))
        );
        assert_eq!(usb[3].instance, "6&2ab01149&0&2");
        assert!(!usb[3].serial_is_unique());
        assert_eq!(when(usb[3].key_last_written), "2012-04-07 10:31:37.6252465");
    }

    /// `MountedDevices`: the same names as RECmd in three hives; a letter
    /// and its volume share their binding.
    #[test]
    fn mounted_devices_match_recmd() {
        for (path, oracle, count) in [
            ("ez-large/SYSTEM", "ez-SYSTEM_MountedDevices", 65),
            ("plaso-large/SYSTEM", "plaso-SYSTEM_MountedDevices", 11),
            (
                "rathbun-large/win10/SYSTEM",
                "rathbun-win10-SYSTEM_MountedDevices",
                3,
            ),
        ] {
            let Some(data) = hive(path) else { continue };
            let hive = Hive::parse(&data).unwrap();
            let found = mounted::read(&hive);
            assert!(found.problems.is_empty(), "{path}");
            let ours: Vec<String> = found.entries.iter().map(|m| m.name.clone()).collect();
            let theirs: Vec<String> = recmd(oracle)
                .iter()
                .map(|r| r["DeviceName"].clone())
                .collect();
            assert_eq!(ours.len(), count, "{path}");
            assert_eq!(ours, theirs, "{path}");
        }
        let Some(data) = hive("ez-large/SYSTEM") else {
            return;
        };
        let hive = Hive::parse(&data).unwrap();
        let found = mounted::read(&hive);
        let j = found
            .entries
            .iter()
            .find(|m| m.target == mounted::Target::DriveLetter('J'))
            .unwrap();
        assert_eq!(
            j.binding.device_parts(),
            Some((
                "USBSTOR",
                "Disk&Ven_ADATA&Prod_USB_Flash_Drive&Rev_1.00",
                "2361808400440061&0"
            ))
        );
        assert_eq!(
            j.same_binding,
            vec![r"\??\Volume{3aa3a4a9-087f-11e4-825d-ac220b2a5a56}".to_owned()]
        );
        let c = found
            .entries
            .iter()
            .find(|m| m.target == mounted::Target::DriveLetter('C'))
            .unwrap();
        assert_eq!(
            c.binding,
            mounted::Binding::Mbr {
                disk_signature: 0xa5ff_c3bd,
                offset: 368_050_176
            }
        );
        let kinds = |f: fn(&mounted::Binding) -> bool| {
            found.entries.iter().filter(|m| f(&m.binding)).count()
        };
        assert_eq!(kinds(|b| matches!(b, mounted::Binding::Gpt(_))), 3);
        assert_eq!(kinds(|b| matches!(b, mounted::Binding::Other(_))), 4);
    }
}

mod remote_desktop {
    use super::*;

    /// Every host of the test NTUSER.DAT, its user name hint, position in
    /// `Default` (RECmd's -1 for none) and key's last write.
    #[test]
    fn matches_recmd() {
        let Some(data) = hive("ez-large/NTUSER.DAT") else {
            return;
        };
        let hive = Hive::parse(&data).unwrap();
        let found = rdp::connections(&hive);
        assert!(found.problems.is_empty());
        let ours: Vec<[String; 4]> = found
            .entries
            .iter()
            .map(|c| {
                [
                    c.host.clone(),
                    text(c.username_hint.as_ref()),
                    c.mru_position.map_or("-1".to_owned(), |p| p.to_string()),
                    when(c.key_last_written),
                ]
            })
            .collect();
        let theirs: Vec<[String; 4]> = recmd("ez-NTUSER_TerminalServerClient")
            .iter()
            .map(|r| {
                [
                    r["HostName"].clone(),
                    r["Username"].clone(),
                    r["MRUPosition"].clone(),
                    r["LastModified"].clone(),
                ]
            })
            .collect();
        assert_eq!(ours, theirs);
        // The most recent connection is dated by `Default`'s last write.
        let latest = found
            .entries
            .iter()
            .find(|c| c.mru_position == Some(0))
            .unwrap();
        assert_eq!(latest.host, "SU-SVR02");
        assert_eq!(
            when(latest.mru_last_written.unwrap()),
            "2014-11-29 18:06:33.2835701"
        );
        assert_eq!(
            found
                .entries
                .iter()
                .filter(|c| c.mru_last_written.is_some())
                .count(),
            1
        );
    }
}

mod most_recently_used {
    use super::*;

    fn entries(path: &str) -> Option<Vec<mru::Entry>> {
        let data = hive(path)?;
        let hive = Hive::parse(&data).unwrap();
        let found = mru::entries(&hive);
        assert!(found.problems.is_empty(), "{path}: {:?}", found.problems);
        Some(found.entries)
    }

    /// `RecentDocs` in three NTUSER.DAT: every entry's list, value, name,
    /// shortcut name and position. RECmd repeats rows (871 for 510 entries
    /// in the test NTUSER.DAT); they're compared once each.
    #[test]
    fn recent_docs_match_recmd() {
        for (path, oracle, count) in [
            ("ez-large/NTUSER.DAT", "ez-NTUSER_RecentDocs", 510),
            (
                "plaso-large/NTUSER-WIN7.DAT",
                "plaso-NTUSER-WIN7_RecentDocs",
                38,
            ),
            (
                "rathbun-large/win10/NTUSER.DAT",
                "rathbun-win10-NTUSER_RecentDocs",
                26,
            ),
        ] {
            let Some(entries) = entries(path) else {
                continue;
            };
            let ours: BTreeSet<[String; 5]> = entries
                .iter()
                .filter(|e| e.list == mru::List::RecentDocs)
                .map(|e| {
                    [
                        e.sublist.clone().unwrap_or_else(|| "RecentDocs".to_owned()),
                        e.value.clone(),
                        e.text.clone(),
                        text(e.lnk_name.as_ref()),
                        e.position.map(|p| p.to_string()).unwrap_or_default(),
                    ]
                })
                .collect();
            let theirs: BTreeSet<[String; 5]> = recmd(oracle)
                .iter()
                .map(|r| {
                    [
                        r["Extension"].clone(),
                        r["ValueName"].clone(),
                        r["TargetName"].clone(),
                        r["LnkName"].clone(),
                        r["MruPosition"].clone(),
                    ]
                })
                .collect();
            assert_eq!(ours.len(), count, "{path}");
            assert_eq!(ours, theirs, "{path}");
        }
    }

    /// plaso's `mrulistex.py`: `RecentDocs` of NTUSER-WIN7.DAT, 19 entries
    /// in the key itself, most recent first, and five extension subkeys;
    /// the key last written 2012-04-01T13:52:39.1137417.
    #[test]
    fn recent_docs_as_plaso_reads_them() {
        let Some(entries) = entries("plaso-large/NTUSER-WIN7.DAT") else {
            return;
        };
        let own: Vec<&mru::Entry> = entries
            .iter()
            .filter(|e| e.list == mru::List::RecentDocs && e.sublist.is_none())
            .collect();
        assert_eq!(own.len(), 19);
        let order: Vec<&str> = own.iter().map(|e| e.value.as_str()).collect();
        assert_eq!(
            order,
            [
                "17", "18", "16", "12", "15", "14", "13", "8", "7", "11", "10", "9", "6", "4", "5",
                "3", "2", "1", "0"
            ]
        );
        assert_eq!(own[0].text, "The SHIELD");
        assert_eq!(own[0].lnk_name.as_deref(), Some("The SHIELD.lnk"));
        assert_eq!(own[7].lnk_name.as_deref(), Some("StarFury (2).lnk"));
        assert_eq!(when(own[0].key_last_written), "2012-04-01 13:52:39.1137417");
        let sublists: BTreeSet<&str> = entries
            .iter()
            .filter_map(|e| e.sublist.as_deref())
            .collect();
        assert_eq!(sublists.len(), 5);
    }

    /// `RunMRU`: plaso's NTUSER-WIN7.DAT against RECmd, and the 17 commands
    /// of `NTUSER slack.DAT` in `MRUList`'s order.
    #[test]
    fn run_mru() {
        if let Some(entries) = entries("plaso-large/NTUSER-WIN7.DAT") {
            let run: Vec<&mru::Entry> = entries
                .iter()
                .filter(|e| e.list == mru::List::RunMru)
                .collect();
            let theirs = recmd("plaso-NTUSER-WIN7_RunMRU");
            assert_eq!(run.len(), theirs.len());
            for (ours, theirs) in run.iter().zip(&theirs) {
                assert_eq!(ours.value, theirs["ValueName"]);
                assert_eq!(ours.text, theirs["Executable"]);
                assert_eq!(ours.position.unwrap().to_string(), theirs["MruPosition"]);
                assert_eq!(when(ours.key_last_written), theirs["OpenedOn"]);
            }
        }
        let Some(entries) = entries("ez-large/NTUSER slack.DAT") else {
            return;
        };
        let run: Vec<&mru::Entry> = entries
            .iter()
            .filter(|e| e.list == mru::List::RunMru)
            .collect();
        let order: String = run.iter().map(|e| e.value.as_str()).collect();
        assert_eq!(order, "bdhjqpfonmlkicgea");
        assert_eq!(run[4].text, "regsvr32 pstorec.dll");
    }

    /// `TypedPaths` against RECmd's batch rows in three NTUSER.DAT, and
    /// plaso's `typedurls.py` (NTUSER-WIN7.DAT: `url1: \\controller`, last
    /// written 2010-11-10T07:58:15.8116250).
    #[test]
    fn typed_paths() {
        for (path, oracle, count) in [
            ("ez-large/NTUSER.DAT", "ez-NTUSER", 15),
            ("plaso-large/NTUSER-WIN7.DAT", "plaso-NTUSER-WIN7", 1),
            ("rathbun-large/win10/NTUSER.DAT", "rathbun-win10-NTUSER", 1),
        ] {
            let Some(entries) = entries(path) else {
                continue;
            };
            let ours: BTreeMap<String, String> = entries
                .iter()
                .filter(|e| e.list == mru::List::TypedPaths)
                .map(|e| (e.value.clone(), e.text.clone()))
                .collect();
            let theirs: BTreeMap<String, String> = recmd(oracle)
                .iter()
                .filter(|r| r["Description"] == "TypedPaths")
                .map(|r| (r["ValueName"].clone(), r["ValueData"].clone()))
                .collect();
            assert_eq!(ours.len(), count, "{path}");
            assert_eq!(ours, theirs, "{path}");
        }
        let Some(entries) = entries("plaso-large/NTUSER-WIN7.DAT") else {
            return;
        };
        let typed = entries
            .iter()
            .find(|e| e.list == mru::List::TypedPaths)
            .unwrap();
        assert_eq!(
            (typed.value.as_str(), typed.text.as_str()),
            ("url1", r"\\controller")
        );
        assert_eq!(typed.position, Some(0));
        assert_eq!(when(typed.key_last_written), "2010-11-10 07:58:15.8116250");
    }

    /// `WordWheelQuery` against RECmd: search terms, value numbers and
    /// positions.
    #[test]
    fn word_wheel_query_matches_recmd() {
        for (path, oracle, count) in [
            ("ez-large/NTUSER.DAT", "ez-NTUSER_WordWheelQuery", 7),
            (
                "plaso-large/NTUSER-WIN7.DAT",
                "plaso-NTUSER-WIN7_WordWheelQuery",
                2,
            ),
        ] {
            let Some(entries) = entries(path) else {
                continue;
            };
            let ours: Vec<[String; 3]> = entries
                .iter()
                .filter(|e| e.list == mru::List::WordWheelQuery)
                .map(|e| {
                    [
                        e.text.clone(),
                        e.position.unwrap().to_string(),
                        e.value.clone(),
                    ]
                })
                .collect();
            let theirs: Vec<[String; 3]> = recmd(oracle)
                .iter()
                .map(|r| {
                    [
                        r["SearchTerm"].clone(),
                        r["MruPosition"].clone(),
                        r["BatchValueName"].clone(),
                    ]
                })
                .collect();
            assert_eq!(ours.len(), count, "{path}");
            assert_eq!(ours, theirs, "{path}");
        }
    }
}

mod network_profiles {
    use super::*;

    fn name_type(profile: &networks::Profile) -> String {
        match profile.kind() {
            Some("wired") => "Wired".to_owned(),
            Some("wireless") => "Wireless".to_owned(),
            other => format!("{other:?}"),
        }
    }

    /// Every profile of three SOFTWARE hives against RECmd's `KnownNetworks`
    /// plugin: name, type, first and last connection (local time, as
    /// stored), managed, DNS suffix, gateway MAC, first network.
    #[test]
    fn matches_recmd() {
        for (path, oracle, count) in [
            ("ez-large/SOFTWARE", "ez-SOFTWARE_KnownNetworks", 1),
            (
                "plaso-large/SOFTWARE-RunTests",
                "plaso-SOFTWARE-RunTests_KnownNetworks",
                3,
            ),
            (
                "rathbun-large/win10/SOFTWARE",
                "rathbun-win10-SOFTWARE_KnownNetworks",
                1,
            ),
        ] {
            let Some(data) = hive(path) else { continue };
            let hive = Hive::parse(&data).unwrap();
            let found = networks::profiles(&hive);
            assert!(found.problems.is_empty(), "{path}");
            let ours: Vec<Vec<String>> = found
                .entries
                .iter()
                .map(|p| {
                    let signature = p.signatures.first();
                    vec![
                        p.guid.clone(),
                        text(p.name.as_ref()),
                        name_type(p),
                        wall(p.created),
                        wall(p.last_connected),
                        if p.managed == Some(true) {
                            "True"
                        } else {
                            "False"
                        }
                        .to_owned(),
                        text(signature.and_then(|s| s.dns_suffix.as_ref())),
                        text(signature.and_then(|s| s.gateway_mac.as_ref())),
                        text(signature.and_then(|s| s.first_network.as_ref())),
                    ]
                })
                .collect();
            let theirs: Vec<Vec<String>> = recmd(oracle)
                .iter()
                .map(|r| {
                    [
                        "ProfileGUID",
                        "NetworkName",
                        "NameType",
                        "FirstConnectLOCAL",
                        "LastConnectedLOCAL",
                        "Managed",
                        "DNSSuffix",
                        "GatewayMacAddress",
                        "FirstNetwork",
                    ]
                    .iter()
                    .map(|c| r[*c].clone())
                    .collect()
                })
                .collect();
            assert_eq!(ours.len(), count, "{path}");
            assert_eq!(ours, theirs, "{path}");
        }
    }

    /// The domain profile of plaso's SOFTWARE-RunTests, every field.
    #[test]
    fn a_domain_network() {
        let Some(data) = hive("plaso-large/SOFTWARE-RunTests") else {
            return;
        };
        let hive = Hive::parse(&data).unwrap();
        let found = networks::profiles(&hive);
        let domain = found
            .entries
            .iter()
            .find(|p| p.name.as_deref() == Some("shieldbase.local"))
            .unwrap();
        assert_eq!(domain.category_name(), Some("domain"));
        assert_eq!(domain.managed, Some(true));
        assert_eq!(domain.signatures.len(), 1);
        assert!(domain.signatures[0].managed);
        assert_eq!(
            domain.signatures[0].gateway_mac.as_deref(),
            Some("00-18-F8-EA-2E-A2")
        );
        let created = domain.created.unwrap();
        assert_eq!(
            (created.year, created.month, created.day, created.hour),
            (2010, 11, 10, 11)
        );
    }
}

mod scheduled_tasks {
    use super::*;

    fn found(path: &str) -> Option<registry::Found<tasks::Task>> {
        let data = hive(path)?;
        let found = tasks::tasks(&Hive::parse(&data).unwrap());
        assert!(found.problems.is_empty(), "{path}: {:?}", found.problems);
        Some(found)
    }

    /// Every task of the Windows 10 SOFTWARE hive against RECmd's TaskCache
    /// plugin: path, `DynamicInfo` (times, state, result), the program and
    /// arguments of the first action that runs one, author, description,
    /// source and security descriptor.
    #[test]
    fn windows_10_matches_recmd() {
        let Some(found) = found("rathbun-large/win10/SOFTWARE") else {
            return;
        };
        let ours: BTreeMap<String, Vec<String>> = found
            .entries
            .iter()
            .filter(|t| t.dynamic.is_some())
            .map(|t| {
                let dynamic = t.dynamic.unwrap();
                let (command, arguments) = match &t.actions {
                    Some(tasks::Actions::Decoded { actions, .. }) => actions
                        .iter()
                        .find_map(|a| match a {
                            tasks::Action::Exec {
                                command, arguments, ..
                            } => Some((command.clone(), arguments.clone())),
                            tasks::Action::ComHandler { .. } => None,
                        })
                        .unwrap_or_default(),
                    _ => panic!("{}: actions not decoded", t.path),
                };
                let time = |t: u64| if t == 0 { String::new() } else { when(t) };
                (
                    t.id.clone().unwrap(),
                    vec![
                        t.path.clone(),
                        time(dynamic.registered),
                        time(dynamic.last_start),
                        time(dynamic.last_stop.unwrap()),
                        dynamic.state.to_string(),
                        (dynamic.last_result as i32).to_string(),
                        command,
                        arguments,
                        text(t.author.as_ref()),
                        text(t.description.as_ref()),
                        text(t.source.as_ref()),
                        text(t.security_descriptor.as_ref()),
                    ],
                )
            })
            .collect();
        let theirs: BTreeMap<String, Vec<String>> = recmd("rathbun-win10-SOFTWARE_TaskCache")
            .iter()
            .map(|r| {
                let mut r = r.clone();
                // RECmd fails on actions with an id ("Error parsing Actions
                // binary"); this one runs RAServer.exe, checked below.
                if r["Command"] == "Error parsing Actions binary" {
                    r.insert("Command".into(), r"%windir%\system32\RAServer.exe".into());
                    r.insert("Arguments".into(), "/offerraupdate".into());
                }
                (
                    r["KeyName"].clone(),
                    [
                        "Path",
                        "CreatedOn",
                        "LastStart",
                        "LastStop",
                        "TaskState",
                        "LastActionResult",
                        "Command",
                        "Arguments",
                        "Author",
                        "Description",
                        "Source",
                        "SecurityDescriptor",
                    ]
                    .iter()
                    .map(|c| r[*c].clone())
                    .collect(),
                )
            })
            .collect();
        assert_eq!(ours.len(), 197);
        assert_eq!(ours, theirs);
        let assistance = found
            .entries
            .iter()
            .find(|t| t.name() == "RemoteAssistanceTask")
            .unwrap();
        let Some(tasks::Actions::Decoded {
            principal, actions, ..
        }) = &assistance.actions
        else {
            panic!("not decoded");
        };
        assert_eq!(principal, "Creator");
        assert_eq!(
            actions,
            &[tasks::Action::Exec {
                command: r"%windir%\system32\RAServer.exe".to_owned(),
                arguments: "/offerraupdate".to_owned(),
                working_directory: "%windir%".to_owned(),
            }]
        );
        // Every Actions blob decodes; Tree entries whose task key is gone
        // (left behind by feature updates) are kept, without an id.
        assert!(found
            .entries
            .iter()
            .all(|t| !matches!(t.actions, Some(tasks::Actions::Strings(_)))));
        assert_eq!(found.entries.iter().filter(|t| t.id.is_none()).count(), 27);
        assert!(found.entries.iter().all(|t| t.in_tree));
    }

    /// plaso's `task_scheduler.py` on SOFTWARE-RunTests (Windows 7): 85
    /// tasks with `DynamicInfo`; `SynchronizeTime`, task
    /// {044A6734-E90E-4F8F-B357-B2DC8AB3B5EC}, last registered
    /// 2009-07-14T05:08:50.8116269, no launch time.
    #[test]
    fn windows_7_as_plaso_reads_it() {
        let Some(found) = found("plaso-large/SOFTWARE-RunTests") else {
            return;
        };
        let cached: Vec<&tasks::Task> = found
            .entries
            .iter()
            .filter(|t| t.dynamic.is_some())
            .collect();
        assert_eq!(cached.len(), 85);
        let sync = cached
            .iter()
            .find(|t| t.id.as_deref() == Some("{044A6734-E90E-4F8F-B357-B2DC8AB3B5EC}"))
            .unwrap();
        assert_eq!(sync.name(), "SynchronizeTime");
        assert_eq!(
            sync.path,
            r"\Microsoft\Windows\Time Synchronization\SynchronizeTime"
        );
        let dynamic = sync.dynamic.unwrap();
        assert_eq!(when(dynamic.registered), "2009-07-14 05:08:50.8116269");
        assert_eq!(dynamic.last_start, 0);
        assert_eq!(dynamic.last_stop, None);
        // Windows 7 keeps no actions in the registry.
        assert!(found.entries.iter().all(|t| t.actions.is_none()));
    }
}

mod persistence_keys {
    use super::*;

    fn entries(path: &str) -> Option<Vec<persistence::Entry>> {
        let data = hive(path)?;
        let found = persistence::entries(&Hive::parse(&data).unwrap());
        assert!(found.problems.is_empty(), "{path}: {:?}", found.problems);
        Some(found.entries)
    }

    /// The machine keys of three SOFTWARE hives hold Windows' defaults:
    /// nothing departs from them. (None of the open hives sets a
    /// `Debugger`, `GlobalFlag`, `MonitorProcess` or `Taskman`: those are
    /// checked by the unit tests of the decisions only.)
    #[test]
    fn defaults_in_clean_hives() {
        for (path, active_setup) in [
            ("ez-large/SOFTWARE", 13),
            ("plaso-large/SOFTWARE-RunTests", 18),
            ("rathbun-large/win10/SOFTWARE", 10),
        ] {
            let Some(entries) = entries(path) else {
                continue;
            };
            assert!(entries.iter().all(|e| !e.deviates), "{path}");
            let of =
                |m: persistence::Mechanism| entries.iter().filter(|e| e.mechanism == m).count();
            assert_eq!(of(persistence::Mechanism::WinlogonShell), 1, "{path}");
            assert_eq!(of(persistence::Mechanism::WinlogonUserinit), 1, "{path}");
            assert_eq!(of(persistence::Mechanism::AppInitDlls), 2, "{path}");
            assert_eq!(
                of(persistence::Mechanism::ActiveSetup),
                active_setup,
                "{path}"
            );
            assert_eq!(of(persistence::Mechanism::IfeoDebugger), 0, "{path}");
        }
    }

    /// `StartupApproved` against RECmd's batch rows (data as bytes), in
    /// the test NTUSER.DAT and the Windows 10 SOFTWARE.
    #[test]
    fn startup_approved_matches_recmd() {
        for (path, oracle, count) in [
            ("ez-large/NTUSER.DAT", "ez-NTUSER", 15),
            ("rathbun-large/win10/SOFTWARE", "rathbun-win10-SOFTWARE", 1),
        ] {
            let Some(entries) = entries(path) else {
                continue;
            };
            let ours: BTreeSet<(String, String)> = entries
                .iter()
                .filter(|e| e.mechanism == persistence::Mechanism::StartupApproved)
                .map(|e| (e.value.clone(), e.data.clone()))
                .collect();
            let theirs: BTreeSet<(String, String)> = recmd(oracle)
                .iter()
                .filter(|r| r["Description"] == "Startup Programs" && !r["ValueName"].is_empty())
                .map(|r| (r["ValueName"].clone(), r["ValueData"].clone()))
                .collect();
            assert_eq!(ours.len(), count, "{path}");
            assert_eq!(ours, theirs, "{path}");
            assert!(entries
                .iter()
                .filter(|e| e.mechanism == persistence::Mechanism::StartupApproved)
                .all(|e| e.enabled == Some(true) && e.disabled_at.is_none()));
        }
    }
}

mod installed_programs {
    use super::*;

    /// Every `Uninstall` subkey of six hives against RECmd's `UnInstall`
    /// plugin: key name, display name and version, publisher, install
    /// date, source and location, uninstall string, key last written.
    #[test]
    fn matches_recmd() {
        for (path, oracle, count) in [
            ("ez-large/SOFTWARE", "ez-SOFTWARE_UnInstall", 31),
            ("ez-large/NTUSER.DAT", "ez-NTUSER_UnInstall", 11),
            (
                "plaso-large/SOFTWARE-RunTests",
                "plaso-SOFTWARE-RunTests_UnInstall",
                81,
            ),
            (
                "plaso-large/NTUSER-WIN7.DAT",
                "plaso-NTUSER-WIN7_UnInstall",
                1,
            ),
            (
                "rathbun-large/win10/SOFTWARE",
                "rathbun-win10-SOFTWARE_UnInstall",
                37,
            ),
            (
                "rathbun-large/win10/NTUSER.DAT",
                "rathbun-win10-NTUSER_UnInstall",
                1,
            ),
        ] {
            let Some(data) = hive(path) else { continue };
            let found = programs::programs(&Hive::parse(&data).unwrap());
            assert!(found.problems.is_empty(), "{path}");
            let ours: BTreeSet<Vec<String>> = found
                .entries
                .iter()
                .map(|p| {
                    vec![
                        p.key_name.clone(),
                        text(p.display_name.as_ref()),
                        text(p.display_version.as_ref()),
                        text(p.publisher.as_ref()),
                        text(p.install_date_text.as_ref()),
                        text(p.install_source.as_ref()),
                        text(p.install_location.as_ref()),
                        // RECmd trims trailing spaces.
                        text(p.uninstall_string.as_ref()).trim_end().to_owned(),
                        when(p.key_last_written),
                    ]
                })
                .collect();
            let theirs: BTreeSet<Vec<String>> = recmd(oracle)
                .iter()
                // A deleted key RECmd recovers from a free cell (this crate
                // doesn't recover deleted keys yet).
                .filter(|r| r["KeyName"] != "{AC76BA86-7AD7-1033-7B44-AA1000000001}")
                .map(|r| {
                    [
                        "KeyName",
                        "DisplayName",
                        "DisplayVersion",
                        "Publisher",
                        "InstallDate",
                        "InstallSource",
                        "InstallLocation",
                        "UninstallString",
                        "Timestamp",
                    ]
                    .iter()
                    .map(|c| r[*c].trim().to_owned())
                    .collect()
                })
                .collect();
            assert_eq!(found.entries.len(), count, "{path}");
            assert_eq!(ours, theirs, "{path}");
        }
    }
}

mod system_identity {
    use super::*;

    fn identity(path: &str) -> Option<system::Identity> {
        let data = hive(path)?;
        let mut found = system::identity(&Hive::parse(&data).unwrap());
        assert!(found.problems.is_empty(), "{path}: {:?}", found.problems);
        found.entries.pop()
    }

    /// SYSTEM: the computer name and last shutdown against RECmd's batch
    /// rows (current control set), the time zone against its plugin.
    #[test]
    fn system_hives_match_recmd() {
        for (path, oracle) in [
            ("ez-large/SYSTEM", "ez-SYSTEM"),
            ("plaso-large/SYSTEM", "plaso-SYSTEM"),
            ("rathbun-large/win10/SYSTEM", "rathbun-win10-SYSTEM"),
        ] {
            let Some(identity) = identity(path) else {
                continue;
            };
            let rows = recmd(oracle);
            let first = |description: &str, value: &str| {
                rows.iter()
                    .find(|r| {
                        r["Description"] == description
                            && r["ValueName"] == value
                            && r["KeyPath"].contains(r"\ControlSet001\")
                    })
                    .map(|r| r["ValueData"].clone())
                    .unwrap()
            };
            assert_eq!(
                identity.computer_name.unwrap().name,
                first("System Info (Current)", "ComputerName"),
                "{path}"
            );
            assert_eq!(
                when(identity.shutdown.unwrap().time),
                first("Shutdown Time", "ShutdownTime"),
                "{path}"
            );
            let zone = identity.time_zone.unwrap();
            let theirs: HashMap<String, String> = recmd(&format!("{oracle}_TimeZoneInfo"))
                .iter()
                .filter(|r| r["BatchKeyPath"].contains(r"\ControlSet001\"))
                .map(|r| (r["ValueName"].clone(), r["ValueData"].clone()))
                .collect();
            let number = |n: Option<i32>| n.map(|n| n.to_string()).unwrap_or_default();
            // RECmd reads the key name past its NUL, into the value's slack
            // (plaso's SYSTEM: `Eastern Standard Time`, a space, garbage);
            // the text before it is compared.
            let key_name = text(theirs.get("TimeZoneKeyName"));
            let ours = text(zone.key_name.as_ref());
            assert!(
                key_name == ours || key_name.starts_with(&format!("{ours} ")),
                "{path}: {key_name}"
            );
            assert_eq!(number(zone.bias), theirs["Bias"], "{path}");
            assert_eq!(
                number(zone.active_time_bias),
                theirs["ActiveTimeBias"],
                "{path}"
            );
            assert_eq!(number(zone.daylight_bias), theirs["DaylightBias"], "{path}");
            assert_eq!(
                text(zone.standard_name.as_ref()),
                theirs["StandardName"],
                "{path}"
            );
        }
    }

    /// plaso's `shutdown.py` and `timezone.py` on its SYSTEM hive: last
    /// shutdown 2012-04-04T01:58:40.8392499; Eastern Standard Time,
    /// `ActiveTimeBias` 240, `Bias` 300, `DaylightBias` -60, `StandardBias` 0.
    #[test]
    fn plaso_system_as_plaso_reads_it() {
        let Some(identity) = identity("plaso-large/SYSTEM") else {
            return;
        };
        assert_eq!(
            when(identity.shutdown.unwrap().time),
            "2012-04-04 01:58:40.8392499"
        );
        let zone = identity.time_zone.unwrap();
        assert_eq!(zone.key_name.as_deref(), Some("Eastern Standard Time"));
        assert_eq!(
            (
                zone.active_time_bias,
                zone.bias,
                zone.daylight_bias,
                zone.standard_bias
            ),
            (Some(240), Some(300), Some(-60), Some(0))
        );
        assert_eq!(zone.daylight_name.as_deref(), Some("@tzres.dll,-111"));
        assert_eq!(zone.dynamic_daylight_disabled, Some(false));
        assert_eq!(when(zone.key_last_written), "2012-03-11 07:00:00.0006424");
        assert!(identity.version.is_none() && identity.profiles.is_empty());
    }

    /// SOFTWARE: the version against RECmd's batch rows, the profiles
    /// against its ProfileList plugin (path, last load and unload).
    #[test]
    fn software_hives_match_recmd() {
        for (path, oracle, profiles) in [
            ("ez-large/SOFTWARE", "ez-SOFTWARE", 4),
            (
                "plaso-large/SOFTWARE-RunTests",
                "plaso-SOFTWARE-RunTests",
                11,
            ),
            ("rathbun-large/win10/SOFTWARE", "rathbun-win10-SOFTWARE", 4),
        ] {
            let Some(identity) = identity(path) else {
                continue;
            };
            let rows = recmd(oracle);
            let version = identity.version.unwrap();
            let info = |value: &str| batch_value(&rows, "System Info (Current)", value);
            assert_eq!(
                text(version.product_name.as_ref()),
                info("ProductName"),
                "{path}"
            );
            assert_eq!(
                text(version.registered_owner.as_ref()),
                info("RegisteredOwner"),
                "{path}"
            );
            assert_eq!(
                text(version.system_root.as_ref()),
                info("SystemRoot"),
                "{path}"
            );
            let install = (u64::from(version.install_date.unwrap()) + 11_644_473_600) * 10_000_000;
            assert_eq!(when(install), info("InstallDate"), "{path}");
            if let Some(time) = version.install_time {
                assert_eq!(when(time), info("InstallTime"), "{path}");
            }
            let ours: Vec<[String; 4]> = identity
                .profiles
                .iter()
                .map(|p| {
                    [
                        p.sid.clone(),
                        text(p.image_path.as_ref()),
                        maybe(p.loaded),
                        maybe(p.unloaded),
                    ]
                })
                .collect();
            let theirs: Vec<[String; 4]> = recmd(&format!("{oracle}_ProfileList"))
                .iter()
                .map(|r| {
                    [
                        r["KeyName"].clone(),
                        r["ProfileImagePath"].clone(),
                        r["LastLogonTime"].clone(),
                        r["LastLogoffTime"].clone(),
                    ]
                })
                .collect();
            assert_eq!(ours.len(), profiles, "{path}");
            assert_eq!(ours, theirs, "{path}");
        }
    }

    /// plaso's `windows_version.py` on SOFTWARE-RunTests: Windows 7
    /// Ultimate, Service Pack 1, version 6.1, owner "Windows User",
    /// installed 2010-11-10T17:10:57.
    #[test]
    fn plaso_software_as_plaso_reads_it() {
        let Some(identity) = identity("plaso-large/SOFTWARE-RunTests") else {
            return;
        };
        let version = identity.version.unwrap();
        assert_eq!(version.product_name.as_deref(), Some("Windows 7 Ultimate"));
        assert_eq!(version.service_pack.as_deref(), Some("Service Pack 1"));
        assert_eq!(version.current_version.as_deref(), Some("6.1"));
        assert_eq!(version.registered_owner.as_deref(), Some("Windows User"));
        let installed = (u64::from(version.install_date.unwrap()) + 11_644_473_600) * 10_000_000;
        assert_eq!(when(installed), "2010-11-10 17:10:57.0000000");
    }
}

mod damage {
    use proptest::prelude::*;
    use registry::{mounted, mru, networks, persistence, programs, rdp, system, tasks, usb};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        /// Corrupted anywhere, a hive gives every artifact reader entries
        /// or problems: never a panic.
        #[test]
        fn corrupted_hives_never_panic(flips in proptest::collection::vec((0_usize..217_088, any::<u8>()), 1..64)) {
            let mut data = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ez/NTUSER1.DAT")).unwrap();
            for (at, byte) in flips {
                data[at] = byte;
            }
            if let Ok(hive) = registry::Hive::parse(&data) {
                let _ = usb::devices(&hive, "ControlSet001");
                let _ = mounted::read(&hive);
                let _ = rdp::connections(&hive);
                let _ = mru::entries(&hive);
                let _ = networks::profiles(&hive);
                let _ = tasks::tasks(&hive);
                let _ = persistence::entries(&hive);
                let _ = programs::programs(&hive);
                let _ = system::identity(&hive);
            }
        }
    }
}
