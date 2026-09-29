//! ShimCache against Eric Zimmerman's AppCompatCacheParser on the test
//! SYSTEM hive (Windows 8.1, fetched by `tests/fetch-hives.sh`; its output
//! is in `tests/fixtures/oracle/`), and built caches for the other layouts.

use std::fs;
use std::path::Path;

use registry::shimcache::{self, Format};
use registry::Hive;

/// FILETIME as AppCompatCacheParser prints it: `2013-12-04 23:47:23`.
fn seconds(filetime: u64) -> String {
    let secs = (filetime / 10_000_000) as i64 - 11_644_473_600;
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

#[test]
fn matches_appcompatcacheparser() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let Ok(data) = fs::read(dir.join("ez-large/SYSTEM")) else {
        eprintln!("skipped: run tests/fetch-hives.sh");
        return;
    };
    let hive = Hive::parse(&data).unwrap();
    let value = hive
        .open(r"ControlSet001\Control\Session Manager\AppCompatCache")
        .unwrap()
        .unwrap()
        .value("AppCompatCache")
        .unwrap()
        .unwrap();
    let (format, entries) = shimcache::parse(&value.bytes).unwrap();
    assert_eq!(format, Format::Windows81);
    let oracle = fs::read_to_string(dir.join("oracle/SYSTEM_AppCompatCacheParser.csv")).unwrap();
    let expected: Vec<Vec<&str>> = oracle
        .lines()
        .skip(1)
        .map(|l| l.splitn(6, ',').collect())
        .collect();
    assert_eq!(entries.len(), expected.len());
    for (entry, row) in entries.iter().zip(&expected) {
        // Paths never contain commas in this hive; the columns split cleanly.
        assert_eq!(entry.position.to_string(), row[1]);
        // AppCompatCacheParser drops the NT object prefix (`\??\`) that
        // Windows recorded; the path is kept as recorded here.
        assert_eq!(
            entry.path.trim_start_matches(r"\??\"),
            row[2],
            "position {}",
            row[1]
        );
        let modified = if entry.last_modified == 0 {
            String::new()
        } else {
            seconds(entry.last_modified)
        };
        assert_eq!(modified, row[3], "{}", entry.path);
        assert_eq!(entry.executed, Some(row[4] == "Yes"), "{}", entry.path);
    }
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn reads_windows10_caches() {
    let mut value = vec![0_u8; 0x34];
    value[..4].copy_from_slice(&0x34_u32.to_le_bytes());
    for (path, time) in [
        (r"C:\Tools\rclone.exe", 0x01d9_0000_0000_0000_u64),
        (r"C:\Windows\cmd.exe", 0),
    ] {
        let path = utf16(path);
        let mut data = (path.len() as u16).to_le_bytes().to_vec();
        data.extend(&path);
        data.extend(time.to_le_bytes());
        data.extend(4_u32.to_le_bytes());
        data.extend([1, 2, 3, 4]);
        value.extend(b"10ts");
        value.extend([0; 4]);
        value.extend((data.len() as u32).to_le_bytes());
        value.extend(data);
    }
    let (format, entries) = shimcache::parse(&value).unwrap();
    assert_eq!(format, Format::Windows10);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path, r"C:\Tools\rclone.exe");
    assert_eq!(entries[0].last_modified, 0x01d9_0000_0000_0000);
    assert_eq!(entries[1].executed, None);
}

#[test]
fn reads_windows7_caches() {
    for x64 in [true, false] {
        let size = if x64 { 48 } else { 32 };
        let path = utf16(r"\??\C:\Windows\System32\psexesvc.exe");
        let mut value = vec![0_u8; 128 + size];
        value[..4].copy_from_slice(&0xbadc_0fee_u32.to_le_bytes());
        value[4..8].copy_from_slice(&1_u32.to_le_bytes());
        let path_at = value.len();
        let e = 128;
        value[e..e + 2].copy_from_slice(&(path.len() as u16).to_le_bytes());
        if x64 {
            value[e + 8..e + 16].copy_from_slice(&(path_at as u64).to_le_bytes());
            value[e + 16..e + 24].copy_from_slice(&0x01cd_0000_0000_0000_u64.to_le_bytes());
            value[e + 24..e + 28].copy_from_slice(&2_u32.to_le_bytes());
        } else {
            value[e + 4..e + 8].copy_from_slice(&(path_at as u32).to_le_bytes());
            value[e + 8..e + 16].copy_from_slice(&0x01cd_0000_0000_0000_u64.to_le_bytes());
            value[e + 16..e + 20].copy_from_slice(&2_u32.to_le_bytes());
        }
        value.extend(&path);
        let (format, entries) = shimcache::parse(&value).unwrap();
        assert_eq!(
            format,
            if x64 {
                Format::Windows7X64
            } else {
                Format::Windows7X86
            }
        );
        assert_eq!(entries[0].path, r"\??\C:\Windows\System32\psexesvc.exe");
        assert_eq!(entries[0].last_modified, 0x01cd_0000_0000_0000);
        assert_eq!(entries[0].executed, Some(true));
    }
}

#[test]
fn refuses_unknown_and_damaged_caches() {
    assert!(shimcache::parse(&[]).is_err());
    assert!(shimcache::parse(&0xdead_beef_u32.to_le_bytes())
        .unwrap_err()
        .reason
        .contains("XP"));
    let mut damaged = 0x34_u32.to_le_bytes().to_vec();
    damaged.resize(0x34, 0);
    damaged.extend(b"10ts\0\0\0\0\xff\xff\0\0");
    assert!(shimcache::parse(&damaged).is_err());
}
