//! Amcache against Eric Zimmerman's AmcacheParser on two real hives
//! (plaso's test data, `tests/fixtures/amcache/`; AmcacheParser's output
//! in `tests/fixtures/oracle/amcache/`): every entry of every class it
//! reports, on every column.
//!
//! AmcacheParser prints absent flags as `False` and absent numbers as `0`,
//! derives `FileExtension` from the path and `ApplicationName` from the
//! program an entry belongs to (`Unassociated` in its list of files
//! without one), prints dates padded, with a time or a zone, and joins
//! lists with spaces; those are compared as it prints them. It prints `HiddenArp` and `InboxModernApp` as
//! `False` even where the hive holds `true` (3 and 44 programs here), so
//! those two aren't compared.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use registry::amcache::{self, Class, Entry};
use registry::Hive;

const HIVES: [&str; 2] = ["plaso-Amcache", "plaso-win10-Amcache"];

fn fixtures() -> &'static Path {
    Box::leak(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .into_boxed_path(),
    )
}

fn records(text: &str) -> Vec<HashMap<String, String>> {
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

/// FILETIME as AmcacheParser prints it: `2017-08-03 11:34:09`.
fn when(filetime: u64) -> String {
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

/// Our value as AmcacheParser prints the column.
fn ours(entry: &Entry, column: &str, programs: &HashMap<String, String>) -> Option<String> {
    let flag = |v: &str| {
        if v.eq_ignore_ascii_case("true") || v == "1" {
            "True".to_owned()
        } else {
            "False".to_owned()
        }
    };
    Some(match column {
        "KeyName" => entry.key.clone(),
        "KeyLastWriteTimestamp" | "FileKeyLastWriteTimestamp" => when(entry.last_written),
        "SHA1" => entry.sha1().unwrap_or_default().to_owned(),
        "FullPath" => entry.file_path().unwrap_or_default().to_owned(),
        "Size" => entry.size().map_or_else(String::new, |s| s.to_string()),
        "LinkDate" => entry.link_date().map_or_else(String::new, when),
        "InstallDate" => entry.install_date().map_or_else(String::new, when),
        "FileExtension" => entry
            .file_path()
            .and_then(|p| Path::new(p).extension())
            .map_or_else(String::new, |e| format!(".{}", e.to_string_lossy())),
        "ApplicationName" => entry
            .program_id()
            .and_then(|id| programs.get(id))
            .cloned()
            .unwrap_or_default(),
        "DriverTimeStamp" => entry.unix_time(column).map_or_else(String::new, when),
        // `2016-5-25`, printed padded.
        "Date" => entry.get(column).map_or_else(String::new, |d| {
            let parts: Vec<&str> = d.split('-').collect();
            match parts.as_slice() {
                [y, m, day] => format!("{y}-{m:0>2}-{day:0>2} 00:00:00"),
                _ => d.to_owned(),
            }
        }),
        "InstallDateMsi" => entry
            .get(column)
            .map_or_else(String::new, |d| format!("{d} +00:00")),
        "InstallDateFromLinkFile" => entry.get(column).unwrap_or_default().replace(", ", " "),
        "HiddenArp" | "InboxModernApp" => return None,
        "IsOsComponent" | "IsPeFile" | "DriverInBox" | "DriverIsKernelMode" | "DriverSigned"
        | "IsActive" | "IsConnected" | "IsMachineContainer" | "IsNetworked" | "IsPaired" => {
            flag(entry.get(column).unwrap_or_default())
        }
        "Usn" | "Language" | "ProblemCode" | "InstallState" => {
            entry.get(column).unwrap_or("0").to_owned()
        }
        other => entry.get(other).unwrap_or_default().to_owned(),
    })
}

fn class_files(class: Class) -> &'static [&'static str] {
    match class {
        Class::File => &["AssociatedFileEntries", "UnassociatedFileEntries"],
        Class::Program => &["ProgramEntries"],
        Class::Shortcut => &["ShortCuts"],
        Class::DriverBinary => &["DriveBinaries"],
        Class::DriverPackage => &["DriverPackages"],
        Class::DevicePnp => &["DevicePnps"],
        Class::DeviceContainer => &["DeviceContainers"],
    }
}

/// The column that identifies an entry in AmcacheParser's output.
fn identity(class: Class) -> &'static str {
    match class {
        Class::File => "LongPathHash",
        Class::Program => "ProgramId",
        _ => "KeyName",
    }
}

#[test]
fn matches_amcacheparser() {
    let mut mismatches: HashMap<(String, String), Vec<String>> = HashMap::new();
    let mut checked = 0;
    for hive_name in HIVES {
        let data = fs::read(fixtures().join(format!("amcache/{hive_name}.hve"))).unwrap();
        let hive = Hive::parse(&data).unwrap();
        let cache = amcache::read(&hive).unwrap().expect("an Amcache hive");
        assert!(
            cache.problems.is_empty(),
            "{hive_name}: {:?}",
            cache.problems
        );
        let current: Vec<&Entry> = cache.entries.iter().filter(|e| !e.legacy).collect();
        let programs: HashMap<String, String> = current
            .iter()
            .filter(|e| e.class == Class::Program)
            .filter_map(|e| Some((e.key.clone(), e.get("Name")?.to_owned())))
            .collect();
        for class in [
            Class::File,
            Class::Program,
            Class::Shortcut,
            Class::DriverBinary,
            Class::DriverPackage,
            Class::DevicePnp,
            Class::DeviceContainer,
        ] {
            let mut rows = Vec::new();
            for file in class_files(class) {
                let path = fixtures().join(format!("oracle/amcache/{hive_name}/{file}.csv"));
                for mut row in records(&fs::read_to_string(path).unwrap()) {
                    // Its list of files without a program names them so.
                    if *file == "UnassociatedFileEntries" {
                        row.insert("ApplicationName".into(), String::new());
                    }
                    rows.push(row);
                }
            }
            let entries: Vec<&&Entry> = current.iter().filter(|e| e.class == class).collect();
            assert_eq!(entries.len(), rows.len(), "{hive_name} {}", class.name());
            let id = identity(class);
            for row in &rows {
                let entry = entries
                    .iter()
                    .find(|e| ours(e, id, &programs).as_deref() == Some(row[id].as_str()))
                    .unwrap_or_else(|| {
                        panic!("{hive_name} {}: no entry {}", class.name(), row[id])
                    });
                for (column, theirs) in row {
                    let Some(mine) = ours(entry, column, &programs) else {
                        continue;
                    };
                    if &mine != theirs {
                        mismatches
                            .entry((class.name().to_owned(), column.clone()))
                            .or_default()
                            .push(format!(
                                "{hive_name} {}: ours {mine:?} theirs {theirs:?}",
                                row[id]
                            ));
                    }
                }
                checked += 1;
            }
        }
    }
    let mut report: Vec<_> = mismatches.iter().collect();
    report.sort();
    for ((class, column), samples) in &report {
        eprintln!("{class}.{column}: {} ({})", samples.len(), samples[0]);
    }
    assert!(report.is_empty(), "{} columns differ", report.len());
    assert_eq!(checked, 247 + 74 + 311 + 2 + 194 + 18 + 30 + 75 + 8 + 53);
}

/// A FILETIME as plaso's microseconds since 1970 (rounded).
fn micros(filetime: u64) -> String {
    ((filetime as i64 + 5) / 10 - 11_644_473_600_000_000).to_string()
}

fn tsv(name: &str) -> Vec<Vec<String>> {
    let path = fixtures().join(format!("oracle/amcache/plaso-Amcache/{name}"));
    let mut rows: Vec<Vec<String>> = fs::read_to_string(path)
        .unwrap()
        .lines()
        .skip(1)
        .map(|l| l.split('\t').map(str::to_owned).collect())
        .collect();
    rows.sort();
    rows
}

/// The older layout (`Root\File`, `Root\Programs`) against plaso's Amcache
/// parser on the same hive (its events in `plaso-files.tsv` and
/// `plaso-programs.tsv`): one event per timestamp, each with the entry's
/// attributes, all 1,153 file and 26 program events equal.
#[test]
fn legacy_layout_matches_plaso() {
    let data = fs::read(fixtures().join("amcache/plaso-Amcache.hve")).unwrap();
    let hive = Hive::parse(&data).unwrap();
    let cache = amcache::read(&hive).unwrap().unwrap();
    let legacy = |class| {
        cache
            .entries
            .iter()
            .filter(move |e: &&Entry| e.legacy && e.class == class)
    };
    let get = |e: &Entry, name: &str| e.get(name).unwrap_or_default().to_owned();
    let mut files = Vec::new();
    for entry in legacy(Class::File) {
        let times = [
            (
                "Content Modification Time",
                entry.filetime("EntryWritten").map(micros),
            ),
            (
                "Content Modification Time",
                entry.filetime("FileModified").map(micros),
            ),
            ("Creation Time", entry.filetime("FileCreated").map(micros)),
            ("Link Time", entry.link_date().map(micros)),
        ];
        for (desc, time) in times {
            let Some(time) = time else { continue };
            files.push(vec![
                desc.to_owned(),
                time,
                entry.file_path().unwrap_or_default().to_owned(),
                entry.sha1().unwrap_or_default().to_owned(),
                get(entry, "ProgramId"),
                get(entry, "ProductName"),
                get(entry, "CompanyName"),
                get(entry, "LanguageCode"),
                get(entry, "FileVersion"),
                get(entry, "Size"),
                get(entry, "FileDescription"),
            ]);
        }
    }
    files.sort();
    assert_eq!(files.len(), 1_153);
    assert_eq!(files, tsv("plaso-files.tsv"));
    let mut programs: Vec<Vec<String>> = legacy(Class::Program)
        .filter_map(|entry| {
            let mut row = vec![
                "Installation Time".to_owned(),
                micros(entry.install_date()?),
            ];
            for name in [
                "Name",
                "Version",
                "Publisher",
                "LanguageCode",
                "EntryType",
                "UninstallKey",
                "FilePaths",
                "ProductCode",
                "PackageCode",
                "MsiProductCode",
                "MsiPackageCode",
            ] {
                row.push(get(entry, name));
            }
            Some(row)
        })
        .collect();
    programs.sort();
    assert_eq!(programs.len(), 26);
    assert_eq!(programs, tsv("plaso-programs.tsv"));
}

mod damage {
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        /// A corrupted Amcache hive is read or refused, and its entries'
        /// accessors never panic.
        #[test]
        fn corrupted_amcache_never_panics(flips in proptest::collection::vec((0_usize..524_288, any::<u8>()), 1..64)) {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/amcache/plaso-win10-Amcache.hve");
            let mut data = std::fs::read(path).unwrap();
            for (at, byte) in flips {
                data[at] = byte;
            }
            if let Ok(hive) = registry::Hive::parse(&data) {
                if let Ok(Some(cache)) = registry::amcache::read(&hive) {
                    for entry in &cache.entries {
                        let _ = (entry.sha1(), entry.size(), entry.link_date(), entry.install_date());
                        let _ = (entry.unix_time("DriverTimeStamp"), entry.filetime("EntryWritten"));
                    }
                }
            }
        }
    }
}
