//! CCleaner, diagnosed applications, ProgramsCache, Outlook's search, the
//! security zones and BootExecute in plaso's test hives and Andrew
//! Rathbun's Windows 10 and 11 hives (`plaso-large/`, `rathbun-large/`,
//! fetched by `tests/fetch-hives.sh`, skipped when absent): every event
//! plaso's `ccleaner`, `diagnosed_applications`, `explorer_programscache`,
//! `microsoft_outlook_mru`, `msie_zone` and `windows_boot_execute` plugins
//! read, read the same (`tests/oracle/plaso-app-keys.tsv`, written by
//! `tests/oracle/gen_app_keys.py` from plaso's output).

use std::fs;
use std::path::Path;

use registry::persistence::{self, Mechanism};
use registry::{cleaners, office, programscache, zones, Hive};

/// FILETIME as microseconds since 1970, rounded as plaso rounds them.
fn micros(filetime: u64) -> String {
    ((i128::from(filetime) - 116_444_736_000_000_000 + 5) / 10).to_string()
}

/// `07/13/2013 10:03:14 AM` as microseconds since 1970, read as UTC (as
/// plaso reads it).
fn update_micros(text: &str) -> String {
    let (date, rest) = text.split_once(' ').unwrap();
    let (clock, half) = rest.split_once(' ').unwrap();
    let date: Vec<u32> = date.split('/').map(|p| p.parse().unwrap()).collect();
    let clock: Vec<i64> = clock.split(':').map(|p| p.parse().unwrap()).collect();
    let hour = clock[0] % 12 + if half == "PM" { 12 } else { 0 };
    let days = common::time::days_from_civil(i64::from(date[2]), date[0], date[1]);
    ((days * 86_400 + hour * 3600 + clock[1] * 60 + clock[2]) * 1_000_000).to_string()
}

/// One event's cells after the file's name.
type Row = Vec<String>;

fn ccleaner_rows(hive: &Hive<'_>) -> Vec<Row> {
    let mut rows = Vec::new();
    for c in cleaners::ccleaner(hive).entries {
        let config: Vec<String> = c
            .settings
            .iter()
            .map(|(n, v)| format!("{n}: {v}"))
            .collect();
        rows.push(vec![
            "ccleaner-config".into(),
            c.key.clone(),
            micros(c.key_last_written),
            config.join("|"),
        ]);
        if let Some(update) = &c.update_key {
            rows.push(vec![
                "ccleaner-update".into(),
                c.key.clone(),
                update_micros(update),
            ]);
        }
    }
    rows
}

fn diagnosed_rows(hive: &Hive<'_>) -> Vec<Row> {
    let mut rows = Vec::new();
    for d in cleaners::diagnosed_applications(hive).entries {
        rows.push(vec![
            "diagnosed-content-modification-time".into(),
            d.key.clone(),
            micros(d.key_last_written),
            d.program.clone(),
        ]);
        if let Some(t) = d.last_detection {
            rows.push(vec![
                "diagnosed-last-detection-time".into(),
                d.key,
                micros(t),
                d.program,
            ]);
        }
    }
    rows
}

fn programscache_rows(hive: &Hive<'_>) -> Vec<Row> {
    programscache::caches(hive)
        .entries
        .into_iter()
        .map(|p| {
            let entries: Vec<String> = p
                .entries
                .iter()
                .enumerate()
                .map(|(i, names)| format!("{i}: {}", plaso_path(names)))
                .collect();
            let known_folder = p
                .known_folder
                .map(|g| g.trim_matches(['{', '}']).to_ascii_lowercase())
                .unwrap_or_default();
            vec![
                "programscache".into(),
                p.key,
                micros(p.key_last_written),
                p.value,
                known_folder,
                entries.join(" "),
            ]
        })
        .collect()
}

fn outlook_rows(hive: &Hive<'_>) -> Vec<Row> {
    office::outlook_search(hive)
        .entries
        .into_iter()
        .map(|o| {
            let stores: Vec<String> = o
                .stores
                .iter()
                .map(|(p, n)| format!("{p}: 0x{n:08x}"))
                .collect();
            vec![
                "outlook".into(),
                o.key,
                micros(o.key_last_written),
                stores.join(" "),
            ]
        })
        .collect()
}

/// Zones, keyed as plaso keys them: the zone's number and name.
fn zone_rows(hive: &Hive<'_>) -> Vec<Row> {
    zones::zones(hive)
        .entries
        .into_iter()
        .map(|z| {
            let settings: Vec<String> =
                z.settings.iter().map(|(n, v)| format!("{n}={v}")).collect();
            let key = match z.name {
                Some(name) => format!(r"{}\{} ({name})", parent(&z.key), z.zone),
                None => z.key.clone(),
            };
            vec![
                "zone".into(),
                key,
                micros(z.key_last_written),
                settings.join("|"),
            ]
        })
        .collect()
}

fn boot_rows(hive: &Hive<'_>) -> Vec<Row> {
    persistence::entries(hive)
        .entries
        .into_iter()
        .filter(|e| e.mechanism == Mechanism::BootExecute)
        .map(|e| {
            vec![
                "boot-execute".into(),
                e.key,
                micros(e.key_last_written),
                e.data,
            ]
        })
        .collect()
}

fn rows(name: &str, data: &[u8]) -> Vec<String> {
    let hive = Hive::parse(data).unwrap();
    [
        ccleaner_rows(&hive),
        diagnosed_rows(&hive),
        programscache_rows(&hive),
        outlook_rows(&hive),
        zone_rows(&hive),
        boot_rows(&hive),
    ]
    .concat()
    .into_iter()
    .map(|cells| format!("{name}\t{}", cells.join("\t")))
    .collect()
}

/// A key's parent path.
fn parent(key: &str) -> &str {
    key.rsplit_once('\\').map_or(key, |(parent, _)| parent)
}

/// A shortcut's path as plaso's shell item path writes it: the first two
/// names with a space between them, the rest each after two backslashes.
fn plaso_path(names: &[String]) -> String {
    // plaso names the taskbar's pinned items' root; this crate keeps its
    // class identifier.
    let names: Vec<String> = names
        .iter()
        .map(|n| match n.as_str() {
            "{1F3427C8-5C10-4210-AA03-2EE45287D668}" => "<User Pinned>".to_owned(),
            other => other.to_owned(),
        })
        .collect();
    match names.as_slice() {
        [first, second, rest @ ..] => {
            let mut path = format!("{first} {second}");
            for name in rest {
                path.push_str("\\\\");
                path.push_str(name);
            }
            path
        }
        _ => names.concat(),
    }
}

fn hive_path(name: &str) -> Option<std::path::PathBuf> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let path = if name.starts_with("win1") {
        base.join("rathbun-large").join(name)
    } else {
        base.join("plaso-large").join(name)
    };
    path.exists().then_some(path)
}

#[test]
fn every_event_as_plaso_reads_it() {
    let oracle = include_str!("oracle/plaso-app-keys.tsv");
    let expected: Vec<&str> = oracle.lines().collect();
    let mut files: Vec<&str> = expected
        .iter()
        .map(|l| l.split('\t').next().unwrap())
        .collect();
    files.dedup();
    let mut got = Vec::new();
    for file in &files {
        let Some(path) = hive_path(file) else {
            eprintln!("skipped: {file} not fetched (tests/fetch-hives.sh)");
            return;
        };
        got.extend(rows(file, &fs::read(path).unwrap()));
    }
    // Key names are case-insensitive: plaso writes each as the hive has it,
    // this crate the documented spelling.
    let mut got: Vec<String> = got.iter().map(|l| fold_key(l)).collect();
    let mut expected: Vec<String> = expected.iter().map(|l| fold_key(l)).collect();
    got.sort();
    expected.sort();
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
    assert_eq!(got.len(), expected.len());
}

/// A line with its key (the third cell) lower-cased.
fn fold_key(line: &str) -> String {
    let mut cells: Vec<String> = line.split('\t').map(str::to_owned).collect();
    if let Some(key) = cells.get_mut(2) {
        *key = key.to_lowercase();
    }
    cells.join("\t")
}

/// The hardware the firmware described, in the Windows 10 and 11 hives and
/// Eric Zimmerman's SYSTEM (MIT, `ez-large/`): what python-registry 1.3.1
/// reads from `HardwareConfig\<LastConfig>` (plaso's `motherboard_info`
/// reads `Control\SystemInformation`, which these hives don't keep).
#[test]
fn hardware_as_python_registry_reads_it() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (file, expected) in [
        (
            "rathbun-large/win10/SYSTEM",
            [
                "VMware, Inc.",
                "VMware7,1",
                "VMW71.00V.18452719.B64.2108091906",
                "08/09/2021",
            ],
        ),
        (
            "rathbun-large/win11/SYSTEM",
            [
                "VMware, Inc.",
                "VMware7,1",
                "VMW71.00V.18452719.B64.2108091906",
                "08/09/2021",
            ],
        ),
        (
            "ez-large/SYSTEM",
            ["ASUS", "All Series", "0711", "07/01/2013"],
        ),
    ] {
        let Ok(data) = fs::read(base.join(file)) else {
            eprintln!("skipped: {file} not fetched (tests/fetch-hives.sh)");
            return;
        };
        let hive = Hive::parse(&data).unwrap();
        let identity = registry::system::identity(&hive).entries.remove(0);
        let hardware = identity.hardware.unwrap();
        let got = [
            hardware.manufacturer,
            hardware.model,
            hardware.bios_version,
            hardware.bios_release_date,
        ]
        .map(Option::unwrap_or_default);
        assert_eq!(got, expected.map(str::to_owned), "{file}");
        assert!(hardware.key.starts_with(r"HardwareConfig\{"), "{file}");
    }
}
