//! Office trust records and WinRAR's history in Eric Zimmerman's
//! `NTUSER.DAT` and `NTUSER slack.DAT` (MIT, `ez-large/`) and plaso's
//! `NTUSER-WIN7.DAT` (Apache-2.0, `plaso-large/`), fetched by
//! `tests/fetch-hives.sh` and skipped when absent: every trust record
//! python-registry reads and every list plaso's `winrar_mru` plugin reads,
//! read the same (`tests/oracle/trust-winrar.tsv`, written by
//! `tests/oracle/gen_trust_winrar.py`).

use std::fs;
use std::path::Path;

use registry::mru::{self, List};
use registry::{office, Hive};

const HIVES: [&str; 3] = [
    "ez-large/NTUSER.DAT",
    "ez-large/NTUSER slack.DAT",
    "plaso-large/NTUSER-WIN7.DAT",
];

/// FILETIME as microseconds since 1970, rounded as plaso rounds them.
fn micros(filetime: u64) -> String {
    ((filetime - 116_444_736_000_000_000 + 5) / 10).to_string()
}

fn rows(name: &str, data: &[u8]) -> Vec<String> {
    let hive = Hive::parse(data).unwrap();
    let records = office::trust_records(&hive);
    assert!(records.problems.is_empty(), "{:?}", records.problems);
    let mut rows: Vec<String> = records
        .entries
        .iter()
        .map(|r| {
            format!(
                "{name}\ttrust\t{}\t{}\t{}\t{}\t{}",
                r.key,
                r.path,
                r.trusted.unwrap(),
                u8::from(r.macros_enabled),
                r.key_last_written
            )
        })
        .collect();
    let entries = mru::entries(&hive);
    assert!(entries.problems.is_empty(), "{:?}", entries.problems);
    for list in [
        List::WinRarArchives,
        List::WinRarArchiveNames,
        List::WinRarExtractPaths,
    ] {
        let items: Vec<&mru::Entry> = entries.entries.iter().filter(|e| e.list == list).collect();
        let Some(first) = items.first() else {
            continue;
        };
        let joined: Vec<String> = items
            .iter()
            .map(|e| format!("{}: {}", e.position.unwrap(), e.text))
            .collect();
        rows.push(format!(
            "{name}\twinrar\t{}\t{}\t{}",
            first.key,
            micros(first.key_last_written),
            joined.join(" ")
        ));
    }
    rows
}

#[test]
fn as_python_registry_and_plaso_read_them() {
    let mut got = Vec::new();
    for name in HIVES {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let Ok(data) = fs::read(&path) else {
            eprintln!("{name} not checked (run tests/fetch-hives.sh)");
            return;
        };
        got.extend(rows(name, &data));
    }
    got.sort();
    let expected: Vec<&str> = include_str!("oracle/trust-winrar.tsv").lines().collect();
    assert_eq!(got, expected);
}
