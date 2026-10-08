//! A user's mount points, network drives, Office lists and typed addresses
//! in plaso's NTUSER.DAT and NTUSER-WIN7.DAT (Apache-2.0, `plaso-large/`,
//! fetched by `tests/fetch-hives.sh`, skipped when absent): every value
//! plaso's `explorer_mountpoints2`, `network_drives`,
//! `microsoft_office_mru` and `windows_typed_urls` plugins read, read the
//! same (`tests/oracle/plaso-user-keys.tsv`, written from plaso's output).

use std::fs;
use std::path::Path;

use registry::drives::{self, MountKind};
use registry::{mru, office, Hive};

/// FILETIME as microseconds since 1970, rounded as plaso rounds them.
fn micros(filetime: u64) -> String {
    ((filetime - 116_444_736_000_000_000 + 5) / 10).to_string()
}

fn rows(name: &str, data: &[u8]) -> Vec<String> {
    let hive = Hive::parse(data).unwrap();
    let mut rows = Vec::new();
    let points = drives::mount_points(&hive);
    assert!(points.problems.is_empty(), "{:?}", points.problems);
    for point in &points.entries {
        let (kind, server, share) = match &point.kind {
            MountKind::Drive => ("", "Drive", ""),
            MountKind::Volume => ("Volume", "Drive", ""),
            MountKind::Remote { server, share } => {
                ("Remote Drive", server.as_str(), share.as_str())
            }
        };
        rows.push(format!(
            "{name}\tmount\t{}\t{}\t{kind}\t{server}\t{share}\t{}",
            micros(point.key_last_written),
            point.name,
            point.label.as_deref().unwrap_or_default()
        ));
    }
    for drive in &drives::network_drives(&hive).entries {
        rows.push(format!(
            "{name}\tnetwork\t{}\t{}\t{}\t{}",
            micros(drive.key_last_written),
            drive.letter,
            drive.server.as_deref().unwrap_or_default(),
            drive.share.as_deref().unwrap_or_default()
        ));
    }
    let items = office::mru(&hive);
    assert!(items.problems.is_empty(), "{:?}", items.problems);
    for item in &items.entries {
        // plaso shows the raw value; this crate splits it.
        let raw = format!(
            "[F00000000][T{:016X}][O00000000]*{}",
            item.opened.unwrap(),
            item.path
        );
        rows.push(format!(
            "{name}\toffice\t{}\t{}\t{raw}",
            micros(item.opened.unwrap()),
            item.key
        ));
    }
    let entries = mru::entries(&hive).entries;
    for list in [mru::List::TypedPaths, mru::List::TypedUrls] {
        let typed: Vec<&mru::Entry> = entries.iter().filter(|e| e.list == list).collect();
        if let Some(first) = typed.first() {
            let joined: Vec<String> = typed
                .iter()
                .map(|e| format!("{}: {}", e.value, e.text))
                .collect();
            rows.push(format!(
                "{name}\ttyped\t{}\t{}\t{}",
                micros(first.key_last_written),
                first.key,
                joined.join(" | ")
            ));
        }
    }
    rows
}

#[test]
fn as_plaso_reads_them() {
    let mut got = Vec::new();
    for name in ["NTUSER.DAT", "NTUSER-WIN7.DAT"] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/plaso-large")
            .join(name);
        let Ok(data) = fs::read(&path) else {
            eprintln!("{name} not checked (run tests/fetch-hives.sh)");
            return;
        };
        got.extend(rows(name, &data));
    }
    got.sort();
    let expected: Vec<&str> = include_str!("oracle/plaso-user-keys.tsv").lines().collect();
    assert_eq!(got, expected);
}
