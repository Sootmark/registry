//! BAM against Eric Zimmerman's RECmd (its BamDam plugin, batch file
//! `tests/oracle/bam.reb`, run with `--nl` on the hive alone): every entry,
//! in every control set RECmd reports, must match.
//!
//! - The SYSTEM hives of Andrew Rathbun's Windows 10 and 11 VMs (MIT, DFIR
//!   Artifact Museum), fetched by `tests/fetch-hives.sh`; RECmd's output is
//!   in `tests/oracle/bam-win10.csv` and `bam-win11.csv`.
//! - Any other hive: set `SOOTMARK_BAM_SYSTEM` to it and
//!   `SOOTMARK_BAM_RECMD` to RECmd's output for it.

use std::collections::BTreeSet;
use std::fs;

use registry::{bam, Hive};

/// FILETIME as RECmd prints it: `2024-02-09 22:52:15.6572778`.
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
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}.{:07}",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60,
        filetime % 10_000_000
    )
}

/// A CSV line split on commas outside quotes.
fn fields(line: &str) -> Vec<String> {
    let (mut out, mut field, mut quoted) = (Vec::new(), String::new(), false);
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut field)),
            c => field.push(c),
        }
    }
    out.push(field);
    out
}

/// Check every BAM entry of the hive against RECmd's output; how many.
fn check(data: &[u8], csv: &str) -> usize {
    let hive = Hive::parse(data).unwrap();
    let mut lines = csv.trim_start_matches('\u{feff}').lines();
    let header = fields(lines.next().unwrap());
    let column = |name: &str| header.iter().position(|h| h == name).unwrap();
    let (key, value, data2) = (column("KeyPath"), column("ValueName"), column("ValueData2"));
    let rows: Vec<Vec<String>> = lines.map(fields).collect();
    let control_sets: BTreeSet<&str> = rows
        .iter()
        .map(|row| row[key].split('\\').nth(1).unwrap())
        .collect();
    assert!(!control_sets.is_empty());
    let mut total = 0;
    for control_set in control_sets {
        let ours: BTreeSet<(String, String, String)> = bam::entries(&hive, control_set)
            .unwrap()
            .into_iter()
            .map(|e| (e.sid, e.program, when(e.last_run)))
            .collect();
        let theirs: BTreeSet<(String, String, String)> = rows
            .iter()
            .filter(|row| row[key].split('\\').nth(1) == Some(control_set))
            .map(|row| {
                let sid = row[key].rsplit('\\').next().unwrap().to_owned();
                let time = row[data2].trim_start_matches("Execution time: ").to_owned();
                (sid, row[value].clone(), time)
            })
            .collect();
        assert_eq!(ours, theirs, "{control_set}");
        total += ours.len();
    }
    total
}

#[test]
fn rathbun_vms_match_recmd() {
    let dir = env!("CARGO_MANIFEST_DIR");
    for (version, entries) in [("win10", 23), ("win11", 19)] {
        let Ok(data) = fs::read(format!(
            "{dir}/tests/fixtures/rathbun-large/{version}/SYSTEM"
        )) else {
            eprintln!("{version} not checked (run tests/fetch-hives.sh)");
            continue;
        };
        let csv = fs::read_to_string(format!("{dir}/tests/oracle/bam-{version}.csv")).unwrap();
        assert_eq!(check(&data, &csv), entries, "{version}");
    }
}

#[test]
fn any_hive_matches_recmd() {
    let (Ok(hive), Ok(csv)) = (
        std::env::var("SOOTMARK_BAM_SYSTEM"),
        std::env::var("SOOTMARK_BAM_RECMD"),
    ) else {
        eprintln!("skipped: set SOOTMARK_BAM_SYSTEM and SOOTMARK_BAM_RECMD");
        return;
    };
    let total = check(&fs::read(hive).unwrap(), &fs::read_to_string(csv).unwrap());
    eprintln!("{total} BAM entries match RECmd");
}
