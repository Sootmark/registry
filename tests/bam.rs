//! BAM against Eric Zimmerman's RECmd (its BamDam plugin) on a real
//! Windows Server 2022 SYSTEM hive, which can't be redistributed here (the
//! CFReDS "Compromised Windows Server 2022" image, CC BY-NC-SA): set
//! `SOOTMARK_BAM_SYSTEM` to the hive and `SOOTMARK_BAM_RECMD` to RECmd's
//! batch CSV for it (`--nl`, key `ControlSet*\Services\bam\State\
//! UserSettings\*`), and every entry must match. Skipped otherwise.

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

#[test]
fn matches_recmd() {
    let (Ok(hive_path), Ok(csv_path)) = (
        std::env::var("SOOTMARK_BAM_SYSTEM"),
        std::env::var("SOOTMARK_BAM_RECMD"),
    ) else {
        eprintln!("skipped: set SOOTMARK_BAM_SYSTEM and SOOTMARK_BAM_RECMD");
        return;
    };
    let data = fs::read(hive_path).unwrap();
    let hive = Hive::parse(&data).unwrap();
    let csv = fs::read_to_string(csv_path).unwrap();
    let mut lines = csv.trim_start_matches('\u{feff}').lines();
    let header = fields(lines.next().unwrap());
    let column = |name: &str| header.iter().position(|h| h == name).unwrap();
    let (key, value, data2) = (column("KeyPath"), column("ValueName"), column("ValueData2"));
    let rows: Vec<Vec<String>> = lines.map(fields).collect();
    let mut total = 0;
    // Both the current control set and the last known good one hold them.
    for control_set in ["ControlSet001", "ControlSet002"] {
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
        assert!(!theirs.is_empty(), "{control_set}");
        assert_eq!(ours, theirs, "{control_set}");
        total += ours.len();
    }
    eprintln!("{total} BAM entries match RECmd");
}
