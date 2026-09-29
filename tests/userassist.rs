//! UserAssist against Eric Zimmerman's RECmd on the test NTUSER.DAT
//! (fetched by `tests/fetch-hives.sh`; RECmd's rows are in
//! `tests/fixtures/oracle/`): names, paths with known folders, run counts
//! and last run times, for all 578 entries.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use registry::{userassist, Hive};

/// FILETIME as RECmd prints it: `2014-12-08 13:35:46.4100000`.
fn ticks(filetime: u64) -> String {
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
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let Ok(data) = fs::read(dir.join("ez-large/NTUSER.DAT")) else {
        eprintln!("skipped: run tests/fetch-hives.sh");
        return;
    };
    let hive = Hive::parse(&data).unwrap();
    let root = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
    let mut ours = HashMap::new();
    for guid in hive.open(root).unwrap().unwrap().subkeys().unwrap() {
        let Some(count) = guid.subkey("Count").unwrap() else {
            continue;
        };
        for value in count.values().unwrap().into_iter().map(Result::unwrap) {
            ours.insert((guid.name.clone(), value.name.clone()), value);
        }
    }
    let oracle = fs::read_to_string(dir.join("oracle/NTUSER_RECmd_UserAssist.csv")).unwrap();
    let mut checked = 0;
    for line in oracle.lines().skip(1) {
        let row = fields(line);
        let guid = row[0].rsplit('\\').nth(1).unwrap().to_owned();
        let value = ours
            .get(&(guid, row[1].clone()))
            .unwrap_or_else(|| panic!("missing {}", row[1]));
        let decoded = userassist::decode(&value.name);
        // RECmd marks GUIDs it has no name for as `{Unmapped GUID: …}`;
        // they're kept as recorded here.
        let expected = row[2].replace("Unmapped GUID: ", "");
        assert_eq!(userassist::path(&decoded), expected, "{}", row[1]);
        // Session data (`UEME_CTLSESSION`, 1,612 bytes) isn't a program's
        // counters: none here. RECmd reads its second field as a run count.
        let Some(counts) = userassist::counts(&value.bytes) else {
            assert_eq!(decoded, "UEME_CTLSESSION");
            assert_eq!(row[3], "Last executed: ", "{decoded}");
            checked += 1;
            continue;
        };
        assert_eq!(
            format!("Run count: {}", counts.run_count),
            row[4],
            "{decoded}"
        );
        let last = if counts.last_run == 0 {
            String::new()
        } else {
            ticks(counts.last_run)
        };
        assert_eq!(format!("Last executed: {last}"), row[3], "{decoded}");
        checked += 1;
    }
    assert_eq!(checked, 578);
}
