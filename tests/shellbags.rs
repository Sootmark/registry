//! ShellBags against Eric Zimmerman's SBECmd on the test
//! `ERZ_Win81_UsrClass.dat` (MIT; fetched by `tests/fetch-hives.sh`; SBECmd's
//! output is in `tests/fixtures/oracle/`): all 523 bags, every column.
//! SBECmd's choices where they differ, each checked by hand: it shows node
//! slot 0 for every top-level bag (here, each bag's own `NodeSlot`), and
//! shows no last write time for one bag whose item class has its high bit
//! set (0xB1).

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use registry::shellbags::{self, Bag};
use registry::Hive;

/// Seconds since 1970 as SBECmd prints them: `2014-06-08 20:23:31`.
fn when(secs: i64) -> String {
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

fn records(text: &str) -> Vec<Vec<String>> {
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
    rows
}

fn fields(bag: &Bag) -> HashMap<&'static str, String> {
    let i = &bag.item;
    let time = |t: Option<i64>| t.map(when).unwrap_or_default();
    HashMap::from([
        (
            "MRUPosition",
            bag.mru_position.map_or_else(String::new, |p| p.to_string()),
        ),
        ("AbsolutePath", bag.path.clone()),
        ("Value", i.name.clone()),
        ("ChildBags", bag.child_bags.to_string()),
        ("CreatedOn", time(i.created)),
        ("ModifiedOn", time(i.modified)),
        ("AccessedOn", time(i.accessed)),
        (
            "MFTEntry",
            i.mft.map_or_else(String::new, |(e, _)| e.to_string()),
        ),
        (
            "MFTSequenceNumber",
            i.mft.map_or_else(String::new, |(_, s)| s.to_string()),
        ),
        ("ExtensionBlockCount", i.extension_blocks.to_string()),
        ("NodeSlot", bag.node_slot.unwrap_or(0).to_string()),
        (
            "LastWriteTime",
            when((bag.parent_written / 10_000_000) as i64 - 11_644_473_600),
        ),
    ])
}

#[test]
fn matches_sbecmd() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let Ok(data) = fs::read(dir.join("ez-large/ERZ_Win81_UsrClass.dat")) else {
        eprintln!("skipped: run tests/fetch-hives.sh");
        return;
    };
    let bags = shellbags::bags(&Hive::parse(&data).unwrap()).unwrap();
    let oracle =
        records(&fs::read_to_string(dir.join("oracle/ERZ_Win81_UsrClass_SBECmd.csv")).unwrap());
    let header = &oracle[0];
    let column = |name: &str| header.iter().position(|h| h == name).unwrap();
    let ours: HashMap<(String, String), &Bag> = bags
        .iter()
        .map(|b| ((b.bag_path.clone(), b.slot.to_string()), b))
        .collect();
    assert_eq!(ours.len(), oracle.len() - 1);
    for row in &oracle[1..] {
        let key = (row[column("BagPath")].clone(), row[column("Slot")].clone());
        let bag = ours.get(&key).unwrap_or_else(|| panic!("missing {key:?}"));
        for (name, value) in fields(bag) {
            let expected = &row[column(name)];
            let quirk = match name {
                "NodeSlot" => key.0 == "BagMRU" || bag.item.class == 0xb1,
                "LastWriteTime" => bag.item.class == 0xb1,
                // SBECmd shows MFT entry 0, no sequence, off NTFS: none here.
                "MFTEntry" => expected == "0",
                _ => false,
            };
            if !quirk {
                assert_eq!(&value, expected, "{key:?} {name}");
            }
        }
    }
}

/// Every hive's ShellBags read without error (UsrClass variants from
/// Windows 7 to 8.1: zip folders, FTP, Unicode names, deleted bags).
#[test]
fn reads_every_hive() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for sub in ["ez", "ez-large"] {
        let Ok(entries) = fs::read_dir(dir.join(sub)) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let data = fs::read(&path).unwrap();
            if let Ok(hive) = Hive::parse(&data) {
                if hive.root().is_ok() {
                    shellbags::bags(&hive).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                }
            }
        }
    }
}

mod garbage {
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2_000))]

        /// Any bytes, as an item list or an item: decoded or skipped,
        /// never a panic.
        #[test]
        fn shell_items_never_panic(data in proptest::collection::vec(any::<u8>(), 0..600), class in any::<u8>()) {
            for item in registry::shellitem::items(&data) {
                let _ = registry::shellitem::decode(item);
            }
            let mut item = data.clone();
            if item.len() > 2 {
                item[2] = class;
            }
            let _ = registry::shellitem::decode(&item);
        }
    }
}
