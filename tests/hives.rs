//! Eric Zimmerman's registry test hives (MIT; `tests/fixtures/EZ-LICENSE.txt`),
//! read whole. Each dump (`tests/dump`) was compared key for key and value
//! for value with python-registry (`tests/oracle/`) and recorded as its key
//! count and SHA-256 in `tests/fixtures/digests.tsv`: any change in what is
//! read shows here. The small hives are in the repository; the large ones
//! come from `tests/fetch-hives.sh` and are checked when present.
//!
//! Where python-registry and this crate differ, python-registry is wrong,
//! each checked by hand: it returns all four bytes of inline data whatever
//! length the value declares (and its type number when that length is 0),
//! reads every `REG_DWORD` as inline (one in NTUSER.DAT holds 8 bytes in a
//! cell), and masks value types to 16 bits (device properties use the
//! upper bits).

use std::fs;
use std::path::Path;

use common::hex;
use common::sha256::Sha256;
use registry::{Data, Hive, Kind};

#[path = "dump/mod.rs"]
mod dump;

fn fixtures() -> &'static Path {
    Box::leak(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .into_boxed_path(),
    )
}

fn sha256(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(&hasher.finalize())
}

#[test]
fn every_hive_reads_as_verified() {
    let digests = fs::read_to_string(fixtures().join("digests.tsv")).unwrap();
    let (mut checked, mut absent) = (0, Vec::new());
    for line in digests.lines().filter(|l| !l.starts_with('#')) {
        let mut parts = line.split('\t');
        let (name, keys, digest) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let small = fixtures().join("ez").join(name);
        let path = if small.exists() {
            small
        } else {
            fixtures().join("ez-large").join(name)
        };
        let Ok(data) = fs::read(&path) else {
            absent.push(name);
            continue;
        };
        let out = dump::hive(&Hive::parse(&data).unwrap()).unwrap();
        assert_eq!(out.lines().count().to_string(), keys, "{name}: keys");
        assert!(!out.contains("\"error\""), "{name}: unreadable parts");
        assert_eq!(sha256(&out), digest, "{name}: what is read changed");
        checked += 1;
    }
    assert!(checked >= 12, "the small hives are in the repository");
    if !absent.is_empty() {
        eprintln!(
            "not checked (run tests/fetch-hives.sh): {}",
            absent.join(", ")
        );
    }
}

#[test]
fn refuses_what_isnt_a_hive() {
    for name in ["NotAHive", "system.LOG1"] {
        let data = fs::read(fixtures().join("ez").join(name)).unwrap();
        assert!(Hive::parse(&data).is_err(), "{name}");
    }
}

#[test]
fn opens_keys_and_reads_typed_values() {
    let data = fs::read(fixtures().join("ez/SAM")).unwrap();
    let hive = Hive::parse(&data).unwrap();
    assert!(hive.header.checksum_ok);
    let names = hive
        .open(r"sam\DOMAINS\Account\Users\Names")
        .unwrap()
        .unwrap();
    let users: Vec<String> = names
        .subkeys()
        .unwrap()
        .into_iter()
        .map(|k| k.name)
        .collect();
    assert!(users.iter().any(|u| u == "Administrator"), "{users:?}");
    assert!(hive.open(r"SAM\No\Such\Key").unwrap().is_none());
    let account = hive.open(r"SAM\Domains\Account").unwrap().unwrap();
    assert_eq!(account.parent().unwrap().unwrap().name, "Domains");
    let f = account.value("F").unwrap().unwrap();
    assert_eq!(f.kind, Kind::Binary);
    assert!(matches!(f.data(), Data::Bytes(b) if b.len() > 16));

    let data = fs::read(fixtures().join("ez/SAM_hasBigEndianDWord")).unwrap();
    let hive = Hive::parse(&data).unwrap();
    let mut big_endian = 0;
    hive.walk(
        |_, key| {
            for value in key.values().unwrap().into_iter().flatten() {
                if value.kind == Kind::DwordBigEndian {
                    // Declared empty in this hive (see above): typed only
                    // when four bytes are there.
                    let typed = matches!(value.data(), Data::Dword(_));
                    assert_eq!(typed, value.bytes.len() >= 4);
                    big_endian += 1;
                }
            }
        },
        |path, e| panic!("{path}: {e}"),
    )
    .unwrap();
    assert!(big_endian > 0, "big-endian DWORDs read");
}

mod damage {
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        /// Corrupted anywhere, a hive is read or refused: no panic, no
        /// endless walk.
        #[test]
        fn corrupted_hives_never_panic(flips in proptest::collection::vec((0_usize..262_144, any::<u8>()), 1..64)) {
            let mut data = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ez/SAM")).unwrap();
            for (at, byte) in flips {
                data[at] = byte;
            }
            if let Ok(hive) = registry::Hive::parse(&data) {
                let mut keys = 0;
                let _ = hive.walk(
                    |_, key| {
                        keys += 1;
                        if let Ok(values) = key.values() {
                            for value in values.into_iter().flatten() {
                                let _ = value.data();
                            }
                        }
                        let _ = key.class_name();
                    },
                    |_, _| {},
                );
                prop_assert!(keys < 100_000);
            }
        }
    }
}
