//! Local accounts and groups from two SAM hives: plaso's (Apache-2.0,
//! `tests/fixtures/sam/`, gzip-compressed) and Eric Zimmerman's test SAM
//! (`tests/fixtures/ez/`). Every account's times, counts and names equal
//! plaso's `windows_sam_users` reading (its 9 events on these hives);
//! groups, which plaso doesn't read, hold Windows' defaults.

use std::io::Read;

use registry::sam::{groups, users, User};
use registry::Hive;

fn plaso_sam() -> Vec<u8> {
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sam/plaso-SAM.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn ez_sam() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ez/SAM"
    ))
    .unwrap()
}

/// An account as plaso reports it: RID, name, last logon, password set,
/// creation (its Names key), logons.
fn summary(user: &User) -> (u32, &str, Option<u64>, Option<u64>, Option<u64>, u16) {
    (
        user.rid,
        user.name.as_deref().unwrap_or_default(),
        user.last_logon,
        user.password_last_set,
        user.created,
        user.logons,
    )
}

#[test]
fn accounts_match_plaso() {
    let data = plaso_sam();
    let hive = Hive::parse(&data).unwrap();
    let found = users(&hive);
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    let accounts: Vec<_> = found.entries.iter().map(summary).collect();
    assert_eq!(
        accounts,
        [
            (
                500,
                "Administrator",
                Some(130_396_116_473_414_256),
                Some(130_396_116_510_757_954),
                Some(130_927_191_960_266_868),
                3
            ),
            (501, "Guest", None, None, Some(130_927_191_960_266_868), 0),
            (
                1001,
                "gold_administrator",
                Some(131_206_891_559_699_859),
                Some(130_927_211_584_321_069),
                Some(130_927_211_583_387_425),
                4
            ),
        ]
    );
    let guest = &found.entries[1];
    assert!(guest.disabled() && guest.password_not_required());
    assert_eq!(
        guest.comment.as_deref(),
        Some("Built-in account for guest access to the computer/domain")
    );

    let data = ez_sam();
    let hive = Hive::parse(&data).unwrap();
    let ez = users(&hive);
    let accounts: Vec<_> = ez.entries.iter().map(summary).collect();
    assert_eq!(
        accounts,
        [
            (
                500,
                "Administrator",
                None,
                None,
                Some(130_488_843_376_056_430),
                0
            ),
            (501, "Guest", None, None, Some(130_488_843_376_056_430), 0),
        ]
    );
}

#[test]
fn groups_and_their_members() {
    let data = plaso_sam();
    let hive = Hive::parse(&data).unwrap();
    let found = groups(&hive);
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    assert_eq!(found.entries.len(), 18);
    let members = |rid: u32| {
        found
            .entries
            .iter()
            .find(|g| g.rid == rid)
            .map(|g| g.members.clone())
            .unwrap()
    };
    let administrators = found.entries.iter().find(|g| g.rid == 544).unwrap();
    assert_eq!(administrators.name.as_deref(), Some("Administrators"));
    assert_eq!(
        members(544)[..2],
        [
            "S-1-5-21-4070822719-3404542230-2541167049-500".to_owned(),
            "S-1-5-21-4070822719-3404542230-2541167049-1001".to_owned()
        ]
    );
    // Windows' defaults: INTERACTIVE and Authenticated Users in Users,
    // IUSR in IIS_IUSRS.
    assert_eq!(
        members(545)[..2],
        ["S-1-5-4".to_owned(), "S-1-5-11".to_owned()]
    );
    assert_eq!(members(568), ["S-1-5-17"]);

    let data = ez_sam();
    let hive = Hive::parse(&data).unwrap();
    let ez = groups(&hive);
    let administrators = ez.entries.iter().find(|g| g.rid == 544).unwrap();
    // A domain member: Domain Admins (RID 512) is a local administrator.
    assert!(administrators.members.iter().any(|m| m.ends_with("-512")));
}
