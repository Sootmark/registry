//! ShellBags: the folders a user opened in Explorer, kept even after the
//! folders are gone. In UsrClass.dat (`Local Settings\Software\Microsoft\
//! Windows\Shell\BagMRU`, Windows 7 and later) and NTUSER.DAT
//! (`Software\Microsoft\Windows\Shell\BagMRU`, `…\ShellNoRoam\BagMRU`).
//!
//! `BagMRU` is a tree: each key's numbered values are shell items (a
//! folder, a drive, …) and the subkey of the same number holds that item's
//! children; `MRUListEx` orders them, most recent first; `NodeSlot` points
//! at the view settings in `Bags`. A bag's path is its ancestors' names
//! from the desktop down.

use std::collections::HashSet;

use crate::artifact::mru_list_ex;
use crate::shellitem::{self, Item};
use crate::{Data, Error, Hive, Key};

/// Where ShellBags live, by hive.
const ROOTS: &[&str] = &[
    r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    r"Software\Microsoft\Windows\Shell\BagMRU",
    r"Software\Microsoft\Windows\ShellNoRoam\BagMRU",
];
/// Deeper than this is damage (or a loop).
const MAX_DEPTH: usize = 64;

/// One ShellBag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bag {
    /// The key holding it, relative to the hive's `BagMRU` parent
    /// (`BagMRU\1\0`).
    pub bag_path: String,
    /// Its value's number in that key.
    pub slot: u32,
    /// Its position in the key's `MRUListEx` (0: most recent).
    pub mru_position: Option<usize>,
    /// The `NodeSlot` of its own key (its view settings in `Bags`).
    pub node_slot: Option<u32>,
    /// Its path from the desktop: `Desktop\This PC\C:\Users`.
    pub path: String,
    /// The shell item.
    pub item: Item,
    /// When the key holding it was last written (FILETIME): the latest
    /// change to that folder's list of children.
    pub parent_written: u64,
    /// How many child bags it has.
    pub child_bags: usize,
}

fn dword(key: &Key<'_>, name: &str) -> Option<u32> {
    match key.value(name).ok()??.data() {
        Data::Dword(n) => Some(n),
        _ => None,
    }
}

/// Every ShellBag in `hive`, depth first.
///
/// # Errors
/// When a `BagMRU` key can't be read.
pub fn bags(hive: &Hive<'_>) -> Result<Vec<Bag>, Error> {
    let mut out = Vec::new();
    for root in ROOTS {
        if let Some(key) = hive.open(root)? {
            let mut seen = HashSet::new();
            walk(&key, "BagMRU", "Desktop", 0, &mut seen, &mut out)?;
        }
    }
    Ok(out)
}

fn walk(
    key: &Key<'_>,
    bag_path: &str,
    path: &str,
    depth: usize,
    seen: &mut HashSet<u32>,
    out: &mut Vec<Bag>,
) -> Result<(), Error> {
    if depth > MAX_DEPTH || !seen.insert(key.offset) {
        return Ok(());
    }
    let order = mru_list_ex(key);
    let subkeys = key.subkeys()?;
    let mut values: Vec<(u32, Vec<u8>)> = key
        .values()?
        .into_iter()
        .flatten()
        .filter_map(|v| Some((v.name.parse::<u32>().ok()?, v.bytes.into_owned())))
        .collect();
    values.sort_by_key(|(slot, _)| *slot);
    for (slot, list) in values {
        let Some(first) = shellitem::items(&list).first().copied() else {
            continue;
        };
        let item = shellitem::decode(first);
        let child_path = format!(r"{path}\{}", item.name);
        let child = subkeys.iter().find(|k| k.name == slot.to_string());
        out.push(Bag {
            bag_path: bag_path.to_owned(),
            slot,
            mru_position: order.iter().position(|&n| n == slot),
            node_slot: child.and_then(|k| dword(k, "NodeSlot")),
            path: child_path.clone(),
            item,
            parent_written: key.last_written,
            child_bags: child.map_or(0, |k| k.subkey_count as usize),
        });
        if let Some(child) = child {
            walk(
                child,
                &format!(r"{bag_path}\{slot}"),
                &child_path,
                depth + 1,
                seen,
                out,
            )?;
        }
    }
    Ok(())
}
