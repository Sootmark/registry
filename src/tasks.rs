//! Scheduled tasks as the Task Scheduler caches them (SOFTWARE, Windows
//! Vista and later), under `Microsoft\Windows NT\CurrentVersion\Schedule\
//! TaskCache`: `Tree` mirrors the task folders, each task's key holding its
//! `Id`; `Tasks\{Id}` holds the task's path, description, author, its
//! actions (Windows 8 and later) and `DynamicInfo`. A task that is in the
//! registry but whose XML file in `System32\Tasks` is gone still runs;
//! one missing from `Tree` is hidden from the Task Scheduler's own views.
//!
//! `DynamicInfo` isn't documented by Microsoft. Its layout here is the one
//! public research agrees on (libyal's "Task Scheduler Keys" notes, plaso's
//! `task_scheduler` plugin, Eric Zimmerman's TaskCache plugin for RECmd):
//! 28 bytes before Windows 8, 36 after, a version, then FILETIMEs at bytes
//! 4 and 12 and, in the longer form, 28. What the times mean is inferred,
//! not documented: libyal and plaso read the first as the last registration
//! (or update) and the second as the last launch; RECmd reads them as
//! created, last start, and the third as last stop. The two 32-bit fields
//! at bytes 20 and 24 are read as RECmd reads them (task state, last
//! result), with the same caution: libyal's own samples show an `HRESULT`
//! at byte 20.
//!
//! `Actions` (Windows 8 and later, version 3) is decoded as RECmd's
//! TaskCache plugin decodes it, and as every task of the test hives
//! confirms (each blob read to its last byte): a version, the principal's
//! id (a length-prefixed UTF-16 string), then actions, each a 16-bit type:
//! `0x6666` runs a program (id, path, arguments, working directory, 16 bits
//! of flags), `0x7777` calls a COM handler (id, CLSID, data). Other types
//! (`0x8888` e-mail, `0x9999` message box, both deprecated) and other
//! versions aren't decoded: their UTF-16 strings are kept instead, so a
//! command line is never lost, but nothing is said of what each string is.

use std::collections::{HashMap, HashSet};

use crate::artifact::{bytes, non_empty, Found};
use crate::{u16_at, u32_at, u64_at, Hive, Key};

const ROOT: &str = r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";
/// Deeper task folders than this are damage (or a loop).
const MAX_DEPTH: usize = 32;

/// What `DynamicInfo` records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dynamic {
    /// The first field (3 in every hive seen).
    pub version: u32,
    /// Bytes 4 to 12 (FILETIME, 0 when not set): the last registration or
    /// update (libyal, plaso), "created on" (RECmd).
    pub registered: u64,
    /// Bytes 12 to 20 (FILETIME, 0 when not set): the last launch.
    pub last_start: u64,
    /// Bytes 28 to 36 (FILETIME, 0 when not set; Windows 8 and later):
    /// "last stop" (RECmd), unnamed by libyal and plaso.
    pub last_stop: Option<u64>,
    /// Bytes 20 to 24: the task's state, as RECmd reads it.
    pub state: u32,
    /// Bytes 24 to 28: the last run's result (an `HRESULT`), as RECmd
    /// reads it.
    pub last_result: u32,
}

impl Dynamic {
    fn read(data: &[u8]) -> Option<Self> {
        if data.len() != 28 && data.len() != 36 {
            return None;
        }
        Some(Self {
            version: u32_at(data, 0)?,
            registered: u64_at(data, 4)?,
            last_start: u64_at(data, 12)?,
            state: u32_at(data, 20)?,
            last_result: u32_at(data, 24)?,
            last_stop: u64_at(data, 28),
        })
    }
}

/// One action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Run a program.
    Exec {
        /// The program, as written (`%windir%\system32\x.exe`).
        command: String,
        /// Its arguments.
        arguments: String,
        /// Its working directory.
        working_directory: String,
    },
    /// Call a COM handler.
    ComHandler {
        /// The handler's class id, braces kept.
        clsid: String,
        /// The data passed to it.
        data: String,
    },
}

/// A task's `Actions` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actions {
    /// Decoded.
    Decoded {
        /// The blob's version.
        version: u16,
        /// The principal the actions run as (`Author`, `LocalSystem`, an
        /// id of the task's XML).
        principal: String,
        /// The actions, in order.
        actions: Vec<Action>,
    },
    /// Not decodable (another version, an unknown action, damage): the
    /// UTF-16 strings of four or more printable ASCII or Latin characters
    /// it holds, in order.
    Strings(Vec<String>),
}

impl Actions {
    fn read(data: &[u8]) -> Self {
        decode(data).unwrap_or_else(|| Self::Strings(utf16_strings(data)))
    }
}

/// One scheduled task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    /// Its id (the `Tasks` subkey's name, braces kept); `None` for a `Tree`
    /// entry naming no `Tasks` key.
    pub id: Option<String>,
    /// Its path: `\Microsoft\Windows\Defrag\ScheduledDefrag`.
    pub path: String,
    /// `URI`, `Author`, `Description`, `Source` and `SecurityDescriptor`,
    /// where present (Windows 8 and later; resource references kept as
    /// written).
    pub uri: Option<String>,
    /// `Author`.
    pub author: Option<String>,
    /// `Description`.
    pub description: Option<String>,
    /// `Source`.
    pub source: Option<String>,
    /// `SecurityDescriptor` (SDDL).
    pub security_descriptor: Option<String>,
    /// `Actions`, where present.
    pub actions: Option<Actions>,
    /// `DynamicInfo`, when 28 or 36 bytes.
    pub dynamic: Option<Dynamic>,
    /// Whether `Tree` has an entry for it.
    pub in_tree: bool,
    /// The `Tasks` key's path (or, without one, the `Tree` key's).
    pub key: String,
    /// When that key was last written (FILETIME).
    pub key_last_written: u64,
    /// When the task's `Tree` key was last written (FILETIME).
    pub tree_last_written: Option<u64>,
}

impl Task {
    /// Its name: the path's last part.
    #[must_use]
    pub fn name(&self) -> &str {
        self.path.rsplit('\\').next().unwrap_or(&self.path)
    }
}

/// A `Tree` entry: the task's path, its key's path and last write.
struct TreeEntry {
    path: String,
    key: String,
    last_written: u64,
}

/// Every task of `Tasks`, then the `Tree` entries naming none.
#[must_use]
pub fn tasks(hive: &Hive<'_>) -> Found<Task> {
    let mut found = Found::default();
    let mut tree = HashMap::new();
    let tree_path = format!(r"{ROOT}\Tree");
    if let Some(root) = found.open(hive, &tree_path) {
        let mut seen = HashSet::new();
        walk_tree(&root, &tree_path, "", 0, &mut seen, &mut tree, &mut found);
    }
    let tasks_path = format!(r"{ROOT}\Tasks");
    if let Some(tasks) = found.open(hive, &tasks_path) {
        for key in found.subkeys(&tasks, &tasks_path) {
            let entry = tree.remove(&key.name.to_uppercase());
            let task = task(&key, format!(r"{tasks_path}\{}", key.name), entry);
            found.entries.push(task);
        }
    }
    let mut orphans: Vec<(String, TreeEntry)> = tree.into_iter().collect();
    orphans.sort_by(|a, b| a.1.key.cmp(&b.1.key));
    for (_, entry) in orphans {
        found.entries.push(Task {
            id: None,
            path: entry.path,
            uri: None,
            author: None,
            description: None,
            source: None,
            security_descriptor: None,
            actions: None,
            dynamic: None,
            in_tree: true,
            key: entry.key,
            key_last_written: entry.last_written,
            tree_last_written: Some(entry.last_written),
        });
    }
    found
}

/// Collect `Tree`'s task keys (those with an `Id`) by upper-case id.
fn walk_tree(
    key: &Key<'_>,
    key_path: &str,
    task_path: &str,
    depth: usize,
    seen: &mut HashSet<u32>,
    tree: &mut HashMap<String, TreeEntry>,
    found: &mut Found<Task>,
) {
    if depth > MAX_DEPTH || !seen.insert(key.offset) {
        found.problem(key_path, None, "task folders loop or nest too deep");
        return;
    }
    if let Some(id) = non_empty(key, "Id") {
        tree.insert(
            id.to_uppercase(),
            TreeEntry {
                path: task_path.to_owned(),
                key: key_path.to_owned(),
                last_written: key.last_written,
            },
        );
    }
    for sub in found.subkeys(key, key_path) {
        let sub_key_path = format!(r"{key_path}\{}", sub.name);
        let sub_task_path = format!(r"{task_path}\{}", sub.name);
        walk_tree(
            &sub,
            &sub_key_path,
            &sub_task_path,
            depth + 1,
            seen,
            tree,
            found,
        );
    }
}

fn task(key: &Key<'_>, path: String, tree: Option<TreeEntry>) -> Task {
    let task_path = non_empty(key, "Path")
        .or_else(|| tree.as_ref().map(|t| t.path.clone()))
        .unwrap_or_else(|| key.name.clone());
    Task {
        id: Some(key.name.clone()),
        path: task_path,
        uri: non_empty(key, "URI"),
        author: non_empty(key, "Author"),
        description: non_empty(key, "Description"),
        source: non_empty(key, "Source"),
        security_descriptor: non_empty(key, "SecurityDescriptor"),
        actions: bytes(key, "Actions").map(|data| Actions::read(&data)),
        dynamic: bytes(key, "DynamicInfo").and_then(|data| Dynamic::read(&data)),
        in_tree: tree.is_some(),
        key: path,
        key_last_written: key.last_written,
        tree_last_written: tree.map(|t| t.last_written),
    }
}

/// A cursor over an `Actions` blob.
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn u16(&mut self) -> Option<u16> {
        let n = u16_at(self.data, self.at)?;
        self.at += 2;
        Some(n)
    }

    fn take(&mut self, len: usize) -> Option<&[u8]> {
        let bytes = self.data.get(self.at..self.at.checked_add(len)?)?;
        self.at += len;
        Some(bytes)
    }

    /// A length-prefixed (32-bit, in bytes) UTF-16 string.
    fn string(&mut self) -> Option<String> {
        let len = u32_at(self.data, self.at)? as usize;
        self.at += 4;
        let bytes = self.take(len)?;
        if len % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }
}

/// Version 3 `Actions`, read to the last byte; `None` otherwise.
fn decode(data: &[u8]) -> Option<Actions> {
    let mut reader = Reader { data, at: 0 };
    let version = reader.u16()?;
    if version != 3 {
        return None;
    }
    let principal = reader.string()?;
    let mut actions = Vec::new();
    while reader.at < data.len() {
        let action = match reader.u16()? {
            0x6666 => {
                reader.string()?;
                let action = Action::Exec {
                    command: reader.string()?,
                    arguments: reader.string()?,
                    working_directory: reader.string()?,
                };
                reader.u16()?;
                action
            }
            0x7777 => {
                reader.string()?;
                let clsid = crate::shellitem::guid(reader.take(16)?)?;
                Action::ComHandler {
                    clsid,
                    data: reader.string()?,
                }
            }
            _ => return None,
        };
        actions.push(action);
    }
    Some(Actions::Decoded {
        version,
        principal,
        actions,
    })
}

/// Whether a character may be part of a kept string: printable ASCII and
/// Latin letters, nothing that a length or a type field (`0x6666` is a
/// CJK ideograph) could pass for.
fn printable(c: char) -> bool {
    c == ' ' || c.is_ascii_graphic() || ('\u{a0}'..='\u{24f}').contains(&c)
}

/// The UTF-16 strings of four or more printable characters, at even
/// offsets.
fn utf16_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for unit in data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
    {
        if let Some(c) = char::from_u32(u32::from(unit)).filter(|&c| printable(c)) {
            current.push(c);
        } else if current.chars().count() >= 4 {
            out.push(std::mem::take(&mut current));
        } else {
            current.clear();
        }
    }
    if current.chars().count() >= 4 {
        out.push(current);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(text: &str) -> Vec<u8> {
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
        out.extend(bytes);
        out
    }

    #[test]
    fn actions_decode_or_keep_their_strings() {
        let mut blob = vec![3, 0];
        blob.extend(string("Author"));
        blob.extend([0x66, 0x66]);
        blob.extend(string(""));
        blob.extend(string(r"%windir%\system32\usoclient.exe"));
        blob.extend(string("StartWork"));
        blob.extend(string(""));
        blob.extend([0, 0]);
        assert_eq!(
            Actions::read(&blob),
            Actions::Decoded {
                version: 3,
                principal: "Author".to_owned(),
                actions: vec![Action::Exec {
                    command: r"%windir%\system32\usoclient.exe".to_owned(),
                    arguments: "StartWork".to_owned(),
                    working_directory: String::new(),
                }],
            }
        );
        // A truncated blob: its strings are kept.
        let truncated = &blob[..blob.len() - 30];
        assert!(matches!(
            Actions::read(truncated),
            Actions::Strings(s) if s.contains(&"Author".to_owned())
        ));
        blob[0] = 2;
        assert!(matches!(Actions::read(&blob), Actions::Strings(_)));
        assert!(Dynamic::read(&[0; 20]).is_none());
        let dynamic = Dynamic::read(&[0; 28]).unwrap();
        assert_eq!(dynamic.last_stop, None);
    }

    proptest::proptest! {
        /// Any bytes are decoded or kept as strings: never a panic.
        #[test]
        fn any_actions_blob_reads(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            let _ = Actions::read(&data);
            let mut blob = vec![3, 0];
            blob.extend(&data);
            let _ = Actions::read(&blob);
        }
    }
}
