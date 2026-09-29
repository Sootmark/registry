# registry

A Windows registry hive (`regf`) parser, written from the public format documentation: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat, Amcache.hve, BCD. One dependency, its sibling `sootmark-shell` (shell items).

```toml
[dependencies]
sootmark-registry = "0.5"
```

```rust
let data = std::fs::read("SYSTEM")?;
let hive = registry::Hive::parse(&data)?;
if let Some(key) = hive.open(r"ControlSet001\Control\ComputerName\ComputerName")? {
    if let Some(value) = key.value("ComputerName")? {
        println!("{:?}", value.data()); // String("DESKTOP-…")
    }
}
hive.walk(|path, key| println!("{path} {}", key.last_written), |path, e| eprintln!("{path}: {e}"))?;
```

## What you get

- `Hive::parse`: the base block (sequence numbers, last written time, version, checksum); `is_dirty()` when a write was interrupted.
- `open(path)` (case-insensitive), `root()`, and `walk()`: every key depth first, in the hive's order, never looping on damage.
- `Key`: name, last written time (FILETIME), class name, parent, `subkeys()` (`lf`, `lh`, `li` and `ri` lists), `values()`.
- `Value`: name (`""` for the default value), type (`Kind`, raw number kept for application types), raw bytes (inline, in a cell, or in big-data segments) and `data()` read by type: strings, multi-strings, DWORD (either byte order), QWORD, bytes.
- Offsets of keys and values in the hive, as stable locators.
- Damage is an error for what it touches, never a panic: a key whose value can't be read keeps its other values.
- `shimcache::parse`: the AppCompatCache value (Windows XP, Vista/2008 and 7 in x86 and x64, 8.0, 8.1, 10/11): each file's path as recorded, last modification time and, before Windows 10, the executed flag.
- `userassist`: ROT13 names decoded, known folders named, run count, focus count and time, last run.
- `shellbags::bags`: the folders a user opened in Explorer (UsrClass.dat and NTUSER.DAT), as paths from the desktop, with MRU position, node slot and the key's last write; each a `shellitem::Item`.
- `shellitem`: shell items (also in LNK files and jump lists): root and known folders, drives, folders and files with their long names, FAT times and NTFS references, control panel pages and categories, "Users Files" delegates, property views, network locations, URIs. Other classes are reported as unknown with their class byte, not guessed.

Not yet: replaying transaction logs (`.LOG1`/`.LOG2`) into a dirty hive, and recovering deleted keys and values from free cells.

## How it's checked

- Eric Zimmerman's 24 test hives (and a file that isn't one) (MIT; `tests/fixtures/EZ-LICENSE.txt`), including a damaged hbin header, duplicate names, a value on the root, big-endian DWORDs, slack and deleted ShellBags: every key and value compared with python-registry (all 153,075 keys of SOFTWARE included), each difference traced to python-registry (documented in `tests/hives.rs`). Each hive's dump is recorded as its key count and SHA-256, so any change in what is read fails the tests. Small hives are in the repository; `tests/fetch-hives.sh` downloads the large ones at a pinned commit, checked by SHA-256.
- ShimCache: all 1,024 entries of the test SYSTEM hive against AppCompatCacheParser (position, path, time, executed), and AppCompatCacheParser's own test values for XP, 2008, 7 (x86, x64), 8.0, 8.1, 10 and 10 Creators (MIT, `tests/fixtures/appcompatcache/`) against its test expectations. UserAssist: all 578 entries of the test NTUSER.DAT against RECmd (names, paths, run counts, times to 100 ns). Where the tools choose a display form (the `\??\` prefix, "Unmapped GUID", session data read as counters), the difference is documented in the tests.
- ShellBags: all 523 bags of the test ERZ_Win81_UsrClass.dat against SBECmd, every column (path, name, MRU position, child bags, created, modified and accessed times, MFT reference, extension blocks); SBECmd's two display choices documented in `tests/shellbags.rs`. The other UsrClass hives (Windows 7, zip folders, FTP, Unicode names, deleted bags) read without error.
- Corrupted hives and arbitrary shell items (property tests): read or refused, never a panic or an endless walk.

## Licence

MIT or Apache-2.0, at your option. The test hives and AppCompatCache values are Eric Zimmerman's, under the MIT licence.
