# registry

A Windows registry hive (`regf`) parser, written from the public format documentation: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat, Amcache.hve, BCD. No dependencies.

```toml
[dependencies]
sootmark-registry = "0.1"
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

Not yet: replaying transaction logs (`.LOG1`/`.LOG2`) into a dirty hive, and recovering deleted keys and values from free cells.

## How it's checked

- Eric Zimmerman's 24 test hives (and a file that isn't one) (MIT; `tests/fixtures/EZ-LICENSE.txt`), including a damaged hbin header, duplicate names, a value on the root, big-endian DWORDs, slack and deleted ShellBags: every key and value compared with python-registry (all 153,075 keys of SOFTWARE included), each difference traced to python-registry (documented in `tests/hives.rs`). Each hive's dump is recorded as its key count and SHA-256, so any change in what is read fails the tests. Small hives are in the repository; `tests/fetch-hives.sh` downloads the large ones at a pinned commit, checked by SHA-256.
- Corrupted hives (property tests): read or refused, never a panic or an endless walk.

## Licence

MIT or Apache-2.0, at your option. The test hives are Eric Zimmerman's, under the MIT licence.
