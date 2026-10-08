# registry

A Windows registry hive (`regf`) parser and the incident-response artifacts it holds, written from the public format documentation: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat, Amcache.hve, BCD. One dependency, its sibling `sootmark-shell` (shell items).

```toml
[dependencies]
sootmark-registry = "0.10"
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
- `amcache::read`: Amcache.hve's entries, both layouts (Windows 10 1607 and later: `Root\Inventory*`; Windows 8 to early 10: `Root\File` and `Root\Programs`, numbered values named): files (path, SHA-1, size, link date, program), programs (name, publisher, version, install date), shortcuts, driver binaries and packages, Plug and Play devices and device containers; every value kept as text, with the key's last write.
- `bam::entries`: BAM and DAM (Windows 10 1709 and later): per user SID, each program (device path or app package) and when it last ran, for any control set (the last known good one keeps older runs).
- `Hive::current_control_set`: `Select\Current` as `ControlSet00N`. The readers below return a `Found`: the entries, and a `Problem` (key, value, reason) for each part damage kept them from reading.
- `usb::devices` (SYSTEM): `Enum\USBSTOR` and `Enum\USB` instances: type, vendor, product, revision, serial (and whether it's the device's own), friendly name, bus-reported description, disk id, the driver install, first install, last arrival and last removal times (device properties `0064` to `0067`, both the Windows 7 and the Windows 8+ layouts; the instance key's last write stands in for a missing arrival, marked as such), and the drive letters and volumes `MountedDevices` last bound to it.
- `mounted::read` (SYSTEM): `MountedDevices`: each drive letter and volume GUID, its binding (MBR disk signature and offset, GPT partition GUID, device path) and the other names sharing it.
- `rdp::connections` (NTUSER.DAT): outbound Remote Desktop hosts from `Terminal Server Client\Servers` (user name hint, key last write) and the `Default` MRU list (position; its last write dates the most recent).
- `mru::entries` (NTUSER.DAT): `RecentDocs` (and its per-extension lists, `MRUListEx` order, the name and the shortcut's name from the binary values), `RunMRU` (`MRUList` order), `TypedPaths`, `WordWheelQuery`, Internet Explorer's `TypedURLs` (each dated from `TypedURLsTime` on Windows 8 and later), WinRAR's `ArcHistory` and the archive names and extraction folders typed in its dialogs.
- `drives::mount_points` and `drives::network_drives` (NTUSER.DAT): `MountPoints2` (each drive letter, volume GUID and network share the user's Explorer saw, server and share split, its label, its key's last write) and `Network\<letter>` (mapped drives: share, server, account used, provider).
- `office::mru` and `office::trust_records` (NTUSER.DAT): every Office version's and application's `File MRU` and `Place MRU` (Microsoft 365's per-account lists included), each item's path and when it was opened (from its `[T…]`); and `Trusted Documents\TrustRecords`, each document trusted, when, and whether its macros were enabled.
- `office::outlook_search` (NTUSER.DAT): the mail stores (`.pst`, `.ost`) each Outlook version's search indexed.
- `zones::zones` (NTUSER.DAT, SOFTWARE and its `Wow6432Node`): the security zones (My Computer, Local intranet, Trusted sites, Internet, Restricted sites) and their lockdown copies, each setting by action number: a zone opened up.
- `programscache::caches` (NTUSER.DAT): Explorer's Start menu and taskbar caches (`StartPage`, `StartPage2`: `ProgramsCache`, `ProgramsCacheSMP`, `ProgramsCacheTBP`), each shortcut's path from its shell items.
- `cleaners::ccleaner` (NTUSER.DAT): CCleaner's settings, what it was set to wipe and its last update check; `cleaners::diagnosed_applications` (SOFTWARE): programs Windows' memory leak diagnosis watched, with their last detection.
- `networks::profiles` (SOFTWARE): `NetworkList\Profiles` (name, description, type, category, managed, first and last connected as wall-clock `SystemTime`s, local time of an unknown zone) with their `Signatures` (gateway MAC, DNS suffix, first network).
- `tasks::tasks` (SOFTWARE): `Schedule\TaskCache`: each task's path, id, author, description, security descriptor, `DynamicInfo` times (as libyal, plaso and RECmd read them; their meaning is inferred, not documented) and, Windows 8 and later, its actions (programs with arguments, COM handlers; an undecodable blob keeps its UTF-16 strings); `Tree` entries without a task are kept.
- `persistence::entries` (SOFTWARE, its `Wow6432Node`, NTUSER.DAT, SYSTEM): Winlogon `Shell`, `Userinit`, `Taskman`; Image File Execution Options `Debugger` and `GlobalFlag`; `SilentProcessExit` `MonitorProcess`; `AppInit_DLLs`, `LoadAppInit_DLLs`; Explorer `StartupApproved` (enabled, when disabled); Active Setup `StubPath`. Each says whether it departs from Windows' default. In SYSTEM, each control set's `Session Manager\BootExecute` (Windows' own `autocheck autochk *` or not) and `BootVerificationProgram\ImagePath`.
- `programs::programs` (SOFTWARE, `Wow6432Node`, NTUSER.DAT): `Uninstall` entries: name, version, publisher, install date, location, source, uninstall string, key last write.
- `system::identity`: computer name, time zone (key name, biases), last shutdown (SYSTEM); product, edition, build, install date and time, registered owner, and `ProfileList` (SID, folder, last load and unload) (SOFTWARE). The hardware as the firmware describes it (maker, model, BIOS version and date), from `Control\SystemInformation` or the last hardware profile (`HardwareConfig`).
- `sam::users` and `sam::groups` (SAM): each local account (RID, name, full name, comment; last logon, password last set, account expiry and last failed logon; account control flags with `disabled()`, `password_not_required()`, `password_never_expires()`, `locked()`; failed and successful logons counted; its creation, from its `Names` key's last write) and each local group (built-in and the machine's: name, description, members' SIDs). Password hashes are never read.
- `shellitem`: shell items (also in LNK files and jump lists): root and known folders, drives, folders and files with their long names, FAT times and NTFS references, control panel pages and categories, "Users Files" delegates, property views, network locations, URIs. Other classes are reported as unknown with their class byte, not guessed.

Not yet: replaying transaction logs (`.LOG1`/`.LOG2`) into a dirty hive, and recovering deleted keys and values from free cells.

## How it's checked

- Eric Zimmerman's 24 test hives (and a file that isn't one) (MIT; `tests/fixtures/EZ-LICENSE.txt`), including a damaged hbin header, duplicate names, a value on the root, big-endian DWORDs, slack and deleted ShellBags: every key and value compared with python-registry (all 153,075 keys of SOFTWARE included), each difference traced to python-registry (documented in `tests/hives.rs`). Each hive's dump is recorded as its key count and SHA-256, so any change in what is read fails the tests. Small hives are in the repository; `tests/fetch-hives.sh` downloads the large ones at a pinned commit, checked by SHA-256.
- SAM: plaso's test SAM (Apache-2.0, `tests/fixtures/sam/`) and Eric Zimmerman's: every account's name, logon and password times, creation and logon count equal to plaso's `windows_sam_users` (all 9 of its events); groups, which plaso doesn't read, hold Windows' defaults (INTERACTIVE and Authenticated Users in Users, IUSR in IIS_IUSRS, Domain Admins in a domain member's Administrators).
- Mount points, network drives, Office lists and typed addresses: plaso's NTUSER.DAT and NTUSER-WIN7.DAT (Apache-2.0, fetched): every value plaso's `explorer_mountpoints2`, `network_drives`, `microsoft_office_mru` and `windows_typed_urls` plugins read, read the same (22 events). Trust records, `TypedURLsTime` and WinRAR's lists have no open hive yet: their decoding is unit-tested.
- CCleaner, diagnosed applications, ProgramsCache, Outlook's search, the zones and BootExecute: plaso's test hives (NTUSER.DAT, NTUSER-WIN7.DAT, NTUSER-CCLEANER.DAT, SOFTWARE, SYSTEM) and Andrew Rathbun's Windows 10 and 11 hives: all 86 events plaso's `ccleaner`, `diagnosed_applications`, `explorer_programscache`, `microsoft_outlook_mru`, `msie_zone` and `windows_boot_execute` plugins read, read the same (`tests/oracle/plaso-app-keys.tsv`; key names compared without case, shortcut paths in plaso's spelling). The hardware: the Windows 10 and 11 and Eric Zimmerman's SYSTEM hives, as python-registry reads `HardwareConfig` (plaso's `motherboard_info` reads `Control\SystemInformation`, which they don't keep).
- ShimCache: all 1,024 entries of the test SYSTEM hive against AppCompatCacheParser (position, path, time, executed), and AppCompatCacheParser's own test values for XP, 2008, 7 (x86, x64), 8.0, 8.1, 10 and 10 Creators (MIT, `tests/fixtures/appcompatcache/`) against its test expectations. UserAssist: all 578 entries of the test NTUSER.DAT against RECmd (names, paths, run counts, times to 100 ns). Where the tools choose a display form (the `\??\` prefix, "Unmapped GUID", session data read as counters), the difference is documented in the tests.
- ShellBags: all 523 bags of the test ERZ_Win81_UsrClass.dat against SBECmd, every column (path, name, MRU position, child bags, created, modified and accessed times, MFT reference, extension blocks); SBECmd's two display choices documented in `tests/shellbags.rs`. The other UsrClass hives (Windows 7, zip folders, FTP, Unicode names, deleted bags) read without error.
- Amcache: plaso's two real test hives (Apache-2.0, `tests/fixtures/amcache/`) against AmcacheParser, all 1,012 entries of every class on every column (its display forms and one bug, flags always printed `False`, documented in `tests/amcache.rs`); the older layout against plaso's Amcache parser, all 1,153 file and 26 program events.
- BAM: every entry of the SYSTEM hives of Andrew Rathbun's Windows 10 and 11 VMs (MIT, [DFIR Artifact Museum](https://github.com/AndrewRathbun/DFIRArtifactMuseum), fetched by `tests/fetch-hives.sh`; 23 and 19 entries) matches RECmd's BamDam plugin (its output in `tests/oracle/`); `tests/bam.rs` checks any other hive it's pointed at.
- USB devices, `MountedDevices`, Remote Desktop history, the MRU lists, network profiles, scheduled tasks, Startup Approved, installed programs and system identity: against Eric Zimmerman's RECmd (its `Kroll_Batch.reb` and plugins; outputs in `tests/oracle/recmd/`) on Eric Zimmerman's test SYSTEM, SOFTWARE and NTUSER.DAT, plaso's SYSTEM, SOFTWARE-RunTests and NTUSER-WIN7.DAT (Apache-2.0, fetched at a pinned commit) and the Windows 10 VM's SYSTEM, SOFTWARE and NTUSER.DAT, every entry on every column RECmd prints (9 USBSTOR and 41 USB devices, 79 mounts, 6 RDP hosts, 574 RecentDocs entries, 197 Windows 10 tasks, 162 programs, …), and the values plaso's own Windows Registry plugin tests expect of its hives (USBSTOR, USB, RecentDocs, TypedPaths, TaskCache, shutdown, time zone, Windows version). Where RECmd differs (it reads Windows 7's device properties not at all, a time zone name past its NUL, task actions with an id as an error, and recovers a deleted key), `tests/artifacts.rs` says so. No open hive sets an IFEO debugger, `GlobalFlag`, `SilentProcessExit` or `Taskman`: those decisions are checked by unit tests only.
- Corrupted hives (through every artifact reader), Amcache hives, task action blobs and arbitrary shell items (property tests): read or refused, never a panic or an endless walk.

## Licence

MIT or Apache-2.0, at your option. The test hives and AppCompatCache values are Eric Zimmerman's, under the MIT licence; the Amcache test hives and the hives `tests/fetch-hives.sh` takes from plaso are plaso's, under the Apache licence 2.0; the VM hives `tests/fetch-hives.sh` downloads are Andrew Rathbun's, under the MIT licence.
