//! Registry places programs use to start with Windows or with another
//! program, beyond Run and RunOnce, in SOFTWARE (and its `Wow6432Node`
//! view for 32-bit programs) and NTUSER.DAT:
//!
//! - Winlogon's `Shell`, `Userinit` and `Taskman`: what Winlogon starts at
//!   logon. A user's own `Winlogon` key overrides the machine's.
//! - Image File Execution Options: a `Debugger` starts instead of the
//!   program named by the key; `GlobalFlag` with `0x200`
//!   (`FLG_MONITOR_SILENT_PROCESS_EXIT`) arms `SilentProcessExit\<program>`,
//!   whose `MonitorProcess` starts when that program exits.
//! - `AppInit_DLLs`, loaded into every process that loads `user32.dll` when
//!   `LoadAppInit_DLLs` is 1.
//! - Explorer's `StartupApproved` (Windows 8 and later): whether each Run
//!   entry and Startup folder item is enabled. Not a way to start, but the
//!   record of one being switched off, and when.
//! - Active Setup's `StubPath`: run once per user at logon, for each
//!   component the user hasn't run yet.
//! - In SYSTEM, each control set's `Session Manager\BootExecute`: native
//!   programs the session manager runs before Windows starts (Windows'
//!   own `autocheck autochk *`, and boot-time tools); and
//!   `BootVerificationProgram\ImagePath`: what decides whether a boot was
//!   good.
//!
//! Where Windows has a default, an entry says whether its data departs
//! from it: `Shell` other than `explorer.exe`, `Userinit` other than
//! `userinit.exe` alone, and any `Taskman`, `Debugger`, `MonitorProcess`,
//! user-level `Shell` or `Userinit`, non-empty `AppInit_DLLs` or
//! `LoadAppInit_DLLs` other than 0. `StartupApproved` and `StubPath` have no
//! default to depart from.
//!
//! `StartupApproved`'s data isn't documented by Microsoft; it is read as
//! DFIR write-ups describe it: 12 bytes, the first even when enabled (2, 6)
//! and odd when disabled (3, 7), then from byte 4 a FILETIME of when it was
//! disabled (0 when it wasn't).

use crate::artifact::{text, Found};
use crate::{u64_at, Data, Hive, Key, Value};

/// How an entry starts something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// Winlogon `Shell`.
    WinlogonShell,
    /// Winlogon `Userinit`.
    WinlogonUserinit,
    /// Winlogon `Taskman`.
    WinlogonTaskman,
    /// Image File Execution Options `Debugger`.
    IfeoDebugger,
    /// Image File Execution Options `GlobalFlag`.
    IfeoGlobalFlag,
    /// `SilentProcessExit` `MonitorProcess`.
    SilentProcessExit,
    /// `AppInit_DLLs`.
    AppInitDlls,
    /// `LoadAppInit_DLLs`.
    LoadAppInitDlls,
    /// Explorer `StartupApproved`.
    StartupApproved,
    /// Active Setup `StubPath`.
    ActiveSetup,
    /// Session Manager `BootExecute`.
    BootExecute,
    /// `BootVerificationProgram` `ImagePath`.
    BootVerification,
}

impl Mechanism {
    /// Its short name: `winlogon_shell`, `ifeo_debugger`, ….
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::WinlogonShell => "winlogon_shell",
            Self::WinlogonUserinit => "winlogon_userinit",
            Self::WinlogonTaskman => "winlogon_taskman",
            Self::IfeoDebugger => "ifeo_debugger",
            Self::IfeoGlobalFlag => "ifeo_global_flag",
            Self::SilentProcessExit => "silent_process_exit",
            Self::AppInitDlls => "appinit_dlls",
            Self::LoadAppInitDlls => "load_appinit_dlls",
            Self::StartupApproved => "startup_approved",
            Self::ActiveSetup => "active_setup",
            Self::BootExecute => "boot_execute",
            Self::BootVerification => "boot_verification",
        }
    }
}

/// One entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// How it starts something.
    pub mechanism: Mechanism,
    /// Whether it's a user's (NTUSER.DAT) rather than the machine's.
    pub user: bool,
    /// Whether it's in `Wow6432Node`, for 32-bit programs.
    pub wow64: bool,
    /// What it applies to: the program (Image File Execution Options,
    /// `SilentProcessExit`), the Run entry or Startup item
    /// (`StartupApproved`), the component's id (Active Setup), the control
    /// set (`BootExecute`, `BootVerificationProgram`).
    pub target: Option<String>,
    /// Active Setup: the component's name (its key's default value).
    pub label: Option<String>,
    /// The value's name.
    pub value: String,
    /// The value's data as text (numbers in hexadecimal, bytes as
    /// `02-00-…`).
    pub data: String,
    /// Windows' default for it, where it has one.
    pub default: Option<&'static str>,
    /// Whether the data departs from Windows' default (or the value has
    /// none and shouldn't be set).
    pub deviates: bool,
    /// `StartupApproved`: whether the entry is enabled.
    pub enabled: Option<bool>,
    /// `StartupApproved`: when it was disabled (FILETIME).
    pub disabled_at: Option<u64>,
    /// The key's path in the hive.
    pub key: String,
    /// When the key was last written (FILETIME).
    pub key_last_written: u64,
}

const NT: &str = r"Microsoft\Windows NT\CurrentVersion";
const SHELL_DEFAULT: &str = "explorer.exe";
const USERINIT_DEFAULT: &str = r"C:\Windows\system32\userinit.exe,";
/// Windows' own `BootExecute`: check the disks that need it.
const BOOT_EXECUTE_DEFAULT: &str = "autocheck autochk *";
/// `FLG_MONITOR_SILENT_PROCESS_EXIT`.
const MONITOR_SILENT_EXIT: u32 = 0x200;

/// Where the machine's keys are: native, then the 32-bit view.
const MACHINE: [(&str, bool); 2] = [("", false), (r"Wow6432Node\", true)];
/// Where a user's are.
const USER: &str = r"Software\";

/// Every entry, machine's first.
#[must_use]
pub fn entries(hive: &Hive<'_>) -> Found<Entry> {
    let mut found = Found::default();
    winlogon(hive, "", false, &mut found);
    winlogon(hive, USER, true, &mut found);
    for (prefix, wow64) in MACHINE {
        image_file_execution_options(hive, prefix, wow64, &mut found);
        appinit(hive, prefix, wow64, &mut found);
        silent_process_exit(hive, prefix, wow64, &mut found);
        active_setup(hive, prefix, wow64, &mut found);
    }
    startup_approved(hive, "", false, &mut found);
    startup_approved(hive, USER, true, &mut found);
    boot(hive, &mut found);
    found
}

/// A value's data as text.
fn data_text(value: &Value<'_>) -> String {
    match value.data() {
        Data::String(s) => s,
        Data::MultiString(list) => list.join(", "),
        Data::Dword(n) => format!("0x{n:08X}"),
        Data::Qword(n) => format!("0x{n:016X}"),
        Data::Bytes(bytes) => bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join("-"),
    }
}

/// A DWORD, or text holding a number (decimal or `0x` hexadecimal).
fn number(value: &Value<'_>) -> Option<u32> {
    match value.data() {
        Data::Dword(n) => Some(n),
        Data::String(s) => {
            let s = s.trim();
            match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => s.parse().ok(),
            }
        }
        _ => None,
    }
}

/// Whether `Userinit` is Windows' own: one program, `userinit.exe` (in any
/// folder ending `\system32`, any case), and nothing else in its list.
#[must_use]
pub fn userinit_is_default(data: &str) -> bool {
    let mut programs = data.split(',').map(str::trim).filter(|p| !p.is_empty());
    let (Some(only), None) = (programs.next(), programs.next()) else {
        return false;
    };
    let only = only.trim_matches('"').to_ascii_lowercase();
    only == "userinit.exe" || only.ends_with(r"\system32\userinit.exe")
}

/// Whether `Shell` is Windows' own: `explorer.exe`, any case.
#[must_use]
pub fn shell_is_default(data: &str) -> bool {
    let shell = data.trim().trim_matches('"').to_ascii_lowercase();
    shell == SHELL_DEFAULT || shell.ends_with(r"\windows\explorer.exe")
}

struct Read<'a> {
    mechanism: Mechanism,
    user: bool,
    wow64: bool,
    target: Option<String>,
    label: Option<String>,
    key: &'a Key<'a>,
    path: &'a str,
}

impl Read<'_> {
    fn entry(&self, value: &Value<'_>, default: Option<&'static str>, deviates: bool) -> Entry {
        Entry {
            mechanism: self.mechanism,
            user: self.user,
            wow64: self.wow64,
            target: self.target.clone(),
            label: self.label.clone(),
            value: value.name.clone(),
            data: data_text(value),
            default,
            deviates,
            enabled: None,
            disabled_at: None,
            key: self.path.to_owned(),
            key_last_written: self.key.last_written,
        }
    }
}

fn winlogon(hive: &Hive<'_>, prefix: &str, user: bool, found: &mut Found<Entry>) {
    let path = format!(r"{prefix}{NT}\Winlogon");
    let Some(key) = found.open(hive, &path) else {
        return;
    };
    for value in found.values(&key, &path) {
        let (mechanism, default) = match value.name.to_ascii_lowercase().as_str() {
            "shell" => (Mechanism::WinlogonShell, Some(SHELL_DEFAULT)),
            "userinit" => (Mechanism::WinlogonUserinit, Some(USERINIT_DEFAULT)),
            "taskman" => (Mechanism::WinlogonTaskman, None),
            _ => continue,
        };
        let data = data_text(&value);
        let deviates = user
            || match mechanism {
                Mechanism::WinlogonShell => !shell_is_default(&data),
                Mechanism::WinlogonUserinit => !userinit_is_default(&data),
                _ => true,
            };
        let read = Read {
            mechanism,
            user,
            wow64: false,
            target: None,
            label: None,
            key: &key,
            path: &path,
        };
        found
            .entries
            .push(read.entry(&value, default.filter(|_| !user), deviates));
    }
}

fn image_file_execution_options(
    hive: &Hive<'_>,
    prefix: &str,
    wow64: bool,
    found: &mut Found<Entry>,
) {
    let root_path = format!(r"{prefix}{NT}\Image File Execution Options");
    let Some(root) = found.open(hive, &root_path) else {
        return;
    };
    for program in found.subkeys(&root, &root_path) {
        let path = format!(r"{root_path}\{}", program.name);
        for value in found.values(&program, &path) {
            let (mechanism, deviates) = match value.name.to_ascii_lowercase().as_str() {
                "debugger" => (Mechanism::IfeoDebugger, true),
                "globalflag" => (
                    Mechanism::IfeoGlobalFlag,
                    number(&value).is_some_and(|f| f & MONITOR_SILENT_EXIT != 0),
                ),
                _ => continue,
            };
            let read = Read {
                mechanism,
                user: false,
                wow64,
                target: Some(program.name.clone()),
                label: None,
                key: &program,
                path: &path,
            };
            found.entries.push(read.entry(&value, None, deviates));
        }
    }
}

fn silent_process_exit(hive: &Hive<'_>, prefix: &str, wow64: bool, found: &mut Found<Entry>) {
    let root_path = format!(r"{prefix}{NT}\SilentProcessExit");
    let Some(root) = found.open(hive, &root_path) else {
        return;
    };
    for program in found.subkeys(&root, &root_path) {
        let path = format!(r"{root_path}\{}", program.name);
        for value in found.values(&program, &path) {
            if !value.name.eq_ignore_ascii_case("MonitorProcess") {
                continue;
            }
            let read = Read {
                mechanism: Mechanism::SilentProcessExit,
                user: false,
                wow64,
                target: Some(program.name.clone()),
                label: None,
                key: &program,
                path: &path,
            };
            found.entries.push(read.entry(&value, None, true));
        }
    }
}

fn appinit(hive: &Hive<'_>, prefix: &str, wow64: bool, found: &mut Found<Entry>) {
    let path = format!(r"{prefix}{NT}\Windows");
    let Some(key) = found.open(hive, &path) else {
        return;
    };
    for value in found.values(&key, &path) {
        let (mechanism, default, deviates) = match value.name.to_ascii_lowercase().as_str() {
            "appinit_dlls" => (
                Mechanism::AppInitDlls,
                "",
                !data_text(&value).trim().is_empty(),
            ),
            "loadappinit_dlls" => (
                Mechanism::LoadAppInitDlls,
                "0x00000000",
                number(&value).is_some_and(|n| n != 0),
            ),
            _ => continue,
        };
        let read = Read {
            mechanism,
            user: false,
            wow64,
            target: None,
            label: None,
            key: &key,
            path: &path,
        };
        found
            .entries
            .push(read.entry(&value, Some(default), deviates));
    }
}

fn active_setup(hive: &Hive<'_>, prefix: &str, wow64: bool, found: &mut Found<Entry>) {
    let root_path = format!(r"{prefix}Microsoft\Active Setup\Installed Components");
    let Some(root) = found.open(hive, &root_path) else {
        return;
    };
    for component in found.subkeys(&root, &root_path) {
        let path = format!(r"{root_path}\{}", component.name);
        let Ok(Some(stub)) = component.value("StubPath") else {
            continue;
        };
        let read = Read {
            mechanism: Mechanism::ActiveSetup,
            user: false,
            wow64,
            target: Some(component.name.clone()),
            label: text(&component, "").filter(|l| !l.is_empty()),
            key: &component,
            path: &path,
        };
        found.entries.push(read.entry(&stub, None, false));
    }
}

fn startup_approved(hive: &Hive<'_>, prefix: &str, user: bool, found: &mut Found<Entry>) {
    for list in ["Run", "Run32", "StartupFolder"] {
        let path =
            format!(r"{prefix}Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{list}");
        let Some(key) = found.open(hive, &path) else {
            continue;
        };
        for value in found.values(&key, &path) {
            let read = Read {
                mechanism: Mechanism::StartupApproved,
                user,
                wow64: false,
                target: Some(value.name.clone()),
                label: None,
                key: &key,
                path: &path,
            };
            let mut entry = read.entry(&value, None, false);
            entry.enabled = value.bytes.first().map(|b| b % 2 == 0);
            entry.disabled_at = u64_at(&value.bytes, 4).filter(|&t| t != 0);
            found.entries.push(entry);
        }
    }
}

/// Each control set's (`ControlSet001`, …, in SYSTEM) `BootExecute` and
/// `BootVerificationProgram`.
fn boot(hive: &Hive<'_>, found: &mut Found<Entry>) {
    let Ok(root) = hive.root() else {
        return;
    };
    let control_sets: Vec<Key<'_>> = found
        .subkeys(&root, "")
        .into_iter()
        .filter(|k| is_control_set(&k.name))
        .collect();
    for control_set in &control_sets {
        for (name, value_name, mechanism) in [
            (
                r"Control\Session Manager",
                "BootExecute",
                Mechanism::BootExecute,
            ),
            (
                r"Control\BootVerificationProgram",
                "ImagePath",
                Mechanism::BootVerification,
            ),
        ] {
            let path = format!(r"{}\{name}", control_set.name);
            let Some(key) = found.open(hive, &path) else {
                continue;
            };
            for value in found.values(&key, &path) {
                if !value.name.eq_ignore_ascii_case(value_name) {
                    continue;
                }
                let default = (mechanism == Mechanism::BootExecute).then_some(BOOT_EXECUTE_DEFAULT);
                let data = data_text(&value);
                let deviates = default.map_or(true, |d| !data.trim().eq_ignore_ascii_case(d));
                let read = Read {
                    mechanism,
                    user: false,
                    wow64: false,
                    target: Some(control_set.name.clone()),
                    label: None,
                    key: &key,
                    path: &path,
                };
                found.entries.push(read.entry(&value, default, deviates));
            }
        }
    }
}

/// `ControlSet` and three digits.
fn is_control_set(name: &str) -> bool {
    name.len() == 13
        && name
            .get(..10)
            .is_some_and(|p| p.eq_ignore_ascii_case("ControlSet"))
        && name
            .get(10..)
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_recognised() {
        assert!(userinit_is_default(r"C:\Windows\system32\userinit.exe,"));
        assert!(userinit_is_default(r"D:\WINDOWS\System32\userinit.exe"));
        assert!(userinit_is_default("userinit.exe"));
        assert!(!userinit_is_default(
            r"C:\Windows\system32\userinit.exe,C:\Users\Public\evil.exe,"
        ));
        assert!(!userinit_is_default(r"C:\Temp\userinit.exe"));
        assert!(!userinit_is_default(""));
        assert!(shell_is_default("explorer.exe"));
        assert!(shell_is_default(r"C:\Windows\explorer.exe"));
        assert!(!shell_is_default("explorer.exe, evil.exe"));
        assert!(!shell_is_default("cmd.exe"));
    }
}
