//! Outbound Remote Desktop history (NTUSER.DAT): the machines a user
//! connected to with the Remote Desktop client (`mstsc`), under
//! `Software\Microsoft\Terminal Server Client`.
//!
//! `Servers\<host>` is written when a connection is made, with the account
//! used in `UsernameHint` (when the user let it be saved); its last write
//! is the latest such connection. `Default` lists the hosts typed in the
//! client, `MRU0` the most recent; its last write dates that most recent
//! one. A host may be in either list or both.

use crate::artifact::{text, Found};
use crate::{Data, Hive};

const ROOT: &str = r"Software\Microsoft\Terminal Server Client";

/// One host connected to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// The host as typed: a name or an address, maybe with `:port`.
    pub host: String,
    /// The account used (`DOMAIN\user`), from `Servers\<host>`.
    pub username_hint: Option<String>,
    /// Its position in `Default`'s list (0: most recent).
    pub mru_position: Option<usize>,
    /// The key it was read from: `…\Servers\<host>`, or `…\Default` for a
    /// host only in the list.
    pub key: String,
    /// When that key was last written (FILETIME): for `Servers\<host>`, the
    /// latest connection to it.
    pub key_last_written: u64,
    /// `Default`'s last write, given to the host at position 0: when the
    /// most recent connection was made.
    pub mru_last_written: Option<u64>,
}

impl Connection {
    /// The host without a `:port`, IPv6 brackets dropped.
    #[must_use]
    pub fn address(&self) -> &str {
        let host = self.host.trim();
        if let Some(inner) = host.strip_prefix('[') {
            return inner.split(']').next().unwrap_or(inner);
        }
        match host.rsplit_once(':') {
            Some((name, port)) if !name.contains(':') && port.parse::<u16>().is_ok() => name,
            _ => host,
        }
    }
}

/// Every host in `Servers` (with its position in `Default`, if listed),
/// then the hosts only in `Default`.
#[must_use]
pub fn connections(hive: &Hive<'_>) -> Found<Connection> {
    let mut found = Found::default();
    let recent = most_recent(hive, &mut found);
    let position_of = |host: &str| {
        recent
            .hosts
            .iter()
            .find(|(_, h)| h.eq_ignore_ascii_case(host))
            .map(|(n, _)| *n)
    };
    let servers_path = format!(r"{ROOT}\Servers");
    if let Some(servers) = found.open(hive, &servers_path) {
        for server in found.subkeys(&servers, &servers_path) {
            found.entries.push(Connection {
                host: server.name.clone(),
                username_hint: text(&server, "UsernameHint"),
                mru_position: position_of(&server.name),
                key: format!(r"{servers_path}\{}", server.name),
                key_last_written: server.last_written,
                mru_last_written: None,
            });
        }
    }
    for (position, host) in &recent.hosts {
        if found
            .entries
            .iter()
            .any(|c| c.host.eq_ignore_ascii_case(host))
        {
            continue;
        }
        found.entries.push(Connection {
            host: host.clone(),
            username_hint: None,
            mru_position: Some(*position),
            key: format!(r"{ROOT}\Default"),
            key_last_written: recent.last_written,
            mru_last_written: None,
        });
    }
    if let Some(latest) = found.entries.iter_mut().find(|c| c.mru_position == Some(0)) {
        latest.mru_last_written = Some(recent.last_written);
    }
    found
}

/// `Default`'s list: each `MRU<n>` host by `n`, and the key's last write.
struct Recent {
    hosts: Vec<(usize, String)>,
    last_written: u64,
}

fn most_recent(hive: &Hive<'_>, found: &mut Found<Connection>) -> Recent {
    let path = format!(r"{ROOT}\Default");
    let Some(key) = found.open(hive, &path) else {
        return Recent {
            hosts: Vec::new(),
            last_written: 0,
        };
    };
    let mut hosts: Vec<(usize, String)> = found
        .values(&key, &path)
        .into_iter()
        .filter_map(|v| {
            let n = v.name.strip_prefix("MRU")?.parse().ok()?;
            match v.data() {
                Data::String(host) if !host.is_empty() => Some((n, host)),
                _ => None,
            }
        })
        .collect();
    hosts.sort_by_key(|(n, _)| *n);
    Recent {
        hosts,
        last_written: key.last_written,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection(host: &str) -> Connection {
        Connection {
            host: host.to_owned(),
            username_hint: None,
            mru_position: None,
            key: String::new(),
            key_last_written: 0,
            mru_last_written: None,
        }
    }

    #[test]
    fn addresses_without_ports() {
        assert_eq!(connection("192.168.16.60").address(), "192.168.16.60");
        assert_eq!(connection("10.0.0.5:3390").address(), "10.0.0.5");
        assert_eq!(connection("[fe80::1]:3389").address(), "fe80::1");
        assert_eq!(connection("fe80::1").address(), "fe80::1");
        assert_eq!(connection("SU-SVR02").address(), "SU-SVR02");
    }
}
