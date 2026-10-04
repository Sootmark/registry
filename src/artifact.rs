//! What the artifact readers share: their result (the entries, and the
//! damage met on the way), Windows' calendar time, and small typed reads of
//! values.

use crate::{Data, Hive, Key, Value};

/// Something an artifact reader couldn't read, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The key's path in the hive.
    pub key: String,
    /// The value's name, when the problem is a value's.
    pub value: Option<String>,
    /// Why.
    pub reason: String,
}

/// What an artifact reader found, and what it couldn't read: damage is a
/// problem for what it touches, never the end of the read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found<T> {
    /// The entries, in the hive's order.
    pub entries: Vec<T>,
    /// Keys and values that couldn't be read, and why.
    pub problems: Vec<Problem>,
}

impl<T> Default for Found<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            problems: Vec::new(),
        }
    }
}

impl<T> Found<T> {
    pub(crate) fn problem(&mut self, key: &str, value: Option<&str>, reason: impl Into<String>) {
        self.problems.push(Problem {
            key: key.to_owned(),
            value: value.map(str::to_owned),
            reason: reason.into(),
        });
    }

    /// The key at `path`, if it's there; a problem when a key on the way
    /// can't be read.
    pub(crate) fn open<'h>(&mut self, hive: &'h Hive<'_>, path: &str) -> Option<Key<'h>> {
        hive.open(path).unwrap_or_else(|e| {
            self.problem(path, None, e.to_string());
            None
        })
    }

    /// A key's subkeys; none, and a problem, when they can't be read.
    pub(crate) fn subkeys<'h>(&mut self, key: &Key<'h>, path: &str) -> Vec<Key<'h>> {
        key.subkeys().unwrap_or_else(|e| {
            self.problem(path, None, e.to_string());
            Vec::new()
        })
    }

    /// A key's readable values; each unreadable one is a problem.
    pub(crate) fn values<'h>(&mut self, key: &Key<'h>, path: &str) -> Vec<Value<'h>> {
        let values = key.values().unwrap_or_else(|e| {
            self.problem(path, None, e.to_string());
            Vec::new()
        });
        let mut out = Vec::with_capacity(values.len());
        for value in values {
            match value {
                Ok(value) => out.push(value),
                Err(e) => self.problem(path, None, e.to_string()),
            }
        }
        out
    }
}

/// A Windows `SYSTEMTIME`: a calendar date and a wall-clock time, in
/// whatever zone its writer used; the structure doesn't say which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemTime {
    /// The year (1601 to 30827).
    pub year: u16,
    /// The month, 1 to 12.
    pub month: u16,
    /// The day of the week, 0 (Sunday) to 6.
    pub day_of_week: u16,
    /// The day of the month, 1 to 31.
    pub day: u16,
    /// The hour, 0 to 23.
    pub hour: u16,
    /// The minute, 0 to 59.
    pub minute: u16,
    /// The second, 0 to 59.
    pub second: u16,
    /// The millisecond, 0 to 999.
    pub millisecond: u16,
}

impl SystemTime {
    /// Read from its 16 bytes; `None` when they're too few or all zero.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let field = |i: usize| crate::u16_at(bytes, 2 * i);
        let time = Self {
            year: field(0)?,
            month: field(1)?,
            day_of_week: field(2)?,
            day: field(3)?,
            hour: field(4)?,
            minute: field(5)?,
            second: field(6)?,
            millisecond: field(7)?,
        };
        (bytes[..16].iter().any(|&b| b != 0)).then_some(time)
    }

    /// A date at midnight (`InstallDate`'s `YYYYMMDD`, …).
    pub(crate) fn date(year: u16, month: u16, day: u16) -> Self {
        Self {
            year,
            month,
            day_of_week: 0,
            day,
            hour: 0,
            minute: 0,
            second: 0,
            millisecond: 0,
        }
    }

    /// The wall-clock time counted as if it were UTC, as a FILETIME: the
    /// caller decides the zone. `None` for impossible fields.
    #[must_use]
    pub fn wall_clock_filetime(&self) -> Option<u64> {
        if !(1..=12).contains(&self.month)
            || !(1..=31).contains(&self.day)
            || self.hour > 23
            || self.minute > 59
            || self.second > 59
            || self.millisecond > 999
        {
            return None;
        }
        let days = days_from_civil(
            i64::from(self.year),
            i64::from(self.month),
            i64::from(self.day),
        );
        let seconds = days * 86_400
            + i64::from(self.hour) * 3_600
            + i64::from(self.minute) * 60
            + i64::from(self.second);
        unix_seconds(seconds)?.checked_add(u64::from(self.millisecond) * 10_000)
    }
}

/// Seconds since 1970 as a FILETIME; `None` before 1601 or for 0.
pub(crate) fn unix_seconds(seconds: i64) -> Option<u64> {
    let ticks = (seconds.checked_add(11_644_473_600)?).checked_mul(10_000_000)?;
    u64::try_from(ticks).ok().filter(|&t| t != 0)
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
pub(crate) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A value's text (`REG_SZ`, `REG_EXPAND_SZ`), if it's there.
pub(crate) fn text(key: &Key<'_>, name: &str) -> Option<String> {
    match key.value(name).ok()??.data() {
        Data::String(s) => Some(s),
        _ => None,
    }
}

/// A value's text, if it's there and not blank.
pub(crate) fn non_empty(key: &Key<'_>, name: &str) -> Option<String> {
    text(key, name).filter(|s| !s.trim().is_empty())
}

/// A value's DWORD, if it's one.
pub(crate) fn dword(key: &Key<'_>, name: &str) -> Option<u32> {
    match key.value(name).ok()??.data() {
        Data::Dword(n) => Some(n),
        _ => None,
    }
}

/// A value's QWORD, if it's one.
pub(crate) fn qword(key: &Key<'_>, name: &str) -> Option<u64> {
    match key.value(name).ok()??.data() {
        Data::Qword(n) => Some(n),
        _ => None,
    }
}

/// A value's raw bytes, if it's there.
pub(crate) fn bytes(key: &Key<'_>, name: &str) -> Option<Vec<u8>> {
    Some(key.value(name).ok()??.bytes.into_owned())
}

/// `MRUListEx`: value numbers, most recent first, ended by `0xFFFFFFFF`.
pub(crate) fn mru_list_ex(key: &Key<'_>) -> Vec<u32> {
    let Ok(Some(value)) = key.value("MRUListEx") else {
        return Vec::new();
    };
    value
        .bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .take_while(|&n| n != u32::MAX)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_times_read_as_wall_clocks() {
        // 2014-05-06 17:02:19.795, from plaso's networks plugin test.
        let bytes = [
            0xde, 0x07, 0x05, 0x00, 0x02, 0x00, 0x06, 0x00, 0x11, 0x00, 0x02, 0x00, 0x13, 0x00,
            0x1b, 0x03,
        ];
        let time = SystemTime::parse(&bytes).unwrap();
        assert_eq!((time.year, time.month, time.day), (2014, 5, 6));
        assert_eq!(
            time.wall_clock_filetime(),
            unix_seconds(1_399_395_739).map(|t| t + 7_950_000)
        );
        assert!(SystemTime::parse(&[0; 16]).is_none());
        assert!(SystemTime::parse(&bytes[..15]).is_none());
        let mut impossible = time;
        impossible.month = 13;
        assert!(impossible.wall_clock_filetime().is_none());
    }
}
