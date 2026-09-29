//! A hive as JSON lines, one per key, depth first, subkeys in the hive's
//! order: path, last written (FILETIME), values with name, type number and
//! data (hex). The format the oracle comparison reads; shared by the
//! `dump` example and the tests.

use std::fmt::Write as _;

fn json(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A hive's dump.
pub fn hive(hive: &registry::Hive<'_>) -> Result<String, registry::Error> {
    let out = std::cell::RefCell::new(String::new());
    hive.walk(
        |path, key| key_line(key, path, &mut out.borrow_mut()),
        |path, e| {
            let _ = writeln!(
                out.borrow_mut(),
                "{{\"error\": {}}}",
                json(&format!("{path}: {e}"))
            );
        },
    )?;
    Ok(out.into_inner())
}

/// One key's line.
fn key_line(key: &registry::Key<'_>, path: &str, out: &mut String) {
    let mut values = Vec::new();
    match key.values() {
        Ok(list) => {
            for value in list {
                match value {
                    Ok(v) => {
                        let name = if v.name.is_empty() {
                            "(default)"
                        } else {
                            &v.name
                        };
                        let hex = common::hex::encode(&v.bytes);
                        let kind = v.kind.number();
                        values.push(format!(
                            "{{\"name\": {}, \"type\": {kind}, \"data\": \"{hex}\"}}",
                            json(name)
                        ));
                    }
                    Err(e) => values.push(format!("{{\"error\": {}}}", json(&e.to_string()))),
                }
            }
        }
        Err(e) => values.push(format!("{{\"error\": {}}}", json(&e.to_string()))),
    }
    let _ = writeln!(
        out,
        "{{\"path\": {}, \"written\": {}, \"values\": [{}]}}",
        json(path),
        key.last_written,
        values.join(", ")
    );
}
