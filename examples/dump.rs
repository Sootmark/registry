//! Every key and value of a hive as JSON lines (the format the oracle
//! comparison reads): `cargo run --example dump -- SYSTEM`.

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

fn walk(key: &registry::Key<'_>, path: &str, depth: usize) {
    let mut values = Vec::new();
    match key.values() {
        Ok(list) => {
            for value in list {
                match value {
                    Ok(v) => {
                        let name = if v.name.is_empty() { "(default)" } else { &v.name };
                        let hex: String = v.bytes.iter().map(|b| format!("{b:02x}")).collect();
                        let kind = match v.kind {
                            registry::Kind::Other(n) => n,
                            k => k_number(k),
                        };
                        values.push(format!("{{\"name\": {}, \"type\": {kind}, \"data\": \"{hex}\"}}", json(name)));
                    }
                    Err(e) => values.push(format!("{{\"error\": {}}}", json(&e.to_string()))),
                }
            }
        }
        Err(e) => values.push(format!("{{\"error\": {}}}", json(&e.to_string()))),
    }
    println!("{{\"path\": {}, \"written\": {}, \"values\": [{}]}}", json(path), key.last_written, values.join(", "));
    if depth > 512 {
        eprintln!("{path}: deeper than 512 keys");
        return;
    }
    match key.subkeys() {
        Ok(subkeys) => {
            for sub in subkeys {
                walk(&sub, &format!("{path}\\{}", sub.name), depth + 1);
            }
        }
        Err(e) => eprintln!("{path}: {e}"),
    }
}

fn k_number(kind: registry::Kind) -> u32 {
    use registry::Kind::*;
    match kind {
        None => 0,
        String => 1,
        ExpandString => 2,
        Binary => 3,
        Dword => 4,
        DwordBigEndian => 5,
        Link => 6,
        MultiString => 7,
        ResourceList => 8,
        FullResourceDescriptor => 9,
        ResourceRequirementsList => 10,
        Qword => 11,
        Other(n) => n,
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: dump <hive>");
    let data = std::fs::read(&path).expect("readable file");
    let hive = match registry::Hive::parse(&data) {
        Ok(hive) => hive,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };
    match hive.root() {
        Ok(root) => walk(&root, "", 0),
        Err(e) => {
            eprintln!("{path}: root: {e}");
            std::process::exit(1);
        }
    }
}
