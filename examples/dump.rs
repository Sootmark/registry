//! Every key and value of a hive as JSON lines (the format the oracle
//! comparison reads): `cargo run --example dump -- SYSTEM`.

#[path = "../tests/dump/mod.rs"]
mod dump;

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
    match dump::hive(&hive) {
        Ok(out) => print!("{out}"),
        Err(e) => {
            eprintln!("{path}: root: {e}");
            std::process::exit(1);
        }
    }
}
