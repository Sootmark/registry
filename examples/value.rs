//! Print a value's first bytes: `cargo run --example value -- SYSTEM 'Key\Path' Name`.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let data = std::fs::read(&args[0]).unwrap();
    let hive = registry::Hive::parse(&data).unwrap();
    let key = hive.open(&args[1]).unwrap().expect("no such key");
    let value = key.value(&args[2]).unwrap().expect("no such value");
    let bytes = &value.bytes;
    println!("{} bytes, type {}", bytes.len(), value.kind.name());
    for (i, chunk) in bytes.chunks(16).take(24).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        println!("{:06x}  {}", i * 16, hex.join(" "));
    }
}
