use std::hint::black_box;
use std::time::Instant;

use reader::Reader;

fn peak_memory_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let line = status.lines().find(|line| line.starts_with("VmHWM:")).unwrap_or_default();
    line.split_whitespace().nth(1).and_then(|value| value.parse().ok()).unwrap_or(0)
}

fn random_addresses(count: usize, seed: u64) -> Vec<String> {
    let mut state = seed;
    let mut address = |index| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        if index % 4 < 3 {
            return std::net::Ipv4Addr::from(state as u32).to_string();
        }
        let high = 0x2000_0000_0000_0000u128 | ((state as u128) << 64 >> 4);
        std::net::Ipv6Addr::from(high | state as u128).to_string()
    };
    (0..count).map(&mut address).collect()
}

fn benchmark(path: &str) -> std::io::Result<()> {
    let started = Instant::now();
    let reader = Reader::open(path)?;
    let open = started.elapsed();
    let typed = |address: &String| drop(black_box(reader.lookup(address)));
    let json = |address: &String| drop(black_box(reader.lookup_json(address)));
    let cold_addresses = random_addresses(1000, 0x9e3779b97f4a7c15);
    let started = Instant::now();
    cold_addresses.iter().for_each(typed);
    let cold = started.elapsed() / cold_addresses.len() as u32;
    let warm_addresses = random_addresses(200_000, 0x9e3779b97f4a7c15 ^ 1);
    warm_addresses.iter().for_each(typed);
    let rate = |lookup: &dyn Fn(&String)| {
        let started = Instant::now();
        warm_addresses.iter().for_each(lookup);
        warm_addresses.len() as f64 / started.elapsed().as_secs_f64()
    };
    let (typed, json) = (rate(&typed), rate(&json));
    println!(
        "open {open:.1?}, cold lookup {cold:.1?}, \
         warm {typed:.0} typed / {json:.0} json lookups/s, \
         peak RSS {} KB, file {} KB",
        peak_memory_kb(),
        std::fs::metadata(path)?.len() / 1024
    );
    Ok(())
}

fn print_about(path: &str) -> std::io::Result<()> {
    let mut about = Reader::open(path)?.about().clone();
    let sections = about["sections"].as_array_mut().into_iter().flatten();
    for section in sections.filter_map(|value| value.as_object_mut()) {
        section.retain(|key, _| key != "offsets" && key != "firsts");
    }
    println!("{}", serde_json::to_string_pretty(&about)?);
    Ok(())
}

fn print_answer(path: &str, address: &str) -> std::io::Result<()> {
    let Some(answer) = Reader::open(path)?.lookup(address) else {
        eprintln!("invalid address: {address}");
        std::process::exit(2);
    };
    println!("{}", serde_json::to_string_pretty(&answer)?);
    Ok(())
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [path, query] = arguments.as_slice() else {
        eprintln!("usage: iplore <file> <address> | --about | --bench");
        std::process::exit(2);
    };
    let result = match query.as_str() {
        "--bench" => benchmark(path),
        "--about" => print_about(path),
        address => print_answer(path, address),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
