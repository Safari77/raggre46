use clap::Parser;
use rand::RngExt;
use std::env;
use std::net::Ipv4Addr;

/// Generate random IPv4 addresses and netblocks.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of addresses to generate
    count: usize,

    /// Allowed prefix lengths (1-32). Accepts a single value (e.g. 24),
    /// an inclusive range (e.g. 16-24), a comma-separated list
    /// (e.g. 16,20,24), or any combination via repeated flags
    /// (e.g. --prefixes 16-20 --prefixes 24,28). When specified, all
    /// generated entries use a uniformly random pick from the union of
    /// these prefix lengths; when omitted, the default split of half /32
    /// single addresses and half /16-/31 netblocks is used.
    #[arg(long = "prefixes", value_parser = parse_prefix_spec, action = clap::ArgAction::Append)]
    prefixes: Vec<Vec<u8>>,
}

fn parse_prefix_spec(s: &str) -> Result<Vec<u8>, String> {
    parse_prefix_spec_bounded(s, 1, 32)
}

fn parse_prefix_spec_bounded(s: &str, min: u8, max: u8) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = part.split_once('-') {
            let start_s = start_s.trim();
            let end_s = end_s.trim();
            let a: u8 =
                start_s.parse().map_err(|e| format!("invalid range start '{}': {}", start_s, e))?;
            let b: u8 =
                end_s.parse().map_err(|e| format!("invalid range end '{}': {}", end_s, e))?;
            // Accept ranges in either order, e.g. 16-24 or 24-16
            let (start, end) = if a <= b { (a, b) } else { (b, a) };
            for p in start..=end {
                if !(min..=max).contains(&p) {
                    return Err(format!("prefix {} out of range {}-{}", p, min, max));
                }
                result.push(p);
            }
        } else {
            let p: u8 = part.parse().map_err(|e| format!("invalid prefix '{}': {}", part, e))?;
            if !(min..=max).contains(&p) {
                return Err(format!("prefix {} out of range {}-{}", p, min, max));
            }
            result.push(p);
        }
    }
    Ok(result)
}

fn generate_random_ipv4() -> Ipv4Addr {
    let mut rng = rand::rng();
    Ipv4Addr::new(rng.random(), rng.random(), rng.random(), rng.random())
}

fn generate_random_ipv4_netblock() -> (Ipv4Addr, u8) {
    let mut rng = rand::rng();
    let prefix_len = rng.random_range(16..=31);
    let mask = (!0u32) << (32 - prefix_len);
    let base_address = rng.random::<u32>() & mask;
    let ip = Ipv4Addr::from(base_address);
    (ip, prefix_len)
}

fn generate_random_ipv4_with_prefix(prefix_len: u8) -> (Ipv4Addr, u8) {
    let mut rng = rand::rng();
    // prefix_len == 0 would make the mask 0 (any address); excluded by validation
    // but kept defensive. prefix_len == 32 yields a 0 shift, i.e. mask = !0u32.
    let mask = if prefix_len == 0 { 0 } else { (!0u32) << (32 - prefix_len) };
    let base_address = rng.random::<u32>() & mask;
    (Ipv4Addr::from(base_address), prefix_len)
}

fn main() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let _ = env::args_os();
    let args = Args::parse();
    let count = args.count;
    let allowed_prefixes: Vec<u8> = args.prefixes.into_iter().flatten().collect();

    if allowed_prefixes.is_empty() {
        let half_count = count / 2;

        for _ in 0..half_count {
            println!("{}/32", generate_random_ipv4());
        }

        for _ in 0..half_count {
            let (ip, prefix_len) = generate_random_ipv4_netblock();
            println!("{}/{}", ip, prefix_len);
        }
    } else {
        // Pick uniformly from the allowed prefix lengths for every entry
        let mut rng = rand::rng();
        for _ in 0..count {
            let idx = rng.random_range(0..allowed_prefixes.len());
            let prefix_len = allowed_prefixes[idx];
            let (ip, plen) = generate_random_ipv4_with_prefix(prefix_len);
            println!("{}/{}", ip, plen);
        }
    }
}
