use clap::Parser;
use rand::RngExt;
use std::net::Ipv6Addr;

/// Generate random IPv6 prefixes with sibling and child routes
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of addresses to generate
    count: usize,

    /// Allowed prefix lengths (1-128) for newly generated subnets and
    /// child routes. Accepts a single value (e.g. 64), an inclusive
    /// range (e.g. 48-64), a comma-separated list (e.g. 48,56,64), or
    /// any combination via repeated flags (e.g. --prefixes 48-56
    /// --prefixes 64,128). Sibling routes always inherit their parent's
    /// prefix length and so are unaffected. When omitted, new subnets
    /// use a uniformly random prefix length in 32..=128.
    #[arg(long = "prefixes", value_parser = parse_prefix_spec, action = clap::ArgAction::Append)]
    prefixes: Vec<Vec<u8>>,
}

fn parse_prefix_spec(s: &str) -> Result<Vec<u8>, String> {
    parse_prefix_spec_bounded(s, 1, 128)
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
            // Accept ranges in either order, e.g. 48-64 or 64-48
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

fn main() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let args = Args::parse();
    let count = args.count;
    let allowed_prefixes: Vec<u8> = args.prefixes.into_iter().flatten().collect();

    let mut rng = rand::rng();

    // Keep a history of generated subnets so we can probabilistically
    // spawn siblings and children to ensure partial aggregation.
    let mut history: Vec<(u128, u8)> = Vec::with_capacity(count);

    use std::io::Write;
    let mut stdout = std::io::stdout().lock();

    for _ in 0..count {
        let action = rng.random_range(0..100);

        if history.is_empty() || action < 50 {
            // 50% chance: Completely new random subnet
            let plen = if allowed_prefixes.is_empty() {
                rng.random_range(32..=128)
            } else {
                allowed_prefixes[rng.random_range(0..allowed_prefixes.len())]
            };
            let shift = 128 - plen;
            // Zero out host bits
            let net = if shift == 128 { 0 } else { (rng.random::<u128>() >> shift) << shift };

            history.push((net, plen));
            let _ = writeln!(stdout, "{}/{}", Ipv6Addr::from(net), plen);
        } else if action < 75 {
            // 25% chance: Sibling (Guarantees your aggregator will merge these up 1 level)
            let idx = rng.random_range(0..history.len());
            let (net, plen) = history[idx];

            if plen > 0 {
                // Flip the last bit of the prefix network portion
                let sibling = net ^ (1u128 << (128 - plen));
                history.push((sibling, plen));
                let _ = writeln!(stdout, "{}/{}", Ipv6Addr::from(sibling), plen);
            } else {
                let _ = writeln!(stdout, "{}/0", Ipv6Addr::from(net));
            }
        } else {
            // 25% chance: Child route (Guarantees your aggregator will swallow this)
            let idx = rng.random_range(0..history.len());
            let (net, plen) = history[idx];

            if plen < 128 {
                // Pick a deeper prefix length (constrained to --prefixes when set)
                let child_plen_opt: Option<u8> = if allowed_prefixes.is_empty() {
                    Some(rng.random_range((plen + 1)..=128))
                } else {
                    let valid: Vec<u8> =
                        allowed_prefixes.iter().copied().filter(|&p| p > plen).collect();
                    if valid.is_empty() {
                        None
                    } else {
                        Some(valid[rng.random_range(0..valid.len())])
                    }
                };

                if let Some(child_plen) = child_plen_opt {
                    let bits_to_generate = child_plen - plen;

                    // Generate random bits for the child sub-space
                    let mask =
                        if bits_to_generate == 128 { !0 } else { (1u128 << bits_to_generate) - 1 };
                    let val = rng.random::<u128>() & mask;
                    let child_net = net | (val << (128 - child_plen));

                    history.push((child_net, child_plen));
                    let _ = writeln!(stdout, "{}/{}", Ipv6Addr::from(child_net), child_plen);
                } else {
                    // No allowed prefix is deeper than the parent; emit a duplicate
                    // (will also be swallowed by the aggregator)
                    history.push((net, plen));
                    let _ = writeln!(stdout, "{}/{}", Ipv6Addr::from(net), plen);
                }
            } else {
                // It's a /128, just output a duplicate (will also be swallowed)
                history.push((net, plen));
                let _ = writeln!(stdout, "{}/{}", Ipv6Addr::from(net), plen);
            }
        }
    }
}
