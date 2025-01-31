use clap::{Arg, Command};
use std::io::{self, BufRead};
use std::net::Ipv6Addr;
use std::str::FromStr;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
struct Netblock {
    network: Ipv6Addr,
    prefix_len: u8,
}

impl Netblock {
    /// Create a new `Netblock`, zeroing out bits beyond `prefix_len`.
    fn new(network: Ipv6Addr, prefix_len: u8) -> Self {
        // Shift-based masking
        let shift = 128 - prefix_len;
        let bits = u128::from(network);
        let masked = (bits >> shift) << shift;
        Self {
            network: Ipv6Addr::from(masked),
            prefix_len,
        }
    }

    /// True if `other` is fully contained in `self`.
    fn contains(&self, other: &Netblock) -> bool {
        let shift = 128 - self.prefix_len;
        ((u128::from(self.network) ^ u128::from(other.network)) >> shift) == 0
            && self.prefix_len <= other.prefix_len
    }

    /// True if both have the same prefix_len and differ only in the last bit of that prefix.
    fn aggregateable_with(&self, other: &Netblock) -> bool {
        if self.prefix_len != other.prefix_len {
            return false;
        }
        let shift = 128 - self.prefix_len;
        let s = u128::from(self.network) >> shift;
        let o = u128::from(other.network) >> shift;
        (s >> 1) == (o >> 1)
    }

    /// Merge two siblings into a single netblock with prefix_len - 1, if possible.
    fn aggregate(&self, other: &Netblock) -> Option<Netblock> {
        if self.aggregateable_with(other) {
            // We create the bigger block by using `self.network` and prefix_len - 1
            Some(Self::new(self.network, self.prefix_len - 1))
        } else {
            None
        }
    }
}

/// Parse a line into a `Netblock`. E.g. "2001:db8::/48" or "fe80::".
fn parse_netblock(line: &str, ignore_invalid: bool) -> Option<Netblock> {
    if let Some((ip_str, prefix_str)) = line.split_once('/') {
        if let (Ok(ip), Ok(prefix)) = (Ipv6Addr::from_str(ip_str), prefix_str.parse::<u8>()) {
            if prefix <= 128 {
                let bits = u128::from(ip);
                let shift = 128 - prefix;
                let masked = (bits >> shift) << shift;
                if ignore_invalid && bits != masked {
                    return None;
                }
                return Some(Netblock::new(ip, prefix));
            }
        }
    } else if let Ok(ip) = Ipv6Addr::from_str(line) {
        // No prefix => assume /128
        return Some(Netblock::new(ip, 128));
    }
    None
}

/// Repeatedly merge netblocks until stable (no more merges/containments).
fn aggregate_netblocks(mut netblocks: Vec<Netblock>) -> Vec<Netblock> {
    loop {
        // Sort for consistent iteration
        netblocks.sort();

        let mut changed = false;
        let mut result = Vec::new();
        let mut iter = netblocks.into_iter().peekable();

        while let Some(mut current) = iter.next() {
            // Keep merging or skipping as long as possible
            while let Some(next) = iter.peek() {
                if current.contains(next) {
                    // Next is contained => skip
                    iter.next();
                    changed = true;
                } else if let Some(new_agg) = current.aggregate(next) {
                    // Merge => aggregator changes, consume `next`
                    iter.next();
                    current = new_agg;
                    changed = true;
                } else {
                    break;
                }
            }
            result.push(current);
        }

        // If no merges or containment happened, we're done
        if !changed {
            return result;
        }
        // Otherwise, repeat
        netblocks = result;
    }
}

fn main() {
    let matches = Command::new("IPv6 Netblock Aggregator")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Sami Farin")
        .about("Aggregates IPv6 netblocks")
        .arg(
            Arg::new("ignore-invalid")
                .long("ignore-invalid")
                .help("Skip invalid IPv6 network entries")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("input")
                .help("Input file")
                .required(false)
                .index(1),
        )
        .get_matches();

    let ignore_invalid = matches.get_flag("ignore-invalid");
    let input: Box<dyn BufRead> = if let Some(file) = matches.get_one::<String>("input") {
        if let Ok(file) = std::fs::File::open(file) {
            Box::new(io::BufReader::new(file))
        } else {
            eprintln!("Error: Could not open file '{}'.", file);
            return;
        }
    } else {
        Box::new(io::BufReader::new(io::stdin()))
    };

    let mut netblocks = Vec::new();
    for line in input.lines().map_while(Result::ok) {
        if let Some(nb) = parse_netblock(&line, ignore_invalid) {
            netblocks.push(nb);
        }
    }
    let aggregated = aggregate_netblocks(netblocks);

    for nb in aggregated {
        println!("{}/{}", nb.network, nb.prefix_len);
    }
}

