use clap::{Arg, Command};
use std::io::{self, BufRead};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
struct Netblock {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Netblock {
    /// Zero out bits beyond `prefix_len`.
    fn new(network: Ipv4Addr, prefix_len: u8) -> Self {
        let shift = 32 - prefix_len;
        let bits = u32::from(network);
        let masked = (bits >> shift) << shift;
        Self {
            network: Ipv4Addr::from(masked),
            prefix_len,
        }
    }

    /// Return true if `other` is a subnet of `self`.
    fn contains(&self, other: &Netblock) -> bool {
        let shift = 32 - self.prefix_len;
        ((u32::from(self.network) ^ u32::from(other.network)) >> shift) == 0
            && self.prefix_len <= other.prefix_len
    }

    /// Return true if both have the same prefix_len and differ only
    /// in the last bit of the prefix (siblings in the address space).
    fn aggregateable_with(&self, other: &Netblock) -> bool {
        if self.prefix_len != other.prefix_len {
            return false;
        }
        let shift = 32 - self.prefix_len;
        let s = u32::from(self.network) >> shift;
        let o = u32::from(other.network) >> shift;
        (s >> 1) == (o >> 1)
    }

    /// Combine sibling netblocks into one with prefix_len - 1.
    fn aggregate(&self, other: &Netblock) -> Option<Netblock> {
        if self.aggregateable_with(other) {
            // We just create a new Netblock with prefix_len-1 from self's network
            Some(Self::new(self.network, self.prefix_len - 1))
        } else {
            None
        }
    }
}

fn parse_netblock(line: &str, ignore_invalid: bool) -> Option<Netblock> {
    if let Some((ip_str, prefix_str)) = line.split_once('/') {
        if let (Ok(ip), Ok(prefix)) = (Ipv4Addr::from_str(ip_str), prefix_str.parse::<u8>()) {
            if prefix <= 32 {
                let bits = u32::from(ip);
                let shift = 32 - prefix;
                let masked = (bits >> shift) << shift;
                // If ignoring invalid, skip if bits differ from masked
                if ignore_invalid && bits != masked {
                    return None;
                }
                return Some(Netblock::new(ip, prefix));
            }
        }
    } else if let Ok(ip) = Ipv4Addr::from_str(line) {
        // No /prefix => assume /32
        return Some(Netblock::new(ip, 32));
    }
    None
}

/// Merge netblocks until no more merges are possible.
fn aggregate_netblocks(mut netblocks: Vec<Netblock>) -> Vec<Netblock> {
    loop {
        // Sort once each iteration.
        netblocks.sort();

        let mut changed = false;
        let mut result = Vec::new();
        let mut iter = netblocks.into_iter().peekable();

        // Single pass that merges and contains
        while let Some(mut current) = iter.next() {
            // Keep trying to merge or skip additional items
            loop {
                match iter.peek() {
                    Some(next) => {
                        if current.contains(next) {
                            // `next` is contained; skip it
                            iter.next();
                            changed = true;
                        } else if let Some(new_agg) = current.aggregate(next) {
                            // Merge siblings
                            iter.next();
                            current = new_agg;
                            changed = true;
                        } else {
                            break; // can't contain or merge => stop the inner loop
                        }
                    }
                    None => break, // no more netblocks
                }
            }
            result.push(current);
        }

        // If no merges or containments happened, we're stable
        if !changed {
            return result;
        }

        // Otherwise, repeat with newly merged netblocks
        netblocks = result;
    }
}

fn main() {
    let matches = Command::new("Netblock Aggregator")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Sami Farin")
        .about("Aggregates IPv4 netblocks")
        .arg(
            Arg::new("ignore-invalid")
                .long("ignore-invalid")
                .help("Skip IPv4 addresses that don't match their prefix (e.g. 1.2.3.4/24 must have last 8 bits zero)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("input")
                .help("Input file to process")
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
    for line_result in input.lines() {
        if let Ok(line) = line_result {
            if let Some(nb) = parse_netblock(&line, ignore_invalid) {
                netblocks.push(nb);
            }
        }
    }

    let aggregated = aggregate_netblocks(netblocks);

    for nb in aggregated {
        println!("{}/{}", nb.network, nb.prefix_len);
    }
}
