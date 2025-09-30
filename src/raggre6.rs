use clap::{Arg, Command};
use std::error::Error;
use std::fmt;
use std::io::{self, BufRead};
use std::net::Ipv6Addr;
use std::str::FromStr;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
struct Netblock {
    network: Ipv6Addr,
    prefix_len: u8,
}

impl Netblock {
    /// Create a new `Netblock`, zeroing out bits beyond `prefix_len`.
    #[inline]
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
    #[inline]
    fn contains(&self, other: &Netblock) -> bool {
        let shift = 128 - self.prefix_len;
        ((u128::from(self.network) ^ u128::from(other.network)) >> shift) == 0
            && self.prefix_len <= other.prefix_len
    }

    /// True if both have the same prefix_len and differ only in the last bit of that prefix.
    #[inline]
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
    #[inline]
    fn aggregate(&self, other: &Netblock) -> Option<Netblock> {
        if self.aggregateable_with(other) {
            // We create the bigger block by using `self.network` and prefix_len - 1
            Some(Self::new(self.network, self.prefix_len - 1))
        } else {
            None
        }
    }

    /// Check if an IPv6 address is canonical for its prefix (all bits beyond prefix are zero)
    #[inline]
    fn is_canonical(&self) -> bool {
        let shift = 128 - self.prefix_len;
        let bits = u128::from(self.network);
        let masked = (bits >> shift) << shift;
        masked == bits
    }
}

/// Custom error for parsing netblocks
#[derive(Debug)]
struct NetblockParseError;

impl fmt::Display for NetblockParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IPv6 netblock format")
    }
}

impl Error for NetblockParseError {}

impl FromStr for Netblock {
    type Err = NetblockParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let ip = Ipv6Addr::from_str(ip_str).map_err(|_| NetblockParseError)?;
            let prefix = prefix_str.parse::<u8>().map_err(|_| NetblockParseError)?;
            if prefix <= 128 {
                return Ok(Self {
                    network: ip,
                    prefix_len: prefix,
                });
            }
        } else {
            // No prefix => assume /128
            if let Ok(ip) = Ipv6Addr::from_str(s) {
                return Ok(Self {
                    network: ip,
                    prefix_len: 128,
                });
            }
        }
        Err(NetblockParseError)
    }
}

impl fmt::Display for Netblock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// Merge netblocks until no more merges are possible.
fn aggregate_netblocks(mut netblocks: Vec<Netblock>) -> Vec<Netblock> {
    if netblocks.len() <= 1 {
        return netblocks;
    }

    // Sort once at the start
    netblocks.sort_unstable();

    // First pass: remove contained netblocks
    let mut deduped = Vec::with_capacity(netblocks.len());
    let mut prev = netblocks[0];
    
    for &current in &netblocks[1..] {
        if !prev.contains(&current) {
            deduped.push(prev);
            prev = current;
        }
        // If contained, skip current and keep prev
    }
    deduped.push(prev);

    // Second pass: iteratively aggregate siblings
    loop {
        let mut result = Vec::with_capacity(deduped.len());
        let mut changed = false;
        let mut i = 0;

        while i < deduped.len() {
            let current = deduped[i];
            
            // Try to aggregate with next element
            if i + 1 < deduped.len()
                && let Some(aggregated) = current.aggregate(&deduped[i + 1])
            {
                result.push(aggregated);
                changed = true;
                i += 2; // Skip both elements
                continue;
            }
            
            result.push(current);
            i += 1;
        }

        if !changed {
            return result;
        }

        // Swap for next iteration - avoids reallocation
        std::mem::swap(&mut deduped, &mut result);
        
        // Re-sort only if we made changes
        deduped.sort_unstable();
    }
}

fn main() -> Result<(), Box<dyn Error>> {
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

    // Create the reader based on input arg
    let mut input: Box<dyn BufRead> = match matches.get_one::<String>("input") {
        Some(file) => Box::new(io::BufReader::new(std::fs::File::open(file)?)),
        None => Box::new(io::BufReader::new(io::stdin())),
    };

    // Parse input lines into netblocks
    let mut netblocks = Vec::new();
    let mut buf = Vec::new();

    // Read lines as raw bytes to handle non-UTF8 content
    loop {
        buf.clear();
        let bytes_read = input.read_until(b'\n', &mut buf)?;
        if bytes_read == 0 {
            break; // End of input
        }

        // Try to convert to string, skip if invalid UTF-8
        if let Ok(line) = String::from_utf8(buf.clone()) {
            let line = line.trim();
            if !line.is_empty()
                && let Ok(nb) = line.parse::<Netblock>()
                && (!ignore_invalid || nb.is_canonical())
            {
                netblocks.push(Netblock::new(nb.network, nb.prefix_len));
            }
        }
        // If invalid UTF-8, just continue to the next line
    }

    // Aggregate and output
    let aggregated = aggregate_netblocks(netblocks);
    for nb in aggregated {
        println!("{}", nb);
    }

    Ok(())
}
