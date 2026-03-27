use clap::{Arg, Command};
use std::error::Error;
use std::fmt;
use std::io::{self, BufRead, Write};
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
        let masked = if prefix_len == 0 {
            0
        } else {
            let shift = 128 - prefix_len;
            let bits = u128::from(network);
            (bits >> shift) << shift
        };
        Self { network: Ipv6Addr::from(masked), prefix_len }
    }

    /// True if `other` is fully contained in `self`.
    #[inline]
    fn contains(&self, other: &Netblock) -> bool {
        if self.prefix_len > other.prefix_len {
            return false;
        }
        if self.prefix_len == 0 {
            return true; // /0 contains all of IPv6 space
        }
        let shift = 128 - self.prefix_len;
        ((u128::from(self.network) ^ u128::from(other.network)) >> shift) == 0
    }

    /// True if both have the same prefix_len and differ only in the last bit of that prefix.
    #[inline]
    fn aggregateable_with(&self, other: &Netblock) -> bool {
        // /0 cannot be aggregated further, and prefixes must match
        if self.prefix_len != other.prefix_len || self.prefix_len == 0 {
            return false;
        }
        let shift = 128 - self.prefix_len;
        let s = u128::from(self.network) >> shift;
        let o = u128::from(other.network) >> shift;
        // XORing them should result in exactly 1 if they are perfect siblings
        (s ^ o) == 1
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
        if self.prefix_len == 0 {
            return true;
        }
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
                return Ok(Self { network: ip, prefix_len: prefix });
            }
        } else {
            // No prefix => assume /128
            if let Ok(ip) = Ipv6Addr::from_str(s) {
                return Ok(Self { network: ip, prefix_len: 128 });
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

/// Convert an arbitrary IPv6 range [start, end] into the minimal set of CIDR prefixes.
fn range_to_prefixes(start: u128, end: u128) -> Vec<Netblock> {
    let mut prefixes = Vec::new();
    let mut cur = start;

    while cur <= end {
        // Find how many trailing zero bits `cur` has — this limits alignment
        let trailing = if cur == 0 { 128 } else { cur.trailing_zeros() };

        // Find the largest block size (power of 2) that fits within [cur, end]
        let max_size_bits = if end - cur == u128::MAX { 128 } else { (end - cur + 1).ilog2() };

        let bits = std::cmp::min(trailing, max_size_bits);
        let prefix_len = 128 - bits as u8;

        prefixes.push(Netblock::new(Ipv6Addr::from(cur), prefix_len));

        // Advance past this block
        let block_size: u128 = 1u128 << bits;
        match cur.checked_add(block_size) {
            Some(next) => cur = next,
            None => break, // We've covered through ffff:...:ffff
        }
    }

    prefixes
}

/// Parse an IPv6 range line of the form "addr1-addr2"
fn parse_range(s: &str) -> Option<(u128, u128)> {
    let (start_str, end_str) = s.split_once('-')?;
    let start = Ipv6Addr::from_str(start_str.trim()).ok()?;
    let end = Ipv6Addr::from_str(end_str.trim()).ok()?;
    let start_u128 = u128::from(start);
    let end_u128 = u128::from(end);
    if start_u128 > end_u128 {
        return None;
    }
    Some((start_u128, end_u128))
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
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

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
            Arg::new("input-range")
                .long("input-range")
                .help("Expect IPv6 ranges (addr1-addr2) instead of CIDR prefixes")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(Arg::new("input").help("Input file").required(false).index(1))
        .get_matches();

    let ignore_invalid = matches.get_flag("ignore-invalid");
    let input_range = matches.get_flag("input-range");

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
        if let Ok(line_str) = std::str::from_utf8(&buf) {
            let line = line_str.trim();
            if !line.is_empty() {
                if input_range {
                    if let Some((start, end)) = parse_range(line) {
                        netblocks.extend(range_to_prefixes(start, end));
                    }
                } else if let Ok(nb) = line.parse::<Netblock>()
                    && (!ignore_invalid || nb.is_canonical())
                {
                    netblocks.push(Netblock::new(nb.network, nb.prefix_len));
                }
            }
        }
        // If invalid UTF-8, just continue to the next line
    }

    // Aggregate and output
    let aggregated = aggregate_netblocks(netblocks);
    let mut stdout = io::stdout().lock();
    for nb in aggregated {
        let _ = writeln!(stdout, "{}", nb);
    }

    Ok(())
}
