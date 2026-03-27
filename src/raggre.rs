use clap::Parser;
use std::error::Error;
use std::fmt;
use std::io::{self, BufRead, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "raggre",
    version,
    author = "Sami Farin",
    about = "Aggregates IPv4 and IPv6 netblocks"
)]
struct Cli {
    /// Only process IPv4 addresses
    #[arg(short = '4')]
    ipv4_only: bool,

    /// Only process IPv6 addresses
    #[arg(short = '6')]
    ipv6_only: bool,

    /// Expect IP ranges (start-end) instead of CIDR prefixes
    #[arg(long)]
    input_range: bool,

    /// Skip addresses that don't match their prefix
    /// (e.g. 1.2.3.4/24 must have last 8 bits zero)
    #[arg(long)]
    ignore_invalid: bool,

    /// Input file to process
    input: Option<String>,
}

impl Cli {
    /// When neither -4 nor -6 is given, accept both address families.
    #[inline]
    fn accept_v4(&self) -> bool {
        !self.ipv6_only || self.ipv4_only
    }

    #[inline]
    fn accept_v6(&self) -> bool {
        !self.ipv4_only || self.ipv6_only
    }
}

// ---------------------------------------------------------------------------
// Trait for generic aggregation
// ---------------------------------------------------------------------------

trait Aggregateable: Ord + Copy + fmt::Display {
    /// Return true if `other` is a subnet of `self`.
    fn contains(&self, other: &Self) -> bool;
    /// Combine sibling netblocks into one, if possible.
    fn aggregate(&self, other: &Self) -> Option<Self>;
}

// ---------------------------------------------------------------------------
// Custom error for parsing netblocks
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NetblockParseError;

impl fmt::Display for NetblockParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid netblock format")
    }
}

impl Error for NetblockParseError {}

// ---------------------------------------------------------------------------
// NetblockV4
// ---------------------------------------------------------------------------

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
struct NetblockV4 {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl NetblockV4 {
    /// Zero out bits beyond `prefix_len`.
    #[inline]
    fn new(network: Ipv4Addr, prefix_len: u8) -> Self {
        let masked = if prefix_len == 0 {
            0
        } else {
            let shift = 32 - prefix_len;
            (u32::from(network) >> shift) << shift
        };
        Self { network: Ipv4Addr::from(masked), prefix_len }
    }

    /// Return true if both have the same prefix_len and differ only
    /// in the last bit of the prefix (siblings in the address space).
    #[inline]
    fn aggregateable_with(&self, other: &NetblockV4) -> bool {
        if self.prefix_len != other.prefix_len || self.prefix_len == 0 {
            return false;
        }
        let shift = 32 - self.prefix_len;
        let s = u32::from(self.network) >> shift;
        let o = u32::from(other.network) >> shift;
        (s ^ o) == 1 // Ensures they differ by EXACTLY the last bit of the prefix
    }

    /// Check if a network address is canonical (i.e., all bits beyond prefix are zero)
    #[inline]
    fn is_canonical(&self) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let shift = 32 - self.prefix_len;
        let bits = u32::from(self.network);
        let masked = (bits >> shift) << shift;
        masked == bits
    }
}

impl Aggregateable for NetblockV4 {
    /// Return true if `other` is a subnet of `self`.
    #[inline]
    fn contains(&self, other: &Self) -> bool {
        if self.prefix_len > other.prefix_len {
            return false;
        }
        if self.prefix_len == 0 {
            return true; // /0 contains everything
        }
        let shift = 32 - self.prefix_len;
        ((u32::from(self.network) ^ u32::from(other.network)) >> shift) == 0
    }

    /// Combine sibling netblocks into one with prefix_len - 1.
    #[inline]
    fn aggregate(&self, other: &Self) -> Option<Self> {
        if self.aggregateable_with(other) {
            Some(Self::new(self.network, self.prefix_len - 1))
        } else {
            None
        }
    }
}

impl FromStr for NetblockV4 {
    type Err = NetblockParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let ip = Ipv4Addr::from_str(ip_str).map_err(|_| NetblockParseError)?;
            let prefix = prefix_str.parse::<u8>().map_err(|_| NetblockParseError)?;

            if prefix <= 32 {
                return Ok(Self { network: ip, prefix_len: prefix });
            }
        } else {
            // No /prefix => assume /32
            if let Ok(ip) = Ipv4Addr::from_str(s) {
                return Ok(Self { network: ip, prefix_len: 32 });
            }
        }
        Err(NetblockParseError)
    }
}

impl fmt::Display for NetblockV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// Convert an arbitrary IPv4 range [start, end] into the minimal set of CIDR prefixes.
fn range_to_prefixes_v4(start: u32, end: u32) -> Vec<NetblockV4> {
    let mut prefixes = Vec::new();
    let mut cur = start;

    while cur <= end {
        // Find how many trailing zero bits `cur` has — this limits alignment
        let trailing = if cur == 0 { 32 } else { cur.trailing_zeros() };

        // Find the largest block size (power of 2) that fits within [cur, end]
        let max_size_bits = if end - cur == u32::MAX { 32 } else { (end - cur + 1).ilog2() };

        let bits = std::cmp::min(trailing, max_size_bits);
        let prefix_len = 32 - bits as u8;

        prefixes.push(NetblockV4::new(Ipv4Addr::from(cur), prefix_len));

        // Advance past this block
        let block_size: u64 = 1u64 << bits;
        let next = cur as u64 + block_size;
        if next > u32::MAX as u64 {
            break; // We've covered through 255.255.255.255
        }
        cur = next as u32;
    }

    prefixes
}

/// Parse an IPv4 range line of the form "A.B.C.D-E.F.G.H"
fn parse_range_v4(s: &str) -> Option<(u32, u32)> {
    let (start_str, end_str) = s.split_once('-')?;
    let start = Ipv4Addr::from_str(start_str.trim()).ok()?;
    let end = Ipv4Addr::from_str(end_str.trim()).ok()?;
    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);
    if start_u32 > end_u32 {
        return None;
    }
    Some((start_u32, end_u32))
}

// ---------------------------------------------------------------------------
// NetblockV6
// ---------------------------------------------------------------------------

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
struct NetblockV6 {
    network: Ipv6Addr,
    prefix_len: u8,
}

impl NetblockV6 {
    /// Create a new `NetblockV6`, zeroing out bits beyond `prefix_len`.
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

    /// True if both have the same prefix_len and differ only in the last bit of that prefix.
    #[inline]
    fn aggregateable_with(&self, other: &NetblockV6) -> bool {
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

impl Aggregateable for NetblockV6 {
    /// True if `other` is fully contained in `self`.
    #[inline]
    fn contains(&self, other: &Self) -> bool {
        if self.prefix_len > other.prefix_len {
            return false;
        }
        if self.prefix_len == 0 {
            return true; // /0 contains all of IPv6 space
        }
        let shift = 128 - self.prefix_len;
        ((u128::from(self.network) ^ u128::from(other.network)) >> shift) == 0
    }

    /// Merge two siblings into a single netblock with prefix_len - 1, if possible.
    #[inline]
    fn aggregate(&self, other: &Self) -> Option<Self> {
        if self.aggregateable_with(other) {
            // We create the bigger block by using `self.network` and prefix_len - 1
            Some(Self::new(self.network, self.prefix_len - 1))
        } else {
            None
        }
    }
}

impl FromStr for NetblockV6 {
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

impl fmt::Display for NetblockV6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// Convert an arbitrary IPv6 range [start, end] into the minimal set of CIDR prefixes.
fn range_to_prefixes_v6(start: u128, end: u128) -> Vec<NetblockV6> {
    let mut prefixes = Vec::new();
    let mut cur = start;

    while cur <= end {
        // Find how many trailing zero bits `cur` has — this limits alignment
        let trailing = if cur == 0 { 128 } else { cur.trailing_zeros() };

        // Find the largest block size (power of 2) that fits within [cur, end]
        let max_size_bits = if end - cur == u128::MAX { 128 } else { (end - cur + 1).ilog2() };

        let bits = std::cmp::min(trailing, max_size_bits);
        let prefix_len = 128 - bits as u8;

        prefixes.push(NetblockV6::new(Ipv6Addr::from(cur), prefix_len));

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
fn parse_range_v6(s: &str) -> Option<(u128, u128)> {
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

// ---------------------------------------------------------------------------
// Generic aggregation — single implementation for both address families
// ---------------------------------------------------------------------------

/// Merge netblocks until no more merges are possible.
fn aggregate_netblocks<T: Aggregateable>(mut netblocks: Vec<T>) -> Vec<T> {
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

// ---------------------------------------------------------------------------
// Input processing
// ---------------------------------------------------------------------------

/// Try to parse a single line, dispatching to the appropriate address family.
/// Pushes results into `v4` and/or `v6` depending on what was detected.
fn process_line(
    line: &str,
    input_range: bool,
    ignore_invalid: bool,
    accept_v4: bool,
    accept_v6: bool,
    v4: &mut Vec<NetblockV4>,
    v6: &mut Vec<NetblockV6>,
) {
    if input_range {
        // Try IPv4 range first (dotted-decimal never contains ':')
        if accept_v4 {
            if let Some((start, end)) = parse_range_v4(line) {
                v4.extend(range_to_prefixes_v4(start, end));
                return;
            }
        }
        if accept_v6 {
            if let Some((start, end)) = parse_range_v6(line) {
                v6.extend(range_to_prefixes_v6(start, end));
            }
        }
    } else {
        // Try IPv4 CIDR / bare address first
        if accept_v4 {
            if let Ok(nb) = line.parse::<NetblockV4>() {
                if !ignore_invalid || nb.is_canonical() {
                    v4.push(NetblockV4::new(nb.network, nb.prefix_len));
                    return;
                }
            }
        }
        if accept_v6 {
            if let Ok(nb) = line.parse::<NetblockV6>() {
                if !ignore_invalid || nb.is_canonical() {
                    v6.push(NetblockV6::new(nb.network, nb.prefix_len));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    let accept_v4 = cli.accept_v4();
    let accept_v6 = cli.accept_v6();

    // Create the reader based on input arg
    let mut input: Box<dyn BufRead> = match &cli.input {
        Some(file) => Box::new(io::BufReader::new(std::fs::File::open(file)?)),
        None => Box::new(io::BufReader::new(io::stdin())),
    };

    // Parse input lines into netblocks
    let mut blocks_v4 = Vec::new();
    let mut blocks_v6 = Vec::new();
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
                process_line(
                    line,
                    cli.input_range,
                    cli.ignore_invalid,
                    accept_v4,
                    accept_v6,
                    &mut blocks_v4,
                    &mut blocks_v6,
                );
            }
        }
        // If invalid UTF-8, just continue to the next line
    }

    // Aggregate and output
    let mut stdout = io::stdout().lock();

    if accept_v4 {
        let aggregated = aggregate_netblocks(blocks_v4);
        for nb in aggregated {
            let _ = writeln!(stdout, "{}", nb);
        }
    }

    if accept_v6 {
        let aggregated = aggregate_netblocks(blocks_v6);
        for nb in aggregated {
            let _ = writeln!(stdout, "{}", nb);
        }
    }

    Ok(())
}
