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

    /// Output aggregated results as IP ranges instead of CIDR prefixes
    #[arg(long)]
    output_range: bool,

    /// Skip addresses that don't match their prefix
    /// (e.g. 1.2.3.4/24 must have last 8 bits zero)
    #[arg(long)]
    ignore_invalid: bool,

    /// Set maximum prefix length (longer prefixes are truncated to this length)
    #[arg(short = 'm', long = "max-length", value_name = "N")]
    max_length: Option<u8>,

    /// Subtract netblocks listed in FILE from the result
    #[arg(long, value_name = "FILE")]
    exclude: Option<String>,

    /// Keep only netblocks that overlap with those in FILE
    #[arg(long, value_name = "FILE")]
    intersect: Option<String>,

    /// Compare two files and show differences (requires exactly two input files)
    #[arg(long)]
    diff: bool,

    /// Print aggregation statistics to stderr
    #[arg(long)]
    stats: bool,

    /// Input file(s) to process (two files required for --diff)
    #[arg(value_name = "FILE")]
    input: Vec<String>,
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
// Trait for generic aggregation and set operations
// ---------------------------------------------------------------------------

trait Aggregateable: Ord + Copy + fmt::Display {
    /// Return true if `other` is a subnet of `self`.
    fn contains(&self, other: &Self) -> bool;

    /// Combine sibling netblocks into one, if possible.
    fn aggregate(&self, other: &Self) -> Option<Self>;

    /// Split a netblock into its two child halves (prefix_len + 1).
    /// Returns None if already at maximum prefix length.
    fn split_halves(&self) -> Option<(Self, Self)>;

    /// Format as an IP range string "start-end".
    fn display_range(&self) -> String;

    /// Number of addresses covered by this prefix, as f64 (for stats display).
    fn address_count_f64(&self) -> f64;
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

    #[inline]
    fn split_halves(&self) -> Option<(Self, Self)> {
        if self.prefix_len >= 32 {
            return None;
        }
        let new_len = self.prefix_len + 1;
        let left = Self::new(self.network, new_len);
        let right_bits = u32::from(self.network) | (1u32 << (31 - self.prefix_len));
        let right = Self::new(Ipv4Addr::from(right_bits), new_len);
        Some((left, right))
    }

    fn display_range(&self) -> String {
        let start = u32::from(self.network);
        let end = if self.prefix_len == 0 {
            u32::MAX
        } else {
            start | ((1u32 << (32 - self.prefix_len)) - 1)
        };
        format!("{}-{}", self.network, Ipv4Addr::from(end))
    }

    #[inline]
    fn address_count_f64(&self) -> f64 {
        2.0f64.powi((32 - self.prefix_len) as i32)
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

    #[inline]
    fn split_halves(&self) -> Option<(Self, Self)> {
        if self.prefix_len >= 128 {
            return None;
        }
        let new_len = self.prefix_len + 1;
        let left = Self::new(self.network, new_len);
        let right_bits = u128::from(self.network) | (1u128 << (127 - self.prefix_len));
        let right = Self::new(Ipv6Addr::from(right_bits), new_len);
        Some((left, right))
    }

    fn display_range(&self) -> String {
        let start = u128::from(self.network);
        let end = if self.prefix_len == 0 {
            u128::MAX
        } else {
            start | ((1u128 << (128 - self.prefix_len)) - 1)
        };
        format!("{}-{}", self.network, Ipv6Addr::from(end))
    }

    #[inline]
    fn address_count_f64(&self) -> f64 {
        2.0f64.powi((128 - self.prefix_len) as i32)
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
// Set operations — generic for both address families
// ---------------------------------------------------------------------------

/// Remove a single netblock from `block`, returning the remaining fragments.
/// Recursively splits `block` until the excluded region is carved out.
fn subtract_single<T: Aggregateable>(block: T, excl: &T) -> Vec<T> {
    if excl.contains(&block) {
        // Entire block is excluded
        return vec![];
    }
    if !block.contains(excl) {
        // No overlap at all
        return vec![block];
    }
    // block contains excl — split into halves and recurse
    let (left, right) = block.split_halves().expect("block must be larger than excl");
    let mut result = subtract_single(left, excl);
    result.extend(subtract_single(right, excl));
    result
}

/// Subtract all `excludes` from `blocks`, returning the remaining netblocks.
fn subtract_set<T: Aggregateable>(mut blocks: Vec<T>, excludes: &[T]) -> Vec<T> {
    for excl in excludes {
        let mut remaining = Vec::with_capacity(blocks.len());
        for &block in &blocks {
            remaining.extend(subtract_single(block, excl));
        }
        blocks = remaining;
    }
    // Re-aggregate to merge any newly-adjacent siblings
    aggregate_netblocks(blocks)
}

/// Intersect two sets of netblocks, keeping only the overlapping regions.
fn intersect_sets<T: Aggregateable>(a: &[T], b: &[T]) -> Vec<T> {
    let mut result = Vec::new();
    for &x in a {
        for &y in b {
            if x.contains(&y) {
                result.push(y);
            } else if y.contains(&x) {
                result.push(x);
                break; // x is fully covered, no need to check more of b
            }
        }
    }
    // Re-aggregate to remove duplicates
    aggregate_netblocks(result)
}

/// Compare two sorted, aggregated lists and write differences to `out`.
/// Lines only in `old` are prefixed with "- ", lines only in `new` with "+ ".
fn diff_sorted<T: Aggregateable>(old: &[T], new: &[T], out: &mut impl Write) {
    let mut i = 0;
    let mut j = 0;
    while i < old.len() && j < new.len() {
        if old[i] == new[j] {
            i += 1;
            j += 1;
        } else if old[i] < new[j] {
            let _ = writeln!(out, "- {}", old[i]);
            i += 1;
        } else {
            let _ = writeln!(out, "+ {}", new[j]);
            j += 1;
        }
    }
    while i < old.len() {
        let _ = writeln!(out, "- {}", old[i]);
        i += 1;
    }
    while j < new.len() {
        let _ = writeln!(out, "+ {}", new[j]);
        j += 1;
    }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/// Write aggregated netblocks to `out`, using range or CIDR format.
fn write_netblocks<T: Aggregateable>(blocks: &[T], output_range: bool, out: &mut impl Write) {
    if output_range {
        for nb in blocks {
            let _ = writeln!(out, "{}", nb.display_range());
        }
    } else {
        for nb in blocks {
            let _ = writeln!(out, "{}", nb);
        }
    }
}

/// Sum address counts across all netblocks (as f64 for display).
fn total_addresses<T: Aggregateable>(blocks: &[T]) -> f64 {
    blocks.iter().map(|b| b.address_count_f64()).sum()
}

/// Format a large address count for human-readable display.
fn format_count(count: f64) -> String {
    if count < 1e15 { format!("{:.0}", count) } else { format!("{:.6e}", count) }
}

// ---------------------------------------------------------------------------
// Input processing
// ---------------------------------------------------------------------------

/// Collected parse results from reading an input source.
struct ParseResult {
    v4: Vec<NetblockV4>,
    v6: Vec<NetblockV6>,
    total_lines: usize,
    invalid_lines: usize,
}

/// Apply --max-length clamping to a vector of IPv4 netblocks.
fn apply_max_length_v4(blocks: &mut [NetblockV4], max_len: u8) {
    let max = max_len.min(32);
    for nb in blocks.iter_mut() {
        if nb.prefix_len > max {
            *nb = NetblockV4::new(nb.network, max);
        }
    }
}

/// Apply --max-length clamping to a vector of IPv6 netblocks.
fn apply_max_length_v6(blocks: &mut [NetblockV6], max_len: u8) {
    let max = max_len.min(128);
    for nb in blocks.iter_mut() {
        if nb.prefix_len > max {
            *nb = NetblockV6::new(nb.network, max);
        }
    }
}

/// Try to parse a single line, dispatching to the appropriate address family.
/// Returns true if the line was successfully parsed into at least one netblock.
fn process_line(
    line: &str,
    input_range: bool,
    ignore_invalid: bool,
    accept_v4: bool,
    accept_v6: bool,
    v4: &mut Vec<NetblockV4>,
    v6: &mut Vec<NetblockV6>,
) -> bool {
    if input_range {
        // Try IPv4 range first (dotted-decimal never contains ':')
        if accept_v4 {
            if let Some((start, end)) = parse_range_v4(line) {
                v4.extend(range_to_prefixes_v4(start, end));
                return true;
            }
        }
        if accept_v6 {
            if let Some((start, end)) = parse_range_v6(line) {
                v6.extend(range_to_prefixes_v6(start, end));
                return true;
            }
        }
        false
    } else {
        // Try IPv4 CIDR / bare address first
        if accept_v4 {
            if let Ok(nb) = line.parse::<NetblockV4>() {
                if !ignore_invalid || nb.is_canonical() {
                    v4.push(NetblockV4::new(nb.network, nb.prefix_len));
                    return true;
                }
            }
        }
        if accept_v6 {
            if let Ok(nb) = line.parse::<NetblockV6>() {
                if !ignore_invalid || nb.is_canonical() {
                    v6.push(NetblockV6::new(nb.network, nb.prefix_len));
                    return true;
                }
            }
        }
        false
    }
}

/// Read netblocks from a `BufRead` source, tracking line counts.
fn read_netblocks(
    reader: &mut dyn BufRead,
    input_range: bool,
    ignore_invalid: bool,
    accept_v4: bool,
    accept_v6: bool,
    max_length: Option<u8>,
) -> Result<ParseResult, Box<dyn Error>> {
    let mut result =
        ParseResult { v4: Vec::new(), v6: Vec::new(), total_lines: 0, invalid_lines: 0 };
    let mut buf = Vec::new();

    // Read lines as raw bytes to handle non-UTF8 content
    loop {
        buf.clear();
        let bytes_read = reader.read_until(b'\n', &mut buf)?;
        if bytes_read == 0 {
            break; // End of input
        }

        // Try to convert to string, skip if invalid UTF-8
        if let Ok(line_str) = std::str::from_utf8(&buf) {
            let line = line_str.trim();
            if !line.is_empty() {
                result.total_lines += 1;
                let parsed = process_line(
                    line,
                    input_range,
                    ignore_invalid,
                    accept_v4,
                    accept_v6,
                    &mut result.v4,
                    &mut result.v6,
                );
                if !parsed {
                    result.invalid_lines += 1;
                }
            }
        }
        // If invalid UTF-8, just continue to the next line
    }

    // Apply max-length clamping if requested
    if let Some(max_len) = max_length {
        apply_max_length_v4(&mut result.v4, max_len);
        apply_max_length_v6(&mut result.v6, max_len);
    }

    Ok(result)
}

/// Open a file and read netblocks from it.
fn read_netblocks_from_file(
    path: &str,
    input_range: bool,
    ignore_invalid: bool,
    accept_v4: bool,
    accept_v6: bool,
    max_length: Option<u8>,
) -> Result<ParseResult, Box<dyn Error>> {
    let mut reader = io::BufReader::new(std::fs::File::open(path)?);
    read_netblocks(&mut reader, input_range, ignore_invalid, accept_v4, accept_v6, max_length)
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

    // Validate flag combinations
    if cli.diff && (cli.exclude.is_some() || cli.intersect.is_some()) {
        eprintln!("error: --diff cannot be combined with --exclude or --intersect");
        std::process::exit(1);
    }
    if cli.diff && cli.input.len() != 2 {
        eprintln!("error: --diff requires exactly two input files");
        std::process::exit(1);
    }
    if cli.diff && cli.output_range {
        eprintln!("error: --diff cannot be combined with --output-range");
        std::process::exit(1);
    }

    let accept_v4 = cli.accept_v4();
    let accept_v6 = cli.accept_v6();

    // -----------------------------------------------------------------------
    // Diff mode — compare two files
    // -----------------------------------------------------------------------
    if cli.diff {
        let old = read_netblocks_from_file(
            &cli.input[0],
            cli.input_range,
            cli.ignore_invalid,
            accept_v4,
            accept_v6,
            cli.max_length,
        )?;
        let new = read_netblocks_from_file(
            &cli.input[1],
            cli.input_range,
            cli.ignore_invalid,
            accept_v4,
            accept_v6,
            cli.max_length,
        )?;

        let old_v4 = aggregate_netblocks(old.v4);
        let new_v4 = aggregate_netblocks(new.v4);
        let old_v6 = aggregate_netblocks(old.v6);
        let new_v6 = aggregate_netblocks(new.v6);

        let mut stdout = io::stdout().lock();

        if accept_v4 {
            diff_sorted(&old_v4, &new_v4, &mut stdout);
        }
        if accept_v6 {
            diff_sorted(&old_v6, &new_v6, &mut stdout);
        }

        if cli.stats {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "--- {}", cli.input[0]);
            let _ = writeln!(
                stderr,
                "  Lines: {}  Invalid: {}  IPv4: {}  IPv6: {}",
                old.total_lines,
                old.invalid_lines,
                old_v4.len(),
                old_v6.len()
            );
            let _ = writeln!(stderr, "+++ {}", cli.input[1]);
            let _ = writeln!(
                stderr,
                "  Lines: {}  Invalid: {}  IPv4: {}  IPv6: {}",
                new.total_lines,
                new.invalid_lines,
                new_v4.len(),
                new_v6.len()
            );
        }

        return Ok(());
    }

    // -----------------------------------------------------------------------
    // Normal mode — aggregate (with optional exclude / intersect)
    // -----------------------------------------------------------------------

    // Create the reader based on input arg
    let mut input: Box<dyn BufRead> = if let Some(file) = cli.input.first() {
        Box::new(io::BufReader::new(std::fs::File::open(file)?))
    } else {
        Box::new(io::BufReader::new(io::stdin()))
    };

    let parsed = read_netblocks(
        &mut input,
        cli.input_range,
        cli.ignore_invalid,
        accept_v4,
        accept_v6,
        cli.max_length,
    )?;

    let v4_before = parsed.v4.len();
    let v6_before = parsed.v6.len();

    let mut result_v4 = aggregate_netblocks(parsed.v4);
    let mut result_v6 = aggregate_netblocks(parsed.v6);

    // Apply --exclude if specified
    if let Some(ref excl_path) = cli.exclude {
        let excl = read_netblocks_from_file(
            excl_path,
            cli.input_range,
            cli.ignore_invalid,
            accept_v4,
            accept_v6,
            cli.max_length,
        )?;
        let excl_v4 = aggregate_netblocks(excl.v4);
        let excl_v6 = aggregate_netblocks(excl.v6);

        if accept_v4 && !excl_v4.is_empty() {
            result_v4 = subtract_set(result_v4, &excl_v4);
        }
        if accept_v6 && !excl_v6.is_empty() {
            result_v6 = subtract_set(result_v6, &excl_v6);
        }
    }

    // Apply --intersect if specified
    if let Some(ref isect_path) = cli.intersect {
        let isect = read_netblocks_from_file(
            isect_path,
            cli.input_range,
            cli.ignore_invalid,
            accept_v4,
            accept_v6,
            cli.max_length,
        )?;
        let isect_v4 = aggregate_netblocks(isect.v4);
        let isect_v6 = aggregate_netblocks(isect.v6);

        if accept_v4 {
            result_v4 = intersect_sets(&result_v4, &isect_v4);
        }
        if accept_v6 {
            result_v6 = intersect_sets(&result_v6, &isect_v6);
        }
    }

    // Output aggregated netblocks to stdout
    let mut stdout = io::stdout().lock();

    if accept_v4 {
        write_netblocks(&result_v4, cli.output_range, &mut stdout);
    }
    if accept_v6 {
        write_netblocks(&result_v6, cli.output_range, &mut stdout);
    }

    // Print statistics to stderr if requested
    if cli.stats {
        let mut stderr = io::stderr().lock();
        let _ =
            writeln!(stderr, "Lines: {}  Invalid: {}", parsed.total_lines, parsed.invalid_lines);
        if accept_v4 {
            let _ = writeln!(
                stderr,
                "IPv4: {} -> {} aggregated ({} addresses)",
                v4_before,
                result_v4.len(),
                format_count(total_addresses(&result_v4))
            );
        }
        if accept_v6 {
            let _ = writeln!(
                stderr,
                "IPv6: {} -> {} aggregated ({} addresses)",
                v6_before,
                result_v6.len(),
                format_count(total_addresses(&result_v6))
            );
        }
    }

    Ok(())
}
