use clap::Parser;
use std::error::Error;
use std::fmt;
use std::io::{self, BufRead, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use unicode_segmentation::UnicodeSegmentation;

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

    /// Output as network/netmask (e.g. 10.0.0.0/255.255.255.0). For IPv6 the
    /// mask is the full address form (e.g. 2001:db8::/ffff:ffff::).
    #[arg(long)]
    output_netmask: bool,

    /// Output as Cisco-style "network wildcard" (e.g. 10.0.0.0 0.0.0.255).
    /// IPv6 has no wildcard-mask convention, so IPv6 blocks fall back to CIDR.
    #[arg(long)]
    output_wildcard: bool,

    /// Emit results as JSON: IPv4 in "results4", IPv6 in "results6". With
    /// --stats, statistics are placed in a separate "stats" object.
    #[arg(long)]
    json: bool,

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

    /// Field delimiter: a single UTF-8 character or U+XXXX / UXXXX specification.
    /// CESU-8 surrogate code points are rejected.
    /// Must be used together with --fields.
    #[arg(short = 'd', long, value_name = "CHAR")]
    delimiter: Option<String>,

    /// Comma-separated list of 1-based field numbers to extract after splitting
    /// by --delimiter. Negative numbers count from the end of the line (-1 = last).
    /// Each extracted field is tried as an IP address or netblock.
    /// Must be used together with --delimiter.
    #[arg(short = 'f', long, value_name = "FIELDS")]
    fields: Option<String>,

    /// Read input as CSV and extract the field at this 1-based column number.
    /// Assumes no header row. Cannot be combined with --delimiter/--fields
    /// or --csv-field-name.
    #[arg(long, value_name = "N")]
    csv_field_number: Option<usize>,

    /// Read input as CSV and extract the field under this column header name.
    /// The header name may contain whitespace. Cannot be combined with
    /// --delimiter/--fields or --csv-field-number.
    #[arg(long, value_name = "NAME")]
    csv_field_name: Option<String>,

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

    /// Format just the first address of this prefix.
    fn display_start(&self) -> String;

    /// Format just the last address of this prefix.
    fn display_end(&self) -> String;

    /// Format as network/netmask (family-specific mask representation).
    fn display_netmask(&self) -> String;

    /// Format as a Cisco-style "network wildcard" pair (IPv4); IPv6
    /// implementations fall back to CIDR since wildcard masks are IPv4-only.
    fn display_wildcard(&self) -> String;

    /// Return true if the last address of self is immediately followed
    /// by the first address of `next` (i.e., they form a contiguous range).
    fn is_contiguous_with(&self, next: &Self) -> bool;

    /// Number of addresses covered by this prefix, as an exact u128.
    /// Returns None only for the whole IPv6 space (/0), whose count is 2^128
    /// and therefore one larger than u128::MAX.
    fn address_count(&self) -> Option<u128>;
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

    fn display_start(&self) -> String {
        format!("{}", self.network)
    }

    fn display_end(&self) -> String {
        let start = u32::from(self.network);
        let end = if self.prefix_len == 0 {
            u32::MAX
        } else {
            start | ((1u32 << (32 - self.prefix_len)) - 1)
        };
        format!("{}", Ipv4Addr::from(end))
    }

    fn display_netmask(&self) -> String {
        // prefix_len == 0 must be special-cased: `u32::MAX << 32` would overflow.
        let mask = if self.prefix_len == 0 { 0 } else { u32::MAX << (32 - self.prefix_len) };
        format!("{}/{}", self.network, Ipv4Addr::from(mask))
    }

    fn display_wildcard(&self) -> String {
        let mask = if self.prefix_len == 0 { 0 } else { u32::MAX << (32 - self.prefix_len) };
        let wildcard = !mask;
        format!("{} {}", self.network, Ipv4Addr::from(wildcard))
    }

    fn is_contiguous_with(&self, next: &Self) -> bool {
        let start = u32::from(self.network);
        let end = if self.prefix_len == 0 {
            u32::MAX
        } else {
            start | ((1u32 << (32 - self.prefix_len)) - 1)
        };
        end < u32::MAX && end + 1 == u32::from(next.network)
    }

    #[inline]
    fn address_count(&self) -> Option<u128> {
        // IPv4 maxes out at 2^32 addresses, which always fits in u128.
        Some(1u128 << (32 - self.prefix_len))
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

    fn display_start(&self) -> String {
        format!("{}", self.network)
    }

    fn display_end(&self) -> String {
        let start = u128::from(self.network);
        let end = if self.prefix_len == 0 {
            u128::MAX
        } else {
            start | ((1u128 << (128 - self.prefix_len)) - 1)
        };
        format!("{}", Ipv6Addr::from(end))
    }

    fn display_netmask(&self) -> String {
        // prefix_len == 0 must be special-cased: `u128::MAX << 128` would overflow.
        let mask = if self.prefix_len == 0 { 0 } else { u128::MAX << (128 - self.prefix_len) };
        format!("{}/{}", self.network, Ipv6Addr::from(mask))
    }

    fn display_wildcard(&self) -> String {
        // IPv6 has no Cisco-style wildcard-mask convention; fall back to CIDR.
        format!("{}/{}", self.network, self.prefix_len)
    }

    fn is_contiguous_with(&self, next: &Self) -> bool {
        let start = u128::from(self.network);
        let end = if self.prefix_len == 0 {
            u128::MAX
        } else {
            start | ((1u128 << (128 - self.prefix_len)) - 1)
        };
        end < u128::MAX && end + 1 == u128::from(next.network)
    }

    #[inline]
    fn address_count(&self) -> Option<u128> {
        // A /0 covers 2^128 addresses, which is one more than u128::MAX,
        // so it cannot be represented; the caller treats None as 2^128.
        if self.prefix_len == 0 { None } else { Some(1u128 << (128 - self.prefix_len)) }
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

        // A /0 covers the entire space in one block; computing block_size below
        // as `1u128 << 128` would overflow the shift, so stop once it is emitted.
        if bits >= 128 {
            break;
        }

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

/// Sort and remove contained (duplicate/subset) netblocks without merging
/// siblings.  Used by --diff so that individual prefixes are compared as-is
/// rather than being collapsed into larger blocks first.
fn normalize_netblocks<T: Aggregateable>(mut netblocks: Vec<T>) -> Vec<T> {
    if netblocks.len() <= 1 {
        return netblocks;
    }

    netblocks.sort_unstable();

    let mut deduped = Vec::with_capacity(netblocks.len());
    let mut prev = netblocks[0];

    for &current in &netblocks[1..] {
        if !prev.contains(&current) {
            deduped.push(prev);
            prev = current;
        }
    }
    deduped.push(prev);
    deduped
}

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
/// Each emitted netblock is rendered using `fmt`.
fn diff_sorted<T: Aggregateable>(old: &[T], new: &[T], fmt: OutputFormat, out: &mut impl Write) {
    let mut i = 0;
    let mut j = 0;
    while i < old.len() && j < new.len() {
        if old[i] == new[j] {
            i += 1;
            j += 1;
        } else if old[i] < new[j] {
            let _ = writeln!(out, "- {}", format_block(&old[i], fmt));
            i += 1;
        } else {
            let _ = writeln!(out, "+ {}", format_block(&new[j], fmt));
            j += 1;
        }
    }
    while i < old.len() {
        let _ = writeln!(out, "- {}", format_block(&old[i], fmt));
        i += 1;
    }
    while j < new.len() {
        let _ = writeln!(out, "+ {}", format_block(&new[j], fmt));
        j += 1;
    }
}

/// Compare two sorted, aggregated lists and collect the differences.
/// Returns (removed, added): netblocks only in `old`, and only in `new`.
fn diff_collect<T: Aggregateable>(old: &[T], new: &[T]) -> (Vec<T>, Vec<T>) {
    let mut removed = Vec::new();
    let mut added = Vec::new();
    let mut i = 0;
    let mut j = 0;
    while i < old.len() && j < new.len() {
        if old[i] == new[j] {
            i += 1;
            j += 1;
        } else if old[i] < new[j] {
            removed.push(old[i]);
            i += 1;
        } else {
            added.push(new[j]);
            j += 1;
        }
    }
    while i < old.len() {
        removed.push(old[i]);
        i += 1;
    }
    while j < new.len() {
        added.push(new[j]);
        j += 1;
    }
    (removed, added)
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/// Selected output rendering for netblocks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    /// network/prefix (e.g. 10.0.0.0/8)
    Cidr,
    /// start-end ranges, merging contiguous blocks
    Range,
    /// network/netmask (e.g. 10.0.0.0/255.0.0.0)
    Netmask,
    /// Cisco "network wildcard" (e.g. 10.0.0.0 0.255.255.255)
    Wildcard,
}

/// Render a single netblock in the given format.
/// Range mode renders this block's own span; contiguous merging across blocks
/// is only performed by `format_blocks`.
fn format_block<T: Aggregateable>(nb: &T, fmt: OutputFormat) -> String {
    match fmt {
        OutputFormat::Cidr => nb.to_string(),
        OutputFormat::Netmask => nb.display_netmask(),
        OutputFormat::Wildcard => nb.display_wildcard(),
        OutputFormat::Range => format!("{}-{}", nb.display_start(), nb.display_end()),
    }
}

/// Render aggregated netblocks into one output string per line.
/// In range mode, adjacent CIDRs are merged into contiguous ranges.
fn format_blocks<T: Aggregateable>(blocks: &[T], fmt: OutputFormat) -> Vec<String> {
    if fmt != OutputFormat::Range {
        return blocks.iter().map(|nb| format_block(nb, fmt)).collect();
    }

    let mut out = Vec::new();
    if blocks.is_empty() {
        return out;
    }
    let mut range_start = blocks[0].display_start();
    let mut range_end = blocks[0].display_end();
    for pair in blocks.windows(2) {
        if pair[0].is_contiguous_with(&pair[1]) {
            // Extend the current range
            range_end = pair[1].display_end();
        } else {
            // Emit the completed range and start a new one
            out.push(format!("{}-{}", range_start, range_end));
            range_start = pair[1].display_start();
            range_end = pair[1].display_end();
        }
    }
    // Emit the final range
    out.push(format!("{}-{}", range_start, range_end));
    out
}

/// Write aggregated netblocks to `out` in the selected format.
fn write_netblocks<T: Aggregateable>(blocks: &[T], fmt: OutputFormat, out: &mut impl Write) {
    for line in format_blocks(blocks, fmt) {
        let _ = writeln!(out, "{}", line);
    }
}

/// Sum address counts across all netblocks, returning an exact decimal string.
/// Counts are accumulated in u128; the only total that does not fit is the
/// whole IPv6 space (2^128 = u128::MAX + 1), which is reported as such.
fn total_addresses_string<T: Aggregateable>(blocks: &[T]) -> String {
    // 2^128 in decimal (u128::MAX + 1); the single value that overflows u128.
    const FULL_IPV6_SPACE: &str = "340282366920938463463374607431768211456";

    let mut sum: u128 = 0;
    for b in blocks {
        match b.address_count() {
            // None marks the IPv6 /0 block, whose count is exactly 2^128.
            None => return FULL_IPV6_SPACE.to_string(),
            Some(c) => match sum.checked_add(c) {
                Some(s) => sum = s,
                // Non-overlapping blocks total at most 2^128; overflowing u128
                // therefore means the sum is exactly 2^128.
                None => return FULL_IPV6_SPACE.to_string(),
            },
        }
    }
    sum.to_string()
}

// ---------------------------------------------------------------------------
// JSON output (dependency-free; results are arrays of plain strings)
// ---------------------------------------------------------------------------

/// Escape a string for safe inclusion inside a JSON string literal.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// `"key": [ ... ]` member with each element on its own line, indented.
fn json_array_member(key: &str, items: &[String], indent: usize) -> String {
    let pad = "  ".repeat(indent);
    if items.is_empty() {
        return format!("{}\"{}\": []", pad, json_escape(key));
    }
    let ipad = "  ".repeat(indent + 1);
    let body = items
        .iter()
        .map(|it| format!("{}\"{}\"", ipad, json_escape(it)))
        .collect::<Vec<_>>()
        .join(",\n");
    format!("{}\"{}\": [\n{}\n{}]", pad, json_escape(key), body, pad)
}

/// `"key": <number>` member.
fn json_num_member(key: &str, val: u64, indent: usize) -> String {
    format!("{}\"{}\": {}", "  ".repeat(indent), json_escape(key), val)
}

/// `"key": "<string>"` member.
fn json_str_member(key: &str, val: &str, indent: usize) -> String {
    format!("{}\"{}\": \"{}\"", "  ".repeat(indent), json_escape(key), json_escape(val))
}

/// `"key": { ... }` member from already-rendered inner members.
fn json_object_member(key: &str, inner: &[String], indent: usize) -> String {
    let pad = "  ".repeat(indent);
    if inner.is_empty() {
        return format!("{}\"{}\": {{}}", pad, json_escape(key));
    }
    format!("{}\"{}\": {{\n{}\n{}}}", pad, json_escape(key), inner.join(",\n"), pad)
}

/// Wrap top-level members into a complete JSON object document.
fn json_document(members: &[String]) -> String {
    if members.is_empty() {
        return "{}\n".to_string();
    }
    format!("{{\n{}\n}}\n", members.join(",\n"))
}

/// Build the per-family stats sub-object (input/aggregated/addresses).
/// Address counts are emitted as strings because IPv6 totals exceed the range
/// of a JSON-safe integer.
fn json_family_stats(key: &str, input: usize, aggregated: usize, addresses: &str) -> String {
    let inner = vec![
        json_num_member("input", input as u64, 3),
        json_num_member("aggregated", aggregated as u64, 3),
        json_str_member("addresses", addresses, 3),
    ];
    json_object_member(key, &inner, 2)
}

// ---------------------------------------------------------------------------
// Delimiter/field extraction (cut-like UTF-8 aware processing)
// ---------------------------------------------------------------------------

/// Options for delimiter-based field extraction (cut-like mode).
struct FieldOptions {
    delimiter: char,
    fields: Vec<i32>,
}

/// Parse a delimiter specification into a single Unicode scalar value.
/// Accepts:
///   - A single UTF-8 character (e.g. ":" or "→")
///   - UXXXX or U+XXXX hex notation (e.g. "U003A" or "U+003A" for ':')
///     Rejects CESU-8 surrogate code points (U+D800..U+DFFF).
fn parse_delimiter(s: &str) -> Result<char, String> {
    // Try U+XXXX or UXXXX format
    let hex_str = if let Some(stripped) = s.strip_prefix("U+") {
        Some(stripped)
    } else {
        s.strip_prefix('U').filter(|&stripped| {
            !stripped.is_empty() && stripped.chars().all(|c| c.is_ascii_hexdigit())
        })
    };

    if let Some(hex) = hex_str {
        if hex.is_empty() {
            return Err("empty code point after 'U' prefix".to_string());
        }
        let code_point =
            u32::from_str_radix(hex, 16).map_err(|_| format!("invalid Unicode escape: {}", s))?;
        // Reject CESU-8 surrogates
        if (0xD800..=0xDFFF).contains(&code_point) {
            return Err(format!("CESU-8 surrogate code point U+{:04X} is not allowed", code_point));
        }
        char::from_u32(code_point)
            .ok_or_else(|| format!("invalid Unicode code point: U+{:04X}", code_point))
    } else {
        // Must be exactly one Unicode scalar value (one grapheme cluster of one code point)
        let graphemes: Vec<&str> = s.graphemes(true).collect();
        if graphemes.len() != 1 {
            return Err(format!(
                "delimiter must be a single character, got {} grapheme cluster(s): {:?}",
                graphemes.len(),
                s
            ));
        }
        let mut chars = graphemes[0].chars();
        let ch = chars.next().ok_or_else(|| "empty delimiter".to_string())?;
        if chars.next().is_some() {
            return Err(format!(
                "delimiter must be a single code point, \
                 {:?} is a multi-code-point grapheme cluster",
                graphemes[0]
            ));
        }
        Ok(ch)
    }
}

/// Parse a comma-separated list of 1-based field numbers.
/// Positive numbers index from the start (1 = first).
/// Negative numbers index from the end (-1 = last).
/// Zero is not a valid field number.
fn parse_field_spec(s: &str) -> Result<Vec<i32>, String> {
    let mut fields = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let n: i32 = part.parse().map_err(|_| format!("invalid field number: {:?}", part))?;
        if n == 0 {
            return Err("field numbers are 1-based, 0 is not valid".to_string());
        }
        fields.push(n);
    }
    if fields.is_empty() {
        return Err("no fields specified".to_string());
    }
    Ok(fields)
}

/// Extract a single field from a line split by delimiter.
/// Positive field numbers are 1-based from the start.
/// Negative field numbers count from the end (-1 = last field).
fn extract_field<'a>(parts: &[&'a str], field: i32) -> Option<&'a str> {
    let index = if field > 0 {
        (field - 1) as usize
    } else {
        // Negative: count from end (-1 = last element)
        let abs_field = (-field) as usize;
        if abs_field > parts.len() {
            return None;
        }
        parts.len() - abs_field
    };
    parts.get(index).copied()
}

// ---------------------------------------------------------------------------
// CSV field extraction
// ---------------------------------------------------------------------------

/// Specifies which column to extract from CSV input.
enum CsvOptions {
    /// Column by 0-based index (user provides 1-based, converted before storing).
    ByNumber(usize),
    /// Column by header name (first row is the header).
    ByName(String),
}

/// Read netblocks from a CSV source using the `csv` crate.
/// Extracts the specified column from each row and feeds it through `process_line`.
fn read_netblocks_csv(
    reader: Box<dyn io::Read>,
    csv_opts: &CsvOptions,
    input_range: bool,
    ignore_invalid: bool,
    accept_v4: bool,
    accept_v6: bool,
    max_length: Option<u8>,
) -> Result<ParseResult, Box<dyn Error>> {
    let mut result = ParseResult {
        v4: Vec::new(),
        v6: Vec::new(),
        total_lines: 0,
        invalid_lines: 0,
        utf8_invalid_lines: 0,
    };

    let col_index: usize;

    match csv_opts {
        CsvOptions::ByNumber(idx) => {
            col_index = *idx;
            let mut rdr = csv::ReaderBuilder::new().has_headers(false).from_reader(reader);

            for row_result in rdr.records() {
                let record = match row_result {
                    Ok(r) => r,
                    Err(e) => {
                        // csv::Error can be a UTF-8 error or a parse error
                        if matches!(e.kind(), csv::ErrorKind::Utf8 { .. }) {
                            result.utf8_invalid_lines += 1;
                        } else {
                            result.invalid_lines += 1;
                        }
                        continue;
                    }
                };
                result.total_lines += 1;

                if let Some(field_val) = record.get(col_index) {
                    let trimmed = field_val.trim();
                    if !trimmed.is_empty() {
                        let parsed = process_line(
                            trimmed,
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
                    } else {
                        result.invalid_lines += 1;
                    }
                } else {
                    result.invalid_lines += 1;
                }
            }
        }
        CsvOptions::ByName(name) => {
            let mut rdr = csv::ReaderBuilder::new().has_headers(true).from_reader(reader);

            // Find the column index from the header row
            let headers = rdr.headers()?.clone();
            col_index = headers.iter().position(|h| h.trim() == name.trim()).ok_or_else(|| {
                format!(
                    "CSV header {:?} not found (available: {})",
                    name,
                    headers.iter().map(|h| format!("{:?}", h)).collect::<Vec<_>>().join(", ")
                )
            })?;

            for row_result in rdr.records() {
                let record = match row_result {
                    Ok(r) => r,
                    Err(e) => {
                        if matches!(e.kind(), csv::ErrorKind::Utf8 { .. }) {
                            result.utf8_invalid_lines += 1;
                        } else {
                            result.invalid_lines += 1;
                        }
                        continue;
                    }
                };
                result.total_lines += 1;

                if let Some(field_val) = record.get(col_index) {
                    let trimmed = field_val.trim();
                    if !trimmed.is_empty() {
                        let parsed = process_line(
                            trimmed,
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
                    } else {
                        result.invalid_lines += 1;
                    }
                } else {
                    result.invalid_lines += 1;
                }
            }
        }
    }

    // Apply max-length clamping if requested
    if let Some(max_len) = max_length {
        apply_max_length_v4(&mut result.v4, max_len);
        apply_max_length_v6(&mut result.v6, max_len);
    }

    Ok(result)
}

/// Open a file and read netblocks from it in CSV mode.
fn read_netblocks_csv_from_file(
    path: &str,
    csv_opts: &CsvOptions,
    input_range: bool,
    ignore_invalid: bool,
    accept_v4: bool,
    accept_v6: bool,
    max_length: Option<u8>,
) -> Result<ParseResult, Box<dyn Error>> {
    let file = std::fs::File::open(path)?;
    read_netblocks_csv(
        Box::new(file),
        csv_opts,
        input_range,
        ignore_invalid,
        accept_v4,
        accept_v6,
        max_length,
    )
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
    /// Lines skipped because they contained invalid UTF-8
    /// (only counted when --delimiter/--fields are active)
    utf8_invalid_lines: usize,
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
        if accept_v4 && let Some((start, end)) = parse_range_v4(line) {
            v4.extend(range_to_prefixes_v4(start, end));
            return true;
        }
        if accept_v6 && let Some((start, end)) = parse_range_v6(line) {
            v6.extend(range_to_prefixes_v6(start, end));
            return true;
        }
        false
    } else {
        // Try IPv4 CIDR / bare address first
        if accept_v4
            && let Ok(nb) = line.parse::<NetblockV4>()
            && (!ignore_invalid || nb.is_canonical())
        {
            v4.push(NetblockV4::new(nb.network, nb.prefix_len));
            return true;
        }
        if accept_v6
            && let Ok(nb) = line.parse::<NetblockV6>()
            && (!ignore_invalid || nb.is_canonical())
        {
            v6.push(NetblockV6::new(nb.network, nb.prefix_len));
            return true;
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
    field_opts: Option<&FieldOptions>,
) -> Result<ParseResult, Box<dyn Error>> {
    let mut result = ParseResult {
        v4: Vec::new(),
        v6: Vec::new(),
        total_lines: 0,
        invalid_lines: 0,
        utf8_invalid_lines: 0,
    };
    let mut buf = Vec::new();

    // Read lines as raw bytes to handle non-UTF8 content
    loop {
        buf.clear();
        let bytes_read = reader.read_until(b'\n', &mut buf)?;
        if bytes_read == 0 {
            break; // End of input
        }

        if let Some(fopts) = field_opts {
            // Delimiter/fields mode: strict UTF-8 validation
            let line_str = match std::str::from_utf8(&buf) {
                Ok(s) => s,
                Err(_) => {
                    // Invalid UTF-8: skip and count as utf8 error
                    result.utf8_invalid_lines += 1;
                    continue;
                }
            };
            let line = line_str.trim();
            if line.is_empty() {
                continue;
            }
            result.total_lines += 1;

            let parts: Vec<&str> = line.split(fopts.delimiter).collect();
            let mut any_parsed = false;

            for &field_num in &fopts.fields {
                if let Some(field_val) = extract_field(&parts, field_num) {
                    let trimmed = field_val.trim();
                    if !trimmed.is_empty() {
                        let parsed = process_line(
                            trimmed,
                            input_range,
                            ignore_invalid,
                            accept_v4,
                            accept_v6,
                            &mut result.v4,
                            &mut result.v6,
                        );
                        if parsed {
                            any_parsed = true;
                        }
                    }
                }
            }

            if !any_parsed {
                result.invalid_lines += 1;
            }
        } else {
            // Original mode: no delimiter/fields, tolerates invalid UTF-8

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
    field_opts: Option<&FieldOptions>,
) -> Result<ParseResult, Box<dyn Error>> {
    let mut reader = io::BufReader::new(std::fs::File::open(path)?);
    read_netblocks(
        &mut reader,
        input_range,
        ignore_invalid,
        accept_v4,
        accept_v6,
        max_length,
        field_opts,
    )
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

    // Validate output formats are mutually exclusive
    let fmt_count =
        [cli.output_range, cli.output_netmask, cli.output_wildcard].iter().filter(|&&b| b).count();
    if fmt_count > 1 {
        eprintln!(
            "error: --output-range, --output-netmask, and --output-wildcard are mutually exclusive"
        );
        std::process::exit(1);
    }

    // Validate --delimiter and --fields must be used together
    if cli.delimiter.is_some() != cli.fields.is_some() {
        eprintln!("error: --delimiter and --fields must be specified together");
        std::process::exit(1);
    }

    // Validate --csv-field-number and --csv-field-name are mutually exclusive
    if cli.csv_field_number.is_some() && cli.csv_field_name.is_some() {
        eprintln!("error: --csv-field-number and --csv-field-name cannot be used together");
        std::process::exit(1);
    }

    // Validate CSV options are not combined with delimiter/fields
    let has_csv = cli.csv_field_number.is_some() || cli.csv_field_name.is_some();
    let has_delim = cli.delimiter.is_some();
    if has_csv && has_delim {
        eprintln!(
            "error: --csv-field-number/--csv-field-name cannot be combined with --delimiter/--fields"
        );
        std::process::exit(1);
    }

    // Validate --csv-field-number is >= 1 (1-based)
    if let Some(n) = cli.csv_field_number
        && n < 1
    {
        eprintln!("error: --csv-field-number is 1-based, 0 is not valid");
        std::process::exit(1);
    }

    // Parse delimiter and fields into FieldOptions
    let field_opts = match (&cli.delimiter, &cli.fields) {
        (Some(delim_str), Some(fields_str)) => {
            let delimiter = match parse_delimiter(delim_str) {
                Ok(ch) => ch,
                Err(e) => {
                    eprintln!("error: invalid delimiter: {}", e);
                    std::process::exit(1);
                }
            };
            let fields = match parse_field_spec(fields_str) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: invalid field specification: {}", e);
                    std::process::exit(1);
                }
            };
            Some(FieldOptions { delimiter, fields })
        }
        _ => None,
    };

    // Parse CSV options
    let csv_opts = if let Some(n) = cli.csv_field_number {
        Some(CsvOptions::ByNumber(n - 1)) // Convert 1-based to 0-based
    } else {
        cli.csv_field_name.as_ref().map(|name| CsvOptions::ByName(name.clone()))
    };

    let accept_v4 = cli.accept_v4();
    let accept_v6 = cli.accept_v6();

    // Resolve output format (flags already validated as mutually exclusive).
    let out_fmt = if cli.output_range {
        OutputFormat::Range
    } else if cli.output_netmask {
        OutputFormat::Netmask
    } else if cli.output_wildcard {
        OutputFormat::Wildcard
    } else {
        OutputFormat::Cidr
    };

    // -----------------------------------------------------------------------
    // Diff mode — compare two files
    // -----------------------------------------------------------------------
    if cli.diff {
        let old = if let Some(ref copts) = csv_opts {
            read_netblocks_csv_from_file(
                &cli.input[0],
                copts,
                cli.input_range,
                cli.ignore_invalid,
                accept_v4,
                accept_v6,
                cli.max_length,
            )?
        } else {
            read_netblocks_from_file(
                &cli.input[0],
                cli.input_range,
                cli.ignore_invalid,
                accept_v4,
                accept_v6,
                cli.max_length,
                field_opts.as_ref(),
            )?
        };
        let new = if let Some(ref copts) = csv_opts {
            read_netblocks_csv_from_file(
                &cli.input[1],
                copts,
                cli.input_range,
                cli.ignore_invalid,
                accept_v4,
                accept_v6,
                cli.max_length,
            )?
        } else {
            read_netblocks_from_file(
                &cli.input[1],
                cli.input_range,
                cli.ignore_invalid,
                accept_v4,
                accept_v6,
                cli.max_length,
                field_opts.as_ref(),
            )?
        };

        let old_v4 = normalize_netblocks(old.v4);
        let new_v4 = normalize_netblocks(new.v4);
        let old_v6 = normalize_netblocks(old.v6);
        let new_v6 = normalize_netblocks(new.v6);

        let mut stdout = io::stdout().lock();

        if cli.json {
            // JSON diff: removed/added per family, with optional per-file stats.
            let (rem4, add4) = diff_collect(&old_v4, &new_v4);
            let (rem6, add6) = diff_collect(&old_v6, &new_v6);

            let mut members = vec![
                json_array_member("removed4", &format_blocks(&rem4, out_fmt), 1),
                json_array_member("added4", &format_blocks(&add4, out_fmt), 1),
                json_array_member("removed6", &format_blocks(&rem6, out_fmt), 1),
                json_array_member("added6", &format_blocks(&add6, out_fmt), 1),
            ];

            if cli.stats {
                let old_inner = vec![
                    json_str_member("file", &cli.input[0], 3),
                    json_num_member("lines", old.total_lines as u64, 3),
                    json_num_member("invalid", old.invalid_lines as u64, 3),
                    json_num_member("utf8_errors", old.utf8_invalid_lines as u64, 3),
                    json_num_member("ipv4", old_v4.len() as u64, 3),
                    json_num_member("ipv6", old_v6.len() as u64, 3),
                ];
                let new_inner = vec![
                    json_str_member("file", &cli.input[1], 3),
                    json_num_member("lines", new.total_lines as u64, 3),
                    json_num_member("invalid", new.invalid_lines as u64, 3),
                    json_num_member("utf8_errors", new.utf8_invalid_lines as u64, 3),
                    json_num_member("ipv4", new_v4.len() as u64, 3),
                    json_num_member("ipv6", new_v6.len() as u64, 3),
                ];
                let stats_inner = vec![
                    json_object_member("old", &old_inner, 2),
                    json_object_member("new", &new_inner, 2),
                ];
                members.push(json_object_member("stats", &stats_inner, 1));
            }

            let _ = write!(stdout, "{}", json_document(&members));
            return Ok(());
        }

        if accept_v4 {
            diff_sorted(&old_v4, &new_v4, out_fmt, &mut stdout);
        }
        if accept_v6 {
            diff_sorted(&old_v6, &new_v6, out_fmt, &mut stdout);
        }

        if cli.stats {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "--- {}", cli.input[0]);
            let _ = writeln!(
                stderr,
                "  Lines: {}  Invalid: {}  UTF-8 errors: {}  IPv4: {}  IPv6: {}",
                old.total_lines,
                old.invalid_lines,
                old.utf8_invalid_lines,
                old_v4.len(),
                old_v6.len()
            );
            let _ = writeln!(stderr, "+++ {}", cli.input[1]);
            let _ = writeln!(
                stderr,
                "  Lines: {}  Invalid: {}  UTF-8 errors: {}  IPv4: {}  IPv6: {}",
                new.total_lines,
                new.invalid_lines,
                new.utf8_invalid_lines,
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
    let parsed = if let Some(ref copts) = csv_opts {
        let input: Box<dyn io::Read> = if let Some(file) = cli.input.first() {
            Box::new(std::fs::File::open(file)?)
        } else {
            Box::new(io::stdin())
        };
        read_netblocks_csv(
            input,
            copts,
            cli.input_range,
            cli.ignore_invalid,
            accept_v4,
            accept_v6,
            cli.max_length,
        )?
    } else {
        let mut input: Box<dyn BufRead> = if let Some(file) = cli.input.first() {
            Box::new(io::BufReader::new(std::fs::File::open(file)?))
        } else {
            Box::new(io::BufReader::new(io::stdin()))
        };
        read_netblocks(
            &mut input,
            cli.input_range,
            cli.ignore_invalid,
            accept_v4,
            accept_v6,
            cli.max_length,
            field_opts.as_ref(),
        )?
    };

    let v4_before = parsed.v4.len();
    let v6_before = parsed.v6.len();

    let mut result_v4 = aggregate_netblocks(parsed.v4);
    let mut result_v6 = aggregate_netblocks(parsed.v6);

    // Apply --exclude if specified
    if let Some(ref excl_path) = cli.exclude {
        let excl = if let Some(ref copts) = csv_opts {
            read_netblocks_csv_from_file(
                excl_path,
                copts,
                cli.input_range,
                cli.ignore_invalid,
                accept_v4,
                accept_v6,
                cli.max_length,
            )?
        } else {
            read_netblocks_from_file(
                excl_path,
                cli.input_range,
                cli.ignore_invalid,
                accept_v4,
                accept_v6,
                cli.max_length,
                field_opts.as_ref(),
            )?
        };
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
        let isect = if let Some(ref copts) = csv_opts {
            read_netblocks_csv_from_file(
                isect_path,
                copts,
                cli.input_range,
                cli.ignore_invalid,
                accept_v4,
                accept_v6,
                cli.max_length,
            )?
        } else {
            read_netblocks_from_file(
                isect_path,
                cli.input_range,
                cli.ignore_invalid,
                accept_v4,
                accept_v6,
                cli.max_length,
                field_opts.as_ref(),
            )?
        };
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

    if cli.json {
        // JSON: results4 / results6 arrays, plus an optional separate stats object.
        let results4 = if accept_v4 { format_blocks(&result_v4, out_fmt) } else { Vec::new() };
        let results6 = if accept_v6 { format_blocks(&result_v6, out_fmt) } else { Vec::new() };

        let mut members = vec![
            json_array_member("results4", &results4, 1),
            json_array_member("results6", &results6, 1),
        ];

        if cli.stats {
            let mut stats_inner = vec![
                json_num_member("lines", parsed.total_lines as u64, 2),
                json_num_member("invalid", parsed.invalid_lines as u64, 2),
                json_num_member("utf8_errors", parsed.utf8_invalid_lines as u64, 2),
            ];
            if accept_v4 {
                stats_inner.push(json_family_stats(
                    "ipv4",
                    v4_before,
                    result_v4.len(),
                    &total_addresses_string(&result_v4),
                ));
            }
            if accept_v6 {
                stats_inner.push(json_family_stats(
                    "ipv6",
                    v6_before,
                    result_v6.len(),
                    &total_addresses_string(&result_v6),
                ));
            }
            members.push(json_object_member("stats", &stats_inner, 1));
        }

        let _ = write!(stdout, "{}", json_document(&members));
        return Ok(());
    }

    if accept_v4 {
        write_netblocks(&result_v4, out_fmt, &mut stdout);
    }
    if accept_v6 {
        write_netblocks(&result_v6, out_fmt, &mut stdout);
    }

    // Print statistics to stderr if requested
    if cli.stats {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "Lines: {}  Invalid: {}  UTF-8 errors: {}",
            parsed.total_lines, parsed.invalid_lines, parsed.utf8_invalid_lines
        );
        if accept_v4 {
            let _ = writeln!(
                stderr,
                "IPv4: {} -> {} aggregated ({} addresses)",
                v4_before,
                result_v4.len(),
                total_addresses_string(&result_v4)
            );
        }
        if accept_v6 {
            let _ = writeln!(
                stderr,
                "IPv6: {} -> {} aggregated ({} addresses)",
                v6_before,
                result_v6.len(),
                total_addresses_string(&result_v6)
            );
        }
    }

    Ok(())
}
