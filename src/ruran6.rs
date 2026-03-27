use rand::RngExt;
use std::env;
use std::net::Ipv6Addr;

fn main() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <number_of_addresses>", args[0]);
        std::process::exit(1);
    }

    let count: usize = args[1].parse().expect("Please provide a valid number");
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
            let plen = rng.random_range(32..=128);
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
                // Pick a deeper prefix length
                let child_plen = rng.random_range((plen + 1)..=128);
                let bits_to_generate = child_plen - plen;

                // Generate random bits for the child sub-space
                let mask =
                    if bits_to_generate == 128 { !0 } else { (1u128 << bits_to_generate) - 1 };
                let val = rng.random::<u128>() & mask;
                let child_net = net | (val << (128 - child_plen));

                history.push((child_net, child_plen));
                let _ = writeln!(stdout, "{}/{}", Ipv6Addr::from(child_net), child_plen);
            } else {
                // It's a /128, just output a duplicate (will also be swallowed)
                history.push((net, plen));
                let _ = writeln!(stdout, "{}/{}", Ipv6Addr::from(net), plen);
            }
        }
    }
}
