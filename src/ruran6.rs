use rand::Rng;
use std::env;
use std::net::Ipv6Addr;

fn generate_random_ipv6() -> Ipv6Addr {
    let mut rng = rand::rng();
    Ipv6Addr::new(
        rng.random(),
        rng.random(),
        rng.random(),
        rng.random(),
        rng.random(),
        rng.random(),
        rng.random(),
        rng.random(),
    )
}

fn generate_random_ipv6_netblock() -> (Ipv6Addr, u8) {
    let mut rng = rand::rng();
    let prefix_len = rng.random_range(32..=127);
    let mask = (!0u128) << (128 - prefix_len);
    let base_address = rng.random::<u128>() & mask;
    let ip = Ipv6Addr::from(base_address);
    (ip, prefix_len)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <number_of_addresses>", args[0]);
        std::process::exit(1);
    }

    let count: usize = args[1].parse().expect("Please provide a valid number");

    let half_count = count / 2;

    for _ in 0..half_count {
        println!("{}/128", generate_random_ipv6());
    }

    for _ in 0..half_count {
        let (ip, prefix_len) = generate_random_ipv6_netblock();
        println!("{}/{}", ip, prefix_len);
    }
}
