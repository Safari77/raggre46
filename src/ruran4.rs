use rand::Rng;
use std::env;
use std::net::Ipv4Addr;

fn generate_random_ipv4() -> Ipv4Addr {
    let mut rng = rand::rng();
    Ipv4Addr::new(rng.random(), rng.random(), rng.random(), rng.random())
}

fn generate_random_ipv4_netblock() -> (Ipv4Addr, u8) {
    let mut rng = rand::rng();
    let prefix_len = rng.random_range(16..=31);
    let mask = (!0u32) << (32 - prefix_len);
    let base_address = rng.random::<u32>() & mask;
    let ip = Ipv4Addr::from(base_address);
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
        println!("{}/32", generate_random_ipv4());
    }

    for _ in 0..half_count {
        let (ip, prefix_len) = generate_random_ipv4_netblock();
        println!("{}/{}", ip, prefix_len);
    }
}
