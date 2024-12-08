mod arp_listener;
mod tarpitter;
mod tcp_listener;

use std::env;
use std::process;

fn parse_arguments() -> (bool, String) {
    let args: Vec<String> = env::args().collect();

    let passive_mode = args.contains(&"--passive".to_string()) || args.contains(&"-p".to_string());

    let interface_index = args.iter().position(|arg| arg == "-i");
    let interface_name = match interface_index {
        Some(index) => {
            if let Some(name) = args.get(index + 1) {
                name.clone()
            } else {
                eprintln!("Error: No value provided for '-i' flag.");
                process::exit(1);
            }
        }
        None => {
            eprintln!("Error: The '-i <interface_name>' flag is mandatory.");
            process::exit(1);
        }
    };

    (passive_mode, interface_name)
}

fn main() {
    let (passive_mode, interface_name) = parse_arguments();

    tarpitter::start_tarpitting(passive_mode, &interface_name);
}
