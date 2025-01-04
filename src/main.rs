mod arp_listener;
mod tarpitter;
mod tcp_listener;

mod cli;

use tracing::info;
use tracing_subscriber::EnvFilter;

fn init_tracing(log_level: &str) {
    let filter = EnvFilter::try_new(log_level).unwrap_or_else(|_| {
        eprintln!("Invalid log level: {log_level}. Defaulting to 'info'.");
        EnvFilter::new("info")
    });

    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn main() {
    let args = cli::parse();

    init_tracing(&args.log_level);

    info!(
        "Starting tarpitting in {} mode",
        if args.passive_mode {
            "passive"
        } else {
            "active"
        }
    );
    info!("Interface: {}", args.interface_name);

    tarpitter::start_tarpitting(args.passive_mode, &args.interface_name);
}
