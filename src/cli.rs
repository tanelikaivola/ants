use clap::Parser;

/// ANTS, the TCP tarpitter
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Enable passive mode
    #[arg(short = 'p', long = "passive")]
    pub passive_mode: bool,

    /// Network interface name
    #[arg(short = 'i', long = "interface", required = true)]
    pub interface_name: String,

    /// Log level
    #[arg(long = "log-level", default_value = "info")]
    pub log_level: String,
}

pub fn parse() -> Args {
    Args::parse()
}
