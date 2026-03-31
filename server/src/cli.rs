use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "linux-link")]
#[command(about = "Linux Link - secure remote desktop over Tailscale")]
pub struct Cli {
    #[arg(short, long)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start the server daemon
    Start,
    /// Stop a running server process started with `linux-link start`
    Stop,
    /// Print local tailscale status
    Status,
    /// List peers currently visible on the tailnet
    List,
    /// Continuously watch peer discovery events
    Watch {
        /// Poll interval in seconds
        #[arg(short, long, default_value_t = 10)]
        interval: u64,
    },
    /// Show configured KDE Connect capability sets
    Capabilities,
    /// Connect to a peer and perform a basic control-channel handshake
    Connect {
        /// Peer hostname, MagicDNS name, or Tailscale IP
        peer: String,
        /// Control port to connect to
        #[arg(short, long, default_value_t = linux_link_core::DEFAULT_CONTROL_PORT)]
        port: u16,
    },
    /// Set or generate a temporary pairing PIN
    Pair {
        /// Optional 6-digit PIN
        pin: Option<String>,
    },
}
