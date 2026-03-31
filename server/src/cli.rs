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
    /// Print local tailscale status
    Status,
    /// List peers currently visible on the tailnet
    List,
}
