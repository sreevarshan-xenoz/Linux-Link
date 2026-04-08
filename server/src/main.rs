//! Linux Link Server
//!
//! Background daemon for remote desktop access over Tailscale.

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cli;
mod config;
mod input_injector;
mod kde;
mod plugins;
mod service;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("Linux Link Server starting");
    let config = config::Config::load()?;

    match cli.command.unwrap_or(cli::Commands::Start) {
        cli::Commands::Start => service::run(config).await,
        cli::Commands::Stop => service::stop().await,
        cli::Commands::Status => service::print_status().await,
        cli::Commands::List => service::list_peers().await,
        cli::Commands::Watch { interval } => service::watch_peers(interval).await,
        cli::Commands::Capabilities => service::print_capabilities().await,
        cli::Commands::Connect { peer, port } => service::connect_peer(peer, port).await,
        cli::Commands::Pair { pin } => service::pair(pin).await,
    }
}
