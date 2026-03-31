//! Linux Link Server
//!
//! Background daemon for remote desktop access over Tailscale.

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cli;
mod config;
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
        cli::Commands::Status => service::print_status().await,
        cli::Commands::List => service::list_peers().await,
    }
}
