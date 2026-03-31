//! Linux Link Server
//!
//! Background daemon for remote desktop access over Tailscale.

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod service;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("Linux Link Server starting");
    let config = config::Config::load()?;
    service::run(config).await
}
