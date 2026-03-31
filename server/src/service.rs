use crate::config::Config;
use anyhow::{Context, Result};

pub async fn run(config: Config) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{}", config.control_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;

    tracing::info!("Control listener ready on {}", bind_addr);
    tracing::info!("Press Ctrl+C to stop");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((_stream, peer_addr)) => tracing::info!("Incoming connection from {}", peer_addr),
                    Err(error) => tracing::warn!("Accept error: {}", error),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutdown signal received");
                break;
            }
        }
    }

    Ok(())
}
