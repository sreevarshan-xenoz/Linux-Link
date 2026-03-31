use crate::config::Config;
use anyhow::{Context, Result};
use linux_link_core::tailscale::{DiscoveryEvent, DiscoveryService, TailscaleClient};
use std::time::Duration;

pub async fn run(config: Config) -> Result<()> {
    let tailscale = TailscaleClient::new().context("failed to initialize Tailscale client")?;
    tailscale
        .wait_for_ready(Duration::from_secs(30))
        .await
        .context("tailscale is not ready")?;

    let self_ip = tailscale.get_self_ip().await?;
    tracing::info!("Tailscale online at {}", self_ip);

    let discovery = DiscoveryService::new(tailscale.clone());
    let mut discovery_rx = discovery.subscribe();
    tokio::spawn(async move {
        discovery.run(Duration::from_secs(10)).await;
    });

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
            event = discovery_rx.recv() => {
                match event {
                    Ok(event) => handle_discovery_event(event),
                    Err(error) => tracing::warn!("Discovery channel error: {}", error),
                }
            }
        }
    }

    Ok(())
}

pub async fn print_status() -> Result<()> {
    let tailscale = TailscaleClient::new().context("failed to initialize Tailscale client")?;
    let status = tailscale.status_text().await?;
    println!("{}", status);
    Ok(())
}

pub async fn list_peers() -> Result<()> {
    let tailscale = TailscaleClient::new().context("failed to initialize Tailscale client")?;
    let peers = tailscale.get_peers().await?;

    if peers.is_empty() {
        println!("No peers found");
        return Ok(());
    }

    for peer in peers {
        let status = if peer.online { "online" } else { "offline" };
        let ip = peer
            .ips
            .first()
            .cloned()
            .unwrap_or_else(|| "n/a".to_string());
        println!("{} [{}] {}", peer.name, status, ip);
    }

    Ok(())
}

fn handle_discovery_event(event: DiscoveryEvent) {
    match event {
        DiscoveryEvent::PeerDiscovered(peer) => {
            tracing::info!("Peer online: {} ({})", peer.name, peer.ips.join(", "));
        }
        DiscoveryEvent::PeerOffline(name) => {
            tracing::info!("Peer offline: {}", name);
        }
        DiscoveryEvent::ServiceReady => {
            tracing::info!("Discovery service ready");
        }
    }
}
