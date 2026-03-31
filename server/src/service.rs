use crate::config::Config;
use crate::kde;
use anyhow::{Context, Result, bail};
use linux_link_core::protocol::connection::ConnectionManager;
use linux_link_core::tailscale::{DiscoveryEvent, DiscoveryService, TailscaleClient};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

const HANDSHAKE_HELLO: &str = "LINUX_LINK_HELLO 1";
const HANDSHAKE_OK: &str = "LINUX_LINK_OK 1";

pub async fn run(config: Config) -> Result<()> {
    let pid_file = pid_file_path()?;
    write_pid_file(&pid_file)?;
    let _pid_guard = PidFileGuard { path: pid_file };

    let tailscale = TailscaleClient::new().context("failed to initialize Tailscale client")?;
    tailscale
        .wait_for_ready(Duration::from_secs(30))
        .await
        .context("tailscale is not ready")?;

    let self_ip = tailscale.get_self_ip().await?;
    tracing::info!("Tailscale online at {}", self_ip);

    let kde_service = kde::build_default_service().context("failed to initialize KDE service")?;
    let plugin_count = kde_service.registry.plugin_names().len();
    let trusted_count = kde_service
        .trust_store
        .as_ref()
        .map(|s| s.trusted_devices().len())
        .unwrap_or(0);
    tracing::info!(
        "KDE service initialized (plugins={}, trusted_devices={})",
        plugin_count,
        trusted_count
    );

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
                    Ok((stream, peer_addr)) => {
                        tracing::info!("Incoming connection from {}", peer_addr);
                        tokio::spawn(async move {
                            if let Err(error) = handle_connection(stream).await {
                                tracing::warn!("connection handler failed: {}", error);
                            }
                        });
                    }
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

pub async fn stop() -> Result<()> {
    let pid_file = pid_file_path()?;
    if !pid_file.exists() {
        println!("No running Linux Link server found");
        return Ok(());
    }

    let raw_pid = std::fs::read_to_string(&pid_file)
        .with_context(|| format!("failed reading {}", pid_file.display()))?;
    let pid: i32 = raw_pid
        .trim()
        .parse()
        .context("invalid PID file contents")?;

    let status = tokio::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .await
        .context("failed to execute kill command")?;

    if !status.success() {
        bail!("failed to stop process {}", pid);
    }

    let _ = std::fs::remove_file(&pid_file);
    println!("Stop signal sent to pid {}", pid);
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

pub async fn watch_peers(interval_secs: u64) -> Result<()> {
    let tailscale = TailscaleClient::new().context("failed to initialize Tailscale client")?;
    tailscale
        .wait_for_ready(Duration::from_secs(30))
        .await
        .context("tailscale is not ready")?;

    let discovery = DiscoveryService::new(tailscale);
    let mut rx = discovery.subscribe();
    let poll = Duration::from_secs(interval_secs.max(1));

    tokio::spawn(async move {
        discovery.run(poll).await;
    });

    println!(
        "Watching peers (interval={}s). Press Ctrl+C to stop.",
        poll.as_secs()
    );

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(DiscoveryEvent::PeerDiscovered(peer)) => {
                        let ip = peer.ips.first().map_or("n/a", |v| v.as_str());
                        println!("ONLINE  {}  {}", peer.name, ip);
                    }
                    Ok(DiscoveryEvent::PeerOffline(name)) => {
                        println!("OFFLINE {}", name);
                    }
                    Ok(DiscoveryEvent::ServiceReady) => {
                        println!("READY");
                    }
                    Err(error) => {
                        tracing::warn!("Discovery channel error: {}", error);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("Stopped watching peers");
                break;
            }
        }
    }

    Ok(())
}

pub async fn connect_peer(peer: String, port: u16) -> Result<()> {
    let tailscale = TailscaleClient::new().context("failed to initialize Tailscale client")?;
    let address = resolve_peer_address(&tailscale, &peer).await?;

    let manager = ConnectionManager::new(Duration::from_secs(10));
    let mut stream = manager
        .connect(&address, port)
        .await
        .with_context(|| format!("failed to connect to {}:{}", address, port))?;

    stream
        .write_all(format!("{}\n", HANDSHAKE_HELLO).as_bytes())
        .await
        .context("failed to write handshake")?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    timeout(Duration::from_secs(5), reader.read_line(&mut response))
        .await
        .context("handshake timeout")?
        .context("failed to read handshake response")?;

    if response.trim() != HANDSHAKE_OK {
        bail!("handshake failed: {}", response.trim());
    }

    println!("Connected to {}:{} ({})", address, port, HANDSHAKE_OK);
    Ok(())
}

pub async fn print_capabilities() -> Result<()> {
    let kde_service = kde::build_default_service().context("failed to initialize KDE service")?;
    let plugin_names = kde_service.registry.plugin_names();
    let (incoming, outgoing) = kde_service.registry.capability_sets();
    let trusted = kde_service
        .trust_store
        .as_ref()
        .map(|s| s.trusted_devices())
        .unwrap_or_default();

    println!(
        "Plugins ({}): {}",
        plugin_names.len(),
        plugin_names.join(", ")
    );
    println!("Incoming capabilities ({}):", incoming.len());
    for cap in incoming {
        println!("  - {}", cap);
    }

    println!("Outgoing capabilities ({}):", outgoing.len());
    for cap in outgoing {
        println!("  - {}", cap);
    }

    println!("Trusted devices ({}):", trusted.len());
    for device in trusted {
        println!("  - {}", device);
    }

    Ok(())
}

pub async fn pair(pin: Option<String>) -> Result<()> {
    let pin_value = match pin {
        Some(value) => {
            if !is_valid_pin(&value) {
                bail!("PIN must be exactly 6 numeric digits");
            }
            value
        }
        None => generate_pin(),
    };

    let path = pair_pin_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(&path, format!("{}\n", pin_value))
        .with_context(|| format!("failed to write {}", path.display()))?;

    println!("Pairing PIN: {}", pin_value);
    println!("Stored at {}", path.display());
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

async fn handle_connection(stream: TcpStream) -> Result<()> {
    let (reader_half, mut writer_half) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();

    let bytes = timeout(Duration::from_secs(8), reader.read_line(&mut line))
        .await
        .context("connection handshake timeout")?
        .context("failed to read incoming handshake")?;

    if bytes == 0 {
        bail!("connection closed before handshake")
    }

    if line.trim() != HANDSHAKE_HELLO {
        writer_half
            .write_all(b"LINUX_LINK_ERR 1\n")
            .await
            .context("failed writing error handshake")?;
        bail!("invalid handshake preface")
    }

    writer_half
        .write_all(format!("{}\n", HANDSHAKE_OK).as_bytes())
        .await
        .context("failed writing handshake ack")?;
    Ok(())
}

async fn resolve_peer_address(client: &TailscaleClient, peer_hint: &str) -> Result<String> {
    if peer_hint.parse::<std::net::IpAddr>().is_ok() {
        return Ok(peer_hint.to_string());
    }

    let peers = client.get_peers().await?;

    for peer in peers {
        if (peer.name == peer_hint
            || peer.dns_name == peer_hint
            || peer
                .dns_name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(peer_hint)
            || peer.ips.iter().any(|ip| ip == peer_hint))
            && let Some(ip) = peer.ips.first()
        {
            return Ok(ip.clone());
        }
    }

    bail!("peer not found on tailnet: {}", peer_hint)
}

fn pid_file_path() -> Result<PathBuf> {
    Ok(state_dir()?.join("server.pid"))
}

fn pair_pin_path() -> Result<PathBuf> {
    Ok(state_dir()?.join("pairing.pin"))
}

fn state_dir() -> Result<PathBuf> {
    let base = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .context("unable to determine local state directory")?;
    Ok(base.join("linux-link"))
}

fn write_pid_file(path: &PathBuf) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(path, format!("{}\n", std::process::id()))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn is_valid_pin(pin: &str) -> bool {
    pin.len() == 6 && pin.chars().all(|c| c.is_ascii_digit())
}

fn generate_pin() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{:06}", nanos % 1_000_000)
}

struct PidFileGuard {
    path: PathBuf,
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
