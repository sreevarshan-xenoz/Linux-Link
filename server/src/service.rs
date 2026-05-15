use crate::config::Config;
use crate::input_injector::InputInjector;
use crate::kde;
use crate::notification_monitor::{start_notification_monitor, ForwardedNotification};
use anyhow::{Context, Result, bail};
use linux_link_core::protocol::connection::ConnectionManager;
use linux_link_core::protocol::kdeconnect::{NetworkPacket, PluginRegistry, TcpDeviceSender};
use linux_link_core::protocol::{HANDSHAKE_HELLO, HANDSHAKE_OK};
use linux_link_core::streaming::StreamingServer;
use linux_link_core::streaming::input_packet::InputPacket;
use linux_link_core::streaming::transport::{CertManager, StreamTransportConfig};
use linux_link_core::tailscale::{DiscoveryEvent, DiscoveryService, TailscaleClient};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Active KDE Connect client connections for broadcasting notifications.
static ACTIVE_CLIENTS: LazyLock<Mutex<Vec<TcpDeviceSender<OwnedWriteHalf>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

pub async fn run(config: Config) -> Result<()> {
    let pid_file = pid_file_path()?;
    write_pid_file(&pid_file)?;
    let _pid_guard = PidFileGuard { path: pid_file };

    let tailscale = TailscaleClient::new().context("failed to initialize Tailscale client")?;
    let tailscale_ready = match tailscale.wait_for_ready(Duration::from_secs(5)).await {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("Tailscale not ready: {e}");
            false
        }
    };

    let mut local_ips = linux_link_core::tailscale::lan::get_local_ips().await;
    if tailscale_ready {
        if let Ok(ip) = tailscale.get_self_ip().await {
            tracing::info!("Tailscale online at {}", ip);
            if !local_ips.contains(&ip) {
                local_ips.push(ip);
            }
        }
    }

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

    // Register mDNS service for LAN discovery
    let lan_discovery = linux_link_core::tailscale::lan::LanDiscoveryService::new()?;
    let host_name = kde_service
        .identity
        .as_ref()
        .map(|i| i.device_name.clone())
        .unwrap_or_else(|| "linux-link-host".to_string());

    lan_discovery.register_service(&host_name, config.control_port, local_ips)?;

    let discovery = DiscoveryService::new(tailscale.clone());
    let mut discovery_rx = discovery.subscribe();
    tokio::spawn(async move {
        discovery.run(Duration::from_secs(10)).await;
    });

    // Also run LAN discovery browser to detect other Linux Link servers
    let mut lan_rx = lan_discovery.subscribe();
    tokio::spawn(async move {
        lan_discovery.run(Duration::from_secs(30)).await;
    });

    let bind_addr = format!("0.0.0.0:{}", config.control_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;

    tracing::info!("Control listener ready on {}", bind_addr);

    // F19: Start notification monitor for forwarding PC notifications to Android clients
    let notification_tx = start_notification_monitor();
    // Spawn a task that broadcasts captured notifications to all connected clients
    {
        let mut notify_rx = notification_tx.subscribe();
        tokio::spawn(async move {
            tracing::info!("Notification broadcast task started");
            loop {
                match notify_rx.recv().await {
                    Ok(notification) => {
                        let packet_json = notification.to_kdeconnect_payload();
                        match NetworkPacket::from_wire(&packet_json) {
                            Ok(packet) => {
                                let mut clients = ACTIVE_CLIENTS.lock().await;
                                let mut alive = Vec::new();
                                for sender in clients.iter() {
                                    match sender.send_packet(&packet).await {
                                        Ok(()) => alive.push(sender.clone()),
                                        Err(e) => {
                                            tracing::debug!("Removing dead client from broadcast: {e}");
                                        }
                                    }
                                }
                                *clients = alive;
                                if clients.len() > 0 {
                                    tracing::debug!("Forwarded notification to {} client(s)", clients.len());
                                }
                            }
                            Err(e) => tracing::warn!("Failed to parse notification packet: {e}"),
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::info!("Notification broadcast channel closed");
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Notification broadcast lagged by {n} messages");
                    }
                }
            }
        });
    }

    // Start the QUIC streaming server in the background for real-time screen control.
    //
    // This runs as a tokio task and accepts one QUIC connection. Input events
    // received from the client over QUIC are forwarded to the InputInjector.
    {
        let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<InputPacket>(128);

        let streaming_config = config.video_quality.to_streaming_config();
        let transport_config = StreamTransportConfig {
            address: format!("0.0.0.0:{}", config.streaming_port)
                .parse()
                .unwrap(),
            ..StreamTransportConfig::default()
        };
        let cert_manager = Arc::new(CertManager::new().expect("Failed to create CertManager"));

        let mut streaming_server =
            StreamingServer::new(streaming_config, transport_config, cert_manager);
        streaming_server.set_input_channel(input_tx);

        tokio::spawn(async move {
            tracing::info!(
                "Streaming server starting on port {}",
                config.streaming_port
            );
            if let Err(e) = streaming_server.run().await {
                tracing::error!("Streaming server error: {e}");
            }
        });

        // Spawn input injection task — receives InputPacket from the QUIC
        // streaming channel and injects them into the host system.
        tokio::spawn(async move {
            tracing::info!("Input injection task started");
            let mut injector = match InputInjector::new() {
                Ok(inj) => inj,
                Err(e) => {
                    tracing::error!("Failed to create InputInjector: {e}");
                    return;
                }
            };

            while let Some(packet) = input_rx.recv().await {
                if let Err(e) = handle_input_packet(&mut injector, packet) {
                    tracing::warn!("Input injection error: {e}");
                }
            }

            tracing::info!("Input injection task ended");
        });
    }

    tracing::info!("Press Ctrl+C to stop");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer_addr)) => {
                        tracing::info!("Incoming connection from {}", peer_addr);
                        let identity_packet = kde_service.identity_packet().clone();
                        let registry: Arc<PluginRegistry> =
                            Arc::new(kde_service.registry.clone_for_dispatch());
                        tokio::spawn(async move {
                            if let Err(error) =
                                handle_connection_with_kde(stream, identity_packet, &registry).await
                            {
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
            lan_event = lan_rx.recv() => {
                match lan_event {
                    Ok(linux_link_core::tailscale::lan::LanEvent::PeerDiscovered(peer)) => {
                        handle_discovery_event(DiscoveryEvent::PeerDiscovered(peer));
                    }
                    Ok(linux_link_core::tailscale::lan::LanEvent::PeerOffline(name)) => {
                        handle_discovery_event(DiscoveryEvent::PeerOffline(name));
                    }
                    _ => {}
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
    let _stream = manager
        .connect(&address, port)
        .await
        .with_context(|| format!("failed to connect to {}:{}", address, port))?;

    println!("Connected to {}:{} ({})", address, port, HANDSHAKE_OK);
    Ok(())
}

/// Handle a TCP connection with KDE Connect protocol support.
///
/// After the initial handshake, this sends our identity packet and then
/// enters a loop reading JSON packets and dispatching them to plugins.
async fn handle_connection_with_kde(
    stream: TcpStream,
    identity_packet: Option<NetworkPacket>,
    registry: &Arc<PluginRegistry>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let peer_addr = stream.peer_addr().ok();
    tracing::info!("Handling new connection from {:?}", peer_addr);

    let (reader_half, writer_half) = stream.into_split();
    let mut reader = BufReader::new(reader_half);

    // Wrap writer in Arc<Mutex> so both handshake and TcpDeviceSender can use it
    let writer = Arc::new(Mutex::new(writer_half));

    // Step 1: LINUX_LINK_HELLO handshake
    let mut line = String::new();
    let bytes = timeout(Duration::from_secs(8), reader.read_line(&mut line))
        .await
        .context("connection handshake timeout")?
        .context("failed to read incoming handshake")?;

    if bytes == 0 {
        bail!("connection closed before handshake")
    }

    tracing::debug!("Received handshake line from {:?}: {:?}", peer_addr, line.trim());

    if line.trim() != HANDSHAKE_HELLO {
        tracing::warn!("Invalid handshake preface from {:?}: {:?}", peer_addr, line.trim());
        let mut w = writer.lock().await;
        w.write_all(b"LINUX_LINK_ERR 1\n")
            .await
            .context("failed writing error handshake")?;
        bail!("invalid handshake preface")
    }

    // Step 1.5: Send HANDSHAKE_OK back to client
    {
        tracing::info!("Handshake successful for {:?}, sending HANDSHAKE_OK", peer_addr);
        let mut w = writer.lock().await;
        w.write_all(format!("{}\n", HANDSHAKE_OK).as_bytes())
            .await
            .context("failed writing handshake OK")?;
        w.flush().await?;
    }

    // Step 2: Send identity packet
    if let Some(ref identity) = identity_packet {
        let mut w = writer.lock().await;
        let wire_bytes = identity.to_wire()?;
        w.write_all(&wire_bytes).await?;
        w.flush().await?;
        drop(w);
        tracing::debug!("Sent identity packet to peer");
    }

    // Step 3: Enter KDE Connect packet loop
    let sender = TcpDeviceSender::from_arc(writer);
    let sender_ref = &sender;

    // Register this client for notification broadcasting.
    // Dead writers are automatically pruned on send failure.
    {
        let mut clients = ACTIVE_CLIENTS.lock().await;
        clients.push(sender.clone());
    }

    loop {
        let mut line = String::new();
        let read_result = timeout(Duration::from_secs(30), reader.read_line(&mut line)).await;

        match read_result {
            Ok(Ok(0)) => {
                // Connection closed
                tracing::debug!("Peer disconnected");
                break;
            }
            Ok(Ok(_)) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                match NetworkPacket::from_wire(trimmed) {
                    Ok(packet) => {
                        tracing::debug!("Received packet: type={}", packet.packet_type);
                        if let Err(e) = registry.dispatch_packet(&packet, sender_ref).await {
                            tracing::warn!("Packet dispatch failed: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Invalid packet: {}", e);
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::warn!("Read error: {}", e);
                break;
            }
            Err(_) => {
                // Timeout - peer is idle
                tracing::debug!("Peer idle - connection still alive");
            }
        }
    }

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

/// Handle an `InputPacket` received over the QUIC streaming channel by injecting
/// it into the host system via the `InputInjector`.
///
/// Delegates all packet variants to `InputInjector::handle_input_packet()`
/// which handles mouse, keyboard, gamepad, and scroll events uniformly
/// across both enigo and uinput backends.
fn handle_input_packet(injector: &mut InputInjector, packet: InputPacket) -> Result<()> {
    injector.handle_input_packet(&packet)?;
    Ok(())
}

struct PidFileGuard {
    path: PathBuf,
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
