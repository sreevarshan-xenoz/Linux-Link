use crate::config::Config;
use crate::input_injector::InputInjector;
use crate::kde;
use crate::notification_monitor::start_notification_monitor;
use uuid;
use anyhow::{Context, Result, bail};
use linux_link_core::protocol::connection::ConnectionManager;
use linux_link_core::protocol::kdeconnect::{
    DeviceIdentity, DeviceSender, NetworkPacket, PluginRegistry, TcpDeviceSender,
};
use linux_link_core::protocol::{HANDSHAKE_HELLO, HANDSHAKE_OK};
use linux_link_core::protocol::v2::{ALPN_V2, IdentityPacketV2};
use linux_link_core::streaming::StreamingServer;
use linux_link_core::streaming::input_packet::InputPacket;
use linux_link_core::streaming::transport::{CertManager, StreamTransportConfig};
use linux_link_core::tailscale::{DiscoveryEvent, DiscoveryService, TailscaleClient};
use crate::v2_multiplexer::handle_v2_session;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Active KDE Connect client connections for broadcasting notifications.
pub static ACTIVE_CLIENTS: LazyLock<Mutex<Vec<Arc<dyn DeviceSender>>>> =
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
    if tailscale_ready && let Ok(ip) = tailscale.get_self_ip().await {
        tracing::info!("Tailscale online at {}", ip);
        if !local_ips.contains(&ip) {
            local_ips.push(ip);
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

    // Prepare shared state for v2 multiplexer and v1 streaming
    let cert_manager = Arc::new(CertManager::new().expect("Failed to create CertManager"));
    let registry = Arc::new(kde_service.registry.clone_for_dispatch());
    let local_v2_identity = IdentityPacketV2 {
        device_id: kde_service.identity.as_ref().map(|i| i.device_id.clone()).unwrap_or_default(),
        device_name: host_name.clone(),
        min_version: 2,
        max_version: 2,
        capabilities: registry.plugin_names(),
    };

    let bind_addr = format!("0.0.0.0:{}", config.control_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;

    tracing::info!("Control listener ready on {}", bind_addr);

    // QUIC Multiplexer (v2) and Streaming (v1) listener
    let streaming_port = config.streaming_port;
    let quic_addr = format!("0.0.0.0:{}", streaming_port).parse::<std::net::SocketAddr>().unwrap();
    let alpns = vec![
        ALPN_V2.to_vec(),
        b"linux-link-stream".to_vec(),
    ];
    let server_config = cert_manager.server_config(alpns).expect("Failed to create server config");
    let quic_endpoint = quinn::Endpoint::server(server_config, quic_addr).expect("Failed to bind QUIC endpoint");
    tracing::info!("Unified QUIC listener ready on {}", quic_addr);

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
                                        Ok(()) => alive.push(Arc::clone(sender)),
                                        Err(e) => {
                                            tracing::debug!("Removing dead client from broadcast: {e}");
                                        }
                                    }
                                }
                                *clients = alive;
                                if !clients.is_empty() {
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

    // Input injection channel shared between v1 and v2
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<InputPacket>(128);
    let streaming_config = config.video_quality.to_streaming_config();

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

    tracing::info!("Press Ctrl+C to stop");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer_addr)) => {
                        tracing::info!("Incoming v1 TCP connection from {}", peer_addr);
                        let identity_packet = kde_service.identity_packet().clone();
                        let registry_clone = Arc::clone(&registry);
                        tokio::spawn(async move {
                            if let Err(error) =
                                handle_connection_with_kde(stream, identity_packet, &registry_clone).await
                            {
                                tracing::warn!("connection handler failed: {}", error);
                            }
                        });
                    }
                    Err(error) => tracing::warn!("Accept error: {}", error),
                }
            }
            quic_incoming = quic_endpoint.accept() => {
                if let Some(incoming) = quic_incoming {
                    let registry_clone = Arc::clone(&registry);
                    let cert_manager_clone = Arc::clone(&cert_manager);
                    let local_v2_identity = local_v2_identity.clone();
                    let streaming_config = streaming_config.clone();
                    let input_tx = input_tx.clone();

                    tokio::spawn(async move {
                        let conn = match incoming.await {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::warn!("QUIC connection failed: {}", e);
                                return;
                            }
                        };

                        let alpn = {
                            let handshake_data = conn.handshake_data();
                            handshake_data.as_ref()
                                .and_then(|any| any.downcast_ref::<quinn::crypto::rustls::HandshakeData>())
                                .and_then(|h| h.protocol.clone())
                        };

                        match alpn.as_deref() {
                            Some(b"linux-link-v2") => {
                                if let Err(e) = handle_v2_session(conn, local_v2_identity, registry_clone).await {
                                    tracing::error!("v2 session error: {}", e);
                                }
                            }
                            Some(b"linux-link-stream") => {
                                let mut streaming_server = StreamingServer::new(
                                    streaming_config,
                                    StreamTransportConfig::default(),
                                    cert_manager_clone
                                );
                                streaming_server.set_input_channel(input_tx);
                                if let Err(e) = streaming_server.run_on_connection(conn).await {
                                    tracing::error!("v1 streaming session error: {}", e);
                                }
                            }
                            _ => {
                                tracing::warn!("Unknown ALPN on QUIC port: {:?}", alpn.map(|a| String::from_utf8_lossy(&a).into_owned()));
                            }
                        }
                    });
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
                    Ok(linux_link_core::tailscale::lan::LanEvent::DiscoveryError { method, reason }) => {
                        handle_discovery_event(DiscoveryEvent::DiscoveryError { method, reason });
                    }
                    Ok(linux_link_core::tailscale::lan::LanEvent::ServiceReady) => {
                        handle_discovery_event(DiscoveryEvent::ServiceReady);
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
                    Ok(DiscoveryEvent::DiscoveryError { method, reason }) => {
                        println!("ERROR   {} - {}", method, reason);
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

pub async fn connect_peer(peer: String, port: u16, identity: &DeviceIdentity) -> Result<()> {
    let tailscale = TailscaleClient::new().context("failed to initialize Tailscale client")?;
    let address = resolve_peer_address(&tailscale, &peer).await?;

    let manager = ConnectionManager::new(Duration::from_secs(10));
    let _stream = manager
        .connect(&address, port, identity)
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
    use tracing::Instrument;

    let peer_addr = stream.peer_addr().ok();
    let conn_id = uuid::Uuid::new_v4().to_string();
    let session_id = uuid::Uuid::new_v4().to_string(); // In v1, session == connection for now
    
    let conn_span = tracing::info_span!(
        "conn",
        id = %conn_id,
        session = %session_id,
        peer = ?peer_addr,
        transport = "tcp",
        proto = %linux_link_core::protocol::PROTOCOL_VERSION
    );

    async move {
        tracing::info!("Handling new connection");

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
            tracing::info!("Connection closed by peer before handshake");
            return Ok(());
        }

        tracing::debug!("Received handshake line: {:?}", line.trim());

        if line.trim() != HANDSHAKE_HELLO {
            tracing::warn!("Invalid handshake preface: {:?}", line.trim());
            let mut w = writer.lock().await;
            w.write_all(b"LINUX_LINK_ERR 1\n")
                .await
                .context("failed writing error handshake")?;
            bail!("invalid handshake preface")
        }

        // Step 1.5: Send HANDSHAKE_OK back to client
        {
            tracing::info!("Handshake successful, sending HANDSHAKE_OK");
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
            tracing::debug!("Sent local identity packet");
        }

        // Step 3: Enter KDE Connect packet loop
        let device_id = peer_addr
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let sender: Arc<dyn DeviceSender> = Arc::new(TcpDeviceSender::from_arc(writer, device_id.clone()));
        let sender_ref = &*sender;

        // Update span with device_id
        tracing::Span::current().record("peer", &device_id);

        // Register this client for notification broadcasting
        {
            let mut clients = ACTIVE_CLIENTS.lock().await;
            clients.push(Arc::clone(&sender));
            tracing::debug!(active_clients = clients.len(), "Client registered for broadcasts");
        }

        tracing::info!("Entering main packet loop");
        loop {
            let mut line = String::new();
            let read_result = timeout(Duration::from_secs(60), reader.read_line(&mut line)).await;

            match read_result {
                Ok(Ok(0)) => {
                    tracing::info!("Peer disconnected");
                    break;
                }
                Ok(Ok(_)) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    match NetworkPacket::from_wire(trimmed) {
                        Ok(packet) => {
                            let packet_type = packet.packet_type.clone();
                            let packet_span = tracing::debug_span!("packet", type = %packet_type);
                            async {
                                tracing::debug!("Processing packet");
                                if let Err(e) = registry.dispatch_packet(&packet, sender_ref).await {
                                    tracing::warn!("Packet dispatch failed: {}", e);
                                }
                            }.instrument(packet_span).await;
                        }
                        Err(e) => {
                            tracing::warn!("Malformed packet received: {}", e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::error!("Read error in control channel: {}", e);
                    break;
                }
                Err(_) => {
                    tracing::debug!("Peer idle - connection still alive");
                }
            }
        }

        // Cleanup
        {
            let conn_id_to_remove = sender.connection_id().to_string();
            let mut clients = ACTIVE_CLIENTS.lock().await;
            clients.retain(|c| c.connection_id() != conn_id_to_remove);
            tracing::info!(active_clients = clients.len(), "Client disconnected, removed from registry");
        }

        Ok(())
    }
    .instrument(conn_span)
    .await
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
            tracing::info!(peer = %peer.name, ips = ?peer.ips, "Peer came online");
        }
        DiscoveryEvent::PeerOffline(name) => {
            tracing::info!(peer = %name, "Peer went offline");
        }
        DiscoveryEvent::ServiceReady => {
            tracing::info!("Discovery service ready");
        }
        DiscoveryEvent::DiscoveryError { method, reason } => {
            tracing::error!(method, error = %reason, "Discovery service failure");
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
