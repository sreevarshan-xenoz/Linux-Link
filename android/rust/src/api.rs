//! FFI API module for flutter_rust_bridge v2.
//! All `#[frb]` annotated items are here so the codegen can find them at `crate::api`.

use flutter_rust_bridge::frb;
use linux_link_core::protocol::connection::ConnectionManager;
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, TcpDeviceSender};
use linux_link_core::streaming::StreamingClient;
use linux_link_core::tailscale::TailscaleClient;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use tokio::sync::Mutex;

use linux_link_core::streaming::InputPacket;

use crate::{
    CONNECTION_STATE, CONTROL_WRITER,
    MAX_AUDIO_PACKETS_PER_RECEIVE, MAX_FRAMES_PER_RECEIVE, STREAMING_ACTIVE, STREAMING_BYTE_COUNT,
    STREAMING_FRAME_COUNT, STREAMING_HANDLE, STREAMING_RTT_US, STREAMING_START_TIME,
    StreamingHandle, update_streaming_rtt,
};

/// Initialize the Linux Link backend
#[frb(init)]
pub fn init_app() {
    crate::init_app_impl();
}

/// Set the persistent data directory for certs and state.
/// Must be called before `connect_streaming` for cert persistence.
#[frb]
pub fn set_data_dir(path: String) {
    let cert_path = PathBuf::from(&path).join("linux-link").join("certs");
    let mut guard = crate::CERT_DIR.lock().unwrap();
    *guard = Some(cert_path);
    tracing::info!("Data directory set to: {path}");
}

/// Get version string
#[frb]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Connection state enumeration for Flutter
#[frb]
pub enum ConnectionState {
    Connected,
    Disconnected,
    Connecting,
    Error(String),
}

/// Peer information for display in Flutter
#[frb]
pub struct PeerInfoDto {
    pub name: String,
    pub dns_name: String,
    pub ips: Vec<String>,
    pub online: bool,
}

/// Discovery event for Flutter
#[frb]
pub enum DiscoveryEvent {
    PeerDiscovered(PeerInfoDto),
    PeerOffline(String),
    ServiceReady,
}

/// Frame data transfer object for Flutter/MediaCodec.
#[frb]
pub struct FrameDto {
    pub data: Vec<u8>,
    pub is_keyframe: bool,
    pub sequence: u64,
}

/// Remote file metadata for the file browser.
#[frb]
pub struct RemoteFileDto {
    pub name: String,
    pub is_directory: bool,
    pub size: u64,
    pub modified: u64,
}
/// Streaming statistics for display in Flutter.
#[frb]
pub struct StreamingStatsDto {
    pub fps: f64,
    pub bitrate_kbps: u64,
    pub e2e_latency_ms: u64,
    pub frame_drops: u64,
}

/// Monitor information for display in Flutter
#[frb]
#[derive(serde::Deserialize, serde::Serialize)]
pub struct MonitorInfoDto {
    pub index: u32,
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub is_primary: bool,
}

/// Check Tailscale status
#[frb]
pub async fn check_tailscale_status() -> Result<bool, String> {
    let client = TailscaleClient::new().map_err(|e: anyhow::Error| e.to_string())?;
    match tokio::time::timeout(
        Duration::from_secs(5),
        client.wait_for_ready(Duration::from_secs(3)),
    )
    .await
    {
        Ok(Ok(_)) => Ok(true),
        _ => Ok(false),
    }
}

/// Get list of peers on the tailnet and LAN
#[frb]
pub async fn get_peers() -> Result<Vec<PeerInfoDto>, String> {
    let mut all_peers = Vec::new();

    // 1. Get Tailscale peers
    if let Ok(client) = TailscaleClient::new() {
        if let Ok(peers) = client.get_peers().await {
            all_peers.extend(peers);
        }
    }

    // 2. Get LAN peers via mDNS
    let lan_peers = linux_link_core::tailscale::lan::scan_lan_once().await;
    for lp in lan_peers {
        // Avoid duplicates if a peer is found on both Tailscale and LAN
        if !all_peers.iter().any(|p| p.name == lp.name) {
            all_peers.push(lp);
        }
    }

    Ok(all_peers
        .into_iter()
        .map(|p| PeerInfoDto {
            name: p.name,
            dns_name: p.dns_name,
            ips: p.ips,
            online: p.online,
        })
        .collect())
}

/// Connect to a peer
#[frb]
pub async fn connect_to_peer(address: String, port: u16) -> Result<ConnectionState, String> {
    let mut state_guard = (*CONNECTION_STATE).lock().await;
    *state_guard = ConnectionState::Connecting;

    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));

    match conn_mgr.connect(&address, port).await {
        Ok(stream) => {
            let (reader, writer) = stream.into_split();
            let mut writer_guard = (*CONTROL_WRITER).lock().await;
            *writer_guard = Some(Arc::new(Mutex::new(writer)));

            // Create a broadcast channel for forwarding incoming packets to Flutter
            let (packet_tx, _) = broadcast::channel(256);
            {
                let mut incoming = crate::INCOMING_PACKETS.lock().await;
                *incoming = Some(packet_tx.clone());
            }

            tokio::spawn(async move {
                let mut reader = tokio::io::BufReader::new(reader);
                let mut line = String::new();
                while let Ok(n) = reader.read_line(&mut line).await {
                    if n == 0 {
                        break;
                    }
                    let trimmed = line.trim().to_string();
                    if !trimmed.is_empty() {
                        let _ = packet_tx.send(trimmed);
                    }
                    line.clear();
                }
                tracing::warn!("Control connection lost");
                let mut state_guard = (*CONNECTION_STATE).lock().await;
                *state_guard = ConnectionState::Disconnected;
                let mut writer_guard = (*CONTROL_WRITER).lock().await;
                *writer_guard = None;
                let mut incoming = crate::INCOMING_PACKETS.lock().await;
                *incoming = None;
            });

            *state_guard = ConnectionState::Connected;
            Ok(ConnectionState::Connected)
        }
        Err(e) => {
            *state_guard = ConnectionState::Error(e.to_string());
            Ok(ConnectionState::Error(e.to_string()))
        }
    }
}

/// Poll for incoming KDE Connect packets from the control connection.
/// Returns up to 16 queued packet JSON strings. Flutter should call this
/// periodically while connected to process server push messages (notifications,
/// clipboard sync, etc.).
#[frb]
pub async fn poll_incoming_packets() -> Vec<String> {
    let rx = {
        let guard = crate::INCOMING_PACKETS.lock().await;
        guard.as_ref().map(|tx| tx.subscribe())
    };
    let Some(mut rx) = rx else { return vec![] };
    let mut packets = vec![];
    // Try to get at least one packet with a short timeout
    match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
        Ok(Ok(pkt)) => packets.push(pkt),
        _ => return packets,
    }
    // Drain any additional queued packets
    while packets.len() < 16 {
        match rx.try_recv() {
            Ok(pkt) => packets.push(pkt),
            Err(_) => break,
        }
    }
    packets
}

/// Send clipboard content to peer using KDE Connect protocol.
#[frb]
pub async fn send_clipboard(address: String, port: u16, content: String) -> Result<(), String> {
    let writer_arc = {
        let guard = (*CONTROL_WRITER).lock().await;
        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| "Not connected".to_string())?
    };
    let sender = TcpDeviceSender::from_arc(writer_arc, address.clone());
    let packet = NetworkPacket::new("kdeconnect.clipboard").with_body(serde_json::json!({
        "content": content,
    }));
    sender
        .send_packet(&packet)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;
    tracing::info!(
        "Clipboard sent to {}:{} ({} chars)",
        address,
        port,
        content.len()
    );
    Ok(())
}

/// Get clipboard content from peer.
///
/// Tries the existing control connection first for lower latency.
/// Falls back to a new TCP connection if not currently connected.
#[frb]
pub async fn get_clipboard(address: String, port: u16) -> Result<String, String> {
    // Try existing control connection first
    let writer_opt = {
        let guard = (*CONTROL_WRITER).lock().await;
        guard.as_ref().cloned()
    };

    if let Some(writer) = writer_opt {
        let sender = TcpDeviceSender::from_arc(writer, address.clone());
        let request = NetworkPacket::new("kdeconnect.clipboard.connect");
        sender
            .send_packet(&request)
            .await
            .map_err(|e: anyhow::Error| e.to_string())?;

        // Subscribe to incoming packets and wait for the clipboard response
        let rx = {
            let guard = crate::INCOMING_PACKETS.lock().await;
            guard.as_ref().map(|tx| tx.subscribe())
        };
        if let Some(mut rx) = rx {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err("Timeout waiting for clipboard response".to_string());
                }
                match tokio::time::timeout(remaining, rx.recv()).await {
                    Ok(Ok(line)) => {
                        if let Ok(packet) = NetworkPacket::from_wire(&line) {
                            if packet.packet_type == "kdeconnect.clipboard" {
                                let content = packet
                                    .body
                                    .get("content")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                return Ok(content);
                            }
                        }
                    }
                    Ok(Err(_)) => return Err("Connection closed".to_string()),
                    Err(_) => return Err("Timeout waiting for clipboard response".to_string()),
                }
            }
        }
    }

    // Fall back to a new TCP connection
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));
    let stream = conn_mgr
        .connect(&address, port)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;
    let (reader, writer) = tokio::io::split(stream);
    let sender = TcpDeviceSender::new(writer, address);
    let request = NetworkPacket::new("kdeconnect.clipboard.connect");
    sender
        .send_packet(&request)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;
    let mut lines = tokio::io::BufReader::new(reader).lines();
    match tokio::time::timeout(Duration::from_secs(5), lines.next_line()).await {
        Ok(Ok(Some(line))) => {
            let packet =
                NetworkPacket::from_wire(&line).map_err(|e: anyhow::Error| e.to_string())?;
            if packet.packet_type == "kdeconnect.clipboard" {
                let content = packet
                    .body
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(content)
            } else {
                Err(format!("Unexpected packet type: {}", packet.packet_type))
            }
        }
        Ok(Ok(None)) => Err("Connection closed before response".to_string()),
        Ok(Err(e)) => Err(format!("Read error: {}", e)),
        Err(_) => Err("Timeout waiting for clipboard response".to_string()),
    }
}

/// Send file to peer using KDE Share protocol.
#[frb]
pub async fn send_file(address: String, port: u16, file_path: String) -> Result<(), String> {
    let metadata = tokio::fs::metadata(&file_path)
        .await
        .map_err(|e| format!("Failed to read file metadata: {}", e))?;
    let file_size = metadata.len();
    let filename = std::path::Path::new(&file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown_file")
        .to_string();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind port: {}", e))?;
    let transfer_port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));
    let stream = conn_mgr
        .connect(&address, port)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;
    let (_reader, writer) = tokio::io::split(stream);
    let sender = TcpDeviceSender::new(writer, address);
    let request = NetworkPacket::new("kdeconnect.share.request")
        .with_body(serde_json::json!({
            "filename": filename,
            "payloadTransferInfo": { "port": transfer_port },
        }))
        .with_payload_size(file_size as u64);
    sender
        .send_packet(&request)
        .await
        .map_err(|e: anyhow::Error| format!("Failed to send share request: {}", e))?;
    let (mut client_stream, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
        .await
        .map_err(|_| "Timeout waiting for file receiver".to_string())?
        .map_err(|e| format!("Failed to accept connection: {}", e))?;
    let mut file = tokio::fs::File::open(&file_path)
        .await
        .map_err(|e| format!("Failed to open file: {}", e))?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut sent: u64 = 0;
    loop {
        let n = file
            .read(&mut buffer)
            .await
            .map_err(|e| format!("Failed to read file: {}", e))?;
        if n == 0 {
            break;
        }
        client_stream
            .write_all(&buffer[..n])
            .await
            .map_err(|e| format!("Failed to write to stream: {}", e))?;
        sent += n as u64;
    }
    client_stream
        .flush()
        .await
        .map_err(|e: std::io::Error| e.to_string())?;
    tracing::info!("File sent: {} ({} bytes)", filename, sent);
    Ok(())
}

/// List files in a remote directory using the file browse protocol.
#[frb]
pub async fn list_remote_files(
    address: String,
    port: u16,
    remote_path: String,
) -> Result<Vec<RemoteFileDto>, String> {
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));
    let stream = conn_mgr
        .connect(&address, port)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;
    let (reader, writer) = tokio::io::split(stream);
    let sender = TcpDeviceSender::new(writer, address);
    let request = NetworkPacket::new("kdeconnect.filebrowse.request")
        .with_body(serde_json::json!({ "path": remote_path }));
    sender
        .send_packet(&request)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;
    let mut lines = tokio::io::BufReader::new(reader).lines();
    match tokio::time::timeout(Duration::from_secs(10), lines.next_line()).await {
        Ok(Ok(Some(line))) => {
            let packet =
                NetworkPacket::from_wire(&line).map_err(|e: anyhow::Error| e.to_string())?;
            if packet.packet_type != "kdeconnect.filebrowse.response" {
                return Err(format!("Unexpected packet type: {}", packet.packet_type));
            }
            if let Some(error) = packet.body.get("error").and_then(|v| v.as_str()) {
                return Err(error.to_string());
            }
            let files = packet
                .body
                .get("files")
                .and_then(|v| v.as_array())
                .ok_or_else(|| "Missing 'files' in response".to_string())?;
            let result: Vec<RemoteFileDto> = files
                .iter()
                .filter_map(|f| {
                    Some(RemoteFileDto {
                        name: f.get("name")?.as_str()?.to_string(),
                        is_directory: f.get("isDirectory")?.as_bool()?,
                        size: f.get("size")?.as_u64()?,
                        modified: f.get("modified")?.as_u64()?,
                    })
                })
                .collect();
            Ok(result)
        }
        Ok(Ok(None)) => Err("Connection closed before response".to_string()),
        Ok(Err(e)) => Err(format!("Read error: {}", e)),
        Err(_) => Err("Timeout waiting for file list response".to_string()),
    }
}

/// Request remote screen streaming.
///
/// `monitor_index` selects which display to stream (0 = primary).
/// Pass `None` to use the default monitor.
#[frb]
pub async fn connect_streaming(
    address: String,
    port: u16,
    monitor_index: Option<u32>,
) -> Result<(), String> {
    // If the control port (1716) is passed, automatically switch to the default streaming port (4716).
    // In a real KDE Connect implementation, this would be negotiated or discovery-based.
    let streaming_port = if port == linux_link_core::DEFAULT_CONTROL_PORT {
        linux_link_core::DEFAULT_STREAMING_PORT
    } else {
        port
    };

    let addr = format!("{address}:{streaming_port}");
    tracing::info!("Connecting to streaming server at {addr}");

    // Create a CertManager with persistent TOFU peer certificate verification.
    // Uses the data directory set via `set_data_dir()`. Falls back to in-memory
    // if no data directory is configured (cert trust lost on restart).
    let cert_manager = {
        let guard = crate::CERT_DIR.lock().unwrap();
        match guard.as_ref() {
            Some(dir) => {
                std::sync::Arc::new(
                    linux_link_core::streaming::transport::CertManager::load_or_create(dir)
                        .map_err(|e| e.to_string())?,
                )
            }
            None => {
                tracing::warn!("No data dir configured — cert trust is ephemeral");
                std::sync::Arc::new(
                    linux_link_core::streaming::transport::CertManager::new()
                        .map_err(|e| e.to_string())?,
                )
            }
        }
    };

    // Store for trust management UI
    {
        let mut cm_guard = crate::CERT_MANAGER.lock().unwrap();
        *cm_guard = Some(cert_manager.clone());
    }

    let (mut client, packet_rx, audio_rx) =
        StreamingClient::connect(&addr, cert_manager, monitor_index)
            .await
            .map_err(|e| e.to_string())?;

    let connection = client
        .connection()
        .ok_or_else(|| "Connection not available after connect".to_string())?
        .clone();

    let cancel = client.cancel_token();
    let client_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        client.start().await;
        tracing::info!("Streaming client start loop exited");
    });

    let rtt_cancel = cancel.clone();
    let rtt_connection = connection.clone();
    let rtt_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = rtt_cancel.cancelled() => {
                    tracing::info!("RTT polling task cancelled");
                    break;
                }
                _ = interval.tick() => {
                    let rtt_us = rtt_connection.stats().path.rtt.as_micros() as u64;
                    update_streaming_rtt(rtt_us);
                }
            }
        }
    });

    STREAMING_ACTIVE.store(true, std::sync::atomic::Ordering::Release);

    let mut handle = (*STREAMING_HANDLE).lock().await;
    *handle = Some(StreamingHandle {
        cancel: client_cancel,
        task,
        rtt_task,
        packet_rx,
        audio_rx,
        connection: connection.clone(),
    });

    tracing::info!("Streaming session connected to {addr}");
    Ok(())
}

/// Stop remote screen streaming.
#[frb]
pub async fn stop_streaming() -> Result<(), String> {
    // Reset streaming metrics
    STREAMING_FRAME_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
    STREAMING_BYTE_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
    *STREAMING_START_TIME.lock().await = None;
    STREAMING_RTT_US.store(0, std::sync::atomic::Ordering::Relaxed);

    let handle = {
        let mut guard = (*STREAMING_HANDLE).lock().await;
        guard.take()
    };
    if let Some(handle) = handle {
        handle.cancel.cancel();
        if let Err(e) = handle.task.await {
            tracing::warn!("Streaming client task exited with error: {e}");
        }
        if let Err(e) = handle.rtt_task.await {
            tracing::warn!("RTT polled task exited with error: {e}");
        }
        tracing::info!("Streaming session stopped");
    }
    STREAMING_ACTIVE.store(false, std::sync::atomic::Ordering::Release);
    Ok(())
}

/// Check if streaming is active using an atomic flag (no lock contention).
#[frb(sync)]
pub fn is_streaming_active() -> bool {
    STREAMING_ACTIVE.load(std::sync::atomic::Ordering::Acquire)
}

/// Get the current RTT to the streaming server in microseconds.
#[frb(sync)]
pub fn get_streaming_rtt() -> u64 {
    STREAMING_RTT_US.load(Ordering::Relaxed)
}

/// Get detailed streaming session statistics.
#[frb(sync)]
pub fn get_streaming_stats() -> StreamingStatsDto {
    let rtt_ms = STREAMING_RTT_US.load(Ordering::Relaxed) / 1000;
    let frame_count = STREAMING_FRAME_COUNT.load(Ordering::Relaxed);
    let byte_count = STREAMING_BYTE_COUNT.load(Ordering::Relaxed);
    let elapsed = STREAMING_START_TIME
        .try_lock()
        .ok()
        .and_then(|g| g.map(|t| t.elapsed()))
        .unwrap_or_default();

    let fps = if elapsed.as_secs() > 0 {
        frame_count as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    let bitrate_kbps = if elapsed.as_secs() > 0 {
        (byte_count * 8) / elapsed.as_secs().max(1) / 1000
    } else {
        0
    };

    StreamingStatsDto {
        fps: (fps * 10.0).round() / 10.0,
        bitrate_kbps,
        e2e_latency_ms: rtt_ms,
        frame_drops: 0,
    }
}

/// List all trusted peers (certificate labels) from the active streaming session's
/// CertManager. Returns an empty list if no streaming session is active.
#[frb(sync)]
pub fn list_trusted_peers() -> Vec<String> {
    let guard = crate::CERT_MANAGER.lock().unwrap();
    match guard.as_ref() {
        Some(cm) => {
            // Can't access known_peers directly — it's behind Arc<Mutex<HashMap>>.
            // We provide the list from a best-effort basis.
            let peers = cm.known_peers();
            peers.into_iter().map(|(label, _hash)| label).collect()
        }
        None => vec![],
    }
}

/// Remove a trusted peer certificate by label. Returns true if the peer was
/// found and removed, false otherwise. Persists the change to disk.
#[frb(sync)]
pub fn forget_trusted_peer(label: String) -> bool {
    let guard = crate::CERT_MANAGER.lock().unwrap();
    match guard.as_ref() {
        Some(cm) => {
            let removed = cm.remove_peer(&label);
            if removed {
                let _ = cm.save_known_peers();
            }
            removed
        }
        None => false,
    }
}

/// Get the number of monitors available on the remote server.
///
/// F2: Multi-monitor support — returns 0 if detection fails or no display.
#[frb]
/// Get detailed list of monitors available on the remote server.
#[frb]
pub async fn get_monitors(address: String, port: u16) -> Result<Vec<MonitorInfoDto>, String> {
    let conn_mgr = ConnectionManager::new(Duration::from_secs(5));
    match conn_mgr.connect(&address, port).await {
        Ok(stream) => {
            let (reader, writer) = tokio::io::split(stream);
            let sender = TcpDeviceSender::new(writer, address);
            let request = NetworkPacket::new("kdeconnect.linuxlink.monitors")
                .with_body(serde_json::json!({}));
            
            if let Err(e) = sender.send_packet(&request).await {
                return Err(format!("Failed to send monitor query: {e}"));
            }

            let mut lines = tokio::io::BufReader::new(reader).lines();
            match tokio::time::timeout(Duration::from_secs(5), lines.next_line()).await {
                Ok(Ok(Some(line))) => {
                    match NetworkPacket::from_wire(&line) {
                        Ok(packet) => {
                            if packet.packet_type == "kdeconnect.linuxlink.monitors" {
                                let monitors: Vec<MonitorInfoDto> = packet
                                    .body
                                    .get("monitors")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                                    .unwrap_or_else(|| {
                                        // Legacy fallback if server only returns count
                                        let count = packet.body.get("count").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
                                        (0..count).map(|i| MonitorInfoDto {
                                            index: i,
                                            name: format!("Monitor {i}"),
                                            width: 1920,
                                            height: 1080,
                                            is_primary: i == 0,
                                        }).collect()
                                    });
                                Ok(monitors)
                            } else {
                                Err("Unexpected response packet type".to_string())
                            }
                        }
                        Err(e) => Err(format!("Failed to parse monitor response: {e}")),
                    }
                }
                Ok(Ok(None)) => Err("Connection closed by peer".to_string()),
                Ok(Err(e)) => Err(format!("Read error: {e}")),
                Err(_) => Err("Timeout waiting for monitor response".to_string()),
            }
        }
        Err(e) => Err(format!("Connection failed: {e}")),
    }
}

/// Get the number of monitors available on the remote server (legacy).
#[frb]
pub async fn get_monitor_count(address: String, port: u16) -> Result<u32, String> {
    get_monitors(address, port).await.map(|m| m.len() as u32)
}

/// Execute a power management command on the remote server.
/// Supported actions: "sleep", "shutdown", "restart", "hibernate".
#[frb]
pub async fn send_power_command(
    address: String,
    port: u16,
    action: String,
) -> Result<(), String> {
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));
    let stream = conn_mgr
        .connect(&address, port)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;
    let (_reader, writer) = tokio::io::split(stream);
    let sender = TcpDeviceSender::new(writer, address);
    let packet = NetworkPacket::new("kdeconnect.linuxlink.power")
        .with_body(serde_json::json!({ "action": action }));
    sender
        .send_packet(&packet)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;
    tracing::info!("Power command sent: {action}");
    Ok(())
}

/// Execute a shell command on the remote server and return stdout + stderr + exit code.
#[frb]
pub async fn execute_remote_command(
    address: String,
    port: u16,
    command: String,
) -> Result<String, String> {
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));
    let stream = conn_mgr
        .connect(&address, port)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;
    let (reader, writer) = tokio::io::split(stream);
    let sender = TcpDeviceSender::new(writer, address);
    let request = NetworkPacket::new("kdeconnect.linuxlink.exec")
        .with_body(serde_json::json!({ "command": command }));
    sender
        .send_packet(&request)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;
    let mut lines = tokio::io::BufReader::new(reader).lines();
    match tokio::time::timeout(Duration::from_secs(10), lines.next_line()).await {
        Ok(Ok(Some(line))) => {
            match NetworkPacket::from_wire(&line) {
                Ok(packet) => {
                    if packet.packet_type == "kdeconnect.linuxlink.exec" {
                        let body = &packet.body;
                        let stdout = body.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
                        let stderr = body.get("stderr").and_then(|v| v.as_str()).unwrap_or("");
                        let exit_code = body.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(-1);
                        Ok(format!("{stdout}\n---END-OUTPUT---\n{stderr}\n---END-ERROR---\n{exit_code}"))
                    } else {
                        Err(format!("Unexpected packet type: {}", packet.packet_type))
                    }
                }
                Err(e) => Err(format!("Failed to parse response: {e}")),
            }
        }
        Ok(Ok(None)) => Err("Connection closed before response".to_string()),
        Ok(Err(e)) => Err(format!("Read error: {e}")),
        Err(_) => Err("Timeout waiting for exec response".to_string()),
    }
}

/// Receive queued audio packets from the streaming client (F1: Audio Streaming).
///
/// Each audio packet contains raw Opus-encoded data (typically 20ms @ 48kHz stereo).
/// Returns up to `MAX_AUDIO_PACKETS_PER_RECEIVE` packets.
#[frb]
pub async fn receive_audio(timeout_ms: u64) -> Vec<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut packets = Vec::with_capacity(MAX_AUDIO_PACKETS_PER_RECEIVE);
    {
        let mut guard = (*STREAMING_HANDLE).lock().await;
        let Some(handle) = guard.as_mut() else {
            return packets;
        };
        match tokio::time::timeout_at(deadline, handle.audio_rx.recv()).await {
            Ok(Some(packet)) => {
                packets.push(packet.data);
                while packets.len() < MAX_AUDIO_PACKETS_PER_RECEIVE {
                    match handle.audio_rx.try_recv() {
                        Ok(packet) => {
                            packets.push(packet.data);
                        }
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                        | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                packets
            }
            _ => packets,
        }
    }
}

/// Receive queued H.264 frames from the streaming client.
///
/// The `timeout_ms` parameter only applies to waiting for the FIRST frame.
/// After the first frame arrives, any additional queued frames are drained
/// immediately with `try_recv()` (no further timeout). Returns up to
/// `MAX_FRAMES_PER_RECEIVE` frames per call.
#[frb]
pub async fn receive_frames(timeout_ms: u64) -> Vec<FrameDto> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut frames = Vec::with_capacity(MAX_FRAMES_PER_RECEIVE);
    {
        let mut guard = (*STREAMING_HANDLE).lock().await;
        let Some(handle) = guard.as_mut() else {
            return frames;
        };
        match tokio::time::timeout_at(deadline, handle.packet_rx.recv()).await {
            Ok(Some(packet)) => {
                STREAMING_FRAME_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                STREAMING_BYTE_COUNT
                    .fetch_add(packet.data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                if STREAMING_START_TIME.lock().await.is_none() {
                    *STREAMING_START_TIME.lock().await = Some(std::time::Instant::now());
                }
                frames.push(FrameDto {
                    data: packet.data,
                    is_keyframe: packet.is_keyframe,
                    sequence: packet.sequence,
                });
                while frames.len() < MAX_FRAMES_PER_RECEIVE {
                    match handle.packet_rx.try_recv() {
                        Ok(packet) => {
                            STREAMING_FRAME_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            STREAMING_BYTE_COUNT.fetch_add(
                                packet.data.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            frames.push(FrameDto {
                                data: packet.data,
                                is_keyframe: packet.is_keyframe,
                                sequence: packet.sequence,
                            });
                        }
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                        | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                frames
            }
            _ => frames,
        }
    }
}

/// Send mouse event to remote, preferring the low-latency QUIC streaming channel.
///
/// Falls back to KDE Connect TCP protocol if streaming is not active.
#[frb]
pub async fn send_mouse_event(
    _address: String,
    _port: u16,
    x: f32,
    y: f32,
    button: i32,
    is_pressed: bool,
) -> Result<(), String> {
    // Try QUIC streaming channel first (lower latency, compact binary protocol)
    let streaming_conn = {
        let guard = (*STREAMING_HANDLE).lock().await;
        guard.as_ref().map(|h| h.connection.clone())
    };

    if let Some(conn) = streaming_conn {
        let packet = if button == 2 {
            // Scroll event (button=2 is reserved for scroll on the Flutter side)
            InputPacket::MouseScroll {
                dx: x as i16,
                dy: y as i16,
            }
        } else if button != 0 {
            InputPacket::MouseClick {
                button: button as u8,
                pressed: is_pressed,
            }
        } else {
            InputPacket::MouseMove {
                dx: x as i16,
                dy: y as i16,
            }
        };

        let data = packet.encode();
        let mut send_stream = conn
            .open_uni()
            .await
            .map_err(|e| format!("QUIC open stream: {e}"))?;
        send_stream
            .write_all(&data)
            .await
            .map_err(|e| format!("QUIC write: {e}"))?;
        send_stream
            .finish()
            .map_err(|e| format!("QUIC finish: {e}"))?;
        return Ok(());
    }

    // Fall back to TCP/KDE Connect protocol
    let writer_arc = {
        let guard = (*CONTROL_WRITER).lock().await;
        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| "Not connected".to_string())?
    };
    let sender = TcpDeviceSender::from_arc(writer_arc, _address.clone());
    let mut body = serde_json::json!({});
    if x != 0.0 || y != 0.0 {
        body["dx"] = serde_json::json!(x);
        body["dy"] = serde_json::json!(y);
    }
    if button != 0 {
        body["isPressed"] = serde_json::json!(is_pressed);
        body["button"] = serde_json::json!(button);
    }
    let packet = NetworkPacket::new("kdeconnect.mousepad.request").with_body(body);
    sender
        .send_packet(&packet)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;
    Ok(())
}

/// Send keyboard event to remote, preferring the low-latency QUIC streaming channel.
///
/// Falls back to KDE Connect TCP protocol if streaming is not active.
#[frb]
pub async fn send_keyboard_event(
    _address: String,
    _port: u16,
    key_code: i32,
    text: String,
) -> Result<(), String> {
    // Try QUIC streaming channel first (lower latency, compact binary protocol)
    let streaming_conn = {
        let guard = (*STREAMING_HANDLE).lock().await;
        guard.as_ref().map(|h| h.connection.clone())
    };

    if let Some(conn) = streaming_conn {
        if !text.is_empty() {
            // Send as text packet
            let packet = InputPacket::Text(text);
            let data = packet.encode();
            let mut send_stream = conn
                .open_uni()
                .await
                .map_err(|e| format!("QUIC open stream: {e}"))?;
            send_stream
                .write_all(&data)
                .await
                .map_err(|e| format!("QUIC write: {e}"))?;
            send_stream
                .finish()
                .map_err(|e| format!("QUIC finish: {e}"))?;
            return Ok(());
        }

        if key_code != 0 {
            // Decode modifier encoding:
            //   key_code > 100000 = modifier release   (subtract 100000)
            //   key_code > 50000  = modifier press      (subtract 50000)
            //   otherwise         = regular key          (press + release)
            const MOD_RELEASE_OFFSET: i32 = 100000;
            const MOD_PRESS_OFFSET: i32 = 50000;

            let evdev_key = android_to_evdev_keycode(if key_code > MOD_RELEASE_OFFSET {
                key_code - MOD_RELEASE_OFFSET
            } else if key_code > MOD_PRESS_OFFSET {
                key_code - MOD_PRESS_OFFSET
            } else {
                key_code
            });

            if key_code > MOD_RELEASE_OFFSET {
                // Modifier release: send single release packet
                let packet = InputPacket::KeyEvent {
                    key: evdev_key,
                    pressed: false,
                };
                let data = packet.encode();
                let mut send_stream = conn
                    .open_uni()
                    .await
                    .map_err(|e| format!("QUIC open stream: {e}"))?;
                send_stream
                    .write_all(&data)
                    .await
                    .map_err(|e| format!("QUIC write: {e}"))?;
                send_stream
                    .finish()
                    .map_err(|e| format!("QUIC finish: {e}"))?;
            } else if key_code > MOD_PRESS_OFFSET {
                // Modifier press: send single press packet
                let packet = InputPacket::KeyEvent {
                    key: evdev_key,
                    pressed: true,
                };
                let data = packet.encode();
                let mut send_stream = conn
                    .open_uni()
                    .await
                    .map_err(|e| format!("QUIC open stream: {e}"))?;
                send_stream
                    .write_all(&data)
                    .await
                    .map_err(|e| format!("QUIC write: {e}"))?;
                send_stream
                    .finish()
                    .map_err(|e| format!("QUIC finish: {e}"))?;
            } else {
                // Regular key: press + release (current behavior)
                for pressed in [true, false] {
                    let packet = InputPacket::KeyEvent {
                        key: evdev_key,
                        pressed,
                    };
                    let data = packet.encode();
                    let mut send_stream = conn
                        .open_uni()
                        .await
                        .map_err(|e| format!("QUIC open stream: {e}"))?;
                    send_stream
                        .write_all(&data)
                        .await
                        .map_err(|e| format!("QUIC write: {e}"))?;
                    send_stream
                        .finish()
                        .map_err(|e| format!("QUIC finish: {e}"))?;
                }
            }
            return Ok(());
        }

        return Ok(());
    }

    // Fall back to TCP/KDE Connect protocol
    let writer_arc = {
        let guard = (*CONTROL_WRITER).lock().await;
        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| "Not connected".to_string())?
    };
    let sender = TcpDeviceSender::from_arc(writer_arc, _address.clone());
    let mut body = serde_json::json!({});
    if !text.is_empty() {
        body["text"] = serde_json::json!(text);
    }
    if key_code != 0 {
        let key_str: String = match key_code {
            66 => "Enter".to_string(),
            67 => "Backspace".to_string(),
            19 => "Up".to_string(),
            20 => "Down".to_string(),
            21 => "Left".to_string(),
            22 => "Right".to_string(),
            62 => "Space".to_string(),
            _ => format!("Key{}", key_code),
        };
        body["key"] = serde_json::json!(key_str);
    }
    let packet = NetworkPacket::new("kdeconnect.mousepad.request").with_body(body);
    sender
        .send_packet(&packet)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;
    Ok(())
}

/// Send gamepad state over the QUIC streaming channel.
///
/// `axes` contains 6 i16 values: [LX, LY, RX, RY, L2, R2] in range -32768..32767.
/// `buttons` is a 16-bit bitmask (A=0, B=1, X=2, Y=3, LB=4, RB=5,
/// Select=6, Start=7, Home=8, LSB=9, RSB=10, DPadUp=11..DPadRight=14).
/// Requires an active streaming session — no TCP fallback for gamepad.
#[frb]
pub async fn send_gamepad_event(
    axes: Vec<i16>,
    buttons: u32,
) -> Result<(), String> {
    let streaming_conn = {
        let guard = (*STREAMING_HANDLE).lock().await;
        guard.as_ref().map(|h| h.connection.clone())
    };

    let Some(conn) = streaming_conn else {
        return Err("No active streaming session for gamepad input".to_string());
    };

    // Pad or truncate axes to 6
    let mut axis_array = [0i16; 6];
    for (i, &val) in axes.iter().enumerate().take(6) {
        axis_array[i] = val;
    }

    let packet = InputPacket::Gamepad {
        axes: axis_array,
        buttons: buttons as u16,
    };

    let data = packet.encode();
    let mut send_stream = conn
        .open_uni()
        .await
        .map_err(|e| format!("QUIC open stream: {e}"))?;
    send_stream
        .write_all(&data)
        .await
        .map_err(|e| format!("QUIC write: {e}"))?;
    send_stream
        .finish()
        .map_err(|e| format!("QUIC finish: {e}"))?;

    Ok(())
}

/// Roughly map Android keycodes to Linux evdev keycodes for QUIC input.
fn android_to_evdev_keycode(android_keycode: i32) -> u16 {
    match android_keycode {
        66 => 28,                    // Enter
        67 => 14,                    // Backspace
        19 => 103,                   // Up
        20 => 108,                   // Down
        21 => 105,                   // Left
        22 => 106,                   // Right
        62 => 57,                    // Space
        4 => 1,                      // Escape
        61 => 15,                    // Tab
        112 => 14,                   // Delete
        85 => 111,                   // Volume Up
        86 => 114,                   // Volume Down
        _ => android_keycode as u16, // Passthrough for keycodes that might match
    }
}
