#![allow(unexpected_cfgs, reason = "flutter_rust_bridge uses frb_expand cfg")]

use flutter_rust_bridge::frb;
use linux_link_core::protocol::connection::ConnectionManager;
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, TcpDeviceSender};
use linux_link_core::streaming::StreamingClient;
use linux_link_core::tailscale::TailscaleClient;
use std::sync::Mutex;
use std::time::Duration;

// Initialize logging for Android
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

/// Initialize the Linux Link backend
#[frb(init)]
pub fn init_app() {
    // Setup logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    flutter_rust_bridge::setup_default_user_utils();
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

/// Get version string
#[frb]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Check Tailscale status
#[frb]
pub async fn check_tailscale_status() -> Result<bool, String> {
    let client = TailscaleClient::new().map_err(|e: anyhow::Error| e.to_string())?;

    // Try to get status with short timeout
    match tokio::time::timeout(
        Duration::from_secs(5),
        client.wait_for_ready(Duration::from_secs(3)),
    )
    .await
    {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(_)) => Ok(false),
        Err(_) => Ok(false),
    }
}

/// Get list of peers on the tailnet
#[frb]
pub async fn get_peers() -> Result<Vec<PeerInfoDto>, String> {
    let client = TailscaleClient::new().map_err(|e: anyhow::Error| e.to_string())?;

    let peers = client
        .get_peers()
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;

    Ok(peers
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
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));

    match conn_mgr.connect(&address, port).await {
        Ok(_) => Ok(ConnectionState::Connected),
        Err(e) => Ok(ConnectionState::Error(e.to_string())),
    }
}

/// Send clipboard content to peer using KDE Connect protocol.
#[frb]
pub async fn send_clipboard(address: String, port: u16, content: String) -> Result<(), String> {
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));
    let stream = conn_mgr
        .connect(&address, port)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;

    let (_reader, writer) = tokio::io::split(stream);
    let sender = TcpDeviceSender::new(writer);

    // Send clipboard packet
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
#[frb]
pub async fn get_clipboard(address: String, port: u16) -> Result<String, String> {
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));
    let stream = conn_mgr
        .connect(&address, port)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;

    let (reader, writer) = tokio::io::split(stream);
    let sender = TcpDeviceSender::new(writer);

    // Request clipboard sync
    let request = NetworkPacket::new("kdeconnect.clipboard.connect");
    sender
        .send_packet(&request)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;

    // Read response
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
                tracing::info!(
                    "Clipboard received from {}:{} ({} chars)",
                    address,
                    port,
                    content.len()
                );
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
    // Read file metadata
    let metadata = tokio::fs::metadata(&file_path)
        .await
        .map_err(|e| format!("Failed to read file metadata: {}", e))?;
    let file_size = metadata.len();

    let filename = std::path::Path::new(&file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown_file")
        .to_string();

    // Bind a port for the receiver to connect to
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind port: {}", e))?;
    let transfer_port = listener.local_addr().map_err(|e| e.to_string())?.port();

    // Send share request with transfer info
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));
    let stream = conn_mgr
        .connect(&address, port)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;

    let (_reader, writer) = tokio::io::split(stream);
    let sender = TcpDeviceSender::new(writer);

    let request = NetworkPacket::new("kdeconnect.share.request")
        .with_body(serde_json::json!({
            "filename": filename,
            "payloadTransferInfo": {
                "port": transfer_port,
            },
        }))
        .with_payload_size(file_size as u64);

    sender
        .send_packet(&request)
        .await
        .map_err(|e: anyhow::Error| format!("Failed to send share request: {}", e))?;

    tracing::info!(
        "Share request sent: {} ({} bytes) on port {}",
        filename,
        file_size,
        transfer_port
    );

    // Accept connection and stream file
    let (mut client_stream, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
        .await
        .map_err(|_| "Timeout waiting for file receiver".to_string())?
        .map_err(|e| format!("Failed to accept connection: {}", e))?;

    let mut file = tokio::fs::File::open(&file_path)
        .await
        .map_err(|e| format!("Failed to open file: {}", e))?;

    let mut buffer = vec![0u8; 64 * 1024]; // 64KB chunks
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
        if sent.is_multiple_of(1024 * 1024) {
            tracing::debug!("Sent {} MB", sent / (1024 * 1024));
        }
    }

    client_stream
        .flush()
        .await
        .map_err(|e: std::io::Error| e.to_string())?;

    tracing::info!("File sent: {} ({} bytes)", filename, sent);
    Ok(())
}

/// Streaming session state
static STREAMING_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Global handle for the active streaming client session.
static STREAMING_HANDLE: Mutex<Option<StreamingHandle>> = Mutex::new(None);

/// Holds the live streaming client and its packet receiver.
struct StreamingHandle {
    /// Token that can be used to cancel the receive loop.
    cancel: tokio_util::sync::CancellationToken,
    /// JoinHandle of the background `client.start()` task.
    task: tokio::task::JoinHandle<()>,
    /// Receiver so the consumer (Flutter) can receive packets.
    /// Accessed via FFI bridge for MediaCodec integration.
    #[allow(dead_code)]
    packet_rx: tokio::sync::mpsc::Receiver<linux_link_core::streaming::EncodedPacket>,
    /// Clone of the QUIC connection for RTT queries.
    connection: quinn::Connection,
}

/// Request remote screen streaming.
///
/// Connects to the server at `address:port` via QUIC, starts a background
/// receive task, and stores the session globally. Use `get_streaming_rtt`
/// to query the current RTT.
#[frb]
pub async fn connect_streaming(address: String, port: u16) -> Result<(), String> {
    let addr = format!("{address}:{port}");
    tracing::info!("Connecting to streaming server at {addr}");

    let (mut client, packet_rx) = StreamingClient::connect(&addr)
        .await
        .map_err(|e| e.to_string())?;

    // Clone the connection for RTT queries before the client is moved into the task
    let connection = client
        .connection()
        .ok_or_else(|| "Connection not available after connect".to_string())?
        .clone();

    let cancel = client.cancel_token();
    let client_cancel = cancel.clone();

    // Spawn the background receive loop
    let task = tokio::spawn(async move {
        client.start().await;
        tracing::info!("Streaming client start loop exited");
    });

    // Store the handle
    let mut handle = STREAMING_HANDLE
        .lock()
        .map_err(|e| format!("Lock poisoned: {e}"))?;
    *handle = Some(StreamingHandle {
        cancel: client_cancel,
        task,
        packet_rx,
        connection,
    });

    STREAMING_ACTIVE.store(true, std::sync::atomic::Ordering::SeqCst);
    tracing::info!("Streaming session connected to {addr}");
    Ok(())
}

/// Stop remote screen streaming.
#[frb]
pub async fn stop_streaming() -> Result<(), String> {
    let handle = {
        let mut guard = STREAMING_HANDLE
            .lock()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        guard.take()
    };

    if let Some(handle) = handle {
        handle.cancel.cancel();
        let _ = handle.task.await;
        tracing::info!("Streaming session stopped");
    }

    STREAMING_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

/// Check if streaming is active
#[frb]
pub fn is_streaming_active() -> bool {
    STREAMING_ACTIVE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Get the current RTT to the streaming server in milliseconds.
///
/// Returns 0 if no streaming session is active.
#[frb]
pub fn get_streaming_rtt() -> u64 {
    let guard = match STREAMING_HANDLE.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    let Some(handle) = guard.as_ref() else {
        return 0;
    };

    handle.connection.stats().path.rtt.as_millis() as u64
}

/// Send mouse event to remote using KDE mousepad protocol.
#[frb]
pub async fn send_mouse_event(
    address: String,
    port: u16,
    x: f32,
    y: f32,
    button: i32,
    is_pressed: bool,
) -> Result<(), String> {
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));
    let stream = conn_mgr
        .connect(&address, port)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;

    let (_reader, writer) = tokio::io::split(stream);
    let sender = TcpDeviceSender::new(writer);

    // Build mousepad request packet
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

/// Send keyboard event to remote using KDE mousepad protocol.
#[frb]
pub async fn send_keyboard_event(
    address: String,
    port: u16,
    key_code: i32,
    text: String,
) -> Result<(), String> {
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));
    let stream = conn_mgr
        .connect(&address, port)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;

    let (_reader, writer) = tokio::io::split(stream);
    let sender = TcpDeviceSender::new(writer);

    // Build mousepad request packet
    let mut body = serde_json::json!({});

    // If text is provided, use text typing mode
    if !text.is_empty() {
        body["text"] = serde_json::json!(text);
    }

    // If key_code is non-zero, send as special key
    if key_code != 0 {
        // Map key_code to KDE Connect key string
        let key_str: String = match key_code {
            // Common Android key codes mapped to KDE Connect key names
            66 => "Enter".to_string(),     // KEYCODE_ENTER
            67 => "Backspace".to_string(), // KEYCODE_DEL
            19 => "Up".to_string(),        // KEYCODE_DPAD_UP
            20 => "Down".to_string(),      // KEYCODE_DPAD_DOWN
            21 => "Left".to_string(),      // KEYCODE_DPAD_LEFT
            22 => "Right".to_string(),     // KEYCODE_DPAD_RIGHT
            62 => "Space".to_string(),     // KEYCODE_SPACE
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
