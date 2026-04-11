#![allow(unexpected_cfgs, reason = "flutter_rust_bridge uses frb_expand cfg")]

mod frb_generated; /* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */

use flutter_rust_bridge::frb;
use linux_link_core::protocol::connection::ConnectionManager;
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, TcpDeviceSender};
use linux_link_core::streaming::StreamingClient;
use linux_link_core::tailscale::TailscaleClient;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::sync::Mutex;

// Initialize logging for Android
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

/// Maximum number of H.264 frames to drain per `receive_frames` call.
const MAX_FRAMES_PER_RECEIVE: usize = 16;

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
    let sender = TcpDeviceSender::new(writer);

    // Send file browse request
    let request =
        NetworkPacket::new("kdeconnect.filebrowse.request").with_body(serde_json::json!({
            "path": remote_path,
        }));
    sender
        .send_packet(&request)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;

    // Read response
    let mut lines = tokio::io::BufReader::new(reader).lines();

    match tokio::time::timeout(Duration::from_secs(10), lines.next_line()).await {
        Ok(Ok(Some(line))) => {
            let packet =
                NetworkPacket::from_wire(&line).map_err(|e: anyhow::Error| e.to_string())?;

            if packet.packet_type != "kdeconnect.filebrowse.response" {
                return Err(format!("Unexpected packet type: {}", packet.packet_type));
            }

            // Check for error
            if let Some(error) = packet.body.get("error").and_then(|v| v.as_str()) {
                return Err(error.to_string());
            }

            // Parse file list
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

/// Last known RTT in microseconds, updated by the streaming stats task.
/// Read atomically from the main thread (no mutex lock needed).
static STREAMING_RTT_US: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Global handle for the active streaming client session.
static STREAMING_HANDLE: LazyLock<Mutex<Option<StreamingHandle>>> =
    LazyLock::new(|| Mutex::new(None));

/// Frame data transfer object for Flutter/MediaCodec.
///
/// Note: No `timestamp` field is included because a monotonic `Instant` cannot
/// cross the FFI boundary in a meaningful way. Flutter should use `sequence`
/// for ordering and assign presentation timestamps via MediaCodec.
#[frb]
pub struct FrameDto {
    /// H.264 NAL unit data (including start codes).
    pub data: Vec<u8>,
    /// Whether this is a keyframe (IDR).
    pub is_keyframe: bool,
    /// Sequence number for ordering.
    pub sequence: u64,
}

/// Remote file metadata for the file browser.
#[frb]
pub struct RemoteFileDto {
    /// File or directory name.
    pub name: String,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// Last modified time as Unix timestamp (seconds since epoch).
    pub modified: u64,
}

/// Holds the live streaming client and its packet receiver.
struct StreamingHandle {
    /// Token that can be used to cancel the receive loop.
    cancel: tokio_util::sync::CancellationToken,
    /// JoinHandle of the background `client.start()` task.
    task: tokio::task::JoinHandle<()>,
    /// JoinHandle of the background RTT polling task.
    rtt_task: tokio::task::JoinHandle<()>,
    /// Receiver so the consumer (Flutter) can receive packets.
    /// Accessed via FFI bridge for MediaCodec integration.
    #[allow(dead_code)]
    packet_rx: tokio::sync::mpsc::Receiver<linux_link_core::streaming::EncodedPacket>,
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

    // Spawn a task to periodically poll RTT and update the atomic.
    // The task shares the same `CancellationToken` as the streaming client so it
    // exits cleanly when `stop_streaming()` is called.
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

    // Store the handle
    let mut handle = (*STREAMING_HANDLE).lock().await;
    *handle = Some(StreamingHandle {
        cancel: client_cancel,
        task,
        rtt_task,
        packet_rx,
    });

    tracing::info!("Streaming session connected to {addr}");
    Ok(())
}

/// Stop remote screen streaming.
#[frb]
pub async fn stop_streaming() -> Result<(), String> {
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

    Ok(())
}

/// Check if streaming is active by inspecting the streaming handle.
#[frb(sync)]
pub fn is_streaming_active() -> bool {
    STREAMING_HANDLE
        .try_lock()
        .map(|guard| guard.is_some())
        .unwrap_or(false)
}

/// Update the global streaming RTT value (called from the stats task).
pub(crate) fn update_streaming_rtt(rtt_us: u64) {
    STREAMING_RTT_US.store(rtt_us, std::sync::atomic::Ordering::Relaxed);
}

/// Get the current RTT to the streaming server in microseconds.
///
/// Returns 0 if no streaming session is active.
/// This is a synchronous, lock-free read safe for the main thread.
#[frb(sync)]
pub fn get_streaming_rtt() -> u64 {
    STREAMING_RTT_US.load(std::sync::atomic::Ordering::Relaxed)
}

/// Receive queued H.264 frames from the streaming client.
///
/// Waits for the first frame with a timeout, then drains up to 15 additional
/// frames from the channel. Returns empty if no streaming session is active
/// or the timeout expires.
#[frb]
pub async fn receive_frames(timeout_ms: u64) -> Vec<FrameDto> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut frames = Vec::with_capacity(MAX_FRAMES_PER_RECEIVE);

    // Scope the lock so it's released before we sleep
    {
        let mut guard = (*STREAMING_HANDLE).lock().await;
        let Some(handle) = guard.as_mut() else {
            return frames;
        };

        // Wait for the first frame with timeout
        match tokio::time::timeout_at(deadline, handle.packet_rx.recv()).await {
            Ok(Some(packet)) => {
                frames.push(FrameDto {
                    data: packet.data,
                    is_keyframe: packet.is_keyframe,
                    sequence: packet.sequence,
                });
                // Drain remaining frames without blocking
                while frames.len() < MAX_FRAMES_PER_RECEIVE {
                    match handle.packet_rx.try_recv() {
                        Ok(packet) => {
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
                return frames;
            }
            Ok(None) => return frames, // channel disconnected
            Err(_) => return frames,   // timeout expired
        }
    }
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
