//! FFI API module for flutter_rust_bridge v2.
//! All `#[frb]` annotated items are here so the codegen can find them at `crate::api`.

use flutter_rust_bridge::frb;
use linux_link_core::protocol::connection::ConnectionManager;
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, TcpDeviceSender};
use linux_link_core::streaming::StreamingClient;
use linux_link_core::tailscale::TailscaleClient;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::{
    CONNECTION_STATE, CONTROL_WRITER, MAX_FRAMES_PER_RECEIVE, STREAMING_HANDLE, STREAMING_RTT_US,
    StreamingHandle, update_streaming_rtt,
};

/// Initialize the Linux Link backend
#[frb(init)]
pub fn init_app() {
    crate::init_app_impl();
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
    let mut state_guard = (*CONNECTION_STATE).lock().await;
    *state_guard = ConnectionState::Connecting;

    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));

    match conn_mgr.connect(&address, port).await {
        Ok(stream) => {
            let (reader, writer) = stream.into_split();
            let mut writer_guard = (*CONTROL_WRITER).lock().await;
            *writer_guard = Some(Arc::new(Mutex::new(writer)));

            tokio::spawn(async move {
                let mut reader = tokio::io::BufReader::new(reader);
                let mut line = String::new();
                while let Ok(n) = reader.read_line(&mut line).await {
                    if n == 0 {
                        break;
                    }
                    line.clear();
                }
                tracing::warn!("Control connection lost");
                let mut state_guard = (*CONNECTION_STATE).lock().await;
                *state_guard = ConnectionState::Disconnected;
                let mut writer_guard = (*CONTROL_WRITER).lock().await;
                *writer_guard = None;
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
    let sender = TcpDeviceSender::from_arc(writer_arc);
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
    let sender = TcpDeviceSender::new(writer);
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
    let sender = TcpDeviceSender::new(writer);
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
#[frb]
pub async fn connect_streaming(address: String, port: u16) -> Result<(), String> {
    let addr = format!("{address}:{port}");
    tracing::info!("Connecting to streaming server at {addr}");

    // Create a CertManager for TOFU peer certificate verification.
    // For now, an in-memory manager (peers lost on app restart).
    // In the future, load from persistent storage using load_or_create().
    let cert_manager = std::sync::Arc::new(
        linux_link_core::streaming::transport::CertManager::new().map_err(|e| e.to_string())?,
    );

    let (mut client, packet_rx) = StreamingClient::connect(&addr, cert_manager)
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

/// Get the current RTT to the streaming server in microseconds.
#[frb(sync)]
pub fn get_streaming_rtt() -> u64 {
    STREAMING_RTT_US.load(Ordering::Relaxed)
}

/// Get detailed streaming session statistics.
#[frb(sync)]
pub fn get_streaming_stats() -> StreamingStatsDto {
    let rtt_ms = STREAMING_RTT_US.load(Ordering::Relaxed) / 1000;
    StreamingStatsDto {
        fps: 0.0,
        bitrate_kbps: 0,
        e2e_latency_ms: rtt_ms,
        frame_drops: 0,
    }
}

/// Receive queued H.264 frames from the streaming client.
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
                frames.push(FrameDto {
                    data: packet.data,
                    is_keyframe: packet.is_keyframe,
                    sequence: packet.sequence,
                });
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
                frames
            }
            _ => frames,
        }
    }
}

/// Send mouse event to remote using KDE mousepad protocol.
#[frb]
pub async fn send_mouse_event(
    _address: String,
    _port: u16,
    x: f32,
    y: f32,
    button: i32,
    is_pressed: bool,
) -> Result<(), String> {
    let writer_arc = {
        let guard = (*CONTROL_WRITER).lock().await;
        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| "Not connected".to_string())?
    };
    let sender = TcpDeviceSender::from_arc(writer_arc);
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
    _address: String,
    _port: u16,
    key_code: i32,
    text: String,
) -> Result<(), String> {
    let writer_arc = {
        let guard = (*CONTROL_WRITER).lock().await;
        guard
            .as_ref()
            .cloned()
            .ok_or_else(|| "Not connected".to_string())?
    };
    let sender = TcpDeviceSender::from_arc(writer_arc);
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
