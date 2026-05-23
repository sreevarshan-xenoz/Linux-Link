//! QUIC stream client for receiving H.264 video frames and Opus audio packets.
//!
//! Connects to a `StreamingServer`, receives encoded packets over unidirectional
//! QUIC streams, and demuxes them into video and audio channels.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::input_packet::InputPacket;
use super::transport::{self, CertManager, StreamClient, StreamTransportConfig};
use super::{AudioPacket, EncodedPacket};

/// Default port for the streaming service.
pub const DEFAULT_STREAMING_PORT: u16 = 4716;

/// Marker bytes for a client-to-server config QUIC stream.
/// Used to transmit settings (e.g. monitor index) before the pipeline starts.
const MONITOR_CONFIG_MARKER: [u8; 2] = [0xFF, 0x00];

/// QUIC Stream Client — connects to a StreamingServer and receives H.264 video frames.
///
/// # Usage
///
/// ```ignore
/// let cert_manager = std::sync::Arc::new(CertManager::new().unwrap());
/// let (mut client, packet_rx) = StreamingClient::connect("100.64.0.1:4716", cert_manager).await?;
/// // Spawn a task to consume packets from packet_rx
/// tokio::spawn(consume_packets(packet_rx));
/// client.start().await; // runs until cancelled
/// ```
pub struct StreamingClient {
    connection: Option<quinn::Connection>,
    #[allow(dead_code)]
    transport_config: StreamTransportConfig,
    #[allow(dead_code)]
    cert_manager: std::sync::Arc<CertManager>,
    frame_tx: mpsc::Sender<EncodedPacket>,
    #[allow(dead_code)]
    audio_tx: mpsc::Sender<AudioPacket>,
    cancel: CancellationToken,
    #[allow(dead_code)]
    channel_capacity: usize,
    /// Unique session ID for tracking this connection
    session_id: String,
}

impl StreamingClient {
    /// Create a new `StreamingClient` (not yet connected).
    ///
    /// `channel_capacity` controls the buffer size between the receive task
    /// and the consumer. A capacity of 8 is a reasonable default for real-time
    /// video. Returns the client and receiver channels for consuming frames and audio.
    pub fn new(
        channel_capacity: usize,
        cert_manager: std::sync::Arc<CertManager>,
    ) -> (Self, mpsc::Receiver<EncodedPacket>, mpsc::Receiver<AudioPacket>) {
        let (frame_tx, frame_rx) = mpsc::channel(channel_capacity);
        let (audio_tx, audio_rx) = mpsc::channel(channel_capacity);
        let client = Self {
            connection: None,
            transport_config: StreamTransportConfig::default(),
            cert_manager,
            frame_tx,
            audio_tx,
            cancel: CancellationToken::new(),
            channel_capacity,
            session_id: "".to_string(), // Will be initialized on connect
        };
        (client, frame_rx, audio_rx)
    }

    /// Connect to a streaming server at the given address.
    ///
    /// The address should be in the form `"host:port"`, e.g. `"100.64.0.1:4716"`.
    /// Optionally sends a `monitor_index` to the server for multi-monitor selection.
    /// Returns the client and receiver channels for consuming video frames and audio packets.
    pub async fn connect(
        addr: &str,
        cert_manager: std::sync::Arc<CertManager>,
        monitor_index: Option<u32>,
    ) -> Result<(
        Self,
        mpsc::Receiver<EncodedPacket>,
        mpsc::Receiver<AudioPacket>,
    )> {
        let addr: SocketAddr = addr
            .parse()
            .with_context(|| format!("Invalid server address: {addr}"))?;

        let channel_capacity = 8;
        let (frame_tx, frame_rx) = mpsc::channel(channel_capacity);
        let (audio_tx, audio_rx) = mpsc::channel(channel_capacity);

        let session_id = uuid::Uuid::new_v4().to_string();
        let conn_id = uuid::Uuid::new_v4().to_string();
        let span = tracing::info_span!(
            "stream_client",
            session = %session_id,
            conn = %conn_id,
            peer = %addr
        );

        use tracing::Instrument;

        async move {
            info!("Connecting to streaming server");

            let transport = StreamClient::new(StreamTransportConfig::default(), &cert_manager)
                .context("Failed to create QUIC transport")?;

            let server_name = addr.ip().to_string();
            let connection = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                transport.connect(addr, &server_name),
            )
            .await
            .context("Connection to streaming server timed out")?
            .context("Failed to connect to streaming server")?;

            info!("Streaming connection established");

            // Send optional monitor_index to the server as a config stream
            if let Some(index) = monitor_index {
                match connection.open_uni().await {
                    Ok(mut config_stream) => {
                        // Format: [0xFF, 0x00] config marker + 4 bytes LE monitor_index
                        let mut config_buf = [0u8; 6];
                        config_buf[0..2].copy_from_slice(&MONITOR_CONFIG_MARKER);
                        config_buf[2..6].copy_from_slice(&index.to_le_bytes());
                        if let Err(e) = config_stream.write_all(&config_buf).await {
                            warn!(error = %e, "Failed to send monitor index");
                        }
                        if let Err(e) = config_stream.finish() {
                            warn!(error = %e, "Failed to finish config stream");
                        }
                        info!(index, "Sent monitor selection to server");
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to open config stream");
                    }
                }
            }

            let client = Self {
                connection: Some(connection),
                transport_config: StreamTransportConfig::default(),
                cert_manager,
                frame_tx,
                audio_tx,
                cancel: CancellationToken::new(),
                channel_capacity,
                session_id,
            };

            Ok((client, frame_rx, audio_rx))
        }.instrument(span).await
    }

    /// Start receiving frames. This runs until cancelled or the connection closes.
    pub async fn start(&mut self) {
        let connection = match &self.connection {
            Some(conn) => conn.clone(),
            None => {
                error!("Cannot start: no active connection (call connect first)");
                return;
            }
        };

        let cancel = self.cancel.clone();
        let frame_tx = self.frame_tx.clone();
        let audio_tx = self.audio_tx.clone();

        let span = tracing::info_span!(
            "client_loop",
            session = %self.session_id,
            transport = "quic"
        );

        use tracing::Instrument;

        async move {
            info!("Starting frame receiver tasks");

            // Clone connection for the stats task before it gets moved into recv task
            let stats_connection = connection.clone();

            // Spawn the receive loop using our cancel-aware receiver
            let recv_cancel = cancel.clone();
            let recv_span = tracing::info_span!("packet_recv");
            let recv_handle = tokio::spawn(async move {
                let result = recv_with_cancel(&connection, frame_tx, audio_tx, recv_cancel).await;
                match result {
                    Ok(()) => debug!("Frame receiver finished normally"),
                    Err(e) => warn!(error = %e, "Frame receiver error"),
                }
            }.instrument(recv_span));

            // Spawn a stats feedback loop that periodically sends RTT data
            let stats_cancel = cancel.clone();
            let stats_span = tracing::info_span!("stats_feedback");
            let _stats_handle = tokio::spawn(async move {
                send_stats_loop(&stats_connection, stats_cancel).await;
            }.instrument(stats_span));

            // Wait for cancellation or receive task completion
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Streaming client loop cancelled");
                }
                result = recv_handle => {
                    if let Err(e) = result {
                        warn!(error = %e, "Receive task panicked");
                    }
                }
            }
        }.instrument(span).await
    }

    /// Signal the client to stop receiving.
    pub fn stop(&mut self) {
        info!("Stopping streaming client");
        self.cancel.cancel();
        self.connection = None;
    }

    /// Get the current QUIC RTT measurement.
    pub fn current_rtt(&self) -> Duration {
        match &self.connection {
            Some(conn) => conn.stats().path.rtt,
            None => Duration::ZERO,
        }
    }

    /// Get the raw QUIC connection (for advanced use cases).
    pub fn connection(&self) -> Option<&quinn::Connection> {
        self.connection.as_ref()
    }

    /// Check if the client is actively receiving.
    pub fn is_running(&self) -> bool {
        self.connection.is_some() && !self.cancel.is_cancelled()
    }

    /// Return a `CancellationToken` that can be used to cancel this client from outside.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Send an input event over the QUIC connection.
    ///
    /// Encodes the packet as compact binary and sends it over a unidirectional
    /// QUIC stream. The server's Task 4 will parse and inject it.
    pub async fn send_input(&self, packet: &InputPacket) -> Result<()> {
        let connection = self.connection.as_ref().context("No active connection")?;

        let data = packet.encode();
        let mut send_stream = connection
            .open_uni()
            .await
            .context("Failed to open input stream")?;

        send_stream
            .write_all(&data)
            .await
            .context("Failed to send input packet")?;

        send_stream
            .finish()
            .context("Failed to finish input stream")?;

        debug!("Sent input packet: {} bytes over QUIC", data.len());
        Ok(())
    }
}

/// Receive packets with cancellation support — demuxes video and audio streams.
///
/// Reads packet headers and routes to the appropriate channel based on `stream_kind`:
/// - `stream_kind == 0` → video frames on `frame_tx`
/// - `stream_kind == 1` → audio packets on `audio_tx`
async fn recv_with_cancel(
    connection: &quinn::Connection,
    frame_tx: mpsc::Sender<EncodedPacket>,
    audio_tx: mpsc::Sender<AudioPacket>,
    cancel: CancellationToken,
) -> Result<()> {
    info!("Starting packet receiver (video + audio)");

    loop {
        tokio::select! {
            biased;

            _ = cancel.cancelled() => {
                debug!("Packet receiver cancelled");
                break;
            }

            result = connection.accept_uni() => {
                match result {
                    Ok(mut recv_stream) => {
                        // Read the 18-byte packet header
                        let mut header_bytes = [0u8; 18];
                        if let Err(e) = recv_stream.read_exact(&mut header_bytes).await {
                            debug!("Failed to read packet header: {e}");
                            continue;
                        }

                        let header = match transport::PacketHeader::from_bytes(&header_bytes) {
                            Ok(h) => h,
                            Err(e) => {
                                warn!("Invalid packet header: {e}");
                                continue;
                            }
                        };

                        // Read the payload (up to 10 MB for video, 64 KB for audio)
                        let max_size = if header.stream_kind == transport::STREAM_KIND_AUDIO {
                            64 * 1024
                        } else {
                            10 * 1024 * 1024
                        };
                        let data = match recv_stream.read_to_end(max_size).await {
                            Ok(data) => data,
                            Err(e) => {
                                warn!("Failed to read packet data (seq={}, kind={}): {e}", header.sequence, header.stream_kind);
                                continue;
                            }
                        };

                        if header.stream_kind == transport::STREAM_KIND_AUDIO {
                            // Route to audio channel
                            let packet = AudioPacket {
                                data,
                                sequence: header.sequence,
                                timestamp: std::time::Instant::now(),
                                is_config: false,
                            };

                            if audio_tx.send(packet).await.is_err() {
                                debug!("Audio receiver dropped — channel closed");
                                break;
                            }
                        } else {
                            // Route to video channel
                            let packet = EncodedPacket {
                                data,
                                is_keyframe: header.is_keyframe,
                                timestamp: std::time::Instant::now(),
                                sequence: header.sequence,
                            };

                            if frame_tx.send(packet).await.is_err() {
                                debug!("Frame receiver dropped — channel closed");
                                break;
                            }
                        }
                    }
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                        debug!("Connection closed by peer");
                        break;
                    }
                    Err(e) => {
                        warn!("Stream accept error: {e}");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Periodically send connection stats (RTT) back to the server on a feedback stream.
///
/// The server can use this information for adaptive bitrate control.
async fn send_stats_loop(connection: &quinn::Connection, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!("Stats feedback cancelled");
                break;
            }

            _ = interval.tick() => {
                let stats = connection.stats();
                let rtt_us = stats.path.rtt.as_micros() as u64;
                let lost = stats.path.lost_packets;

                // Simple binary feedback message:
                // [0..8]  RTT in microseconds (u64 LE)
                // [8..16] Lost packets (u64 LE)
                let mut buf = [0u8; 16];
                buf[0..8].copy_from_slice(&rtt_us.to_le_bytes());
                buf[8..16].copy_from_slice(&lost.to_le_bytes());

                match connection.open_uni().await {
                    Ok(mut stream) => {
                        if let Err(e) = stream.write_all(&buf).await {
                            debug!("Failed to send stats to server: {e}");
                        } else {
                            let _ = stream.finish();
                        }
                    }
                    Err(e) => {
                        debug!("Failed to open stats stream: {e}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_streaming_client_new() {
        use super::transport::CertManager;
        let cert_manager =
            std::sync::Arc::new(CertManager::new().expect("Failed to create CertManager"));
        let (client, _frame_rx, _audio_rx) = StreamingClient::new(8, cert_manager);
        assert!(!client.is_running());
        assert_eq!(client.current_rtt(), Duration::ZERO);
    }

    #[test]
    fn test_stats_buffer_format() {
        let rtt = Duration::from_millis(50);
        let lost: u64 = 3;

        let rtt_us = rtt.as_micros() as u64;
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&rtt_us.to_le_bytes());
        buf[8..16].copy_from_slice(&lost.to_le_bytes());

        let recovered_rtt = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let recovered_lost = u64::from_le_bytes(buf[8..16].try_into().unwrap());

        assert_eq!(recovered_rtt, 50_000); // 50 ms in microseconds
        assert_eq!(recovered_lost, 3);
    }
}
