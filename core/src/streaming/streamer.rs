//! Streaming loop orchestration
//!
//! Wires together capture → encoder → QUIC send into a single coordinated pipeline.
//! Manages lifecycle, error handling, and graceful shutdown.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::bitrate::AdaptiveBitrate;
use super::capture;
use super::encoder::VideoEncoder;
use super::transport::{self, StreamServer, StreamTransportConfig};
use super::{EncodedPacket, StreamingConfig, VideoFrame};

/// Controls the streaming server lifecycle
pub struct StreamingServer {
    config: StreamingConfig,
    transport_config: StreamTransportConfig,
    cancel: CancellationToken,
    /// Watch channel for adaptive bitrate updates
    bitrate_tx: watch::Sender<u32>,
    /// Adaptive bitrate controller (optional)
    adaptive_bitrate: Option<AdaptiveBitrate>,
}

impl StreamingServer {
    /// Create a new streaming server with the given configurations
    pub fn new(config: StreamingConfig, transport_config: StreamTransportConfig) -> Self {
        let (bitrate_tx, _) = watch::channel(config.bitrate_bps);
        Self {
            config,
            transport_config,
            cancel: CancellationToken::new(),
            bitrate_tx,
            adaptive_bitrate: None,
        }
    }

    /// Enable adaptive bitrate control with the given controller
    pub fn with_adaptive_bitrate(mut self, mut adaptive: AdaptiveBitrate) -> Self {
        adaptive.attach(self.bitrate_tx.clone());
        self.adaptive_bitrate = Some(adaptive);
        self
    }

    /// Update the target bitrate dynamically (for adaptive bitrate control)
    pub fn update_bitrate(&self, new_bitrate_bps: u32) {
        let _ = self.bitrate_tx.send_if_modified(|current| {
            if *current != new_bitrate_bps {
                *current = new_bitrate_bps;
                info!("Adaptive bitrate: {} bps", new_bitrate_bps);
                true
            } else {
                false
            }
        });
    }

    /// Get a receiver for bitrate updates
    pub fn bitrate_watcher(&self) -> watch::Receiver<u32> {
        self.bitrate_tx.subscribe()
    }

    /// Start the streaming server — accepts one client connection and runs the pipeline
    ///
    /// This function:
    /// 1. Creates the QUIC server endpoint
    /// 2. Accepts an incoming connection
    /// 3. Starts the capture → encode → send pipeline
    /// 4. Runs until the connection is closed or an error occurs
    pub async fn run(&mut self) -> Result<()> {
        info!(
            "Starting streaming server: {}x{}@{}fps, {}bps",
            self.config.width, self.config.height, self.config.fps, self.config.bitrate_bps
        );

        // 1. Create QUIC server endpoint
        let server = StreamServer::new(self.transport_config.clone())
            .await
            .context("Failed to create QUIC server")?;

        let local_addr = server.local_addr()?;
        info!("Streaming server listening on {}", local_addr);

        // 2. Wait for incoming connection
        let incoming = tokio::select! {
            Some(conn) = server.accept_connection() => conn,
            _ = self.cancel.cancelled() => {
                info!("Streaming server cancelled while waiting for connection");
                return Ok(());
            }
        };

        let connection = incoming.await.context("Failed to accept QUIC connection")?;

        let peer = connection.remote_address();
        info!("Streaming client connected: {}", peer);

        // 3. Run the capture → encode → send pipeline
        self.run_pipeline(connection, server).await
    }

    /// Run the full streaming pipeline for a single connection
    async fn run_pipeline(
        &mut self,
        connection: quinn::Connection,
        _server: StreamServer,
    ) -> Result<()> {
        let cancel = self.cancel.clone();
        let (frame_tx, mut frame_rx) = mpsc::channel::<VideoFrame>(4);
        let (packet_tx, mut packet_rx) = mpsc::channel::<EncodedPacket>(8);

        let mut tasks = JoinSet::new();

        // Task 1: Screen capture (runs on dedicated OS thread internally)
        let capture_config = self.config.clone();
        let _capture_bitrate_rx = self.bitrate_watcher();
        let capture_cancel = cancel.clone();
        let capture_session = capture::start_capture(capture_config, frame_tx, capture_cancel)
            .await
            .context("Failed to start screen capture")?;

        info!("Screen capture session started");

        // Clone connection for use across multiple tasks
        let conn_for_transport = connection.clone();
        let conn_for_monitor = connection.clone();

        // Task 2: Video encoding
        // Clone config for encoder (bitrate will be updated via watch channel)
        let mut encoder_config = self.config.clone();
        let mut encoder_bitrate_rx = self.bitrate_watcher();

        // Update encoder config with current bitrate
        encoder_config.bitrate_bps = *encoder_bitrate_rx.borrow();

        let mut encoder =
            VideoEncoder::new(encoder_config).context("Failed to create video encoder")?;

        info!("Video encoder started (FFmpeg process spawned)");

        // Spawn encoding task — reads frames, produces packets
        let encode_cancel = cancel.clone();
        tasks.spawn(async move {
            info!("Encoding task started");
            let mut packets_encoded = 0u64;
            let mut frames_dropped = 0u64;

            loop {
                tokio::select! {
                    biased;

                    _ = encode_cancel.cancelled() => {
                        info!("Encoding task cancelled");
                        break;
                    }

                    // Check for bitrate updates
                    Ok(()) = encoder_bitrate_rx.changed() => {
                        let current_bitrate = *encoder_bitrate_rx.borrow();
                        debug!("Bitrate updated to {} bps", current_bitrate);
                        // Note: FFmpeg process can't change bitrate mid-stream
                        // This would require restarting the encoder for dynamic bitrate
                        // For now, we log and apply on next encoder lifecycle
                    }

                    // Process next frame
                    Some(frame) = frame_rx.recv() => {
                        match encoder.encode_frame(&frame) {
                            Ok(Some(packet)) => {
                                packets_encoded += 1;
                                if packet.is_keyframe {
                                    debug!("Keyframe encoded (seq={}, size={} bytes)", packet.sequence, packet.data.len());
                                }
                                trace_packet_stats(&packet);

                                // Send packet to transport
                                if packet_tx.send(packet).await.is_err() {
                                    warn!("Packet receiver dropped, stopping encoder");
                                    break;
                                }
                            }
                            Ok(None) => {
                                // Encoder has no output yet (latency/drain phase)
                                frames_dropped += 1;
                                if frames_dropped.is_multiple_of(30) {
                                    debug!("Encoder latency: {} frames waiting for output", frames_dropped);
                                }
                            }
                            Err(e) => {
                                error!("Encoding error: {}", e);
                                // Try to recover — continue processing frames
                            }
                        }
                    }
                }
            }

            // Drain remaining packets
            match encoder.drain() {
                Ok(packets) => {
                    let count = packets.len();
                    for packet in packets {
                        if packet_tx.send(packet).await.is_err() {
                            break;
                        }
                    }
                    info!("Drained {} remaining packets from encoder", count);
                }
                Err(e) => {
                    warn!("Error draining encoder: {}", e);
                }
            }

            info!(
                "Encoding task complete: {} packets encoded, {} frames dropped",
                packets_encoded, frames_dropped
            );
        });

        // Task 3: Packet transport — sends packets over QUIC
        let transport_cancel = cancel.clone();
        tasks.spawn(async move {
            info!("Transport task started");
            let mut packets_sent = 0u64;
            let mut bytes_sent = 0u64;
            let mut connection_closed = false;

            loop {
                tokio::select! {
                    biased;

                    _ = transport_cancel.cancelled() => {
                        info!("Transport task cancelled");
                        break;
                    }

                    // Send next packet
                    Some(packet) = packet_rx.recv() => {
                        if connection_closed {
                            warn!("Connection closed, dropping packet");
                            continue;
                        }

                        // Open a unidirectional stream for this packet
                        match conn_for_transport.open_uni().await {
                            Ok(mut send_stream) => {
                                // Build and send header
                                let header = transport::PacketHeader {
                                    sequence: packet.sequence,
                                    is_keyframe: packet.is_keyframe,
                                    timestamp_us: packet.timestamp.elapsed().as_micros() as u64,
                                };

                                if let Err(e) = send_stream.write_all(&header.as_bytes()).await {
                                    error!("Failed to send packet header (seq={}): {}", packet.sequence, e);
                                    connection_closed = true;
                                    continue;
                                }

                                let data_len = packet.data.len();
                                if let Err(e) = send_stream.write_all(&packet.data).await {
                                    error!("Failed to send packet data (seq={}): {}", packet.sequence, e);
                                    connection_closed = true;
                                    continue;
                                }

                                if let Err(e) = send_stream.finish() {
                                    error!("Failed to finish stream (seq={}): {}", packet.sequence, e);
                                    connection_closed = true;
                                    continue;
                                }

                                packets_sent += 1;
                                bytes_sent += data_len as u64;

                                if packets_sent.is_multiple_of(60) {
                                    debug!(
                                        "Transport stats: {} packets, {} bytes ({:.1} Mbps)",
                                        packets_sent,
                                        bytes_sent,
                                        (bytes_sent as f64 * 8.0) / 1_000_000.0
                                    );
                                }
                            }
                            Err(e) => {
                                error!("Failed to open stream: {}", e);
                                connection_closed = true;
                            }
                        }
                    }

                    // Connection closed
                    else => {
                        info!("All packet senders finished, transport task ending");
                        break;
                    }
                }
            }

            info!(
                "Transport task complete: {} packets sent, {} bytes transmitted",
                packets_sent, bytes_sent
            );
        });

        // Task 4: Monitor connection state and handle input streams from client
        let monitor_cancel = cancel.clone();
        tasks.spawn(async move {
            info!("Connection monitor started");

            loop {
                tokio::select! {
                    _ = monitor_cancel.cancelled() => {
                        info!("Connection monitor cancelled");
                        break;
                    }

                    // Accept unidirectional streams from client (input events, acks)
                    result = conn_for_monitor.accept_uni() => {
                        match result {
                            Ok(mut stream) => {
                                debug!("Received client stream");
                                // Read and discard client data (input events would be handled here)
                                let data = stream.read_to_end(4096).await;
                                match data {
                                    Ok(data) if !data.is_empty() => {
                                        debug!("Received {} bytes from client", data.len());
                                        // In full implementation, parse input events here
                                        // and route to the input injection module
                                    }
                                    Ok(_) => {
                                        debug!("Client stream closed (empty)");
                                    }
                                    Err(e) => {
                                        warn!("Error reading client stream: {}", e);
                                    }
                                }
                            }
                            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                                info!("Client disconnected");
                                break;
                            }
                            Err(e) => {
                                warn!("Connection error: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Task 5: Adaptive bitrate monitoring (if enabled)
        if let Some(adaptive_bitrate) = self.adaptive_bitrate.take() {
            let bitrate_cancel = cancel.clone();
            let rtt_connection = connection.clone();
            tasks.spawn(async move {
                info!("Adaptive bitrate monitor started");
                let monitor = AdaptiveBitrateMonitor::new(adaptive_bitrate);
                monitor.run(&rtt_connection, bitrate_cancel).await;
            });
        }

        // Wait for all tasks to complete or connection to close
        let result = tasks.join_next().await;

        // Cancel all tasks
        info!("Shutting down streaming pipeline...");
        cancel.cancel();

        // Drop capture session to clean up PipeWire resources
        drop(capture_session);

        // Wait for remaining tasks
        while let Some(res) = tasks.join_next().await {
            if let Err(e) = res {
                warn!("Task panicked: {}", e);
            }
        }

        info!("Streaming pipeline shut down complete");

        match result {
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) => Err(anyhow::anyhow!("Task failed: {}", e)),
            None => Ok(()),
        }
    }

    /// Signal the server to stop accepting new connections and shut down
    pub fn stop(&self) {
        info!("Stopping streaming server...");
        self.cancel.cancel();
    }

    /// Check if the server is still running
    pub fn is_running(&self) -> bool {
        !self.cancel.is_cancelled()
    }
}

/// Log packet statistics for monitoring
fn trace_packet_stats(packet: &EncodedPacket) {
    debug!(
        "Packet: seq={}, keyframe={}, size={} bytes, age={}ms",
        packet.sequence,
        packet.is_keyframe,
        packet.data.len(),
        packet.timestamp.elapsed().as_millis()
    );
}

/// Streaming client that connects to a server and receives video packets
pub struct StreamingClient {
    #[allow(dead_code)]
    config: StreamingConfig,
    transport_config: StreamTransportConfig,
}

impl StreamingClient {
    /// Create a new streaming client
    pub fn new(config: StreamingConfig, transport_config: StreamTransportConfig) -> Self {
        Self {
            config,
            transport_config,
        }
    }

    /// Connect to a streaming server and receive packets
    pub async fn connect(&self, server_addr: SocketAddr) -> Result<mpsc::Receiver<EncodedPacket>> {
        info!("Connecting to streaming server at {}", server_addr);

        let client = transport::StreamClient::new(self.transport_config.clone())
            .context("Failed to create streaming client")?;

        let connection = client
            .connect(server_addr)
            .await
            .context("Failed to connect to server")?;

        info!("Streaming connection established");

        let (packet_tx, packet_rx) = mpsc::channel(8);

        // Spawn packet receiver task
        tokio::spawn(async move {
            match transport::receive_packets(&connection, packet_tx).await {
                Ok(()) => info!("Streaming client receiver finished"),
                Err(e) => warn!("Streaming client receiver error: {}", e),
            }
        });

        Ok(packet_rx)
    }
}

/// Monitors QUIC connection stats and feeds RTT to the adaptive bitrate controller
struct AdaptiveBitrateMonitor {
    controller: AdaptiveBitrate,
    check_interval: tokio::time::Interval,
}

impl AdaptiveBitrateMonitor {
    fn new(controller: AdaptiveBitrate) -> Self {
        let check_interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        Self {
            controller,
            check_interval,
        }
    }

    async fn run(mut self, connection: &quinn::Connection, cancel: CancellationToken) {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("Adaptive bitrate monitor cancelled");
                    break;
                }

                _ = self.check_interval.tick() => {
                    // Get QUIC connection stats
                    let stats = connection.stats();
                    let rtt_ms = stats.path.rtt.as_millis();
                    debug!("QUIC RTT: {}ms", rtt_ms);
                    self.controller.update_rtt(rtt_ms);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::{EncoderPreset, H264Profile};

    #[test]
    fn test_streaming_server_creation() {
        let config = StreamingConfig::default();
        let transport_config = StreamTransportConfig::default();
        let server = StreamingServer::new(config, transport_config);

        assert!(server.is_running());
    }

    #[test]
    fn test_bitrate_update() {
        let config = StreamingConfig::default();
        let transport_config = StreamTransportConfig::default();
        let server = StreamingServer::new(config.clone(), transport_config);

        let new_bitrate = 4_000_000;
        server.update_bitrate(new_bitrate);

        let rx = server.bitrate_watcher();
        assert_eq!(*rx.borrow(), new_bitrate);
    }

    #[test]
    fn test_streaming_config_variants() {
        // Low quality config
        let low = StreamingConfig {
            width: 1280,
            height: 720,
            fps: 30,
            bitrate_bps: 2_000_000,
            profile: H264Profile::Baseline,
            preset: EncoderPreset::UltraFast,
        };
        assert_eq!(low.bitrate_bps, 2_000_000);

        // High quality config
        let high = StreamingConfig {
            width: 3840,
            height: 2160,
            fps: 60,
            bitrate_bps: 20_000_000,
            profile: H264Profile::High,
            preset: EncoderPreset::Medium,
        };
        assert_eq!(high.bitrate_bps, 20_000_000);
    }

    #[test]
    fn test_packet_header_export() {
        // Verify PacketHeader is accessible from transport module
        use super::transport::PacketHeader;

        let header = PacketHeader {
            sequence: 42,
            is_keyframe: true,
            timestamp_us: 1_000_000,
        };

        let bytes = header.as_bytes();
        assert_eq!(bytes.len(), 17);
    }
}
