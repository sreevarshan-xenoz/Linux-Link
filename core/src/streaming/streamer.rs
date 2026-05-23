//! Streaming loop orchestration
//!
//! Wires together capture → encoder → QUIC send into a single coordinated pipeline.
//! Manages lifecycle, error handling, and graceful shutdown.

use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Instrument};
use uuid::Uuid;

use super::audio::{AudioConfig, AudioEncoder as AudioOpusEncoder};
use super::audio_capture;
use super::bitrate::AdaptiveBitrate;
use super::capture;
use super::encoder::VideoEncoder;
use super::input_packet::InputPacket;
use super::transport::{self, CertManager, StreamServer, StreamTransportConfig};
use super::{EncodedPacket, StreamingConfig, VideoFrame};

/// Controls the streaming server lifecycle
pub struct StreamingServer {
    config: StreamingConfig,
    transport_config: StreamTransportConfig,
    cert_manager: std::sync::Arc<CertManager>,
    cancel: CancellationToken,
    /// Unique session ID for the lifetime of this server instance
    session_id: String,
    /// Watch channel for adaptive bitrate updates
    bitrate_tx: watch::Sender<u32>,
    /// Adaptive bitrate controller (optional)
    adaptive_bitrate: Option<AdaptiveBitrate>,
    /// Channel for routing input events received from client over this QUIC connection
    input_tx: Option<mpsc::Sender<InputPacket>>,
}

impl StreamingServer {
    /// Create a new streaming server with the given configurations
    pub fn new(
        config: StreamingConfig,
        transport_config: StreamTransportConfig,
        cert_manager: std::sync::Arc<CertManager>,
    ) -> Self {
        let (bitrate_tx, _) = watch::channel(config.bitrate_bps);
        Self {
            config,
            transport_config,
            cert_manager,
            cancel: CancellationToken::new(),
            session_id: Uuid::new_v4().to_string(),
            bitrate_tx,
            adaptive_bitrate: None,
            input_tx: None,
        }
    }

    /// Enable adaptive bitrate control with the given controller
    pub fn with_adaptive_bitrate(mut self, mut adaptive: AdaptiveBitrate) -> Self {
        adaptive.attach(self.bitrate_tx.clone());
        self.adaptive_bitrate = Some(adaptive);
        self
    }

    /// Set a channel to receive input events from the remote client.
    ///
    /// When set, the server will parse incoming QUIC streams as binary `InputPacket`
    /// values and forward them through this channel for injection on the host system.
    pub fn set_input_channel(&mut self, tx: mpsc::Sender<InputPacket>) {
        self.input_tx = Some(tx);
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
    pub async fn run(&mut self) -> Result<()> {
        let conn_id = Uuid::new_v4().to_string();
        let span = tracing::info_span!(
            "stream_session",
            session = %self.session_id,
            conn = %conn_id,
            proto = %crate::protocol::PROTOCOL_VERSION,
            peer = tracing::field::Empty,
            transport = "quic"
        );

        use tracing::Instrument;

        async {
            info!(
                "Starting streaming server: {}x{}@{}fps, {}bps",
                self.config.width, self.config.height, self.config.fps, self.config.bitrate_bps
            );

            // 1. Create QUIC server endpoint
            let server = StreamServer::new(self.transport_config.clone(), &self.cert_manager)
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
            tracing::Span::current().record("peer", &peer.to_string());
            info!("Streaming client connected: {}", peer);

            // 3. Run the capture → encode → send pipeline
            self.run_pipeline(connection, server).await
        }
        .instrument(span)
        .await
    }

    /// Run the full streaming pipeline for a single connection
    async fn run_pipeline(
        &mut self,
        connection: quinn::Connection,
        _server: StreamServer,
    ) -> Result<()> {
        // Read optional client config stream before starting the pipeline.
        read_client_config(&connection, &mut self.config).await;

        let cancel = self.cancel.clone();
        let (frame_tx, mut frame_rx) = mpsc::channel::<VideoFrame>(4);
        let (packet_tx, mut packet_rx) = mpsc::channel::<EncodedPacket>(8);

        let mut tasks = JoinSet::new();

        // Task 1: Screen capture (runs on dedicated OS thread internally)
        let capture_config = self.config.clone();
        let _capture_bitrate_rx = self.bitrate_watcher();
        let capture_cancel = cancel.clone();
        let capture_session = capture::start_capture_auto(capture_config, frame_tx, capture_cancel)
            .await
            .context("Failed to start screen capture")?;

        info!("Screen capture session started");

        // Clone connection for use across multiple tasks
        let conn_for_transport = connection.clone();
        let conn_for_monitor = connection.clone();
        let conn_for_bitrate = connection.clone();
        let conn_for_audio = connection.clone();

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
        let encode_span = tracing::info_span!("video_encode");
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
                                if frames_dropped % 30 == 0 {
                                    debug!("Encoder latency: {} frames waiting for output", frames_dropped);
                                }
                            }
                            Err(e) => {
                                error!(error = %e, "Encoding failure");
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
                    info!(count, "Drained remaining packets from encoder");
                }
                Err(e) => {
                    warn!(error = %e, "Error draining encoder");
                }
            }

            info!(
                packets_encoded,
                frames_dropped,
                "Encoding task complete"
            );
        }.instrument(encode_span));

        // Task 3: Packet transport — sends packets over QUIC
        let transport_cancel = cancel.clone();
        let transport_span = tracing::info_span!("video_transport");
        tasks.spawn(async move {
            info!("Transport task started");
            let mut packets_sent = 0u64;
            let mut bytes_sent = 0u64;
            let mut packets_dropped = 0u64;
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
                            packets_dropped += 1;
                            continue;
                        }

                        // Open a unidirectional stream for this packet
                        match conn_for_transport.open_uni().await {
                            Ok(mut send_stream) => {
                                // Build and send header
                                let header = transport::PacketHeader {
                                    sequence: packet.sequence,
                                    stream_kind: transport::STREAM_KIND_VIDEO,
                                    is_keyframe: packet.is_keyframe,
                                    timestamp_us: packet.timestamp.elapsed().as_micros() as u64,
                                };

                                if let Err(e) = send_stream.write_all(&header.as_bytes()).await {
                                    error!(error = %e, seq = packet.sequence, "Failed to send packet header");
                                    connection_closed = true;
                                    packets_dropped += 1;
                                    continue;
                                }

                                let data_len = packet.data.len();
                                if let Err(e) = send_stream.write_all(&packet.data).await {
                                    error!(error = %e, seq = packet.sequence, "Failed to send packet data");
                                    connection_closed = true;
                                    packets_dropped += 1;
                                    continue;
                                }

                                if let Err(e) = send_stream.finish() {
                                    error!(error = %e, seq = packet.sequence, "Failed to finish stream");
                                    connection_closed = true;
                                    packets_dropped += 1;
                                    continue;
                                }

                                packets_sent += 1;
                                bytes_sent += data_len as u64;

                                if packets_sent % 60 == 0 {
                                    debug!(
                                        sent = packets_sent,
                                        bytes = bytes_sent,
                                        dropped = packets_dropped,
                                        mbps = %format!("{:.1}", (bytes_sent as f64 * 8.0) / 1_000_000.0),
                                        "Transport stats"
                                    );
                                }
                            }
                            Err(e) => {
                                error!(error = %e, "Failed to open QUIC stream");
                                connection_closed = true;
                                packets_dropped += 1;
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
                packets_sent,
                bytes_sent,
                packets_dropped,
                "Transport task complete"
            );
        }.instrument(transport_span));

        // Task 4: Monitor connection state and handle input streams from client
        let monitor_cancel = cancel.clone();
        let input_tx = self.input_tx.clone();
        let monitor_span = tracing::info_span!("connection_monitor");
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
                                debug!("Accepted client stream");
                                // Read the entire payload (max 64KB per input packet)
                                let data = stream.read_to_end(64 * 1024).await;
                                match data {
                                    Ok(data) if !data.is_empty() => {
                                        debug!(size = data.len(), "Received client data");

                                        // Skip 16-byte packets: these are stats feedback
                                        if data.len() == 16 {
                                            debug!("Handled stats packet via low-level loop");
                                            continue;
                                        }

                                        // Parse as binary InputPacket
                                        match InputPacket::decode(&data) {
                                            Ok(packet) => {
                                                // Forward to input injector via channel
                                                if let Some(ref tx) = input_tx {
                                                   if tx.send(packet).await.is_err() {
                                                       debug!("Input receiver dropped, stopping monitor");
                                                       break;
                                                   }
                                                }
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "Failed to parse input packet");
                                            }
                                        }
                                    }
                                    Ok(_) => {
                                        debug!("Client stream closed gracefully");
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "Error reading client stream");
                                    }
                                }
                            }
                            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                                info!("Client disconnected via application close");
                                break;
                            }
                            Err(e) => {
                                warn!(error = %e, "Connection error in monitor");
                                break;
                            }
                        }
                    }
                }
            }
        }.instrument(monitor_span));

        // Task 5: Adaptive bitrate monitoring (if enabled)
        if let Some(adaptive_bitrate) = self.adaptive_bitrate.take() {
            let bitrate_cancel = cancel.clone();
            let bitrate_span = tracing::info_span!("bitrate_monitor");
            tasks.spawn(async move {
                info!("Adaptive bitrate monitor started");
                let monitor = AdaptiveBitrateMonitor::new(adaptive_bitrate);
                monitor.run(&conn_for_bitrate, bitrate_cancel).await;
            }.instrument(bitrate_span));
        }

        // Task 6: Audio capture + Opus encoding + QUIC send (F1: Audio Streaming)
        let audio_cancel = cancel.clone();
        let audio_pipeline_cancel = cancel.clone();
        let audio_span = tracing::info_span!("audio_pipeline");
        tasks.spawn(async move {
            info!("Audio task started");

            let audio_config = AudioConfig {
                sample_rate: 48000,
                channels: 2,
                bitrate_bps: 64_000,
                frame_duration_ms: 20,
            };

            let mut encoder = match AudioOpusEncoder::new(audio_config) {
                Ok(e) => e,
                Err(e) => {
                    error!(error = %e, "Failed to create Opus encoder");
                    return;
                }
            };

            let frame_samples = encoder.config().samples_per_frame();
            let channels = encoder.config().channels;
            let frame_size_ms = encoder.config().frame_duration_ms as u64;

            // Try PipeWire audio loopback capture
            let (pcm_tx, mut pcm_rx) = mpsc::channel::<audio_capture::PcmBuffer>(8);
            let pw_cancel = audio_pipeline_cancel.clone();
            let pw_err = match audio_capture::start_audio_capture(
                48000, 2, 20, pcm_tx, pw_cancel,
            )
            .await
            {
                Ok(_session) => {
                    info!("PipeWire audio loopback active");
                    None
                }
                Err(e) => {
                    info!(error = %e, "PipeWire audio capture unavailable, falling back to silence");
                    Some(e)
                }
            };
            let using_pipewire = pw_err.is_none();

            // Silence fallback buffer
            let silence_buffer = vec![0i16; frame_samples * channels as usize];
            let mut silence_interval = tokio::time::interval(Duration::from_millis(frame_size_ms));
            silence_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut packet_seq = 0u64;
            let mut packets_sent = 0u64;
            let mut connection_closed = false;

            if using_pipewire {
                loop {
                    tokio::select! {
                        biased;
                        _ = audio_cancel.cancelled() => {
                            info!(packets = packets_sent, "Audio task cancelled");
                            break;
                        }
                        pcm = pcm_rx.recv() => {
                            let Some(pcm) = pcm else {
                                info!("Audio capture source closed");
                                break;
                            };
                            if connection_closed { break; }

                            let packet = match encoder.encode(&pcm.data) {
                                Ok(Some(p)) => p,
                                Ok(None) => continue,
                                Err(e) => { debug!(error = %e, "Opus encode skip"); continue; }
                            };

                            if let Err(e) = send_audio_packet(
                                &conn_for_audio, packet, packet_seq, &mut connection_closed,
                            ).await {
                                warn!(error = %e, "Audio transport failed");
                                connection_closed = true;
                                continue;
                            }

                            packets_sent += 1;
                            packet_seq += 1;

                            if packets_sent % 600 == 0 {
                                debug!(sent = packets_sent, "Audio streaming healthy");
                            }
                        }
                    }
                }
            } else {
                loop {
                    tokio::select! {
                        biased;
                        _ = audio_cancel.cancelled() => {
                            info!(packets = packets_sent, "Silence audio task cancelled");
                            break;
                        }
                        _ = silence_interval.tick() => {
                            if connection_closed { break; }

                            let packet = match encoder.encode(&silence_buffer) {
                                Ok(Some(p)) => p,
                                Ok(None) => continue,
                                Err(e) => { debug!(error = %e, "Silence encode skip"); continue; }
                            };

                            if let Err(e) = send_audio_packet(
                                &conn_for_audio, packet, packet_seq, &mut connection_closed,
                            ).await {
                                warn!(error = %e, "Silence audio transport failed");
                                connection_closed = true;
                                continue;
                            }

                            packets_sent += 1;
                            packet_seq += 1;
                        }
                    }
                }
            }

            info!(packets_sent, "Audio task complete");
        }.instrument(audio_span));

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

/// Read an optional client config stream from the QUIC connection.
///
/// The client may send a small config packet (6 bytes) immediately after
/// establishing the connection to request a specific monitor index.
/// This is read with a short timeout so the pipeline is not blocked if
/// no config is sent.
async fn read_client_config(connection: &quinn::Connection, config: &mut StreamingConfig) {
    tokio::select! {
        biased;
        result = connection.accept_uni() => {
            match result {
                Ok(mut stream) => {
                    let mut buf = [0u8; 6];
                    match tokio::time::timeout(Duration::from_millis(500), stream.read_exact(&mut buf)).await {
                        Ok(Ok(())) => {
                            if buf[0..2] == [0xFF, 0x00] {
                                let monitor_index = u32::from_le_bytes(
                                    buf[2..6].try_into().unwrap_or([0u8; 4]),
                                );
                                config.monitor_index = monitor_index;
                                info!(
                                    "Client config: monitor_index={}",
                                    monitor_index
                                );
                            } else {
                                debug!(
                                    "Unknown config marker: {:02X?}",
                                    &buf[0..2]
                                );
                            }
                        }
                        Ok(Err(e)) => {
                            debug!("Config stream read error: {e}");
                        }
                        Err(_) => {
                            debug!("Config stream timeout — no client config");
                        }
                    }
                }
                Err(e) => {
                    debug!("No config stream from client: {e}");
                }
            }
        }
        _ = tokio::time::sleep(Duration::from_millis(200)) => {
            debug!("No client config stream within 200ms");
        }
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

/// Helper: send an encoded audio packet over the QUIC connection.
async fn send_audio_packet(
    conn: &quinn::Connection,
    packet: super::AudioPacket,
    sequence: u64,
    connection_closed: &mut bool,
) -> Result<()> {
    match conn.open_uni().await {
        Ok(mut send_stream) => {
            let header = transport::PacketHeader {
                sequence,
                stream_kind: transport::STREAM_KIND_AUDIO,
                is_keyframe: false,
                timestamp_us: packet.timestamp.elapsed().as_micros() as u64,
            };
            send_stream.write_all(&header.as_bytes()).await?;
            send_stream.write_all(&packet.data).await?;
            send_stream.finish()?;
            Ok(())
        }
        Err(e) => {
            *connection_closed = true;
            Err(anyhow::anyhow!("Failed to open audio stream: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::{EncoderPreset, H264Profile, HardwareEncoder, VideoCodec};

    #[test]
    fn test_streaming_server_creation() {
        let config = StreamingConfig::default();
        let transport_config = StreamTransportConfig::default();
        let cert_manager =
            std::sync::Arc::new(CertManager::new().expect("Failed to create CertManager"));
        let server = StreamingServer::new(config, transport_config, cert_manager);

        assert!(server.is_running());
    }

    #[test]
    fn test_bitrate_update() {
        let config = StreamingConfig::default();
        let transport_config = StreamTransportConfig::default();
        let cert_manager =
            std::sync::Arc::new(CertManager::new().expect("Failed to create CertManager"));
        let server = StreamingServer::new(config.clone(), transport_config, cert_manager);

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
            codec: VideoCodec::H264,
            profile: H264Profile::Baseline,
            preset: EncoderPreset::UltraFast,
            hardware_encoder: HardwareEncoder::Auto,
            monitor_index: 0,
        };
        assert_eq!(low.bitrate_bps, 2_000_000);

        // High quality config
        let high = StreamingConfig {
            width: 3840,
            height: 2160,
            fps: 60,
            bitrate_bps: 20_000_000,
            codec: VideoCodec::H264,
            profile: H264Profile::High,
            preset: EncoderPreset::Medium,
            hardware_encoder: HardwareEncoder::Auto,
            monitor_index: 0,
        };
        assert_eq!(high.bitrate_bps, 20_000_000);
    }

    #[test]
    fn test_packet_header_export() {
        // Verify PacketHeader is accessible from transport module
        use super::transport::{PacketHeader, STREAM_KIND_VIDEO};

        let header = PacketHeader {
            sequence: 42,
            stream_kind: STREAM_KIND_VIDEO,
            is_keyframe: true,
            timestamp_us: 1_000_000,
        };

        let bytes = header.as_bytes();
        assert_eq!(bytes.len(), 18);
    }
}
