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

use super::connection::{ConnectionError, QuinnConnection, SharedConnection};
use super::input_packet::InputPacket;
use super::transport::{self, CertManager, StreamTransportConfig};
use super::{AudioPacket, EncodedPacket};

/// Default port for the streaming service.
pub const DEFAULT_STREAMING_PORT: u16 = 4716;

/// Marker bytes for a client-to-server config QUIC stream.
/// Used to transmit settings (e.g. monitor index) before the pipeline starts.
pub(crate) const MONITOR_CONFIG_MARKER: [u8; 2] = [0xFF, 0x00];

/// Marker bytes for a client-to-server identity QUIC stream:
/// `[0xFE, 0x00, len:u8, utf8 deviceId]`. The QUIC TLS layer is anonymous
/// (`with_no_client_auth` on both ends), so this is how the server binds a
/// video session to the device that paired over the control channel.
pub(crate) const DEVICE_ID_MARKER: [u8; 2] = [0xFE, 0x00];

/// Marker bytes for a client-to-server codec-capability QUIC stream (R4 C1):
/// `[0xFD, 0x00, caps:u8]`. Absent = legacy client that only decodes H.264.
pub(crate) const CODEC_CAPS_MARKER: [u8; 2] = [0xFD, 0x00];

/// `CODEC_CAPS_MARKER` bit 0: the client can decode H.265/HEVC Annex-B.
/// H.264 is assumed for every client; future bits cover AV1 etc.
pub const CODEC_CAP_HEVC: u8 = 0b0000_0001;

/// QUIC Stream Client — connects to a StreamingServer and receives H.264 video frames.
///
/// # Usage
///
/// ```ignore
/// let cert_manager = std::sync::Arc::new(CertManager::new().unwrap());
/// let (mut client, packet_rx) = StreamingClient::connect("100.64.0.1:4716", cert_manager, None, None, None).await?;
/// // Spawn a task to consume packets from packet_rx
/// tokio::spawn(consume_packets(packet_rx));
/// client.start().await; // runs until cancelled
/// ```
pub struct StreamingClient {
    connection: Option<SharedConnection>,
    frame_tx: mpsc::Sender<EncodedPacket>,
    audio_tx: mpsc::Sender<AudioPacket>,
    cancel: CancellationToken,
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
        _cert_manager: std::sync::Arc<CertManager>,
    ) -> (
        Self,
        mpsc::Receiver<EncodedPacket>,
        mpsc::Receiver<AudioPacket>,
    ) {
        let (frame_tx, frame_rx) = mpsc::channel(channel_capacity);
        let (audio_tx, audio_rx) = mpsc::channel(channel_capacity);
        let client = Self {
            connection: None,
            frame_tx,
            audio_tx,
            cancel: CancellationToken::new(),
            session_id: String::new(),
        };
        (client, frame_rx, audio_rx)
    }

    /// Connect to a streaming server at the given address.
    ///
    /// The address should be in the form `"host:port"`, e.g. `"100.64.0.1:4716"`.
    /// Optionally sends a `monitor_index` to the server for multi-monitor selection.
    /// `device_id` is announced in-band so the server can apply its pairing gate.
    /// `codec_caps` (R4 C1, see [`CODEC_CAP_HEVC`]) advertises the client's
    /// decodable set; `None` (older callers) means H.264-only.
    /// Returns the client and receiver channels for consuming video frames and audio packets.
    pub async fn connect(
        addr: &str,
        cert_manager: std::sync::Arc<CertManager>,
        monitor_index: Option<u32>,
        device_id: Option<&str>,
        codec_caps: Option<u8>,
    ) -> Result<(
        Self,
        mpsc::Receiver<EncodedPacket>,
        mpsc::Receiver<AudioPacket>,
    )> {
        let addr: SocketAddr = addr
            .parse()
            .with_context(|| format!("Invalid server address: {addr}"))?;

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

            let transport = super::transport::StreamClient::new(
                StreamTransportConfig::default(),
                &cert_manager,
            )
            .context("Failed to create QUIC transport")?;

            let server_name = addr.ip().to_string();
            let quic_connection = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                transport.connect(addr, &server_name),
            )
            .await
            .context("Connection to streaming server timed out")?
            .context("Failed to connect to streaming server")?;
            info!("Streaming connection established");

            let (client, frame_rx, audio_rx) = Self::attach_with_session(
                QuinnConnection::shared(quic_connection),
                monitor_index,
                device_id,
                codec_caps,
                session_id,
            )
            .await;
            Ok((client, frame_rx, audio_rx))
        }
        .instrument(span)
        .await
    }

    /// Adopt an already-established transport-agnostic connection — e.g. an
    /// iroh WAN dial (`super::IrohDial`) — into the same receive pipeline
    /// `connect` builds. The caller keeps ownership of the endpoint/TLS
    /// lifecycle; this only wraps the connection and optionally ships the
    /// monitor-selection config stream.
    pub async fn attach(
        connection: SharedConnection,
        monitor_index: Option<u32>,
        device_id: Option<&str>,
        codec_caps: Option<u8>,
    ) -> (
        Self,
        mpsc::Receiver<EncodedPacket>,
        mpsc::Receiver<AudioPacket>,
    ) {
        Self::attach_with_session(
            connection,
            monitor_index,
            device_id,
            codec_caps,
            uuid::Uuid::new_v4().to_string(),
        )
        .await
    }

    async fn attach_with_session(
        connection: SharedConnection,
        monitor_index: Option<u32>,
        device_id: Option<&str>,
        codec_caps: Option<u8>,
        session_id: String,
    ) -> (
        Self,
        mpsc::Receiver<EncodedPacket>,
        mpsc::Receiver<AudioPacket>,
    ) {
        let channel_capacity = 8;
        let (frame_tx, frame_rx) = mpsc::channel(channel_capacity);
        let (audio_tx, audio_rx) = mpsc::channel(channel_capacity);

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

        // Announce our device id so the server's pairing gate can bind this
        // video session to the device that paired over the control channel.
        if let Some(id) = device_id {
            let id_bytes = id.as_bytes();
            if id_bytes.len() <= u8::MAX as usize {
                match connection.open_uni().await {
                    Ok(mut identity_stream) => {
                        let mut buf = Vec::with_capacity(3 + id_bytes.len());
                        buf.extend_from_slice(&DEVICE_ID_MARKER);
                        buf.push(id_bytes.len() as u8);
                        buf.extend_from_slice(id_bytes);
                        if let Err(e) = identity_stream.write_all(&buf).await {
                            warn!(error = %e, "Failed to send device identity");
                        }
                        if let Err(e) = identity_stream.finish() {
                            warn!(error = %e, "Failed to finish identity stream");
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to open identity stream");
                    }
                }
            } else {
                warn!("Device id too long to announce — pairing gate will reject");
            }
        }

        // Advertise our decodable codec set (R4 C1). Absent = H.264-only.
        if let Some(caps) = codec_caps
            && caps != 0
        {
            match connection.open_uni().await {
                Ok(mut caps_stream) => {
                    let buf = [CODEC_CAPS_MARKER[0], CODEC_CAPS_MARKER[1], caps];
                    if let Err(e) = caps_stream.write_all(&buf).await {
                        warn!(error = %e, "Failed to send codec caps");
                    }
                    if let Err(e) = caps_stream.finish() {
                        warn!(error = %e, "Failed to finish codec caps stream");
                    }
                    info!(caps, "Sent codec capabilities to server");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to open codec caps stream");
                }
            }
        }

        let client = Self {
            connection: Some(connection),
            frame_tx,
            audio_tx,
            cancel: CancellationToken::new(),
            session_id,
        };

        (client, frame_rx, audio_rx)
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
            let recv_handle = tokio::spawn(
                async move {
                    let result =
                        recv_with_cancel(&connection, frame_tx, audio_tx, recv_cancel).await;
                    match result {
                        Ok(()) => debug!("Frame receiver finished normally"),
                        Err(e) => warn!(error = %e, "Frame receiver error"),
                    }
                }
                .instrument(recv_span),
            );

            // Spawn a stats feedback loop that periodically sends RTT data
            let stats_cancel = cancel.clone();
            let stats_span = tracing::info_span!("stats_feedback");
            let _stats_handle = tokio::spawn(
                async move {
                    send_stats_loop(&stats_connection, stats_cancel).await;
                }
                .instrument(stats_span),
            );

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
        }
        .instrument(span)
        .await
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
            Some(conn) => conn.stats().rtt,
            None => Duration::ZERO,
        }
    }

    /// Get the transport-agnostic connection handle (for input sends / stats).
    pub fn connection(&self) -> Option<&SharedConnection> {
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
    connection: &SharedConnection,
    frame_tx: mpsc::Sender<EncodedPacket>,
    audio_tx: mpsc::Sender<AudioPacket>,
    cancel: CancellationToken,
) -> Result<()> {
    info!("Starting packet receiver (video + audio)");

    // Video sequence-gap tracking for IDR requests. Because each frame is sent
    // on its own unidirectional stream, frames can complete out of order; we
    // only ask for a fresh IDR when a *non-keyframe* arrives with a gap before
    // it (a broken delta chain), and rate-limit so we don't spam the server.
    let mut last_video_seq: Option<u64> = None;
    let mut last_idr_request: Option<std::time::Instant> = None;
    const IDR_REQUEST_INTERVAL: Duration = Duration::from_millis(250);

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
                            // Gap detection: a missing frame between the last
                            // delta we got and this one breaks the decode chain.
                            // A keyframe restarts the chain, so it never needs a
                            // request; a delta after a gap does.
                            let gap = !header.is_keyframe
                                && last_video_seq
                                    .is_some_and(|last| header.sequence > last + 1);
                            if gap {
                                let now = std::time::Instant::now();
                                let throttled = last_idr_request
                                    .is_some_and(|t| now.duration_since(t) < IDR_REQUEST_INTERVAL);
                                if !throttled {
                                    last_idr_request = Some(now);
                                    debug!(
                                        seq = header.sequence,
                                        last = ?last_video_seq,
                                        "Video sequence gap — requesting IDR"
                                    );
                                    send_keyframe_request(connection).await;
                                }
                            }
                            last_video_seq = Some(header.sequence);

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
                    Err(ConnectionError::Closed) => {
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

/// Best-effort IDR request to the server after a detected video gap.
async fn send_keyframe_request(connection: &SharedConnection) {
    let data = InputPacket::RequestKeyframe.encode();
    match connection.open_uni().await {
        Ok(mut stream) => {
            if let Err(e) = stream.write_all(&data).await {
                debug!("Failed to send IDR request: {e}");
            } else {
                let _ = stream.finish();
            }
        }
        Err(e) => {
            debug!("Failed to open IDR request stream: {e}");
        }
    }
}

/// Periodically send connection stats (RTT) back to the server on a feedback stream.
///
/// The server can use this information for adaptive bitrate control.
async fn send_stats_loop(connection: &SharedConnection, cancel: CancellationToken) {
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
                let rtt_us = stats.rtt.as_micros() as u64;
                let lost = stats.lost_packets;

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
