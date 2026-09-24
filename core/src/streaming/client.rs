//! QUIC stream client for receiving H.264 video frames and Opus audio packets.
//!
//! Connects to a `StreamingServer`, receives encoded packets over unidirectional
//! QUIC streams, and demuxes them into video and audio channels.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::connection::{ConnectionError, QuinnConnection, SharedConnection};
use super::input_packet::{InputPacket, SAMPLE_E2E, SampleBatch};
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
pub const CODEC_CAPS_MARKER: [u8; 2] = [0xFD, 0x00];

/// `CODEC_CAPS_MARKER` bit 0: the client can decode H.265/HEVC Annex-B.
/// H.264 is assumed for every client; future bits cover AV1 etc.
pub const CODEC_CAP_HEVC: u8 = 0b0000_0001;

/// R4 E3 — compositor-true end-to-end latency probe.
///
/// Every video packet header carries the frame's *age at send* measured on
/// the desktop clock: `Instant::elapsed()` of the capture instant, which on
/// the damage-driven backends is the compositor's copy moment. That makes
/// the dominant, variable part of the latency chain measurable without any
/// cross-device clock sync: sample = capture→send age (pure server-clock
/// interval) + one network leg (transport RTT / 2). What it deliberately
/// does NOT include: the phone's decode→panel present (unmeasurable from
/// software) and any queueing after the client's packet read.
static E2E_EWMA_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// One probe sample in microseconds (see [`E2E_EWMA_MS`] docs for
/// semantics/limits): the capture→send age the header carried, plus one
/// network leg. Microseconds are the primary unit because that is what the
/// session record's distribution needs; the millisecond form below is the same
/// number divided down for the HUD.
pub fn e2e_sample_us(capture_age_us: u64, rtt: Duration) -> u64 {
    capture_age_us + (rtt.as_micros() as u64) / 2
}

/// One probe sample in ms (see [`E2E_EWMA_MS`] docs for semantics/limits).
pub fn e2e_sample_ms(capture_age_us: u64, rtt: Duration) -> u64 {
    e2e_sample_us(capture_age_us, rtt) / 1_000
}

/// EWMA (¾ old, ¼ new) so the HUD doesn't jitter per frame. First sample
/// after [`reset_e2e_probe`] seeds it directly.
pub fn record_e2e_sample(sample_ms: u64) {
    use std::sync::atomic::Ordering;
    E2E_EWMA_MS
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |prev| {
            Some(if prev == 0 {
                sample_ms.max(1)
            } else {
                (3 * prev + sample_ms) / 4
            })
        })
        .ok();
}

/// Smoothed compositor-true e2e estimate, ms. 0 until the first video
/// packet of the current session arrives (per-session seed, not stale data).
pub fn e2e_estimate_ms() -> u64 {
    E2E_EWMA_MS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Clear the probe at session start.
pub fn reset_e2e_probe() {
    E2E_EWMA_MS.store(0, std::sync::atomic::Ordering::Relaxed);
}

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

            // Samples taken between flushes, shared by the receiver (which
            // measures) and the feedback loop (which reports).
            let e2e_samples = Arc::<SampleBatch>::default();

            // Clone connection for the stats task before it gets moved into recv task
            let stats_connection = connection.clone();
            let stats_samples = e2e_samples.clone();

            // Spawn the receive loop using our cancel-aware receiver
            let recv_cancel = cancel.clone();
            let recv_span = tracing::info_span!("packet_recv");
            let recv_handle = tokio::spawn(
                async move {
                    let result =
                        recv_with_cancel(&connection, frame_tx, audio_tx, recv_cancel, e2e_samples)
                            .await;
                    match result {
                        Ok(()) => debug!("Frame receiver finished normally"),
                        Err(e) => warn!(error = %e, "Frame receiver error"),
                    }
                }
                .instrument(recv_span),
            );

            // Spawn a stats feedback loop that periodically reports the client's
            // own view of the link, plus whatever it measured since the last tick
            let stats_cancel = cancel.clone();
            let stats_span = tracing::info_span!("stats_feedback");
            let _stats_handle = tokio::spawn(
                async move {
                    send_stats_loop(&stats_connection, stats_cancel, &stats_samples).await;
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

    /// Report one frame's worth of the durations a [`SampleBatch`] holds, as
    /// samples of type `kind` (a `SAMPLE_*` id), and say whether anything was
    /// sent.
    ///
    /// The batch keeps whatever did not fit the frame, so a caller flushing on
    /// a timer cannot lose samples to a busy period — it just reports them on
    /// the next tick. This is how the phone hands its decode and render timings
    /// to the server, which is where the session's percentiles are computed.
    pub async fn flush_samples(&self, kind: u8, batch: &SampleBatch) -> Result<bool> {
        let Some(values) = batch.take_chunk() else {
            return Ok(false);
        };
        self.send_input(&InputPacket::ClientSamples { kind, values })
            .await?;
        Ok(true)
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
    e2e_samples: Arc<SampleBatch>,
) -> Result<()> {
    info!("Starting packet receiver (video + audio)");
    reset_e2e_probe();

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

                            // R4 E3: compositor-true latency sample — the
                            // header's age is capture→send on the desktop
                            // clock, plus half the transport RTT for the
                            // wire leg. The EWMA feeds the HUD; the raw
                            // sample joins the batch the server turns into
                            // the session's e2e tail.
                            let rtt = connection.stats().rtt;
                            record_e2e_sample(e2e_sample_ms(header.timestamp_us, rtt));
                            e2e_samples.push(e2e_sample_us(header.timestamp_us, rtt));

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

/// Send one frame to the server on its own unidirectional stream. Best effort:
/// a feedback frame that cannot be sent is not worth an error path, since the
/// next tick reports again.
async fn send_frame(connection: &SharedConnection, packet: &InputPacket) {
    let data = packet.encode();
    match connection.open_uni().await {
        Ok(mut stream) => {
            if let Err(e) = stream.write_all(&data).await {
                debug!("Failed to send feedback to server: {e}");
            } else {
                let _ = stream.finish();
            }
        }
        Err(e) => {
            debug!("Failed to open feedback stream: {e}");
        }
    }
}

/// Periodically report the client's own account of the session: the link as its
/// transport sees it, and every latency sample it took since the last tick.
///
/// The two travel as ordinary [`InputPacket`] frames so the server dispatches
/// them by tag like any other client control. This loop used to write a bare
/// 16-byte buffer that the server matched on length and discarded.
async fn send_stats_loop(
    connection: &SharedConnection,
    cancel: CancellationToken,
    e2e_samples: &SampleBatch,
) {
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
                send_frame(
                    connection,
                    &InputPacket::LinkFeedback {
                        rtt: stats.rtt,
                        lost_packets: stats.lost_packets,
                    },
                )
                .await;

                // Drain in frame-sized chunks: a stalled flush loop must not
                // lose the samples it already holds, only delay them.
                while let Some(values) = e2e_samples.take_chunk() {
                    send_frame(
                        connection,
                        &InputPacket::ClientSamples {
                            kind: SAMPLE_E2E,
                            values,
                        },
                    )
                    .await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2e_sample_math() {
        // 12.34 ms capture→send age + 51 ms RTT (25.5 → 25 ms one-way).
        assert_eq!(e2e_sample_ms(12_340, Duration::from_millis(51)), 12 + 25);
        assert_eq!(e2e_sample_ms(0, Duration::ZERO), 0);
    }

    #[test]
    fn e2e_ewma_seed_smooth_and_reset() {
        reset_e2e_probe();
        assert_eq!(
            e2e_estimate_ms(),
            0,
            "fresh session must not show stale data"
        );
        record_e2e_sample(100);
        assert_eq!(e2e_estimate_ms(), 100, "first sample seeds directly");
        record_e2e_sample(0);
        assert_eq!(e2e_estimate_ms(), 75, "EWMA must be 3/4 old + 1/4 new");
        reset_e2e_probe();
        assert_eq!(e2e_estimate_ms(), 0);
    }

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
    fn feedback_frames_are_what_the_stats_loop_puts_on_the_wire() {
        // The loop's two exports, checked as shapes the server dispatches by
        // tag: a link reading and one batch of e2e samples. This is the frame
        // format that replaced an untagged 16-byte buffer the server discarded.
        let feedback = InputPacket::LinkFeedback {
            rtt: Duration::from_millis(28),
            lost_packets: 4,
        };
        let decoded = InputPacket::decode(&feedback.encode()).expect("feedback decodes");
        assert!(
            matches!(
                decoded,
                InputPacket::LinkFeedback {
                    lost_packets: 4,
                    ..
                }
            ),
            "{decoded:?}"
        );

        let batch = SampleBatch::default();
        batch.push(e2e_sample_us(12_340, Duration::from_millis(51)));
        batch.push(e2e_sample_us(9_000, Duration::from_millis(30)));
        let values = batch.take_chunk().expect("two samples pending");
        assert_eq!(values, vec![37_840, 24_000]);
        let samples = InputPacket::ClientSamples {
            kind: SAMPLE_E2E,
            values,
        };
        match InputPacket::decode(&samples.encode()).unwrap() {
            InputPacket::ClientSamples { kind, values } => {
                assert_eq!(kind, SAMPLE_E2E);
                assert_eq!(
                    values.iter().map(|&v| v as u64 / 1_000).collect::<Vec<_>>(),
                    vec![
                        e2e_sample_ms(12_340, Duration::from_millis(51)),
                        e2e_sample_ms(9_000, Duration::from_millis(30))
                    ],
                    "the tail and the HUD must be the same number, divided"
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
        assert!(batch.take_chunk().is_none());
    }
}
