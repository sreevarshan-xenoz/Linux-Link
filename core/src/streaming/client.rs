//! QUIC stream client for receiving H.264 video frames.
//!
//! Connects to a `StreamingServer`, receives encoded packets over unidirectional
//! QUIC streams, and feeds them into an mpsc channel for the Flutter/MediaCodec side.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::EncodedPacket;
use super::transport::{self, StreamClient, StreamTransportConfig};

/// Default port for the streaming service.
pub const DEFAULT_STREAMING_PORT: u16 = 4716;

/// QUIC Stream Client — connects to a StreamingServer and receives H.264 video frames.
///
/// # Usage
///
/// ```ignore
/// let (mut client, packet_rx) = StreamingClient::connect("100.64.0.1:4716").await?;
/// // Spawn a task to consume packets from packet_rx
/// tokio::spawn(consume_packets(packet_rx));
/// client.start().await; // runs until cancelled
/// ```
pub struct StreamingClient {
    connection: Option<quinn::Connection>,
    #[allow(dead_code)]
    transport_config: StreamTransportConfig,
    frame_tx: mpsc::Sender<EncodedPacket>,
    cancel: CancellationToken,
    #[allow(dead_code)]
    channel_capacity: usize,
}

impl StreamingClient {
    /// Create a new `StreamingClient` (not yet connected).
    ///
    /// `channel_capacity` controls the buffer size between the receive task
    /// and the consumer. A capacity of 8 is a reasonable default for real-time
    /// video.
    pub fn new(channel_capacity: usize) -> Self {
        let (frame_tx, _frame_rx) = mpsc::channel(channel_capacity);
        Self {
            connection: None,
            transport_config: StreamTransportConfig::default(),
            frame_tx,
            cancel: CancellationToken::new(),
            channel_capacity,
        }
    }

    /// Connect to a streaming server at the given address.
    ///
    /// The address should be in the form `"host:port"`, e.g. `"100.64.0.1:4716"`.
    /// Returns the client and a receiver channel for consuming frames.
    pub async fn connect(addr: &str) -> Result<(Self, mpsc::Receiver<EncodedPacket>)> {
        let addr: SocketAddr = addr
            .parse()
            .with_context(|| format!("Invalid server address: {addr}"))?;

        let channel_capacity = 8;
        let (frame_tx, frame_rx) = mpsc::channel(channel_capacity);

        info!("Connecting to streaming server at {addr}");

        let transport = StreamClient::new(StreamTransportConfig::default())
            .context("Failed to create QUIC transport")?;

        let connection = transport
            .connect(addr)
            .await
            .context("Failed to connect to streaming server")?;

        info!("Streaming connection established to {addr}");

        let client = Self {
            connection: Some(connection),
            transport_config: StreamTransportConfig::default(),
            frame_tx,
            cancel: CancellationToken::new(),
            channel_capacity,
        };

        Ok((client, frame_rx))
    }

    /// Start receiving frames. This runs until cancelled or the connection closes.
    ///
    /// Spawns a background receive task and a stats-feedback task, then waits
    /// for cancellation. The caller should have already taken the `frame_rx`
    /// channel from `connect()` to consume packets.
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

        info!("Starting frame receiver");

        // Clone connection for the stats task before it gets moved into recv task
        let stats_connection = connection.clone();

        // Spawn the receive loop using our cancel-aware receiver
        let recv_cancel = cancel.clone();
        let recv_handle = tokio::spawn(async move {
            let result = recv_with_cancel(&connection, frame_tx, recv_cancel).await;
            match result {
                Ok(()) => debug!("Frame receiver finished normally"),
                Err(e) => warn!("Frame receiver error: {e}"),
            }
        });

        // Spawn a stats feedback loop that periodically sends RTT data
        // back to the server on a second unidirectional stream.
        let stats_cancel = cancel.clone();
        let _stats_handle = tokio::spawn(async move {
            send_stats_loop(&stats_connection, stats_cancel).await;
        });

        // Wait for cancellation or receive task completion
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Streaming client cancelled");
            }
            result = recv_handle => {
                if let Err(e) = result {
                    warn!("Receive task panicked: {e}");
                }
            }
        }
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
}

/// Receive packets with cancellation support.
///
/// Wraps `transport::receive_packets` so it can be aborted on cancellation.
async fn recv_with_cancel(
    connection: &quinn::Connection,
    frame_tx: mpsc::Sender<EncodedPacket>,
    cancel: CancellationToken,
) -> Result<()> {
    // We implement our own receive loop here so we can interleave cancellation.
    // The transport::receive_packets function does not support cancellation.
    info!("Starting packet receiver");

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
                        // Read the 17-byte packet header
                        let mut header_bytes = [0u8; 17];
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

                        // Read the NAL payload (up to 10 MB)
                        let data = match recv_stream.read_to_end(10 * 1024 * 1024).await {
                            Ok(data) => data,
                            Err(e) => {
                                warn!("Failed to read packet data (seq={}): {e}", header.sequence);
                                continue;
                            }
                        };

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
        let client = StreamingClient::new(8);
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
