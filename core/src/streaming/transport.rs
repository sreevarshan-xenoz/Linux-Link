//! QUIC-based streaming transport
//!
//! Provides low-latency, unreliable (lossy) QUIC streams for video delivery.
//! Uses quinn with datagram mode for minimal latency over reliability.

use anyhow::{Context, Result};
use rustls::pki_types::PrivateKeyDer;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::EncodedPacket;

/// Our own transport config to avoid name collision with quinn::TransportConfig
#[derive(Debug, Clone)]
pub struct StreamTransportConfig {
    /// Address to listen on (server) or connect to (client)
    pub address: SocketAddr,
    /// ALPN protocol identifier for streaming
    pub alpn: Vec<u8>,
    /// Enable datagram mode (unordered, lower latency)
    pub use_datagrams: bool,
}

impl Default for StreamTransportConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:4716".parse().unwrap(),
            alpn: b"linux-link-stream".to_vec(),
            use_datagrams: true,
        }
    }
}

/// Server-side streaming transport
pub struct StreamServer {
    endpoint: quinn::Endpoint,
    _config: StreamTransportConfig,
}

impl StreamServer {
    /// Create a new streaming server endpoint
    pub async fn new(config: StreamTransportConfig) -> Result<Self> {
        info!(
            "Creating streaming server on {} (datagrams={})",
            config.address, config.use_datagrams
        );

        let mut transport_config = quinn::TransportConfig::default();
        if config.use_datagrams {
            // Enable datagram mode for lower latency
            transport_config.datagram_send_buffer_size(16 * 1024 * 1024); // 16 MB
            transport_config.datagram_receive_buffer_size(Some(16 * 1024 * 1024));
        }

        // Self-signed certificate for local streaming
        // In production, use Tailscale's identity verification instead
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .context("Failed to generate certificate")?;

        let server_config = quinn::ServerConfig::with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::try_from(cert.signing_key.serialize_der())
                .map_err(|e| anyhow::anyhow!("Failed to parse private key: {}", e))?,
        )
        .context("Failed to configure server")?;

        let endpoint = quinn::Endpoint::server(server_config, config.address)
            .context("Failed to create endpoint")?;

        Ok(Self {
            endpoint,
            _config: config,
        })
    }

    /// Accept incoming connections
    pub async fn accept_connection(&self) -> Option<quinn::Incoming> {
        self.endpoint.accept().await
    }

    /// Handle a single streaming connection
    pub async fn handle_connection(
        &self,
        connection: quinn::Connection,
        _packet_tx: mpsc::Sender<EncodedPacket>,
    ) -> Result<()> {
        let peer = connection.remote_address();
        info!("Streaming connection from {}", peer);

        loop {
            // Accept incoming streams from client (for input events)
            let mut stream = match connection.accept_uni().await {
                Ok(stream) => stream,
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    debug!("Streaming connection closed by peer");
                    break;
                }
                Err(e) => {
                    warn!("Stream accept error: {}", e);
                    break;
                }
            };

            // Read packets from the stream
            // This would be used if the client sends acknowledgments or feedback
            let _ = stream.read_to_end(1024).await;
        }

        Ok(())
    }

    /// Get the server address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().context("No local address")
    }
}

/// Client-side streaming transport
pub struct StreamClient {
    endpoint: quinn::Endpoint,
    _config: StreamTransportConfig,
}

impl StreamClient {
    /// Create a new streaming client
    pub fn new(config: StreamTransportConfig) -> Result<Self> {
        info!("Creating streaming client");

        let mut transport_config = quinn::TransportConfig::default();
        if config.use_datagrams {
            transport_config.datagram_send_buffer_size(16 * 1024 * 1024);
            transport_config.datagram_receive_buffer_size(Some(16 * 1024 * 1024));
        }

        // Dangerous: skip certificate verification for local streaming
        // In production, use Tailscale's identity instead
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("Failed to create QUIC client config")?;

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)
            .context("Failed to create client endpoint")?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            _config: config,
        })
    }

    /// Connect to the streaming server
    pub async fn connect(&self, server_addr: SocketAddr) -> Result<quinn::Connection> {
        info!("Connecting to streaming server at {}", server_addr);

        let connection = self
            .endpoint
            .connect(server_addr, "localhost")
            .context("Failed to initiate connection")?
            .await
            .context("Connection failed")?;

        info!("Streaming connection established");
        Ok(connection)
    }
}

/// Send encoded packets over a QUIC connection
pub async fn send_packets(
    connection: &quinn::Connection,
    mut packets: mpsc::Receiver<EncodedPacket>,
) -> Result<()> {
    info!("Starting packet sender");

    while let Some(packet) = packets.recv().await {
        // Open a unidirectional stream for this packet
        // In production, we'd reuse streams and use datagrams for lower latency
        let mut send_stream = connection.open_uni().await?;

        // Send packet header
        let header = PacketHeader {
            sequence: packet.sequence,
            is_keyframe: packet.is_keyframe,
            timestamp_us: packet.timestamp.elapsed().as_micros() as u64,
        };

        send_stream
            .write_all(&header.as_bytes())
            .await
            .context("Failed to send header")?;

        // Send packet data
        send_stream
            .write_all(&packet.data)
            .await
            .context("Failed to send packet")?;

        send_stream.finish().context("Failed to finish stream")?;
    }

    Ok(())
}

/// Receive encoded packets from a QUIC connection
pub async fn receive_packets(
    connection: &quinn::Connection,
    packet_tx: mpsc::Sender<EncodedPacket>,
) -> Result<()> {
    info!("Starting packet receiver");

    loop {
        let mut recv_stream = match connection.accept_uni().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                debug!("Connection closed");
                break;
            }
            Err(e) => {
                warn!("Stream accept error: {}", e);
                break;
            }
        };

        // Read header (17 bytes)
        let mut header_bytes = [0u8; 17];
        recv_stream
            .read_exact(&mut header_bytes)
            .await
            .context("Failed to read header")?;

        let header = PacketHeader::from_bytes(&header_bytes)?;

        // Read packet data
        let data = recv_stream
            .read_to_end(10 * 1024 * 1024) // 10 MB max packet
            .await
            .context("Failed to read packet data")?;

        let packet = EncodedPacket {
            data,
            is_keyframe: header.is_keyframe,
            timestamp: std::time::Instant::now(), // Server timestamp not preserved
            sequence: header.sequence,
        };

        packet_tx
            .send(packet)
            .await
            .context("Failed to forward packet")?;
    }

    Ok(())
}

/// Packet header for streaming transport
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    pub sequence: u64,
    pub is_keyframe: bool,
    pub timestamp_us: u64,
}

impl PacketHeader {
    pub fn as_bytes(&self) -> [u8; 17] {
        let mut bytes = [0u8; 17];
        bytes[0..8].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[8] = if self.is_keyframe { 1 } else { 0 };
        bytes[9..17].copy_from_slice(&self.timestamp_us.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8; 17]) -> Result<Self> {
        Ok(Self {
            sequence: u64::from_le_bytes(bytes[0..8].try_into()?),
            is_keyframe: bytes[8] != 0,
            timestamp_us: u64::from_le_bytes(bytes[9..17].try_into()?),
        })
    }
}

/// No-op certificate verifier for local streaming
/// In production, use Tailscale's identity instead
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_header_roundtrip() {
        let header = PacketHeader {
            sequence: 12345,
            is_keyframe: true,
            timestamp_us: 999999,
        };

        let bytes = header.as_bytes();
        let recovered = PacketHeader::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.sequence, 12345);
        assert!(recovered.is_keyframe);
        assert_eq!(recovered.timestamp_us, 999999);
    }

    #[test]
    fn test_transport_config_default() {
        let config = StreamTransportConfig::default();
        assert_eq!(config.alpn, b"linux-link-stream");
        assert!(config.use_datagrams);
    }
}
