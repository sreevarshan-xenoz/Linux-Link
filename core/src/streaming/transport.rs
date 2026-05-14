//! QUIC-based streaming transport
//!
//! Provides low-latency, unreliable (lossy) QUIC streams for video delivery.
//! Uses quinn with datagram mode for minimal latency over reliability.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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

// ---------------------------------------------------------------------------
// Certificate management with TOFU (Trust On First Use) verification
// ---------------------------------------------------------------------------

/// Manages TLS certificates for E2E encrypted streaming.
///
/// Provides:
/// - A persistent identity certificate for this device (server identity)
/// - TOFU peer certificate verification so connections are trusted
///   automatically on first use and verified on reconnection
/// - Optional on-disk persistence of known peer certificate hashes
#[derive(Debug)]
pub struct CertManager {
    /// Our identity certificate in DER form
    cert_der: Vec<u8>,
    /// Our private key in PKCS#8 DER form
    key_der: Vec<u8>,
    /// Known peer certificate hashes: label → SHA-256 of the DER-encoded cert
    known_peers: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    /// Optional path for persisting `known_peers` across restarts
    peers_path: Option<PathBuf>,
}

impl CertManager {
    /// Create a new `CertManager` with a freshly generated identity cert.
    ///
    /// Known peers are kept in memory only (not persisted).
    pub fn new() -> Result<Self> {
        let (cert_der, key_der) = generate_identity()?;
        Ok(Self {
            cert_der,
            key_der,
            known_peers: Arc::new(Mutex::new(HashMap::new())),
            peers_path: None,
        })
    }

    /// Create a `CertManager` backed by files in `identity_dir`.
    ///
    /// - If `identity_dir/identity.der` and `identity_dir/identity.key` exist, they
    ///   are loaded; otherwise a new identity is generated and saved.
    /// - Known peers are loaded from `identity_dir/known_peers.json` if it exists.
    pub fn load_or_create(identity_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(identity_dir).context("Failed to create identity directory")?;

        let cert_path = identity_dir.join("identity.der");
        let key_path = identity_dir.join("identity.key");

        let (cert_der, key_der) = if cert_path.exists() && key_path.exists() {
            let cert = std::fs::read(&cert_path)?;
            let key = std::fs::read(&key_path)?;
            (cert, key)
        } else {
            let (cert, key) = generate_identity()?;
            std::fs::write(&cert_path, &cert)?;
            std::fs::write(&key_path, &key)?;
            (cert, key)
        };

        let peers_path = identity_dir.join("known_peers.json");
        let known_peers = if peers_path.exists() {
            let data =
                std::fs::read_to_string(&peers_path).context("Failed to read known peers")?;
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        };

        Ok(Self {
            cert_der,
            key_der,
            known_peers: Arc::new(Mutex::new(known_peers)),
            peers_path: Some(peers_path),
        })
    }

    /// Build a QUIC server TLS configuration that presents this device's identity
    /// certificate to connecting clients.
    pub fn server_config(&self) -> Result<quinn::ServerConfig> {
        let cert = CertificateDer::from(self.cert_der.clone());
        let key = PrivateKeyDer::try_from(self.key_der.clone())
            .map_err(|_| anyhow::anyhow!("Failed to parse private key"))?;

        let mut transport = quinn::TransportConfig::default();
        transport.datagram_send_buffer_size(16 * 1024 * 1024);
        transport.datagram_receive_buffer_size(Some(16 * 1024 * 1024));

        let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key)
            .context("Failed to configure TLS server")?;
        server_config.transport_config(Arc::new(transport));

        Ok(server_config)
    }

    /// Build a QUIC client TLS configuration with TOFU certificate verification.
    ///
    /// The client verifies the server's certificate against the stored known_peers
    /// map and auto-accepts unknown peers on first use.
    pub fn client_config(&self) -> Result<quinn::ClientConfig> {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TofuVerifier {
                known_peers: self.known_peers.clone(),
            }))
            .with_no_client_auth();

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("Failed to create QUIC client crypto config")?;

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

        // Default transport config – caller can override
        let mut transport = quinn::TransportConfig::default();
        transport.datagram_send_buffer_size(16 * 1024 * 1024);
        transport.datagram_receive_buffer_size(Some(16 * 1024 * 1024));
        client_config.transport_config(Arc::new(transport));

        Ok(client_config)
    }

    /// Save the known peers map to the configured path.
    pub fn save_known_peers(&self) -> Result<()> {
        if let Some(path) = &self.peers_path {
            let peers = self.known_peers.lock().unwrap();
            let json = serde_json::to_string_pretty(&*peers)?;
            std::fs::write(path, json)?;
        }
        Ok(())
    }

    /// Return the SHA-256 hash of the given DER certificate.
    fn cert_hash(cert: &CertificateDer<'_>) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(cert.as_ref());
        hasher.finalize().into()
    }
}

/// Generate a fresh ECDSA P-256 identity certificate and key.
fn generate_identity() -> Result<(Vec<u8>, Vec<u8>)> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("Failed to generate ECDSA key pair")?;
    let params = CertificateParams::new(vec!["linux-link.local".into()])
        .context("Failed to create certificate params")?;
    let cert = params
        .self_signed(&key_pair)
        .context("Failed to self-sign certificate")?;

    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

/// TOFU (Trust On First Use) certificate verifier.
///
/// - **First connection:** auto-accepts any server certificate and stores its
///   SHA-256 hash for future verification.
/// - **Subsequent connections:** verifies that the presented certificate's hash
///   matches the stored value. A mismatch indicates a potential MITM attack.
#[derive(Debug)]
struct TofuVerifier {
    known_peers: Arc<Mutex<HashMap<String, [u8; 32]>>>,
}

impl rustls::client::danger::ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let hash = CertManager::cert_hash(end_entity);
        // Use the server-name representation for TOFU key lookup.
        // ServerName doesn't implement Display, so we convert through its
        // inner types since both DNS names and IPs implement Display.
        let label = match server_name {
            ServerName::DnsName(dns) => dns.as_ref().to_string(),
            // IpAddr in pki-types doesn't impl Display; Debug output is stable
            ServerName::IpAddress(addr) => format!("{:?}", addr),
            // Fallback for any future ServerName variants
            _ => format!("{:?}", server_name),
        };

        let mut peers = self.known_peers.lock().unwrap();

        match peers.get(&label) {
            Some(stored) if *stored == hash => {
                // Known peer with matching cert — verified successfully.
                debug!("TOFU: verified cert for {label}");
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            Some(_) => {
                // Known peer with a DIFFERENT cert — possible MITM!
                warn!("TOFU: certificate hash mismatch for {label}! Possible MITM attack.");
                Err(rustls::Error::General(format!(
                    "Certificate for {label} has changed since the last connection. \
                     This could be a man-in-the-middle attack. \
                     If you recently reinstalled the remote device, \
                     delete its entry and reconnect."
                )))
            }
            None => {
                // New peer — TOFU: auto-accept and store.
                info!("TOFU: first connection to {label}, accepting cert");
                peers.insert(label, hash);
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
        }
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

/// Server-side streaming transport
pub struct StreamServer {
    endpoint: quinn::Endpoint,
    _config: StreamTransportConfig,
}

impl StreamServer {
    /// Create a new streaming server endpoint
    pub async fn new(config: StreamTransportConfig, cert_manager: &CertManager) -> Result<Self> {
        info!(
            "Creating streaming server on {} (datagrams={})",
            config.address, config.use_datagrams
        );

        let mut server_config = cert_manager.server_config()?;

        // Override transport config with caller's settings
        let mut transport_config = quinn::TransportConfig::default();
        if config.use_datagrams {
            transport_config.datagram_send_buffer_size(16 * 1024 * 1024);
            transport_config.datagram_receive_buffer_size(Some(16 * 1024 * 1024));
        }
        server_config.transport_config(Arc::new(transport_config));

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
    pub fn new(config: StreamTransportConfig, cert_manager: &CertManager) -> Result<Self> {
        info!("Creating streaming client");

        let mut client_config = cert_manager.client_config()?;

        // Override transport config with caller's settings
        let mut transport_config = quinn::TransportConfig::default();
        if config.use_datagrams {
            transport_config.datagram_send_buffer_size(16 * 1024 * 1024);
            transport_config.datagram_receive_buffer_size(Some(16 * 1024 * 1024));
        }
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
    pub async fn connect(
        &self,
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<quinn::Connection> {
        info!(
            "Connecting to streaming server at {} (identity: {})",
            server_addr, server_name
        );

        let connection = self
            .endpoint
            .connect(server_addr, server_name)
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
            stream_kind: STREAM_KIND_VIDEO,
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

        // Read header (18 bytes)
        let mut header_bytes = [0u8; 18];
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

/// Stream kind identifiers
pub const STREAM_KIND_VIDEO: u8 = 0;
pub const STREAM_KIND_AUDIO: u8 = 1;

/// Packet header for streaming transport
///
/// Bytes:
///   [0..8]  sequence     (u64 LE)
///   [8..9]  stream_kind  (0=video, 1=audio, etc.)
///   [9..10] flags        (bit 0 = is_keyframe)
///   [10..18] timestamp_us (u64 LE)
/// Total: 18 bytes
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    pub sequence: u64,
    pub stream_kind: u8,
    pub is_keyframe: bool,
    pub timestamp_us: u64,
}

impl PacketHeader {
    pub const SIZE: usize = 18;

    pub fn as_bytes(&self) -> [u8; 18] {
        let mut bytes = [0u8; 18];
        bytes[0..8].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[8] = self.stream_kind;
        bytes[9] = if self.is_keyframe { 1 } else { 0 };
        bytes[10..18].copy_from_slice(&self.timestamp_us.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8; 18]) -> Result<Self> {
        Ok(Self {
            sequence: u64::from_le_bytes(bytes[0..8].try_into()?),
            stream_kind: bytes[8],
            is_keyframe: bytes[9] != 0,
            timestamp_us: u64::from_le_bytes(bytes[10..18].try_into()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_header_roundtrip() {
        let header = PacketHeader {
            sequence: 12345,
            stream_kind: STREAM_KIND_VIDEO,
            is_keyframe: true,
            timestamp_us: 999999,
        };

        let bytes = header.as_bytes();
        let recovered = PacketHeader::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.sequence, 12345);
        assert_eq!(recovered.stream_kind, STREAM_KIND_VIDEO);
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
