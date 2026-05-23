use super::kdeconnect::DeviceIdentity;
use super::{HANDSHAKE_HELLO, HANDSHAKE_OK, PROTOCOL_VERSION};
use crate::error::{LinuxLinkError, Result};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info_span, Instrument};
use uuid;

#[derive(Debug, Clone)]
pub struct ConnectionManager {
    timeout: Duration,
}

impl ConnectionManager {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub async fn connect(
        &self,
        address: &str,
        port: u16,
        identity: &DeviceIdentity,
    ) -> Result<TcpStream> {
        let conn_id = uuid::Uuid::new_v4().to_string();
        let span = info_span!(
            "handshake",
            conn_id = %conn_id,
            peer = %address,
            proto = %PROTOCOL_VERSION
        );

        async move {
            let socket_addr = format!("{address}:{port}");

            let mut stream = tokio::time::timeout(self.timeout, TcpStream::connect(&socket_addr))
                .await
                .map_err(|_| LinuxLinkError::Timeout {
                    operation: "connect",
                    duration_ms: self.timeout.as_millis() as u64,
                })?
                .map_err(|e| LinuxLinkError::ConnectionFailed {
                    address: address.to_string(),
                    port,
                    reason: e.to_string(),
                })?;

            stream.set_nodelay(true)?;

            // Step 1: Perform Handshake Hello
            stream
                .write_all(format!("{}\n", HANDSHAKE_HELLO).as_bytes())
                .await
                .map_err(|e| LinuxLinkError::Io {
                    operation: "write handshake hello",
                    detail: e.to_string(),
                })?;

            // Step 2: Read handshake response with timeout
            let mut reader = BufReader::new(stream);
            let mut response = String::new();
            tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut response))
                .await
                .map_err(|_| LinuxLinkError::Timeout {
                    operation: "handshake response",
                    duration_ms: 5000,
                })?
                .map_err(|e| LinuxLinkError::HandshakeFailed {
                    peer: address.to_string(),
                    response: e.to_string(),
                })?;

            if response.trim() != HANDSHAKE_OK {
                return Err(LinuxLinkError::HandshakeFailed {
                    peer: address.to_string(),
                    response: response.trim().to_string(),
                });
            }

            // Step 3: Read server's identity packet (optional)
            let mut identity_response = String::new();
            match tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut identity_response))
                .await
            {
                Ok(Ok(_)) if !identity_response.trim().is_empty() => {
                    debug!("Received server identity: {}", identity_response.trim());
                }
                _ => {
                    debug!("No server identity packet received or timeout");
                }
            }

            // Step 4: Send client identity packet
            let identity_packet = identity.as_identity_packet();
            let identity_bytes = identity_packet.to_wire().map_err(|e| {
                LinuxLinkError::Serialization {
                    format: "JSON",
                    detail: e.to_string(),
                }
            })?;

            let mut stream = reader.into_inner();
            stream
                .write_all(&identity_bytes)
                .await
                .map_err(|e| LinuxLinkError::Io {
                    operation: "send identity packet",
                    detail: e.to_string(),
                })?;
            stream.flush().await.map_err(|e| LinuxLinkError::Io {
                operation: "flush identity packet",
                detail: e.to_string(),
            })?;

            Ok(stream)
        }
        .instrument(span)
        .await
    }
}
