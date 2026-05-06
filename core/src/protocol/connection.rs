use super::kdeconnect::DeviceIdentity;
use super::{HANDSHAKE_HELLO, HANDSHAKE_OK};
use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::time::Duration;
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct ConnectionManager {
    timeout: Duration,
}

impl ConnectionManager {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub async fn connect(&self, address: &str, port: u16) -> Result<TcpStream> {
        let socket_addr = format!("{address}:{port}");

        let mut stream = tokio::time::timeout(self.timeout, TcpStream::connect(&socket_addr))
            .await
            .context("connection timeout")?
            .context("failed to connect")?;

        stream.set_nodelay(true)?;

        // Step 1: Perform Handshake Hello
        stream
            .write_all(format!("{}\n", HANDSHAKE_HELLO).as_bytes())
            .await
            .context("failed to write handshake")?;

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut response))
            .await
            .context("handshake timeout")?
            .context("failed to read handshake response")?;

        if response.trim() != HANDSHAKE_OK {
            bail!("handshake failed: {}", response.trim());
        }

        // Step 2: Send Identity Packet (Required by server)
        let identity = DeviceIdentity::new("linux-link-client", "Linux Link Android Client");
        let identity_packet = identity.as_identity_packet();
        let identity_bytes = identity_packet.to_wire()?;
        let mut stream = reader.into_inner();
        stream.write_all(&identity_bytes).await.context("failed to send identity packet")?;
        stream.flush().await?;

        Ok(stream)
    }
}
