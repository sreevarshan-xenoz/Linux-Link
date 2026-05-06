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

        // Perform Handshake
        stream
            .write_all(format!("{}\n", HANDSHAKE_HELLO).as_bytes())
            .await
            .context("failed to write handshake")?;

        let mut reader = BufReader::new(&mut stream);
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut response))
            .await
            .context("handshake timeout")?
            .context("failed to read handshake response")?;

        if response.trim() != HANDSHAKE_OK {
            bail!("handshake failed: {}", response.trim());
        }

        Ok(stream)
    }
}
