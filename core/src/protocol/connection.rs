use anyhow::{Context, Result};
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

        let stream = tokio::time::timeout(self.timeout, TcpStream::connect(&socket_addr))
            .await
            .context("connection timeout")?
            .context("failed to connect")?;

        stream.set_nodelay(true)?;
        Ok(stream)
    }
}
