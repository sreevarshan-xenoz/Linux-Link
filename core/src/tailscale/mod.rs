use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub name: String,
    pub dns_name: String,
    pub ips: Vec<String>,
    pub online: bool,
}

#[derive(Debug, Default, Clone)]
pub struct TailscaleClient;

impl TailscaleClient {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    pub async fn get_self_ip(&self) -> Result<String> {
        if let Ok(ip) = std::env::var("LINUX_LINK_TAILSCALE_IP") {
            return Ok(ip);
        }

        bail!("Tailscale IP not configured yet (set LINUX_LINK_TAILSCALE_IP for local testing)")
    }

    pub async fn get_peers(&self) -> Result<Vec<PeerInfo>> {
        Ok(Vec::new())
    }
}
