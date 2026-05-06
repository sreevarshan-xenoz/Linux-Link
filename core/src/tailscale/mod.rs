use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::sleep;

pub mod discovery;
pub use discovery::{DiscoveryEvent, DiscoveryService};

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
        let status = self.status().await?;
        status
            .self_node
            .and_then(|node| node.tailscale_ips.into_iter().next())
            .context("No Tailscale IP assigned")
    }

    pub async fn get_peers(&self) -> Result<Vec<PeerInfo>> {
        let status = self.status().await?;
        let peers = status
            .peer
            .into_values()
            .map(|peer| PeerInfo {
                name: peer
                    .host_name
                    .or(peer.dns_name.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                dns_name: peer.dns_name.unwrap_or_default(),
                ips: peer.tailscale_ips,
                online: peer.active.unwrap_or(false),
            })
            .collect();

        Ok(peers)
    }

    pub async fn is_peer_online(&self, peer_name: &str) -> Result<bool> {
        let peers = self.get_peers().await?;
        Ok(peers
            .iter()
            .any(|peer| peer.name == peer_name && peer.online))
    }

    pub async fn wait_for_ready(&self, timeout: Duration) -> Result<()> {
        let started = Instant::now();
        loop {
            if started.elapsed() > timeout {
                bail!("Tailscale not ready within timeout")
            }

            match self.status().await {
                Ok(status) if status.backend_state.as_deref() == Some("Running") => {
                    return Ok(());
                }
                Ok(status) => {
                    tracing::debug!(
                        "Waiting for Tailscale, state={}",
                        status
                            .backend_state
                            .unwrap_or_else(|| "unknown".to_string())
                    );
                }
                Err(error) => {
                    tracing::debug!("Tailscale not ready: {}", error);
                }
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    pub async fn status_text(&self) -> Result<String> {
        let output = Command::new("tailscale").arg("status").output().await;

        match output {
            Ok(output) if output.status.success() => {
                Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
            }
            _ => {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()?;
                let res = client.get("http://100.100.100.100:1053/localapi/v0/status").send().await;
                match res {
                    Ok(r) if r.status().is_success() => Ok("Tailscale Online (via LocalAPI)".to_string()),
                    _ => bail!("tailscale status failed"),
                }
            }
        }
    }

    async fn status(&self) -> Result<TailscaleStatus> {
        if let Ok(ip) = std::env::var("LINUX_LINK_TAILSCALE_IP") {
            return Ok(TailscaleStatus {
                backend_state: Some("Running".to_string()),
                self_node: Some(StatusPeer {
                    host_name: Some("linux-link-dev".to_string()),
                    dns_name: None,
                    tailscale_ips: vec![ip],
                    active: Some(true),
                }),
                peer: HashMap::new(),
            });
        }

        // Try CLI first
        let output = Command::new("tailscale")
            .arg("status")
            .arg("--json")
            .output()
            .await;

        if let Ok(output) = output {
            if output.status.success() {
                return serde_json::from_slice::<TailscaleStatus>(&output.stdout)
                    .context("failed to parse tailscale status JSON");
            }
        }

        // Fallback to Local API (especially for Android/container environments)
        // Tailscale LocalAPI usually listens on 100.100.100.100:1053 (internal DNS)
        // or a local port. 100.100.100.100:1053 is a standard path.
        tracing::debug!("Tailscale CLI failed, falling back to Local API HTTP endpoint");

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;

        let res = client
            .get("http://100.100.100.100:1053/localapi/v0/status")
            .send()
            .await;

        match res {
            Ok(r) if r.status().is_success() => {
                let status: TailscaleStatus = r.json().await?;
                Ok(status)
            }
            Ok(r) => bail!("tailscale localapi returned error: {}", r.status()),
            Err(e) => bail!("tailscale status failed (CLI error, and HTTP fallback failed: {})", e),
        }
    }
}

#[derive(Debug, Deserialize)]
struct TailscaleStatus {
    #[serde(rename = "BackendState")]
    backend_state: Option<String>,
    #[serde(rename = "Self")]
    self_node: Option<StatusPeer>,
    #[serde(rename = "Peer", default)]
    peer: HashMap<String, StatusPeer>,
}

#[derive(Debug, Deserialize)]
struct StatusPeer {
    #[serde(rename = "HostName")]
    host_name: Option<String>,
    #[serde(rename = "DNSName")]
    dns_name: Option<String>,
    #[serde(rename = "TailscaleIPs", default)]
    tailscale_ips: Vec<String>,
    #[serde(rename = "Active")]
    active: Option<bool>,
}
t)]
    tailscale_ips: Vec<String>,
    #[serde(rename = "Active")]
    active: Option<bool>,
}
