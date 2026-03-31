use super::{PeerInfo, TailscaleClient};
use anyhow::Result;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::interval;

#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    PeerDiscovered(PeerInfo),
    PeerOffline(String),
    ServiceReady,
}

#[derive(Debug, Clone)]
pub struct DiscoveryService {
    client: TailscaleClient,
    tx: broadcast::Sender<DiscoveryEvent>,
}

impl DiscoveryService {
    pub fn new(client: TailscaleClient) -> Self {
        let (tx, _) = broadcast::channel(100);
        Self { client, tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.tx.subscribe()
    }

    pub async fn run(&self, check_interval: Duration) {
        let mut ticker = interval(check_interval);
        let mut known_peers: HashMap<String, bool> = HashMap::new();

        if let Ok(peers) = self.scan_peers().await {
            for peer in peers {
                known_peers.insert(peer.name.clone(), peer.online);
                if peer.online {
                    let _ = self.tx.send(DiscoveryEvent::PeerDiscovered(peer));
                }
            }
        }

        let _ = self.tx.send(DiscoveryEvent::ServiceReady);

        loop {
            ticker.tick().await;

            match self.scan_peers().await {
                Ok(peers) => {
                    let mut current_online: HashMap<String, bool> = HashMap::new();

                    for peer in peers {
                        current_online.insert(peer.name.clone(), peer.online);
                        let was_online = known_peers.get(&peer.name).copied().unwrap_or(false);

                        if peer.online && !was_online {
                            let _ = self.tx.send(DiscoveryEvent::PeerDiscovered(peer.clone()));
                        }

                        if !peer.online && was_online {
                            let _ = self.tx.send(DiscoveryEvent::PeerOffline(peer.name.clone()));
                        }
                    }

                    for name in known_peers.keys() {
                        if !current_online.contains_key(name) {
                            let _ = self.tx.send(DiscoveryEvent::PeerOffline(name.clone()));
                        }
                    }

                    known_peers = current_online;
                }
                Err(error) => {
                    tracing::warn!("peer scan failed: {}", error);
                }
            }
        }
    }

    async fn scan_peers(&self) -> Result<Vec<PeerInfo>> {
        self.client.get_peers().await
    }
}
