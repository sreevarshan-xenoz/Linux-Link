//! LAN peer discovery via mDNS (multicast DNS)
//!
//! Discovers Linux Link servers on the local network without Tailscale.
//! Uses `mdns-sd` to discover `_linux-link._tcp.local` services and resolves
//! their IP addresses and ports.
//!
//! This is a fallback for environments where Tailscale isn't running or
//! peers are on the same LAN and don't need Tailscale routing.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::time::Duration;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use super::PeerInfo;

/// mDNS service type used by Linux Link servers.
const SERVICE_TYPE: &str = "_linux-link._tcp.local.";

/// Scan timeout: how long to wait for mDNS responses during a single scan.
const SCAN_TIMEOUT: Duration = Duration::from_secs(3);

/// Events emitted by [`LanDiscoveryService`].
#[derive(Debug, Clone)]
pub enum LanEvent {
    /// A new LAN peer was discovered.
    PeerDiscovered(PeerInfo),
    /// A previously discovered peer is no longer responding.
    PeerOffline(String),
    /// The service is ready to emit events.
    ServiceReady,
}

/// LAN peer discovery service using mDNS polling.
///
/// Periodically scans the LAN for `_linux-link._tcp.local.` services using
/// mDNS. Emits [`LanEvent`]s through a broadcast channel whenever a peer
/// appears or disappears.
///
/// # Example
///
/// ```ignore
/// let service = LanDiscoveryService::new()?;
/// let mut rx = service.subscribe();
/// tokio::spawn(service.run(Duration::from_secs(30)));
///
/// while let Ok(event) = rx.recv().await {
///     match event {
///         LanEvent::PeerDiscovered(peer) => println!("Found peer: {}", peer.name),
///         _ => {}
///     }
/// }
/// ```
pub struct LanDiscoveryService {
    tx: broadcast::Sender<LanEvent>,
}

impl LanDiscoveryService {
    /// Create a new LAN discovery service.
    ///
    /// Does not start scanning until [`run()`](Self::run) is called.
    pub fn new() -> Result<Self> {
        let (tx, _) = broadcast::channel(100);
        Ok(Self { tx })
    }

    /// Subscribe to LAN discovery events.
    pub fn subscribe(&self) -> broadcast::Receiver<LanEvent> {
        self.tx.subscribe()
    }

    /// Run the discovery loop, polling mDNS at the given interval.
    ///
    /// On each tick, scans the LAN for `_linux-link._tcp.local.` services and
    /// emits [`LanEvent::PeerDiscovered`] for new peers and
    /// [`LanEvent::PeerOffline`] for peers that disappeared.
    ///
    /// Runs until cancelled (e.g. by dropping the receiving side of the
    /// broadcast channel).
    pub async fn run(&self, scan_interval: Duration) {
        let mut ticker = tokio::time::interval(scan_interval);
        let mut known_peers: HashMap<String, bool> = HashMap::new();

        // Initial scan
        match self.scan_lan_peers().await {
            Ok(peers) => {
                for peer in peers {
                    known_peers.insert(peer.name.clone(), true);
                    let _ = self.tx.send(LanEvent::PeerDiscovered(peer));
                }
            }
            Err(e) => warn!("Initial LAN scan failed: {e}"),
        }

        let _ = self.tx.send(LanEvent::ServiceReady);

        // Periodic re-scan
        loop {
            ticker.tick().await;
            match self.scan_lan_peers().await {
                Ok(peers) => {
                    let mut current_names: HashMap<String, bool> = HashMap::new();
                    for peer in &peers {
                        let name = peer.name.clone();
                        current_names.insert(name.clone(), true);
                        if !known_peers.contains_key(&name) {
                            info!("Discovered new LAN peer: {}", peer.name);
                            let _ = self.tx.send(LanEvent::PeerDiscovered(peer.clone()));
                        }
                    }
                    // Detect peers that went offline
                    for name in known_peers.keys() {
                        if !current_names.contains_key(name) {
                            info!("LAN peer went offline: {name}");
                            let _ = self.tx.send(LanEvent::PeerOffline(name.clone()));
                        }
                    }
                    known_peers = current_names;
                }
                Err(e) => warn!("LAN scan failed: {e}"),
            }
        }
    }

    /// Perform a single scan of the LAN for Linux Link servers.
    ///
    /// Creates a temporary mDNS daemon, browses for the service type, and
    /// collects responses for up to [`SCAN_TIMEOUT`].
    async fn scan_lan_peers(&self) -> Result<Vec<PeerInfo>> {
        let daemon =
            ServiceDaemon::new().context("Failed to create mDNS daemon for scan")?;
        let receiver = daemon
            .browse(SERVICE_TYPE)
            .context("Failed to browse mDNS")?;

        let mut peers = Vec::new();
        let deadline = std::time::Instant::now() + SCAN_TIMEOUT;

        // Collect mDNS responses within the timeout
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match receiver.recv_timeout(remaining.min(Duration::from_millis(500))) {
                Ok(ServiceEvent::ServiceResolved(info)) => {
                    if let Some(peer) = service_info_to_peer(&info) {
                        peers.push(peer);
                    }
                }
                Ok(ServiceEvent::ServiceFound(_, _)) | Ok(ServiceEvent::ServiceRemoved(_, _)) => {
                    // The service will be resolved (or removed) in a separate event
                }
                Ok(ServiceEvent::SearchStarted(_))
                | Ok(ServiceEvent::SearchStopped(_)) => {}
                Err(_) => break, // timeout or channel closed
            }
        }

        drop(daemon);
        Ok(peers)
    }

    /// Get a reference to the event sender (for testing).
    #[cfg(test)]
    pub fn tx(&self) -> &broadcast::Sender<LanEvent> {
        &self.tx
    }
}

/// Convert an mDNS `ServiceInfo` to a `PeerInfo`.
fn service_info_to_peer(info: &ServiceInfo) -> Option<PeerInfo> {
    let hostname = info.get_hostname();
    let hostname = hostname.trim_end_matches('.'); // Remove trailing dot

    // Try to get a friendly name from TXT records, fall back to hostname
    let name = info
        .get_property("name")
        .and_then(|prop| prop.val())
        .and_then(|v| String::from_utf8(v.to_vec()).ok())
        .unwrap_or_else(|| hostname.split('.').next().unwrap_or("unknown").to_string());

    // Collect all IP addresses from the mDNS response
    let ips: Vec<String> = info
        .get_addresses()
        .iter()
        .map(|addr| addr.to_string())
        .collect();

    if ips.is_empty() {
        debug!("mDNS service {} has no IP addresses", name);
        return None;
    }

    let port = info.get_port();
    let dns_name = format!("{hostname}:{port}");

    Some(PeerInfo {
        name,
        dns_name,
        ips,
        online: true,
    })
}

/// Quick check whether mDNS is available on this system.
///
/// Returns `true` if an mDNS daemon can be created and a browse query
/// starts without error.
pub fn check_mdns_available() -> bool {
    match ServiceDaemon::new() {
        Ok(daemon) => {
            let available = daemon.browse(SERVICE_TYPE).is_ok();
            drop(daemon);
            available
        }
        Err(_) => false,
    }
}

/// Scan the LAN once for Linux Link servers.
///
/// Returns all discovered peers within the default timeout (3 seconds).
/// Useful for quick "list available peers" commands.
pub async fn scan_lan_once() -> Vec<PeerInfo> {
    let service = match LanDiscoveryService::new() {
        Ok(s) => s,
        Err(e) => {
            debug!("Failed to create LAN discovery service: {e}");
            return Vec::new();
        }
    };
    match service.scan_lan_peers().await {
        Ok(peers) => peers,
        Err(e) => {
            debug!("LAN scan failed: {e}");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lan_discovery_service_new() {
        let service = LanDiscoveryService::new();
        assert!(service.is_ok());
    }

    #[test]
    fn test_check_mdns_available_runs() {
        // Should not panic. May return false in CI without mDNS.
        let _ = check_mdns_available();
    }

    #[test]
    fn test_service_info_to_peer_valid() {
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            "test-peer",
            "test-peer.local.",
            "192.168.1.10",
            1716,
            None,
        )
        .expect("Failed to create test ServiceInfo");

        let peer = service_info_to_peer(&info);
        assert!(peer.is_some());
        let peer = peer.unwrap();
        assert_eq!(peer.name, "test-peer");
        assert!(peer.ips.contains(&"192.168.1.10".to_string()));
        assert_eq!(peer.dns_name, "test-peer.local:1716");
    }

    #[test]
    fn test_service_info_to_peer_no_name_property() {
        // Without "name" TXT property, should fall back to hostname
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            "my-machine",
            "my-machine.local.",
            "10.0.0.5",
            1716,
            None,
        )
        .expect("Failed to create test ServiceInfo");

        let peer = service_info_to_peer(&info);
        assert!(peer.is_some());
        let peer = peer.unwrap();
        // Falls back to hostname without domain suffix
        assert_eq!(peer.name, "my-machine");
        assert!(peer.ips.contains(&"10.0.0.5".to_string()));
    }

    #[test]
    fn test_event_channel() {
        let service = LanDiscoveryService::new().unwrap();
        let mut rx = service.subscribe();

        let _ = service.tx.send(LanEvent::ServiceReady);
        let event = rx.try_recv();
        assert!(matches!(event, Ok(LanEvent::ServiceReady)));
    }
}
