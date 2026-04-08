use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::PROTOCOL_VERSION;

/// A KDE Connect network packet (JSON, newline-terminated on wire).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPacket {
    #[serde(rename = "type")]
    pub packet_type: String,
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub body: Value,
    #[serde(default)]
    pub payload_size: Option<u64>,
}

impl NetworkPacket {
    pub fn new(packet_type: impl Into<String>) -> Self {
        Self {
            packet_type: packet_type.into(),
            id: 0,
            body: Value::Null,
            payload_size: None,
        }
    }

    pub fn with_body(mut self, body: Value) -> Self {
        self.body = body;
        self
    }

    pub fn with_payload_size(mut self, size: u64) -> Self {
        self.payload_size = Some(size);
        self
    }

    /// Serialize to JSON bytes with a trailing newline (wire format).
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Parse from a single wire-format line (trailing newline optional).
    pub fn from_wire(line: &str) -> Result<Self> {
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if trimmed.is_empty() {
            anyhow::bail!("empty packet line");
        }
        serde_json::from_str(trimmed).context("failed to parse NetworkPacket")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub protocol_version: u32,
    pub incoming_capabilities: Vec<String>,
    pub outgoing_capabilities: Vec<String>,
}

impl DeviceIdentity {
    pub fn new(device_id: impl Into<String>, device_name: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            device_name: device_name.into(),
            device_type: "desktop".to_string(),
            protocol_version: PROTOCOL_VERSION,
            incoming_capabilities: Vec::new(),
            outgoing_capabilities: Vec::new(),
        }
    }

    pub fn as_identity_packet(&self) -> NetworkPacket {
        NetworkPacket::new("kdeconnect.identity").with_body(serde_json::json!({
            "deviceId": self.device_id,
            "deviceName": self.device_name,
            "deviceType": self.device_type,
            "protocolVersion": self.protocol_version,
            "incomingCapabilities": self.incoming_capabilities,
            "outgoingCapabilities": self.outgoing_capabilities,
        }))
    }
}

/// Trait for KDE Connect plugins.
///
/// Plugins declare capability strings and handle incoming packets asynchronously.
/// To send packets back to the peer, plugins use the `DeviceSender` passed at runtime.
#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn incoming_capabilities(&self) -> &'static [&'static str];
    fn outgoing_capabilities(&self) -> &'static [&'static str];

    /// Handle an incoming packet. `sender` can be used to reply to the peer.
    async fn handle_packet(&self, packet: &NetworkPacket, sender: &dyn DeviceSender) -> Result<()>;
}

/// Abstraction for sending packets back to the connected peer.
/// Implemented per-connection so plugins can reply without owning the socket.
#[async_trait::async_trait]
pub trait DeviceSender: Send + Sync {
    async fn send_packet(&self, packet: &NetworkPacket) -> Result<()>;
}

/// Concrete sender that wraps the per-connection TCP write half.
pub struct TcpDeviceSender<W> {
    writer: Arc<Mutex<W>>,
}

impl<W> TcpDeviceSender<W>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    pub fn new(writer: W) -> Self {
        Self {
            writer: Arc::new(Mutex::new(writer)),
        }
    }

    pub fn from_arc(writer: Arc<Mutex<W>>) -> Self {
        Self { writer }
    }
}

#[async_trait::async_trait]
impl<W> DeviceSender for TcpDeviceSender<W>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    async fn send_packet(&self, packet: &NetworkPacket) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let bytes = packet.to_wire()?;
        let mut guard = self.writer.lock().await;
        guard.write_all(&bytes).await?;
        guard.flush().await?;
        Ok(())
    }
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, Arc<dyn Plugin>>,
    incoming_map: HashMap<String, Vec<String>>,
}

impl Clone for PluginRegistry {
    fn clone(&self) -> Self {
        Self {
            plugins: self.plugins.clone(),
            incoming_map: self.incoming_map.clone(),
        }
    }
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clone the registry for sharing across tasks via Arc.
    pub fn clone_for_dispatch(&self) -> Self {
        self.clone()
    }

    pub fn register<P>(&mut self, plugin: P)
    where
        P: Plugin + 'static,
    {
        let plugin_arc: Arc<dyn Plugin> = Arc::new(plugin);
        let plugin_name = plugin_arc.name().to_string();

        for packet_type in plugin_arc.incoming_capabilities() {
            self.incoming_map
                .entry((*packet_type).to_string())
                .or_default()
                .push(plugin_name.clone());
        }

        self.plugins.insert(plugin_name, plugin_arc);
    }

    pub fn plugin_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.plugins.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn plugins_for_packet(&self, packet_type: &str) -> Vec<String> {
        self.incoming_map
            .get(packet_type)
            .cloned()
            .unwrap_or_default()
    }

    pub fn capability_sets(&self) -> (Vec<String>, Vec<String>) {
        let mut incoming = Vec::new();
        let mut outgoing = Vec::new();

        for plugin in self.plugins.values() {
            incoming.extend(
                plugin
                    .incoming_capabilities()
                    .iter()
                    .map(|v| (*v).to_string()),
            );
            outgoing.extend(
                plugin
                    .outgoing_capabilities()
                    .iter()
                    .map(|v| (*v).to_string()),
            );
        }

        incoming.sort();
        incoming.dedup();
        outgoing.sort();
        outgoing.dedup();

        (incoming, outgoing)
    }

    /// Dispatch an incoming packet to all registered plugins that handle this packet type.
    /// Errors from individual plugins are logged but don't stop dispatch to others.
    pub async fn dispatch_packet(
        &self,
        packet: &NetworkPacket,
        sender: &dyn DeviceSender,
    ) -> Result<()> {
        let plugin_names = self.plugins_for_packet(&packet.packet_type);

        if plugin_names.is_empty() {
            tracing::debug!("no plugin handles packet type: {}", packet.packet_type);
            return Ok(());
        }

        for name in &plugin_names {
            if let Some(plugin) = self.plugins.get(name)
                && let Err(e) = plugin.handle_packet(packet, sender).await
            {
                tracing::warn!("plugin '{}' failed to handle packet: {}", name, e);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TrustStore {
    path: PathBuf,
    trusted_device_ids: HashSet<String>,
}

impl TrustStore {
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            let empty = TrustStoreFile::default();
            std::fs::write(&path, serde_json::to_vec_pretty(&empty)?)
                .with_context(|| format!("failed to initialize {}", path.display()))?;
            return Ok(Self {
                path,
                trusted_device_ids: HashSet::new(),
            });
        }

        let bytes =
            std::fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let decoded: TrustStoreFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", path.display()))?;

        Ok(Self {
            path,
            trusted_device_ids: decoded.trusted_device_ids.into_iter().collect(),
        })
    }

    pub fn is_trusted(&self, device_id: &str) -> bool {
        self.trusted_device_ids.contains(device_id)
    }

    pub fn trust_device(&mut self, device_id: impl Into<String>) -> Result<()> {
        self.trusted_device_ids.insert(device_id.into());
        self.persist()
    }

    pub fn untrust_device(&mut self, device_id: &str) -> Result<()> {
        self.trusted_device_ids.remove(device_id);
        self.persist()
    }

    pub fn trusted_devices(&self) -> Vec<String> {
        let mut values: Vec<String> = self.trusted_device_ids.iter().cloned().collect();
        values.sort();
        values
    }

    fn persist(&self) -> Result<()> {
        let payload = TrustStoreFile {
            trusted_device_ids: self.trusted_devices(),
        };
        let bytes = serde_json::to_vec_pretty(&payload)?;
        std::fs::write(&self.path, bytes)
            .with_context(|| format!("failed to write {}", self.path.display()))?;
        Ok(())
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TrustStoreFile {
    #[serde(default)]
    trusted_device_ids: Vec<String>,
}

#[derive(Default)]
pub struct KdeConnectService {
    pub identity: Option<DeviceIdentity>,
    pub registry: PluginRegistry,
    pub trust_store: Option<TrustStore>,
}

impl KdeConnectService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_identity(&mut self, identity: DeviceIdentity) {
        self.identity = Some(identity);
    }

    pub fn set_trust_store(&mut self, store: TrustStore) {
        self.trust_store = Some(store);
    }

    pub fn identity_packet(&self) -> Option<NetworkPacket> {
        self.identity
            .as_ref()
            .map(DeviceIdentity::as_identity_packet)
    }

    pub fn register_plugin<P>(&mut self, plugin: P)
    where
        P: Plugin + 'static,
    {
        self.registry.register(plugin);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ClipboardPlugin;

    #[async_trait::async_trait]
    impl Plugin for ClipboardPlugin {
        fn name(&self) -> &'static str {
            "clipboard"
        }

        fn incoming_capabilities(&self) -> &'static [&'static str] {
            &["kdeconnect.clipboard"]
        }

        fn outgoing_capabilities(&self) -> &'static [&'static str] {
            &["kdeconnect.clipboard"]
        }

        async fn handle_packet(
            &self,
            _packet: &NetworkPacket,
            _sender: &dyn DeviceSender,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn registry_indexes_plugin_capabilities() {
        let mut registry = PluginRegistry::new();
        registry.register(ClipboardPlugin);

        assert_eq!(registry.plugin_names(), vec!["clipboard".to_string()]);
        assert_eq!(
            registry.plugins_for_packet("kdeconnect.clipboard"),
            vec!["clipboard".to_string()]
        );
    }

    #[test]
    fn trust_store_roundtrip_persists_devices() {
        let unique = format!(
            "linux-link-trust-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);

        let mut store = TrustStore::load_or_create(&path).expect("create trust store");
        store
            .trust_device("device-a")
            .expect("write trusted device");

        let reloaded = TrustStore::load_or_create(&path).expect("reload trust store");
        assert!(reloaded.is_trusted("device-a"));

        let _ = std::fs::remove_file(path);
    }
}
