use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::PROTOCOL_VERSION;

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

pub trait Plugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn incoming_capabilities(&self) -> &'static [&'static str];
    fn outgoing_capabilities(&self) -> &'static [&'static str];
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, Arc<dyn Plugin>>,
    incoming_map: HashMap<String, Vec<String>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
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
