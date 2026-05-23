use anyhow::{Context, Result};
use linux_link_core::protocol::kdeconnect::{DeviceIdentity, KdeConnectService, TrustStore};
use std::path::PathBuf;

/// Directory for server state files (device ID, trust store, etc.)
fn state_dir() -> Result<PathBuf> {
    let base = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .context("unable to determine local state directory")?;
    Ok(base.join("linux-link"))
}

use crate::plugins::{
    battery::BatteryPlugin, clipboard::ClipboardPlugin, exec::ExecPlugin,
    file_browse::FileBrowsePlugin, input::InputPlugin, monitors::MonitorsPlugin,
    notification::NotificationPlugin, power::PowerPlugin, share::SharePlugin,
};

pub fn host_identity() -> DeviceIdentity {
    DeviceIdentity::new(host_device_id(), host_device_name())
}

pub fn build_default_service() -> Result<KdeConnectService> {
    let mut service = KdeConnectService::new();

    service.register_plugin(BatteryPlugin::new());
    service.register_plugin(ClipboardPlugin::new());
    service.register_plugin(NotificationPlugin::new());
    service.register_plugin(SharePlugin::new());
    service.register_plugin(InputPlugin::new());
    service.register_plugin(FileBrowsePlugin::new());
    service.register_plugin(PowerPlugin::new());
    service.register_plugin(ExecPlugin::new());
    service.register_plugin(MonitorsPlugin);

    let (incoming, outgoing) = service.registry.capability_sets();

    let mut identity = host_identity();
    identity.incoming_capabilities = incoming;
    identity.outgoing_capabilities = outgoing;
    service.set_identity(identity);

    let trust_store = TrustStore::load_or_create(trust_store_path()?)?;
    service.set_trust_store(trust_store);

    Ok(service)
}

fn trust_store_path() -> Result<PathBuf> {
    let base = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .context("unable to determine local state directory")?;
    Ok(base.join("linux-link").join("trusted_devices.json"))
}

fn host_device_id() -> String {
    if let Ok(id) = std::env::var("LINUX_LINK_DEVICE_ID") {
        return id;
    }

    let path = state_dir()
        .map(|d| d.join("device_id"))
        .unwrap_or_else(|_| PathBuf::from("device_id"));
    if let Ok(id) = std::fs::read_to_string(&path) {
        let trimmed = id.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    // Generate and persist a stable UUID
    let id = uuid::Uuid::new_v4().to_string();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, &id);
    id
}

fn host_device_name() -> String {
    if let Ok(name) = std::env::var("HOSTNAME")
        && !name.is_empty()
    {
        return name;
    }

    "linux-link-host".to_string()
}
