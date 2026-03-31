use anyhow::{Context, Result};
use linux_link_core::protocol::kdeconnect::{DeviceIdentity, KdeConnectService, TrustStore};
use std::path::PathBuf;

use crate::plugins::{
    battery::BatteryPlugin, clipboard::ClipboardPlugin, input::InputPlugin,
    notification::NotificationPlugin, share::SharePlugin,
};

pub fn build_default_service() -> Result<KdeConnectService> {
    let mut service = KdeConnectService::new();

    service.register_plugin(BatteryPlugin::new());
    service.register_plugin(ClipboardPlugin::new());
    service.register_plugin(NotificationPlugin::new());
    service.register_plugin(SharePlugin::new());
    service.register_plugin(InputPlugin::new());

    let (incoming, outgoing) = service.registry.capability_sets();

    let mut identity = DeviceIdentity::new(host_device_id(), host_device_name());
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

    format!("linux-link-{}", std::process::id())
}

fn host_device_name() -> String {
    if let Ok(name) = std::env::var("HOSTNAME")
        && !name.is_empty()
    {
        return name;
    }

    "linux-link-host".to_string()
}
