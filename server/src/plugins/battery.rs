use linux_link_core::protocol::kdeconnect::Plugin;

#[derive(Debug, Default)]
pub struct BatteryPlugin;

impl BatteryPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Plugin for BatteryPlugin {
    fn name(&self) -> &'static str {
        "battery"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.battery.request"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.battery"]
    }
}
