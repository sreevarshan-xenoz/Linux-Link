use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};
use serde_json::json;

#[derive(Debug)]
pub struct BatteryPlugin;

impl BatteryPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
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

    async fn handle_packet(
        &self,
        packet: &NetworkPacket,
        sender: &dyn DeviceSender,
    ) -> anyhow::Result<()> {
        match packet.packet_type.as_str() {
            "kdeconnect.battery.request" => {
                let charge = read_battery_charge().await;
                let is_charging = read_is_charging().await;
                let response = NetworkPacket::new("kdeconnect.battery").with_body(json!({
                    "currentCharge": charge,
                    "isCharging": is_charging,
                }));
                sender.send_packet(&response).await?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Read battery charge percentage from UPower (or fallback to 100 for desktops).
async fn read_battery_charge() -> u8 {
    read_upower_property("Percentage").await.unwrap_or(100u8)
}

/// Check if battery is charging via UPower.
async fn read_is_charging() -> bool {
    read_upower_property("State")
        .await
        .map(|state: u32| state == 1)
        .unwrap_or(true)
}

/// Read a property from UPower's display-device via dbus-send.
async fn read_upower_property<T: std::str::FromStr>(property: &str) -> Option<T> {
    let output = tokio::process::Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.UPower",
            "--object-path",
            "/org/freedesktop/UPower/devices/DisplayDevice",
            "--method",
            "org.freedesktop.DBus.Properties.Get",
            "org.freedesktop.UPower.Device",
            property,
        ])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // gdbus returns a variant like `(variant <value>)` - try to parse
    parse_gdbus_variant(&stdout).and_then(|v| v.parse::<T>().ok())
}

/// Parse a gdbus variant response, extracting the inner value.
fn parse_gdbus_variant(output: &str) -> Option<String> {
    // Example: "(variant uint32 85)" -> "85"
    // Example: "(variant <'Charging'>)" -> "Charging"
    let trimmed = output.trim();
    if let Some(start) = trimmed.find("variant ") {
        let inner = &trimmed[start + 8..];
        let inner = inner.trim().trim_matches(|c| c == '(' || c == ')');
        // For string variants like <'Charging'>, extract the quoted part
        if let Some(q_start) = inner.find('\'') {
            if let Some(q_end) = inner[q_start + 1..].find('\'') {
                return Some(inner[q_start + 1..q_start + 1 + q_end].to_string());
            }
        }
        // For numeric variants, take the last token
        return inner.split_whitespace().last().map(String::from);
    }
    None
}
