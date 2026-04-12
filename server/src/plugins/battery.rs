use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};

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
        if packet.packet_type.as_str() == "kdeconnect.battery.request" {
            let (charge, is_charging) = match (
                read_battery_charge().await,
                read_is_charging().await,
            ) {
                (Some(charge), Some(charging)) => (charge, charging),
                _ => {
                    // No battery found — send explicit "no battery" response
                    let response = NetworkPacket::new("kdeconnect.battery").with_body(
                        serde_json::json!({
                            "currentCharge": 0,
                            "isCharging": false,
                            "noBattery": true,
                        }),
                    );
                    sender.send_packet(&response).await?;
                    return Ok(());
                }
            };
            let response = NetworkPacket::new("kdeconnect.battery").with_body(
                serde_json::json!({
                    "currentCharge": charge,
                    "isCharging": is_charging,
                }),
            );
            sender.send_packet(&response).await?;
        }
        Ok(())
    }
}

/// Read battery charge percentage.
///
/// Tries UPower D-Bus first, then falls back to sysfs.
/// Returns None if no battery is found (desktop system).
async fn read_battery_charge() -> Option<u8> {
    // Try UPower first
    if let Some(charge) = read_upower_percentage().await {
        return Some(charge);
    }

    // Fall back to sysfs
    read_sysfs_capacity()
}

/// Try to read battery percentage from UPower via gdbus.
async fn read_upower_percentage() -> Option<u8> {
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
            "Percentage",
        ])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse "(variant <double> 85.0)" → 85
    stdout
        .trim()
        .split_whitespace()
        .last()
        .and_then(|s| s.parse::<f64>().ok())
        .map(|v| v as u8)
}

/// Read battery capacity from sysfs.
fn read_sysfs_capacity() -> Option<u8> {
    // Try BAT0, BAT1, BAT2
    for bat in &["BAT0", "BAT1", "BAT2"] {
        let path = format!("/sys/class/power_supply/{}/capacity", bat);
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(capacity) = content.trim().parse::<u8>() {
                return Some(capacity);
            }
        }
    }
    None
}

/// Check if battery is charging.
///
/// Tries UPower first, then sysfs.
/// Returns None if no battery is found.
async fn read_is_charging() -> Option<bool> {
    // Try UPower first
    if let Some(charging) = read_upower_charging().await {
        return Some(charging);
    }

    // Fall back to sysfs
    read_sysfs_status()
}

/// Try to read charging status from UPower via gdbus.
async fn read_upower_charging() -> Option<bool> {
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
            "State",
        ])
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // UPower State: 1=Charging, 2=Discharging, 3=Not charging
    stdout
        .contains("variant <uint32> 1")
        .then_some(true)
        .or_else(|| stdout.contains("variant <uint32>").then_some(false))
}

/// Read charging status from sysfs.
fn read_sysfs_status() -> Option<bool> {
    for bat in &["BAT0", "BAT1", "BAT2"] {
        let path = format!("/sys/class/power_supply/{}/status", bat);
        if let Ok(content) = std::fs::read_to_string(&path) {
            let status = content.trim();
            return Some(status == "Charging");
        }
    }
    None
}
