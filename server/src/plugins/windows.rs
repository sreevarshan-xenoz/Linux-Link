use linux_link_core::error::Result;
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};
use tracing::info;

use crate::hyprland::HyprlandIpc;

/// R3#7: Hyprland window enumeration for the phone-side picker.
///
/// Responds to `kdeconnect.linuxlink.windows` queries with the visible
/// windows (address, title, class, geometry, workspace) plus the active
/// window address. On non-Hyprland sessions replies `available: false`.
pub struct WindowsPlugin;

#[async_trait::async_trait]
impl Plugin for WindowsPlugin {
    fn name(&self) -> &'static str {
        "windows"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.linuxlink.windows"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &[]
    }

    async fn handle_packet(&self, packet: &NetworkPacket, sender: &dyn DeviceSender) -> Result<()> {
        if packet.packet_type != "kdeconnect.linuxlink.windows" {
            return Ok(());
        }

        let body = match HyprlandIpc::from_env() {
            Ok(ipc) => match ipc.visible_windows().await {
                Ok(windows) => {
                    let active = ipc.active_window().await.ok().flatten().map(|w| w.address);
                    info!("Windows queried: {} visible", windows.len());
                    serde_json::json!({
                        "available": true,
                        "activeAddress": active,
                        "windows": windows,
                    })
                }
                Err(e) => {
                    info!("Hyprland window query failed: {e}");
                    serde_json::json!({ "available": false, "activeAddress": null, "windows": [] })
                }
            },
            Err(_) => {
                serde_json::json!({ "available": false, "activeAddress": null, "windows": [] })
            }
        };

        let response = NetworkPacket::new("kdeconnect.linuxlink.windows").with_body(body);
        sender.send_packet(&response).await?;
        Ok(())
    }
}
