//! Hyprland workspace-HUD event bridge (R3#8).
//!
//! Streams socket2 compositor events and pushes them to connected clients
//! as `kdeconnect.linuxlink.hyprland.event` packets, plus a full
//! `kdeconnect.linuxlink.hyprland.state` snapshot whenever a client
//! registers. The phone renders both into a workspace HUD and switches
//! workspaces through the existing Super+N input path (Hyprland's socket1
//! write dispatchers are broken upstream, so actions never ride IPC).

use std::sync::Arc;
use std::time::Duration;

use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket};

use crate::hyprland::{HyprEvent, HyprlandIpc};

/// Packet type for a single Hyprland event (body: `{event, data}`).
pub const EVENT_PACKET: &str = "kdeconnect.linuxlink.hyprland.event";

/// Packet type for the full workspace/window snapshot (sent on register).
pub const STATE_PACKET: &str = "kdeconnect.linuxlink.hyprland.state";

/// Compositor events the HUD consumes. Everything socket2 emits
/// (`render`, `monitorremoved`, …) is filtered out.
pub fn is_hud_event(name: &str) -> bool {
    matches!(
        name,
        "activewindow"
            | "workspace"
            | "openwindow"
            | "closewindow"
            | "movewindow"
            | "focuswindow"
            | "createworkspace"
            | "destroyworkspace"
            | "renameworkspace"
    )
}

/// Wrap a compositor event into a push packet, or `None` if irrelevant.
pub fn event_packet(ev: &HyprEvent) -> Option<NetworkPacket> {
    if !is_hud_event(&ev.name) {
        return None;
    }
    Some(
        NetworkPacket::new(EVENT_PACKET).with_body(serde_json::json!({
            "event": ev.name,
            "data": ev.data,
        })),
    )
}

/// Full HUD state: workspaces, visible windows, and the focused window.
pub async fn state_packet(ipc: &HyprlandIpc) -> Option<NetworkPacket> {
    let workspaces = ipc.workspaces().await.ok()?;
    let clients = ipc.visible_windows().await.unwrap_or_default();
    let active = ipc.active_window().await.ok().flatten();
    Some(
        NetworkPacket::new(STATE_PACKET).with_body(serde_json::json!({
            "workspaces": workspaces
                .iter()
                .map(|w| serde_json::json!({"id": w.id, "name": w.name, "active": w.active}))
                .collect::<Vec<_>>(),
            "activeWorkspace": workspaces.iter().find(|w| w.active).map(|w| w.id),
            "windows": clients
                .iter()
                .map(|w| serde_json::json!({
                    "address": w.address,
                    "workspace": w.workspace.id,
                    "class": w.class,
                    "title": w.title,
                }))
                .collect::<Vec<_>>(),
            "activeAddress": active.as_ref().map(|a| a.address.clone()),
            "activeTitle": active.as_ref().map(|a| a.title.clone()),
        })),
    )
}

/// Send the current snapshot to one freshly-registered client. Best-effort.
pub async fn push_state_to(sender: &Arc<dyn DeviceSender>, ipc: &HyprlandIpc) {
    if let Some(packet) = state_packet(ipc).await {
        let _ = sender.send_packet(&packet).await;
    }
}

/// Spawn the socket2 reader with reconnect and fan events out on a
/// broadcast channel. The loop is cheap when Hyprland goes away (a failed
/// unix-socket connect per retry) so it self-heals on compositor restart
/// within the same session.
pub fn start_hypr_event_monitor(ipc: HyprlandIpc) -> tokio::sync::broadcast::Sender<HyprEvent> {
    let (tx, _) = tokio::sync::broadcast::channel::<HyprEvent>(128);
    let monitor_tx = tx.clone();
    tokio::spawn(async move {
        run_monitor(ipc, monitor_tx).await;
    });
    tx
}

async fn run_monitor(ipc: HyprlandIpc, tx: tokio::sync::broadcast::Sender<HyprEvent>) {
    loop {
        match ipc.subscribe_events().await {
            Ok(mut rx) => {
                tracing::info!("Hyprland event monitor started");
                while let Some(ev) = rx.recv().await {
                    let _ = tx.send(ev);
                }
                tracing::warn!("Hyprland event stream ended; resubscribing");
            }
            Err(e) => {
                tracing::debug!("Hyprland event socket unavailable: {e}");
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hud_events_are_whitelisted() {
        assert!(is_hud_event("activewindow"));
        assert!(is_hud_event("workspace"));
        assert!(is_hud_event("renameworkspace"));
        assert!(!is_hud_event("render"));
        assert!(!is_hud_event("monitorremoved"));
    }

    #[test]
    fn event_packet_wraps_name_and_data() {
        let ev = HyprEvent::parse("activewindow>>brave-browser,Some, Title").unwrap();
        let packet = event_packet(&ev).expect("activewindow is pushed");
        assert_eq!(packet.packet_type, EVENT_PACKET);
        assert_eq!(packet.body["event"], "activewindow");
        assert_eq!(packet.body["data"], "brave-browser,Some, Title");
        assert!(event_packet(&HyprEvent::parse("render>>").unwrap()).is_none());
    }
}
