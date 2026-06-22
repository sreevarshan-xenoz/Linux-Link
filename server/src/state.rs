//! Shared server state: state directory paths and active client registry.
//!
//! Centralizes path resolution and client lifecycle management so that
//! `service.rs`, `v2_multiplexer.rs`, and `kde.rs` don't duplicate logic.

use anyhow::{Context, Result};
use linux_link_core::protocol::kdeconnect::DeviceSender;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// State directory paths
// ---------------------------------------------------------------------------

/// Base state directory for Linux Link server files.
///
/// Resolves to `$XDG_STATE_HOME/linux-link` (or equivalent on the current OS).
pub fn state_dir() -> Result<PathBuf> {
    let base = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .context("unable to determine local state directory")?;
    Ok(base.join("linux-link"))
}

/// Path to the server PID file.
pub fn pid_file_path() -> Result<PathBuf> {
    Ok(state_dir()?.join("server.pid"))
}

/// Path to the pairing PIN file.
pub fn pair_pin_path() -> Result<PathBuf> {
    Ok(state_dir()?.join("pairing.pin"))
}

/// Path to the trust store file.
pub fn trust_store_path() -> Result<PathBuf> {
    Ok(state_dir()?.join("trusted_devices.json"))
}

/// Write the current process ID to the given file, creating parent dirs as needed.
pub fn write_pid_file(path: &PathBuf) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(path, format!("{}\n", std::process::id()))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Active client registry
// ---------------------------------------------------------------------------

/// Active KDE Connect client connections for broadcasting notifications.
pub static ACTIVE_CLIENTS: LazyLock<Mutex<Vec<Arc<dyn DeviceSender>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// Register a client, evicting any stale session with the same `device_id`.
///
/// Returns the number of stale sessions that were evicted (for logging).
pub async fn register_client(sender: Arc<dyn DeviceSender>) -> usize {
    let mut clients = ACTIVE_CLIENTS.lock().await;
    let device_id = sender.device_id().to_string();

    // Kick out any existing clients with the same device_id to prevent Parallel Brain
    let old_len = clients.len();
    clients.retain(|c| c.device_id() != device_id);
    let kicked = old_len - clients.len();

    if kicked > 0 {
        tracing::warn!(
            device_id = %device_id,
            "Kicked {} stale session(s) due to reconnect storm",
            kicked
        );
    }

    clients.push(sender);
    tracing::debug!(active_clients = clients.len(), "Client registered for broadcasts");

    kicked
}

/// Remove a client by its connection ID.
pub async fn unregister_client(connection_id: &str) {
    let mut clients = ACTIVE_CLIENTS.lock().await;
    clients.retain(|c| c.connection_id() != connection_id);
    tracing::info!(active_clients = clients.len(), "Client disconnected, removed from registry");
}

/// Clone the current client list (for iteration without holding the lock).
pub async fn clone_clients() -> Vec<Arc<dyn DeviceSender>> {
    let clients = ACTIVE_CLIENTS.lock().await;
    clients.clone()
}

/// Remove clients whose `connection_id` appears in `dead_ids`.
pub async fn prune_dead_clients(dead_ids: &[String]) {
    let mut clients = ACTIVE_CLIENTS.lock().await;
    clients.retain(|c| !dead_ids.iter().any(|d| d == c.connection_id()));
}
