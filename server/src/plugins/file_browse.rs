use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

pub struct FileBrowsePlugin;

impl FileBrowsePlugin {
    pub fn new() -> Self {
        Self
    }

    /// Validate that the requested path is safe to serve.
    /// Only allows paths within the user's home directory.
    fn sanitize_path(requested: &str) -> Option<PathBuf> {
        let home = dirs::home_dir()?;
        let path = Path::new(requested);

        // Reject relative paths
        if !path.is_absolute() {
            return None;
        }

        // Reject paths outside home
        if !path.starts_with(&home) {
            return None;
        }

        // Reject paths containing ".." components
        for component in path.components() {
            if let std::path::Component::ParentDir = component {
                return None;
            }
        }

        Some(path.to_path_buf())
    }

    /// List directory contents as a JSON array of file entries.
    fn list_directory(path: &Path) -> anyhow::Result<serde_json::Value> {
        let entries: Vec<serde_json::Value> = std::fs::read_dir(path)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let metadata = entry.metadata().ok()?;
                let name = entry.file_name().to_string_lossy().to_string();
                let is_dir = metadata.is_dir();
                let size = if is_dir { 0 } else { metadata.len() };
                let modified = metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                Some(json!({
                    "name": name,
                    "isDirectory": is_dir,
                    "size": size,
                    "modified": modified,
                }))
            })
            .collect();

        Ok(json!(entries))
    }
}

#[async_trait::async_trait]
impl Plugin for FileBrowsePlugin {
    fn name(&self) -> &'static str {
        "filebrowse"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.filebrowse.request"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.filebrowse.response"]
    }

    async fn handle_packet(
        &self,
        packet: &NetworkPacket,
        sender: &dyn DeviceSender,
    ) -> anyhow::Result<()> {
        if packet.packet_type.as_str() == "kdeconnect.filebrowse.request" {
            let requested_path = packet
                .body
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let path = match Self::sanitize_path(requested_path) {
                Some(p) => p,
                None => {
                    let response =
                        NetworkPacket::new("kdeconnect.filebrowse.response").with_body(json!({
                            "error": "Invalid or unauthorized path",
                            "path": requested_path,
                            "files": [],
                        }));
                    sender.send_packet(&response).await?;
                    return Ok(());
                }
            };

            let files = match Self::list_directory(&path) {
                Ok(f) => f,
                Err(e) => {
                    let response =
                        NetworkPacket::new("kdeconnect.filebrowse.response").with_body(json!({
                            "error": e.to_string(),
                            "path": requested_path,
                            "files": [],
                        }));
                    sender.send_packet(&response).await?;
                    return Ok(());
                }
            };

            let response = NetworkPacket::new("kdeconnect.filebrowse.response").with_body(json!({
                "path": requested_path,
                "files": files,
            }));
            sender.send_packet(&response).await?;
        }

        Ok(())
    }
}
