use linux_link_core::error::Result;
use dashmap::DashMap;
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};
use serde_json::json;
use std::path::PathBuf;
use tokio::process::Command;

/// Remote command execution plugin.
///
/// Allows running predefined commands on the host system.
///
/// NOTE: For security, in a production environment, this should only allow
/// executing scripts from a specific whitelist directory.
pub struct ExecPlugin {
    #[allow(dead_code)]
    commands: DashMap<String, PathBuf>,
}

impl ExecPlugin {
    pub fn new() -> Self {
        Self {
            commands: DashMap::new(),
        }
    }
}

impl Default for ExecPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Plugin for ExecPlugin {
    fn name(&self) -> &'static str {
        "exec"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.linuxlink.exec"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.linuxlink.exec"]
    }

    async fn handle_packet(&self, packet: &NetworkPacket, sender: &dyn DeviceSender) -> Result<()> {
        if packet.packet_type.as_str() == "kdeconnect.linuxlink.exec" {
            let command = packet.body.get("command").and_then(|v| v.as_str());

            if let Some(cmd) = command {
                tracing::info!("Executing remote command: {}", cmd);

                // Run the command using sh -c
                let output = Command::new("sh").arg("-c").arg(cmd).output().await;

                match output {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        let exit_code = out.status.code().unwrap_or(-1);

                        let response =
                            NetworkPacket::new("kdeconnect.linuxlink.exec").with_body(json!({
                                "stdout": stdout,
                                "stderr": stderr,
                                "exit_code": exit_code,
                            }));
                        sender.send_packet(&response).await?;
                    }
                    Err(e) => {
                        let response =
                            NetworkPacket::new("kdeconnect.linuxlink.exec").with_body(json!({
                                "stdout": "",
                                "stderr": format!("Execution error: {e}"),
                                "exit_code": -1,
                            }));
                        sender.send_packet(&response).await?;
                    }
                }
            }
        }
        Ok(())
    }
}
