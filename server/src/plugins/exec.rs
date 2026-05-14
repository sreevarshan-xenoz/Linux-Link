use anyhow::{Context, Result};
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};
use serde_json::json;
use tokio::process::Command;

/// Remote command execution plugin.
///
/// Handles `kdeconnect.linuxlink.exec` packets. Executes a shell command
/// on the server and returns stdout, stderr, and the exit code.
///
/// By default, commands run through `/bin/sh -c` for maximum compatibility.    /// A command whitelist can be configured in the server config.
pub struct ExecPlugin {
    #[allow(dead_code)]
    whitelist: Option<Vec<String>>,
}

impl ExecPlugin {
    pub fn new() -> Self {
        Self { whitelist: None }
    }

    #[allow(dead_code)]
    pub fn with_whitelist(commands: Vec<String>) -> Self {
        Self {
            whitelist: Some(commands),
        }
    }

    fn is_allowed(&self, command: &str) -> bool {
        match &self.whitelist {
            Some(list) => list.iter().any(|allowed| command.starts_with(allowed)),
            None => true, // No whitelist = all commands allowed
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
            let body = &packet.body;
            let command = body.get("command").and_then(|v| v.as_str()).unwrap_or("");

            if command.is_empty() {
                let response = NetworkPacket::new("kdeconnect.linuxlink.exec").with_body(json!({
                    "stdout": "",
                    "stderr": "Empty command",
                    "exit_code": 1,
                }));
                sender.send_packet(&response).await?;
                return Ok(());
            }

            if !self.is_allowed(command) {
                let response = NetworkPacket::new("kdeconnect.linuxlink.exec").with_body(json!({
                    "stdout": "",
                    "stderr": format!("Command not allowed: {command}"),
                    "exit_code": 1,
                }));
                sender.send_packet(&response).await?;
                return Ok(());
            }

            tracing::info!("Executing command: {command}");

            match execute_command(command).await {
                Ok((stdout, stderr, exit_code)) => {
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
        Ok(())
    }
}

/// Execute a shell command and return (stdout, stderr, exit_code).
async fn execute_command(command: &str) -> Result<(String, String, i32)> {
    let output = Command::new("/bin/sh")
        .args(["-c", command])
        .output()
        .await
        .with_context(|| format!("Failed to execute: {command}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    tracing::debug!(
        "Command exit_code={} stdout={} stderr={}",
        exit_code,
        stdout.len(),
        stderr.len()
    );

    Ok((stdout, stderr, exit_code))
}
