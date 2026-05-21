use anyhow::Result;
use dashmap::DashMap;
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};
use serde_json::json;
use std::path::PathBuf;
use tokio::process::Command;

/// Remote command execution plugin.
///
/// Handles `kdeconnect.linuxlink.exec` packets. Executes a shell command
/// on the server and returns stdout, stderr, and the exit code.
///
/// By default, commands run through `/bin/sh -c` for maximum compatibility.
pub struct ExecPlugin {
    #[allow(dead_code)]
    whitelist: Option<Vec<String>>,
    /// Map of device_id -> current working directory for stateful sessions.
    cwd_map: DashMap<String, PathBuf>,
}

impl ExecPlugin {
    pub fn new() -> Self {
        Self {
            whitelist: None,
            cwd_map: DashMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn with_whitelist(commands: Vec<String>) -> Self {
        Self {
            whitelist: Some(commands),
            cwd_map: DashMap::new(),
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
            let device_id = sender.device_id().to_string();

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

            tracing::info!("Executing command [{}]: {}", device_id, command);

            let initial_cwd = self
                .cwd_map
                .get(&device_id)
                .map(|p| p.clone())
                .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")));

            // To support persistent 'cd', we run the command and then print the new PWD with a marker.
            // We use ';' instead of '&&' so that pwd runs even if the command fails (important for 'cd' to bad paths).
            let marker = "---LINUX_LINK_CWD---";
            let wrapped_command = format!("{} ; echo -n \"\n{}\"; pwd", command, marker);

            let output = Command::new("/bin/sh")
                .args(["-c", &wrapped_command])
                .current_dir(&initial_cwd)
                .output()
                .await;

            match output {
                Ok(output) => {
                    let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);

                    // Parse the new CWD from stdout
                    if let Some(idx) = stdout.rfind(marker) {
                        let new_cwd = stdout[idx + marker.len()..].trim().to_string();
                        if !new_cwd.is_empty() {
                            self.cwd_map.insert(device_id, PathBuf::from(new_cwd));
                        }
                        // Remove the marker and the path from stdout
                        stdout.truncate(idx);
                        // Also remove a trailing newline if it exists
                        if stdout.ends_with('\n') {
                            stdout.pop();
                        }
                    }

                    tracing::debug!(
                        "Command exit_code={} stdout={} stderr={}",
                        exit_code,
                        stdout.len(),
                        stderr.len()
                    );

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
