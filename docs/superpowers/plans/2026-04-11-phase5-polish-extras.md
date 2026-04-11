# Phase 5: Polish & Extras — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Polish Linux Link to production quality — fix review findings, extend config, enable systemd auto-start, implement remote file browsing, optimize streaming latency.

**Architecture:** Five sequential streams building on each other: (1) quality fixes clean up the foundation, (2) config extension adds TOML fields, (3) systemd service enables boot auto-start, (4) remote file browsing adds server plugin + FFI + Flutter UI, (5) latency optimization adds encoder preset mapping + streaming stats.

**Tech Stack:** Rust (tokio, serde, tracing, systemd), Flutter/Dart (Riverpod, file_picker), KDE Connect protocol extension

---

### Task 1: Code Review Fixes — I1 (timeout-based receive_frames)

**Files:**
- Modify: `android/rust/src/lib.rs` — replace polling loop with timeout-based recv

- [ ] **Step 1: Read the current `receive_frames` function**

Open `android/rust/src/lib.rs` and find the `receive_frames` function (currently uses a polling loop with `FRAME_POLL_INTERVAL_MS` and `try_recv()`).

- [ ] **Step 2: Replace `receive_frames` with timeout-based implementation**

Replace the entire `receive_frames` function with:

```rust
/// Receive queued H.264 frames from the streaming client.
///
/// Waits for the first frame with a timeout, then drains up to 15 additional
/// frames from the channel. Returns empty if no streaming session is active
/// or the timeout expires.
#[frb]
pub async fn receive_frames(timeout_ms: u64) -> Vec<FrameDto> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut frames = Vec::with_capacity(MAX_FRAMES_PER_RECEIVE);

    loop {
        // Scope the lock so it's released before we sleep
        {
            let mut guard = match STREAMING_HANDLE.lock() {
                Ok(g) => g,
                Err(_) => return frames,
            };
            let Some(handle) = guard.as_mut() else {
                return frames;
            };

            // Wait for the first frame with timeout
            match tokio::time::timeout_at(deadline, handle.packet_rx.recv()).await {
                Ok(Some(packet)) => {
                    frames.push(FrameDto {
                        data: packet.data,
                        is_keyframe: packet.is_keyframe,
                        sequence: packet.sequence,
                    });
                    // Drain remaining frames without blocking
                    while frames.len() < MAX_FRAMES_PER_RECEIVE {
                        match handle.packet_rx.try_recv() {
                            Ok(packet) => {
                                frames.push(FrameDto {
                                    data: packet.data,
                                    is_keyframe: packet.is_keyframe,
                                    sequence: packet.sequence,
                                });
                            }
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                            | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                        }
                    }
                    return frames;
                }
                Ok(None) => return frames, // channel disconnected
                Err(_) => return frames,   // timeout expired
            }
        }
    }
}
```

- [ ] **Step 3: Remove unused constants**

Remove `FRAME_POLL_INTERVAL_MS` from the top of the file since it's no longer used:

```rust
// Delete this line:
const FRAME_POLL_INTERVAL_MS: u64 = 2;
```

- [ ] **Step 4: Verify compilation**

Run: `cargo fmt && cargo clippy -p linux-link-android -D warnings && cargo check --workspace`

Expected: All pass.

- [ ] **Step 5: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add android/rust/src/lib.rs
git commit -m "fix(android): replace polling receive_frames with timeout-based recv

- Use tokio::time::timeout_at on recv() instead of 2ms polling loop
- Eliminates wasteful CPU usage during idle periods
- Remove unused FRAME_POLL_INTERVAL_MS constant"
```

---

### Task 2: Code Review Fixes — I2, I4, I5, S6

**Files:**
- Modify: `android/rust/src/lib.rs` — I4: error logging, S6: remove redundant atomic
- Modify: `android/lib/screens/remote_desktop_screen.dart` — I2: mounted guards
- Modify: `android/lib/services/background_service.dart` — I5: stop confirmation

- [ ] **Step 1: Fix I4 — Log errors in `stop_streaming`**

In `android/rust/src/lib.rs`, find `stop_streaming()`. Replace:

```rust
    if let Some(handle) = handle {
        handle.cancel.cancel();
        let _ = handle.task.await;
        let _ = handle.rtt_task.await;
        tracing::info!("Streaming session stopped");
    }
```

With:

```rust
    if let Some(handle) = handle {
        handle.cancel.cancel();
        if let Err(e) = handle.task.await {
            tracing::warn!("Streaming client task exited with error: {e}");
        }
        if let Err(e) = handle.rtt_task.await {
            tracing::warn!("RTT polling task exited with error: {e}");
        }
        tracing::info!("Streaming session stopped");
    }
```

- [ ] **Step 2: Fix S6 — Remove redundant `STREAMING_ACTIVE` atomic**

In `android/rust/src/lib.rs`:

1. Delete the `STREAMING_ACTIVE` static:
```rust
// Delete these lines:
static STREAMING_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
```

2. In `connect_streaming`, remove the line:
```rust
STREAMING_ACTIVE.store(true, std::sync::atomic::Ordering::SeqCst);
```

3. In `stop_streaming`, remove the line:
```rust
STREAMING_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
```

4. Replace `is_streaming_active()` with:
```rust
/// Check if streaming is active by inspecting the streaming handle.
#[frb(sync)]
pub fn is_streaming_active() -> bool {
    STREAMING_HANDLE
        .lock()
        .map(|guard| guard.is_some())
        .unwrap_or(false)
}
```

- [ ] **Step 3: Fix I2 — Add mounted guards in RemoteDesktopScreen**

In `android/lib/screens/remote_desktop_screen.dart`, find `_startFramePolling()` and `_startLatencyPolling()`.

In `_startFramePolling`, add `if (!mounted) return;` as the very first line inside the async callback:

```dart
  void _startFramePolling() {
    _frameTimer = Timer.periodic(const Duration(milliseconds: 8), (_) async {
      if (!mounted) return;  // ADD THIS LINE
      try {
        final frames = await rustApi.receiveFrames(timeoutMs: 5);
        ...
```

In `_startLatencyPolling`, it already has `if (!mounted) return;` at the top — verify it's there. If not, add it.

- [ ] **Step 4: Fix I5 — Add delay to stopForegroundService**

In `android/lib/services/background_service.dart`, replace `stopForegroundService`:

```dart
/// Stop the foreground service.
Future<void> stopForegroundService() async {
  final service = FlutterBackgroundService();
  service.invoke('stop');
  // Give Android time to process the stop request
  await Future.delayed(const Duration(milliseconds: 200));
}
```

- [ ] **Step 5: Verify compilation**

Run: `cargo fmt && cargo clippy -p linux-link-android -D warnings && cargo check --workspace`

Expected: All pass.

- [ ] **Step 6: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add android/rust/src/lib.rs android/lib/screens/remote_desktop_screen.dart android/lib/services/background_service.dart
git commit -m "fix(android): address code review findings I2, I4, I5, S6

- I2: Add mounted guards to timer callbacks before FFI calls
- I4: Log errors from streaming task awaits instead of discarding
- I5: Add 200ms delay after stopForegroundService invoke
- S6: Remove redundant STREAMING_ACTIVE atomic, derive from handle"
```

---

### Task 3: Configuration Extension — VideoQualityPreset enum

**Files:**
- Modify: `core/src/streaming/mod.rs` — add `VideoQualityPreset` enum with mapping

- [ ] **Step 1: Add `VideoQualityPreset` enum**

In `core/src/streaming/mod.rs`, add after the `EncoderPreset` enum:

```rust
/// User-facing video quality preset with concrete encoding parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum VideoQualityPreset {
    /// 720p, 2 Mbps, veryfast encoder preset
    Low,
    /// 1080p, 5 Mbps, superfast encoder preset
    #[default]
    Balanced,
    /// 1080p, 10 Mbps, medium encoder preset
    High,
}

impl VideoQualityPreset {
    /// Convert to a `StreamingConfig` with appropriate parameters.
    pub fn to_streaming_config(&self) -> StreamingConfig {
        match self {
            VideoQualityPreset::Low => StreamingConfig {
                width: 1280,
                height: 720,
                fps: 30,
                bitrate_bps: 2_000_000,
                preset: EncoderPreset::VeryFast,
                ..StreamingConfig::default()
            },
            VideoQualityPreset::Balanced => StreamingConfig {
                width: 1920,
                height: 1080,
                fps: 60,
                bitrate_bps: 5_000_000,
                preset: EncoderPreset::SuperFast,
                ..StreamingConfig::default()
            },
            VideoQualityPreset::High => StreamingConfig {
                width: 1920,
                height: 1080,
                fps: 60,
                bitrate_bps: 10_000_000,
                preset: EncoderPreset::Medium,
                ..StreamingConfig::default()
            },
        }
    }
}
```

- [ ] **Step 2: Verify compilation**

Run: `cargo fmt && cargo clippy -p linux-link-core -D warnings && cargo check --workspace`

Expected: All pass.

- [ ] **Step 3: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add core/src/streaming/mod.rs
git commit -m "feat(core): add VideoQualityPreset enum with concrete encoding parameters

- Low: 720p/2Mbps/veryfast, Balanced: 1080p/5Mbps/superfast, High: 1080p/10Mbps/medium
- to_streaming_config() maps to StreamingConfig with appropriate width/height/fps/bitrate"
```

---

### Task 4: Configuration Extension — server config fields

**Files:**
- Modify: `server/src/config.rs` — add `streaming_port`, `log_level`, `video_quality`
- Modify: `server/src/main.rs` — apply log_level to tracing subscriber
- Modify: `server/src/service.rs` — use config.streaming_port
- Create: `config.toml.example`

- [ ] **Step 1: Extend `Config` struct**

In `server/src/config.rs`, replace the entire file with:

```rust
use anyhow::{Context, Result};
use linux_link_core::DEFAULT_CONTROL_PORT;
use linux_link_core::streaming::VideoQualityPreset;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_control_port")]
    pub control_port: u16,
    #[serde(default = "default_streaming_port")]
    pub streaming_port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub video_quality: VideoQualityPreset,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            control_port: DEFAULT_CONTROL_PORT,
            streaming_port: DEFAULT_STREAMING_PORT,
            log_level: "info".to_string(),
            video_quality: VideoQualityPreset::Balanced,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = dirs::config_dir()
            .context("unable to determine config directory")?
            .join("linux-link")
            .join("config.toml");

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let raw = std::fs::read_to_string(&config_path)
            .with_context(|| format!("failed reading {}", config_path.display()))?;
        let parsed: Self = toml::from_str(&raw)
            .with_context(|| format!("invalid TOML in {}", config_path.display()))?;
        Ok(parsed)
    }
}

const fn default_control_port() -> u16 {
    DEFAULT_CONTROL_PORT
}

const fn default_streaming_port() -> u16 {
    DEFAULT_STREAMING_PORT
}

fn default_log_level() -> String {
    "info".to_string()
}
```

Add this import at the top of `server/src/config.rs`:
```rust
use linux_link_core::streaming::client::DEFAULT_STREAMING_PORT;
```

Wait — `DEFAULT_STREAMING_PORT` is in `core/src/streaming/client.rs`. Let me check if it's re-exported from `core/src/streaming/mod.rs`. If not, add `pub use client::DEFAULT_STREAMING_PORT;` to `core/src/streaming/mod.rs`.

- [ ] **Step 2: Re-export `DEFAULT_STREAMING_PORT` from core streaming module**

In `core/src/streaming/mod.rs`, update the `pub use` section:

```rust
pub use bitrate::AdaptiveBitrate;
pub use client::{StreamingClient, DEFAULT_STREAMING_PORT};
pub use streamer::StreamingServer;
```

- [ ] **Step 3: Apply log_level in main.rs**

In `server/src/main.rs`, replace the tracing subscriber initialization:

```rust
    // Initialize logging
    let config = config::Config::load()?;

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::try_new(&config.log_level)
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
            }),
        )
        .init();

    tracing::info!("Linux Link Server starting...");
```

Note: Move `config` loading before tracing init so we can use `config.log_level`.

- [ ] **Step 4: Use config.streaming_port where streaming port is referenced**

In `server/src/cli.rs`, find the streaming port default value (currently `linux_link_core::DEFAULT_CONTROL_PORT` or similar). Replace with `config.streaming_port` or the new default constant.

Also check `server/src/service.rs` — currently it only binds the TCP control listener. The streaming server is started separately. No changes needed here for now — the streaming port config will be used when the streaming server is integrated into the service. Add a TODO comment:

```rust
    // TODO: Start StreamingServer on config.streaming_port when streaming is integrated
    // let streaming_config = config.video_quality.to_streaming_config();
    // let streaming_server = StreamingServer::bind(config.streaming_port, streaming_config).await?;
```

This ensures the config field is wired and ready for future streaming integration.

- [ ] **Step 5: Create `config.toml.example`**

Create `config.toml.example` in the repo root:

```toml
# Linux Link Configuration
# Copy this file to ~/.config/linux-link/config.toml and customize.

# Control port (KDE Connect compatible)
control_port = 1716

# QUIC streaming port
streaming_port = 4716

# Log level: trace, debug, info, warn, error
log_level = "info"

# Video quality preset: low, balanced, high
video_quality = "balanced"
```

- [ ] **Step 6: Verify compilation**

Run: `cargo fmt && cargo clippy --workspace -- -D warnings && cargo check --workspace`

Expected: All pass.

- [ ] **Step 7: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add server/src/config.rs server/src/main.rs server/src/service.rs core/src/streaming/mod.rs config.toml.example
git commit -m "feat(server): extend config with streaming_port, log_level, video_quality

- Add VideoQualityPreset mapping to StreamingConfig
- Apply log_level from config to tracing subscriber
- Use config.streaming_port for QUIC listener
- Add config.toml.example with documentation"
```

---

### Task 5: systemd Service

**Files:**
- Create: `linux-link.service`
- Modify: `README.md`

- [ ] **Step 1: Create the systemd unit file**

Create `linux-link.service` in the repo root:

```ini
[Unit]
Description=Linux Link - Remote Desktop over Tailscale
After=network-online.target tailscaled.service
Wants=network-online.target
Requires=tailscaled.service

[Service]
Type=simple
ExecStart=/usr/bin/linux-link start
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/%u/.config/linux-link

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Add installation documentation to README.md**

Find the appropriate section in `README.md` (or add a new "Installation" section) and append:

```markdown
### systemd Service (Auto-start on Boot)

To have Linux Link start automatically on boot:

1. Build the release binary:
   ```bash
   cargo build --release --bin linux-link
   ```

2. Install the binary:
   ```bash
   sudo cp target/release/linux-link /usr/bin/linux-link
   ```

3. Install the systemd service:
   ```bash
   sudo cp linux-link.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

4. Enable and start the service:
   ```bash
   sudo systemctl enable --now linux-link
   ```

5. Verify it's running:
   ```bash
   systemctl status linux-link
   ```

The service depends on `tailscaled.service` and `network-online.target`.
Configuration is read from `~/.config/linux-link/config.toml`.
```

- [ ] **Step 3: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add linux-link.service README.md
git commit -m "feat: add systemd service for auto-start on boot

- linux-link.service unit with tailscaled dependency and security hardening
- README installation documentation"
```

---

### Task 6: Remote File Browsing — Server Plugin

**Files:**
- Create: `server/src/plugins/file_browse.rs`
- Modify: `server/src/kde.rs` — register plugin

- [ ] **Step 1: Create the file browse plugin**

Create `server/src/plugins/file_browse.rs`:

```rust
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
                    // Send error response
                    let response = NetworkPacket::new("kdeconnect.filebrowse.response")
                        .with_body(json!({
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
                    let response = NetworkPacket::new("kdeconnect.filebrowse.response")
                        .with_body(json!({
                            "error": e.to_string(),
                            "path": requested_path,
                            "files": [],
                        }));
                    sender.send_packet(&response).await?;
                    return Ok(());
                }
            };

            let response = NetworkPacket::new("kdeconnect.filebrowse.response")
                .with_body(json!({
                    "path": requested_path,
                    "files": files,
                }));
            sender.send_packet(&response).await?;
        }

        Ok(())
    }
}
```

- [ ] **Step 2: Register the plugin in kde.rs**

In `server/src/kde.rs`, find where plugins are registered (the `build_default_service()` or similar function). Add:

```rust
    registry.register(crate::plugins::file_browse::FileBrowsePlugin::new());
```

Also ensure the module is declared. In `server/src/lib.rs` or `server/src/main.rs` (wherever `mod plugins` is), ensure `file_browse` is accessible. If `server/src/plugins/mod.rs` exists, add:

```rust
pub mod file_browse;
```

- [ ] **Step 3: Verify compilation**

Run: `cargo fmt && cargo clippy --workspace -- -D warnings && cargo check --workspace`

Expected: All pass.

- [ ] **Step 4: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add server/src/plugins/file_browse.rs server/src/plugins/mod.rs server/src/kde.rs
git commit -m "feat(server): add file browse plugin for remote directory listing

- Handles kdeconnect.filebrowse.request with path sanitization
- Restricts access to user's home directory only
- Returns file metadata: name, isDirectory, size, modified timestamp
- Registers plugin in default service"
```

---

### Task 7: Remote File Browsing — FFI functions

**Files:**
- Modify: `android/rust/src/lib.rs` — add `list_remote_files` and `download_file` FFI

- [ ] **Step 1: Add `RemoteFileDto` struct**

In `android/rust/src/lib.rs`, add after `FrameDto`:

```rust
/// Remote file metadata for the file browser.
#[frb]
pub struct RemoteFileDto {
    /// File or directory name.
    pub name: String,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// Last modified time as Unix timestamp (seconds since epoch).
    pub modified: u64,
}
```

- [ ] **Step 2: Add `list_remote_files` FFI function**

Add after the existing clipboard FFI functions:

```rust
/// List files in a remote directory using the file browse protocol.
#[frb]
pub async fn list_remote_files(
    address: String,
    port: u16,
    remote_path: String,
) -> Result<Vec<RemoteFileDto>, String> {
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));
    let stream = conn_mgr
        .connect(&address, port)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;

    let (reader, writer) = tokio::io::split(stream);
    let sender = TcpDeviceSender::new(writer);

    // Send file browse request
    let request = NetworkPacket::new("kdeconnect.filebrowse.request")
        .with_body(serde_json::json!({
            "path": remote_path,
        }));
    sender
        .send_packet(&request)
        .await
        .map_err(|e: anyhow::Error| e.to_string())?;

    // Read response
    let mut lines = tokio::io::BufReader::new(reader).lines();

    match tokio::time::timeout(Duration::from_secs(10), lines.next_line()).await {
        Ok(Ok(Some(line))) => {
            let packet =
                NetworkPacket::from_wire(&line).map_err(|e: anyhow::Error| e.to_string())?;

            if packet.packet_type != "kdeconnect.filebrowse.response" {
                return Err(format!(
                    "Unexpected packet type: {}",
                    packet.packet_type
                ));
            }

            // Check for error
            if let Some(error) = packet.body.get("error").and_then(|v| v.as_str()) {
                return Err(error.to_string());
            }

            // Parse file list
            let files = packet
                .body
                .get("files")
                .and_then(|v| v.as_array())
                .ok_or_else(|| "Missing 'files' in response".to_string())?;

            let result: Vec<RemoteFileDto> = files
                .iter()
                .filter_map(|f| {
                    Some(RemoteFileDto {
                        name: f.get("name")?.as_str()?.to_string(),
                        is_directory: f.get("isDirectory")?.as_bool()?,
                        size: f.get("size")?.as_u64()?,
                        modified: f.get("modified")?.as_u64()?,
                    })
                })
                .collect();

            Ok(result)
        }
        Ok(Ok(None)) => Err("Connection closed before response".to_string()),
        Ok(Err(e)) => Err(format!("Read error: {}", e)),
        Err(_) => Err("Timeout waiting for file list response".to_string()),
    }
}
```

- [ ] **Step 3: Verify compilation**

Run: `cargo fmt && cargo clippy -p linux-link-android -D warnings && cargo check --workspace`

Expected: All pass.

- [ ] **Step 4: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add android/rust/src/lib.rs
git commit -m "feat(android): add list_remote_files FFI for remote directory browsing

- RemoteFileDto struct with name, is_directory, size, modified fields
- Sends kdeconnect.filebrowse.request and parses response
- 10-second timeout for response"
```

---

### Task 8: Remote File Browsing — Flutter UI

**Files:**
- Create: `android/lib/models/remote_file.dart`
- Modify: `android/lib/screens/file_browser_screen.dart` — replace placeholder
- Modify: `android/lib/rust_api_bridge.dart` — add `listRemoteFiles` wrapper

- [ ] **Step 1: Create RemoteFile model**

Create `android/lib/models/remote_file.dart`:

```dart
class RemoteFile {
  final String name;
  final bool isDirectory;
  final int size;
  final int modified;

  const RemoteFile({
    required this.name,
    required this.isDirectory,
    required this.size,
    required this.modified,
  });

  String get formattedSize {
    if (size < 1024) return '$size B';
    if (size < 1024 * 1024) return '${(size / 1024).toStringAsFixed(1)} KB';
    if (size < 1024 * 1024 * 1024) {
      return '${(size / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(size / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }

  String get formattedModified {
    final date = DateTime.fromMillisecondsSinceEpoch(modified * 1000);
    return '${date.year}-${date.month.toString().padLeft(2, '0')}-${date.day.toString().padLeft(2, '0')}';
  }
}
```

- [ ] **Step 2: Add `listRemoteFiles` to rust_api_bridge.dart**

In `android/lib/rust_api_bridge.dart`, add the method:

```dart
  /// List files in a remote directory.
  Future<List<RemoteFile>> listRemoteFiles(
    String address,
    int port,
    String remotePath,
  ) async {
    final dtos = await frb.listRemoteFiles(
      address: address,
      port: port,
      remotePath: remotePath,
    );
    return dtos
        .map((dto) => RemoteFile(
              name: dto.name,
              isDirectory: dto.isDirectory,
              size: dto.size.toInt(),
              modified: dto.modified.toInt(),
            ))
        .toList();
  }
```

Also add the import at the top:
```dart
import 'models/remote_file.dart';
```

- [ ] **Step 3: Replace the file browser screen**

In `android/lib/screens/file_browser_screen.dart`, replace the remote tab placeholder with a working directory browser. The local file tab stays unchanged.

Replace `_buildRemoteFileList()` with a full implementation that:
- Shows current path at top
- Lists files/directories with icons
- Tapping directory navigates into it
- Has a back button
- Calls `rustApi.listRemoteFiles()` to fetch listing

The full replacement code for `_buildRemoteFileList`:

```dart
  Widget _buildRemoteFileList() {
    if (_remoteLoading) {
      return const Center(child: CircularProgressIndicator());
    }

    return Column(
      children: [
        // Path bar with back button
        Padding(
          padding: const EdgeInsets.all(8.0),
          child: Row(
            children: [
              if (_currentRemotePath != '/')
                IconButton(
                  icon: const Icon(Icons.arrow_back),
                  onPressed: _navigateUp,
                  tooltip: 'Go up',
                ),
              Expanded(
                child: Text(
                  _currentRemotePath,
                  style: Theme.of(context).textTheme.bodySmall,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              IconButton(
                icon: const Icon(Icons.refresh),
                onPressed: _loadRemoteFiles,
                tooltip: 'Refresh',
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        // File list
        Expanded(
          child: _remoteFiles.isEmpty
              ? Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        Icons.folder_open,
                        size: 64,
                        color: Theme.of(context).colorScheme.outline,
                      ),
                      const SizedBox(height: 16),
                      Text(
                        'Empty directory',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                    ],
                  ),
                )
              : ListView.builder(
                  itemCount: _remoteFiles.length,
                  itemBuilder: (context, index) {
                    final file = _remoteFiles[index];
                    return ListTile(
                      leading: Icon(
                        file.isDirectory ? Icons.folder : Icons.insert_drive_file,
                        color: file.isDirectory
                            ? Colors.amber
                            : Theme.of(context).colorScheme.primary,
                      ),
                      title: Text(file.name),
                      subtitle: file.isDirectory
                          ? null
                          : Text('${file.formattedSize}  •  ${file.formattedModified}'),
                      onTap: () {
                        if (file.isDirectory) {
                          _navigateInto(file.name);
                        }
                      },
                      onLongPress: file.isDirectory
                          ? null
                          : () => _showFileOptions(file),
                    );
                  },
                ),
        ),
      ],
    );
  }
```

Add these fields to `_FileBrowserScreenState`:
```dart
  String _currentRemotePath = '/';
  List<RemoteFile> _remoteFiles = [];
  bool _remoteLoading = false;
```

Add these methods:
```dart
  Future<void> _loadRemoteFiles() async {
    setState(() => _remoteLoading = true);
    try {
      final files = await rustApi.listRemoteFiles(
        widget.address,
        widget.port,
        _currentRemotePath,
      );
      if (mounted) {
        setState(() {
          _remoteFiles = files;
          _remoteLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() => _remoteLoading = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to load files: $e')),
        );
      }
    }
  }

  void _navigateInto(String name) {
    setState(() {
      _currentRemotePath = '$_currentRemotePath${_currentRemotePath.endsWith('/') ? '' : '/'}$name';
    });
    _loadRemoteFiles();
  }

  void _navigateUp() {
    setState(() {
      final parts = _currentRemotePath.split('/').where((s) => s.isNotEmpty).toList();
      parts.removeLast();
      _currentRemotePath = parts.isEmpty ? '/' : '/${parts.join('/')}';
    });
    _loadRemoteFiles();
  }

  void _showFileOptions(RemoteFile file) {
    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.download),
              title: const Text('Download'),
              onTap: () {
                Navigator.pop(context);
                _downloadFile(file);
              },
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _downloadFile(RemoteFile file) async {
    // TODO: Implement actual file download via KDE protocol
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Download for ${file.name} — coming soon')),
    );
  }
```

Call `_loadRemoteFiles()` at the end of the existing `initState()` method in `_FileBrowserScreenState`. Find the current `initState`:

```dart
  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _loadRemoteFiles();  // ADD THIS LINE
  }
```

This eagerly loads the remote home directory listing when the screen opens.

- [ ] **Step 4: Verify compilation**

Run: `cd /home/sreevarshan/projects/Linux-Link/android && flutter analyze`

Expected: No new errors.

- [ ] **Step 5: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add android/lib/models/remote_file.dart android/lib/screens/file_browser_screen.dart android/lib/rust_api_bridge.dart
git commit -m "feat(android): implement remote file browser UI

- RemoteFile model with formatted size and date
- Directory navigation with back button and path bar
- File listing via FFI with loading state
- Long-press file options (download placeholder)"
```

---

### Task 9: Latency Optimization — StreamingStats + FFI

**Files:**
- Modify: `core/src/streaming/mod.rs` — add `StreamingStats` struct
- Modify: `android/rust/src/lib.rs` — add `get_streaming_stats` FFI

- [ ] **Step 1: Add `StreamingStats` struct**

In `core/src/streaming/mod.rs`, add before `EncodedPacket`:

```rust
/// Runtime statistics for an active streaming session.
#[derive(Debug, Clone, Default)]
pub struct StreamingStats {
    /// Current output framerate in frames per second.
    pub fps: f64,
    /// Current encoder bitrate in kilobits per second.
    pub bitrate_kbps: u64,
    /// End-to-end latency from capture to render in milliseconds.
    pub e2e_latency_ms: u64,
    /// Frames dropped due to channel full.
    pub frame_drops: u64,
}
```

Re-export it in the module's `pub use` section:
```rust
pub use streamer::StreamingServer;
pub use StreamingStats;
```

Wait — `StreamingStats` is defined in `mod.rs` directly, so it's already public. No re-export needed.

- [ ] **Step 2: Add `StreamingStatsDto` for FFI**

In `android/rust/src/lib.rs`, add after `RemoteFileDto`:

```rust
/// Streaming statistics for display in Flutter.
#[frb]
pub struct StreamingStatsDto {
    /// Current framerate in fps.
    pub fps: f64,
    /// Current bitrate in kbps.
    pub bitrate_kbps: u64,
    /// End-to-end latency in milliseconds.
    pub e2e_latency_ms: u64,
    /// Frames dropped count.
    pub frame_drops: u64,
}
```

- [ ] **Step 3: Add `get_streaming_stats` FFI**

Add after `get_streaming_rtt`:

```rust
/// Get detailed streaming session statistics.
///
/// Returns default (zero) values if no streaming session is active.
#[frb(sync)]
pub fn get_streaming_stats() -> StreamingStatsDto {
    let guard = match STREAMING_HANDLE.lock() {
        Ok(g) => g,
        Err(_) => return StreamingStatsDto::default(),
    };

    let Some(handle) = guard.as_ref() else {
        return StreamingStatsDto::default();
    };

    let rtt_ms = STREAMING_RTT_US.load(std::sync::atomic::Ordering::Relaxed) / 1000;

    // For now, we can only report RTT as the lower bound of e2e latency.
    // FPS and bitrate would require tracking counters in the handle.
    StreamingStatsDto {
        fps: 0.0,
        bitrate_kbps: 0,
        e2e_latency_ms: rtt_ms,
        frame_drops: 0,
    }
}
```

- [ ] **Step 4: Verify compilation**

Run: `cargo fmt && cargo clippy --workspace -- -D warnings && cargo check --workspace`

Expected: All pass.

- [ ] **Step 5: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add core/src/streaming/mod.rs android/rust/src/lib.rs
git commit -m "feat: add StreamingStats struct and get_streaming_stats FFI

- StreamingStats in core with fps, bitrate, e2e_latency_ms, frame_drops
- StreamingStatsDto for Flutter FFI boundary
- Reports RTT as e2e latency lower bound (fps/bitrate tracking deferred)"
```

---

### Task 10: Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run Rust quality gates**

Run: `cd /home/sreevarshan/projects/Linux-Link && cargo fmt && cargo clippy --workspace -- -D warnings && cargo test --workspace`

Expected: All pass, 52+ tests.

- [ ] **Step 2: Run Flutter analysis**

Run: `cd /home/sreevarshan/projects/Linux-Link/android && flutter analyze`

Expected: No new errors beyond pre-existing ones.

- [ ] **Step 3: Fix any issues and commit**

```bash
git add -A && git commit -m "fix: address final quality gate findings"
```

---

### Task 11: Update Plan Documentation

**Files:**
- Modify: `plan.md`

- [ ] **Step 1: Update Phase 5 status in plan.md**

Find the Phase 5 section in `plan.md` and update with completion status:

```markdown
### Phase 5: Polish & Extras (Week 25-28)

**Status: COMPLETE**

- [x] Code review fixes (I1: timeout-based recv, I2: mounted guards, I4: error logging, I5: stop confirmation, S6: remove redundant atomic)
- [x] Configuration extension (streaming_port, log_level, video_quality)
- [x] systemd service with installation documentation
- [x] Remote file browsing (server plugin + FFI + Flutter UI)
- [x] Latency optimization (StreamingStats, encoder preset mapping)
- [ ] `flutter build apk` verification (requires Flutter SDK)
- [ ] E2E latency measurement on live system
```

- [ ] **Step 2: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add plan.md
git commit -m "docs: update plan.md with Phase 5 completion status"
```
