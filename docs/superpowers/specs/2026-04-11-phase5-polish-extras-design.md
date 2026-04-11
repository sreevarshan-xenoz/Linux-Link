# Phase 5: Polish & Extras — Design Spec

> **Date:** 2026-04-11
> **Status:** Draft — awaiting review
> **Scope:** Code review fixes, config extension, systemd service, remote file browsing, latency optimization

---

## 1. Objective

Polish the Linux Link codebase to production quality: fix review findings, extend configuration, enable auto-start via systemd, implement remote file browsing, and optimize the streaming pipeline for <100ms latency.

---

## 2. Workstreams

### Stream 1: Code Review Fixes (Quality Foundation)

Five important issues from the Phase 4 final review:

**I1: `receive_frames` polling inefficiency**
- Current: 2ms polling loop with `try_recv()` + `tokio::time::sleep` while holding no lock, but still wasteful during idle
- Fix: Use `tokio::time::timeout` on `handle.packet_rx.recv()` — suspends until a frame arrives or deadline expires. Then drain remaining with `try_recv()`.
- File: `android/rust/src/lib.rs`

**I2: Timer callbacks fire after dispose**
- Current: `_frameTimer` and `_latencyTimer` callbacks can execute FFI calls after `dispose()` if a callback was already in-flight
- Fix: Add `if (!mounted) return;` at the very top of each async timer callback, before any FFI call
- File: `android/lib/screens/remote_desktop_screen.dart`

**I4: Silent error swallowing in `stop_streaming`**
- Current: `let _ = handle.task.await;` discards panic/errors
- Fix: Log errors with `tracing::warn!` if tasks exit abnormally
- File: `android/rust/src/lib.rs`

**I5: `stopForegroundService` is fire-and-forget**
- Current: `service.invoke('stop')` returns nothing
- Fix: Add a short `Future.delayed` after invoke to let Android process the stop, or await a confirmation channel
- File: `android/lib/services/background_service.dart`

**S6: Redundant `STREAMING_ACTIVE` atomic**
- Current: Both `STREAMING_ACTIVE` atomic and `STREAMING_HANDLE` Option track the same state
- Fix: Replace `is_streaming_active()` with a lock-free derivation: `STREAMING_HANDLE.lock().map(|g| g.is_some()).unwrap_or(false)`. The mutex lock is fine here since it's called every 2 seconds, not in a hot path.
- File: `android/rust/src/lib.rs`

### Stream 2: Configuration Extension

**Current state:** `server/src/config.rs` already has TOML loading with `control_port` field. Uses `dirs::config_dir()/linux-link/config.toml`. Falls back to defaults if file missing.

**Add fields:**
```toml
# ~/.config/linux-link/config.toml
control_port = 1716        # KDE Connect compatible
streaming_port = 4716      # QUIC streaming port
log_level = "info"         # trace/debug/info/warn/error
video_quality = "balanced" # low/balanced/high (maps to encoder preset)
```

**Changes:**
- Extend `Config` struct in `server/src/config.rs` with `streaming_port`, `log_level`, `video_quality`
- Update `main.rs` to apply `log_level` to the tracing subscriber
- Update `service.rs` to use `config.streaming_port` for the QUIC listener
- Create `config.toml.example` in repo root
- Add `VideoQualityPreset` enum to `core/src/streaming/mod.rs` with variants:
  - `Low` — 720p, 2 Mbps, `veryfast` preset
  - `Balanced` — 1080p, 5 Mbps, `superfast` preset
  - `High` — 1080p, 10 Mbps, `medium` preset
- Config string `"low"`/`"balanced"`/`"high"` maps to enum variants

### Stream 3: systemd Service

**Goal:** Auto-start the Linux Link daemon on boot so the machine is always reachable over Tailscale.

**Unit file** (`linux-link.service`):
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

**Installation steps** (documented in README, not automated):
1. `cargo build --release --bin linux-link`
2. `sudo cp target/release/linux-link /usr/bin/linux-link`
3. `sudo cp linux-link.service /etc/systemd/system/`
4. `sudo systemctl daemon-reload`
5. `sudo systemctl enable --now linux-link`

**Deliverables:**
- `linux-link.service` file in repo root
- README section documenting installation
- Verification: `systemctl status linux-link` shows active after install

### Stream 4: Remote File Browsing

**Server-side changes:**

Create `server/src/plugins/file_browse.rs` — a KDE Connect plugin that handles directory listing and file download requests:

- Handles `kdeconnect.filebrowse.request` with `path` field → responds with `kdeconnect.filebrowse.response` containing file list
- Handles `kdeconnect.filebrowse.download` with `path` and `port` → streams file to requesting port
- Uses `std::fs::read_dir` for directory listing
- Returns file metadata: name, is_directory, size, modified timestamp
- Security: restrict to user's home directory (`dirs::home_dir()`). Reject any path outside home. Block-listed: `/proc`, `/sys`, `/dev`, `/root`, `/etc/shadow`, any path containing `..`. Only serve files the user has read access to.
- Default path: user's home directory when no path specified.

Packet format for listing request:
```json
{
  "type": "kdeconnect.filebrowse.request",
  "body": { "path": "/home/user/Documents" }
}
```

Packet format for listing response:
```json
{
  "type": "kdeconnect.filebrowse.response",
  "body": {
    "path": "/home/user/Documents",
    "files": [
      { "name": "notes.txt", "isDirectory": false, "size": 4096, "modified": "2024-01-15T10:30:00Z" },
      { "name": "photos", "isDirectory": true, "size": 0, "modified": "2024-01-10T08:00:00Z" }
    ]
  }
}
```

**FFI functions** (`android/rust/src/lib.rs`):
- `list_remote_files(address, port, remote_path) -> Result<Vec<RemoteFile>, String>`
- `download_file(address, port, remote_path, local_path) -> Result<(), String>`

**Flutter changes:**
- `android/lib/screens/file_browser_screen.dart` — replace the placeholder with a real directory browser
- Navigation: tap directory → list its contents, back button → parent directory
- Download: long-press file → "Download" → saves to Android Downloads folder
- Add `RemoteFile` model in `android/lib/models/`

### Stream 5: Latency Optimization

**Target:** <100ms end-to-end latency (capture → encode → QUIC → decode → render)

**Current pipeline analysis:**
1. **PipeWire capture** — callback-based, delivers BGRA frames as they arrive. Should be near-zero latency.
2. **FFmpeg encoder** — persistent process, stdin/stdout non-blocking. Latency depends on encoder preset and keyframe interval.
3. **QUIC transport** — datagram mode for lowest latency. RTT is the floor.
4. **MediaCodec decode** — hardware-accelerated on Android, typically 1-2 frame delay.

**Optimization levers:**

| Lever | Current | Optimized | Impact |
|-------|---------|-----------|--------|
| Encoder preset | `ultrafast` (default) | `superfast` or `veryfast` | Medium — better quality at same bitrate |
| Keyframe interval | 2s default | 1s | Low — faster recovery from packet loss |
| QUIC mode | Datagrams | Datagrams (already set) | N/A — already optimal |
| Frame pacing | As-as | Cap at 30fps for LAN, 60fps if RTT < 20ms | Medium — prevents encoder backlog |
| Adaptive bitrate | 3 presets (LAN/internet/low) | Same, but tighten RTT thresholds | Low — already well-tuned |

**Actions:**
1. Add encoder preset selection from config (`video_quality` → bitrate/preset mapping)
2. Cap encoder output at 30fps when RTT > 50ms (adaptive frame rate)
3. Add a `StreamingStats` struct:
   ```rust
   pub struct StreamingStats {
       pub fps: f64,              // Current output framerate
       pub bitrate_kbps: u64,     // Current encoder bitrate
       pub e2e_latency_ms: u64,   // Capture-to-render (measured via timestamps)
       pub frame_drops: u64,      // Frames dropped due to channel full
   }
   ```
   Tracked by incrementing counters in the encoder (frames out) and frame receiver (drops). End-to-end latency measured by embedding capture timestamp in `EncodedPacket` and comparing with render timestamp on the Android side.
4. Expose stats via FFI: `get_streaming_stats() -> { fps, bitrate, e2e_latency_ms }`

---

## 3. Execution Order

```
Stream 1 (Review fixes) ──────────────────────── 2 days
    ↓
Stream 2 (Config extension) ──────────────────── 2 days
    ↓
Stream 3 (systemd service) ───────────────────── 1 day
    ↓
Stream 4 (Remote file browsing) ──────────────── 3-4 days
    ↓
Stream 5 (Latency optimization) ──────────────── 2-3 days
```

Total: ~10-12 days of implementation work.

---

## 4. File Map

### Stream 1: Review Fixes
| File | Change |
|------|--------|
| `android/rust/src/lib.rs` | I1: timeout-based recv, I4: error logging, S6: remove redundant atomic |
| `android/lib/screens/remote_desktop_screen.dart` | I2: mounted guard on timers |
| `android/lib/services/background_service.dart` | I5: stop confirmation |

### Stream 2: Config
| File | Change |
|------|--------|
| `server/src/config.rs` | Add `streaming_port`, `log_level`, `video_quality` fields |
| `server/src/main.rs` | Apply log_level to tracing subscriber |
| `server/src/service.rs` | Use config.streaming_port |
| `core/src/streaming/mod.rs` | Add `VideoQualityPreset` enum |
| `config.toml.example` | New file — example configuration |

### Stream 3: systemd
| File | Change |
|------|--------|
| `linux-link.service` | New file — systemd unit |
| `README.md` | Document installation |

### Stream 4: Remote File Browsing
| File | Change |
|------|--------|
| `server/src/plugins/file_browse.rs` | New — file browse plugin |
| `server/src/kde.rs` | Register file_browse plugin |
| `android/rust/src/lib.rs` | Add `list_remote_files`, `download_file` FFI |
| `android/lib/models/remote_file.dart` | New — RemoteFile model |
| `android/lib/screens/file_browser_screen.dart` | Replace placeholder with real browser |

### Stream 5: Latency Optimization
| File | Change |
|------|--------|
| `core/src/streaming/mod.rs` | Add `StreamingStats` struct |
| `core/src/streaming/streamer.rs` | Track timestamps, expose stats |
| `android/rust/src/lib.rs` | Add `get_streaming_stats` FFI |
| `android/lib/providers/streaming_provider.dart` | Add stats provider |

---

## 5. Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| systemd unit fails on non-Systemd distros | Low | Document Arch Linux only; other distros can use alternative init |
| File browse plugin exposes sensitive files | High | Restrict to home directory; no `/proc`, `/sys`, `/dev`, `/root` |
| Latency optimization breaks streaming | Medium | Guard behind config flag; default to current behavior |
| FRB types for remote files clash with existing DTOs | Low | Use distinct names (`RemoteFile` vs `FileItem`) |

---

## 6. Success Criteria

- [ ] `cargo clippy -D warnings` — 0 warnings
- [ ] `cargo test --workspace` — all tests pass (52+)
- [ ] `flutter analyze` — no new errors
- [ ] `linux-link start` reads config from `~/.config/linux-link/config.toml`
- [ ] `systemctl enable linux-link` — daemon starts on boot
- [ ] Remote file browsing works: list directories, download files
- [ ] Streaming latency <100ms on LAN (measured end-to-end)
