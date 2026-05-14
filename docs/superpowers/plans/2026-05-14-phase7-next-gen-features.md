# Phase 7: Next-Gen Features — 25+ Feature Plan

> **Date:** 2026-05-14
> **Status:** Draft — awaiting prioritization
> **Scope:** 7 workstreams spanning streaming enhancements, input refinement, connectivity features, mobile UX, platform expansion, security hardening, and developer tooling
> **Target:** 3-4 months of implementation work with iterative releases

---

## 1. Executive Summary

Linux Link's foundation is complete: a Rust-based remote desktop over Tailscale with KDE Connect protocol, H.264 streaming, and a Flutter Android client. Phase 7 transforms it from a **functional remote desktop** into a **full-featured productivity platform**.

**Theme:** *From "it works" to "it's delightful"*

**Highlights:**
- **Audio streaming** — hear your PC audio on your phone
- **Multi-monitor** — switch between displays like a KVM
- **HEVC/H.265** — 50% bandwidth savings at same quality
- **Wake-on-LAN** — wake sleeping machines remotely
- **Touch gestures** — pinch-to-zoom, two-finger scroll
- **Desktop client** — cross-platform with Tauri
- **Auto-reconnect** — seamless session persistence
- **25+ total features** across 7 workstreams

---

## 2. Workstream Overview

| # | Workstream | Features | Effort | Dependencies | Risk |
|---|-----------|----------|--------|-------------|------|
| **S1** | Streaming Enhancements | 8 features | 5-6 weeks | Phase 3 streaming | Medium |
| **S2** | Input & Interaction | 5 features | 4-5 weeks | Phase 3 input | Low |
| **S3** | Connectivity | 4 features | 3-4 weeks | Phase 1 tailscale | Low |
| **S4** | Mobile UX (Android) | 4 features | 4-5 weeks | Phase 4 Flutter | Low |
| **S5** | Platform Expansion | 3 features | 6-8 weeks | Phase 4 design | High |
| **S6** | Security Hardening | 2 features | 2-3 weeks | Phase A TOFU | Medium |
| **S7** | Developer Tooling | 3 features | 2-3 weeks | Phase 1 CI | Low |

**Total:** 29 features over ~26-34 weeks (6-8 months)

---

## 3. Detailed Feature Specifications

### S1: Streaming Enhancements (8 features)

#### F1. Audio Streaming — System Audio to Android

**Goal:** Stream system audio from the remote PC to the Android device alongside the video feed.

**Architecture:**
```
PipeWire Audio → Opus Encoder → QUIC Datagram → Opus Decoder → Android AudioTrack
```

**Implementation:**
- **Capture:** PipeWire audio stream via `libspa` node (monitor output) or `ashpd` screencast audio channel
- **Encode:** Integrate Opus encoding (`audiopus` crate or `ffmpeg-sidecar` audio pipe)
- **Transport:** Dedicated QUIC datagram stream (separate from video for priority handling)
- **Decode:** Android `MediaCodec` Opus decoder or raw PCM decode via Rust FFI
- **Render:** `AudioTrack` in native mode for low-latency playback
- **Sync:** Timestamp-based A/V sync (±50ms tolerance)

**Files:**
- New: `core/src/streaming/audio_capture.rs` — PipeWire audio capture
- New: `core/src/streaming/audio_encoder.rs` — Opus encoding (via ffmpeg or audiopus)
- New: `android/rust/src/audio.rs` — Audio decode FFI
- New: `android/lib/services/audio_player_service.dart` — Audio playback
- Modify: `core/src/streaming/streamer.rs` — Audio task integration

**Success Criteria:**
- [ ] Audio plays on Android within 200ms of capture
- [ ] A/V sync within ±100ms
- [ ] <5% CPU overhead on server

---

#### F2. Multi-Monitor Support

**Goal:** When the server has multiple monitors, let the user select which one to stream.

**Implementation:**
- **Server:** Expose available monitors via KDE Connect packet or streaming handshake
- **Client:** Monitor selection dropdown in remote desktop screen
- **Streamer:** Switch PipeWire capture node on monitor change (or restart session)
- **Detection:** Use `ashpd` to enumerate available monitors/sources

**Packet format (streaming handshake):**
```json
{
  "type": "kdeconnect.linuxlink.monitors",
  "body": {
    "monitors": [
      { "id": 0, "name": "eDP-1", "width": 1920, "height": 1080 },
      { "id": 1, "name": "HDMI-A-1", "width": 2560, "height": 1440 }
    ]
  }
}
```

**Files:**
- Modify: `core/src/streaming/capture.rs` — Accept monitor selector
- Modify: `core/src/streaming/streamer.rs` — Monitor switch handling
- Modify: `android/lib/screens/remote_desktop_screen.dart` — Monitor selector UI
- New: `core/src/streaming/monitor.rs` — Monitor enumeration

**Success Criteria:**
- [ ] All monitors listed in UI
- [ ] Switching monitors restarts stream with correct resolution
- [ ] Last selection persisted in settings

---

#### F3. HEVC/H.265 Encoding Support

**Goal:** Add H.265 encoding for 50% bandwidth savings at equivalent quality.

**Implementation:**
- **Encoder:** Check VAAPI/NVENC for HEVC support, fall back to H.264
- **Config:** Add `codec` field to `StreamingConfig` (`H264` / `HEVC`)
- **FFmpeg:** Switch output codec from `h264_vaapi` → `hevc_vaapi` (or NVENC equivalents)
- **Client:** Detect HEVC decoder support via `MediaCodecList`
- **Fallback:** Auto-downgrade to H.264 if HEVC not supported on client

**Files:**
- Modify: `core/src/streaming/mod.rs` — Add `Codec` enum
- Modify: `core/src/streaming/encoder.rs` — HEVC encoder configuration
- Modify: `android/rust/src/lib.rs` — Codec negotiation in connect_streaming
- Modify: `android/lib/services/video_player_service.dart` — HEVC decoder setup
- Modify: `android/lib/screens/settings_screen.dart` — Codec selection

**Success Criteria:**
- [ ] HEVC encoded frames play on Android
- [ ] Bandwidth savings ≥40% vs H.264 at same quality
- [ ] Graceful fallback to H.264 when HEVC unavailable

---

#### F4. Stream Quality Presets UI

**Goal:** Let users select/customize stream quality from the app, with real-time switching.

**Implementation:**
- **Presets:** Expand from 3 (Low/Med/High) to 6 (UltraLow, Low, Balanced, High, UltraHigh, Custom)
- **Custom:** Bitrate slider, resolution dropdown, FPS selector
- **Real-time:** Send new config via streaming channel; `StreamingServer` applies without restart
- **QoS:** Preserve active stream during quality change

**Files:**
- Modify: `core/src/streaming/mod.rs` — Extended quality presets
- Modify: `android/lib/screens/settings_screen.dart` — Custom quality UI
- Modify: `android/rust/src/api.rs` — `set_streaming_quality()` FFI
- Modify: `core/src/streaming/streamer.rs` — Dynamic reconfiguration

**Success Criteria:**
- [ ] Quality change applies within 1 second
- [ ] Custom presets persisted in SharedPreferences
- [ ] No frame drops during quality transition

---

#### F5. Session Recording

**Goal:** Record a remote session to a video file on the Android device.

**Implementation:**
- **Client-side:** Record received H.264 frames to MP4 file using `MediaMuxer`
- **Controls:** Record button in overlay, countdown indicator
- **Format:** MP4 with H.264 video track + AAC audio (if audio streaming active)
- **Storage:** Save to Android `Movies/LinuxLink/` directory
- **Share:** Share button after recording completes

**Files:**
- New: `android/rust/src/recorder.rs` — Session recording FFI (or use Android MediaMuxer via JNI)
- New: `android/lib/services/recording_service.dart` — Recording management
- Modify: `android/lib/screens/remote_desktop_screen.dart` — Record button in overlay

**Success Criteria:**
- [ ] MP4 file created and playable
- [ ] Recording can be started/stopped without disrupting stream
- [ ] Audio included when streaming

---

#### F6. Hardware Encoder Selection

**Goal:** Let users choose between VAAPI (Intel/AMD), NVENC (NVIDIA), or software encoding.

**Implementation:**
- **Detection:** Runtime probe for available encoders (`ffmpeg -encoders`)
- **Config:** Add `hardware_encoder` field with `Auto`, `VAAPI`, `NVENC`, `Software` options
- **Fallback:** Auto-detect best available; fall back gracefully

**Files:**
- New: `core/src/streaming/encoder_detect.rs` — Encoder detection
- Modify: `server/src/config.rs` — `hardware_encoder` field
- Modify: `core/src/streaming/encoder.rs` — Encoder selection logic
- Modify: `android/lib/screens/settings_screen.dart` — Encoder picker

**Success Criteria:**
- [ ] VAAPI detected and functional on Intel/AMD GPUs
- [ ] NVENC detected on NVIDIA GPUs
- [ ] Software fallback works on all systems

---

#### F7. Stream Rotation

**Goal:** Rotate the stream to match phone orientation (portrait/landscape).

**Implementation:**
- **Rotation modes:** Auto (sensor-based), Portrait, Landscape, 180°
- **Video renderer:** Apply rotation matrix to `TextureWidget` or use `Transform` widget
- **Input correction:** Remap touch coordinates when rotated
- **Server:** No server changes needed — rotation is client-side

**Files:**
- Modify: `android/lib/screens/remote_desktop_screen.dart` — Rotation transform + sensor listener
- Modify: `android/lib/providers/streaming_provider.dart` — Rotation state

**Success Criteria:**
- [ ] Stream follows device orientation in auto mode
- [ ] Input coordinates correctly remapped
- [ ] No additional latency from rotation

---

#### F8. Stream Statistics Overlay

**Goal:** Show real-time FPS, latency, bitrate, and packet loss as an overlay on the stream.

**Implementation:**
- **Stats source:** Periodic polling of `get_streaming_stats()` (every 1s)
- **Display:** Semi-transparent overlay in corner, toggled by double-tap or button
- **Visual:** Color-coded indicators (green/yellow/red) for latency and packet loss
- **Graph:** Mini line chart for latency history (optional, stretch goal)

**Files:**
- New: `android/lib/widgets/stream_stats_overlay.dart` — Overlay widget
- Modify: `android/lib/screens/remote_desktop_screen.dart` — Stats toggle + overlay

**Success Criteria:**
- [ ] Stats visible and updating in real-time
- [ ] Toggle on/off works
- [ ] Latency color coding matches thresholds

---

### S2: Input & Interaction (5 features)

#### F9. Pinch-to-Zoom & Touch Gestures

**Goal:** Multi-touch gesture support — pinch to zoom, two-finger scroll, long-press right-click.

**Implementation:**
- **Pinch zoom:** Scale gesture → apply to video viewport; adjust mouse coordinate mapping
- **Two-finger scroll:** Pan gesture → forward as scroll events via input channel
- **Right-click:** Long press → send right mouse button click
- **Middle-click:** Three-finger tap → send middle button click

**Files:**
- Modify: `android/lib/screens/remote_desktop_screen.dart` — `ScaleGestureRecognizer`, gesture arena
- Modify: `android/rust/src/api.rs` — No changes (uses existing send_mouse_event/send_keyboard_event)

**Success Criteria:**
- [ ] Pinch zoom smoothly scales viewport (1x-4x range)
- [ ] Two-finger scroll forwarded as scroll events
- [ ] Long-press right-click works reliably

---

#### F10. Gamepad/Controller Forwarding

**Goal:** Connect a Bluetooth gamepad to Android and forward inputs to the remote PC.

**Implementation:**
- **Capture:** Android gamepad events via `InputDevice` API (native plugin)
- **Mapping:** Map Android keycodes/axes to Linux evdev codes
- **Transport:** New `InputPacket::Gamepad` variant with axes + buttons
- **Server:** `InputInjector` handles gamepad events (via enigo or evdev)
- **UI:** Gamepad connection indicator + button test screen

**Files:**
- New: `android/android/app/src/main/kotlin/com/linuxlink/linux_link_client/GamepadPlugin.kt`
- New: `core/src/streaming/input_packet.rs` — Gamepad variant (already planned in types)
- Modify: `android/rust/src/api.rs` — `send_gamepad_event()` FFI
- Modify: `server/src/input_injector.rs` — Gamepad event handling

**Success Criteria:**
- [ ] Gamepad connects and inputs reach remote PC
- [ ] All buttons (A/B/X/Y, d-pad, triggers, thumbsticks) mapped correctly
- [ ] <50ms input latency

---

#### F11. Keyboard Shortcuts Overlay

**Goal:** Show a visual overlay of available keyboard shortcuts for the remote desktop.

**Implementation:**
- **Shortcut database:** Common shortcuts (Ctrl+C, Alt+Tab, Super+D, etc.)
- **Trigger:** Long-press on screen edge or dedicated button
- **Display:** Full-screen overlay with categorized shortcuts
- **Quick actions:** Tap a shortcut to execute it

**Files:**
- New: `android/lib/widgets/shortcuts_overlay.dart` — Shortcut overlay
- Modify: `android/lib/screens/remote_desktop_screen.dart` — Shortcut button

**Success Criteria:**
- [ ] Overlay appears/disappears smoothly
- [ ] Tapping a shortcut sends the key combination
- [ ] Categories organized logically

---

#### F12. Drag-and-Drop File Transfer (Android → PC)

**Goal:** Drag a file from Android file explorer and drop it onto the remote desktop to transfer.

**Implementation:**
- **Drag source:** Long-press a file in the local file browser tab
- **Visual:** Draggable widget floating image
- **Drop zone:** Remote desktop viewport as drop target
- **Transfer:** Use existing KDE Share protocol (`send_file` FFI) via QUIC or TCP

**Files:**
- Modify: `android/lib/screens/file_browser_screen.dart` — Drag source for local files
- Modify: `android/lib/screens/remote_desktop_screen.dart` — Drop target overlay

**Success Criteria:**
- [ ] Drag visual follows finger
- [ ] Drop initiates file transfer
- [ ] Progress shown during transfer

---

#### F13. Clipboard Auto-Sync

**Goal:** Automatically sync clipboard between Android and PC when background service is running.

**Implementation:**
- **Polling:** Check clipboard content every 3 seconds on both sides
- **Dedup:** Compare content hash to avoid sync loops
- **Direction:** Bidirectional — copy on Android appears on PC and vice versa
- **Config:** Toggle in settings, default off
- **Channels:** Use existing `kdeconnect.clipboard` protocol

**Files:**
- New: `android/lib/services/clipboard_sync_service.dart` — Auto-sync logic
- Modify: `android/lib/services/background_service.dart` — Start sync service
- Modify: `android/lib/screens/settings_screen.dart` — Auto-sync toggle

**Success Criteria:**
- [ ] Clipboard syncs within 5 seconds
- [ ] No infinite loop (change A → send B → receive A → ignored by hash match)
- [ ] Battery impact minimal

---

### S3: Connectivity (4 features)

#### F14. Wake-on-LAN

**Goal:** Wake a sleeping machine on the same LAN subnet via Wake-on-LAN magic packet.

**Implementation:**
- **Discovery:** Show "Wake" button next to offline peers on LAN
- **Packet:** Send magic packet (UDP broadcast on port 9) with peer's MAC address
- **MAC resolution:** Store MAC from mDNS/ARP when peer is online; or prompt user to enter
- **Retry:** Send 3 packets with 500ms interval
- **Feedback:** Show "Magic packet sent" toast; detect when peer comes online

**Files:**
- New: `core/src/tailscale/wol.rs` — Wake-on-LAN logic
- Modify: `android/rust/src/api.rs` — `send_wol()` FFI
- Modify: `android/lib/screens/connection_screen.dart` — Wake button
- Modify: `android/lib/models/peer_info.dart` — MAC address field

**Success Criteria:**
- [ ] Magic packet sent to correct MAC/broadcast address
- [ ] Peer wakes up within 30 seconds
- [ ] Peer appears online after wake

---

#### F15. Auto-Reconnect

**Goal:** Automatically reconnect if the streaming session drops unexpectedly.

**Implementation:**
- **Detection:** `_onKeyEvent`/frame polling detects broken connection
- **Backoff:** Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s (max 30s)
- **Persistence:** Retain streaming session UI, show "Reconnecting..." overlay
- **State:** Re-establish QUIC stream, then resume frame feed
- **Limit:** Max 5 reconnect attempts, then show error

**Files:**
- Modify: `android/lib/providers/streaming_provider.dart` — Reconnect logic
- Modify: `android/lib/screens/remote_desktop_screen.dart` — Reconnecting overlay
- Modify: `core/src/streaming/client.rs` — Re-connection support

**Success Criteria:**
- [ ] Reconnect within 30 seconds of drop
- [ ] Exponential backoff doesn't hammer server
- [ ] User can cancel reconnect attempt

---

#### F16. Bookmark Peers

**Goal:** Save frequently accessed peers for quick connection.

**Implementation:**
- **Star button:** Next to peer name to favorite
- **Storage:** Saved in SharedPreferences as list of `{name, ip, port}` 
- **UI:** "Favorites" section at top of peer list, "All Peers" below
- **Quick connect:** Tap bookmarked peer → immediately connect

**Files:**
- Modify: `android/lib/screens/connection_screen.dart` — Favorites section
- New: `android/lib/providers/bookmarks_provider.dart` — Bookmark state

**Success Criteria:**
- [ ] Bookmark/unbookmark works
- [ ] Favorites persisted across app restarts
- [ ] Favorites appear at top of peer list

---

#### F17. Connection Health Monitoring

**Goal:** Visual indicators for network quality — latency, packet loss, bandwidth.

**Implementation:**
- **Metrics:** Track RTT, frame drops, receive rate over sliding 10s window
- **Indicator:** Small colored dot in overlay: green (<50ms), yellow (<150ms), red (>150ms)
- **Notification:** Alert when quality degrades significantly
- **Auto-adapt:** Trigger adaptive bitrate downgrade when persistent degradation detected

**Files:**
- New: `android/lib/providers/health_provider.dart` — Health monitoring
- Modify: `android/lib/screens/remote_desktop_screen.dart` — Health indicator
- Modify: `core/src/streaming/bitrate.rs` — Integration with adaptive bitrate

**Success Criteria:**
- [ ] Health indicator reflects actual network conditions
- [ ] Auto-downgrade prevents frame drops
- [ ] User notified on major quality changes

---

### S4: Mobile UX (4 features)

#### F18. Connection History

**Goal:** Show a log of past connections with timestamps and durations.

**Implementation:**
- **Storage:** SQLite via `sqflite` package or JSON file
- **Display:** History screen accessible from connection screen
- **Fields:** Peer name, IP, connection start, duration, bytes transferred
- **Actions:** Tap to reconnect; swipe to delete entry

**Files:**
- New: `android/lib/screens/connection_history_screen.dart` — History UI
- New: `android/lib/services/history_service.dart` — History persistence
- Modify: `android/lib/screens/connection_screen.dart` — History button

**Success Criteria:**
- [ ] Connection logged on connect/disconnect
- [ ] History persists across app restarts
- [ ] Reconnect from history works

---

#### F19. Notification Mirroring

**Goal:** Show PC notifications on the Android device in real-time.

**Implementation:**
- **Server:** Extend notification plugin to forward notifications to connected client
- **Packet:** New KDE Connect packet type or use existing notification channels
- **Client:** Show as Android notification via `flutter_local_notifications`
- **Actions:** Support notification actions (Dismiss, Open, etc.)
- **Filtering:** Let user choose which apps forward notifications

**Files:**
- Modify: `server/src/plugins/notification.rs` — Forward to client
- New: `android/rust/src/notifications.rs` — Notification forward FFI
- New: `android/lib/services/notification_service.dart` — Process notifications
- Modify: `android/lib/screens/settings_screen.dart` — Notification filter settings

**Success Criteria:**
- [ ] PC notifications appear on Android within 2 seconds
- [ ] App name and icon shown
- [ ] Dismiss on phone dismisses on PC

---

#### F20. Power Management (Remote Shutdown/Sleep)

**Goal:** Send sleep, shutdown, or restart commands to the remote PC.

**Implementation:**
- **Commands:** `systemctl suspend`, `systemctl poweroff`, `systemctl reboot`
- **UI:** Power menu in remote desktop screen, confirmation dialog
- **Security:** Require confirmation + optional PIN
- **Protocol:** New KDE Connect packet type `kdeconnect.linuxlink.power`

**Files:**
- New: `server/src/plugins/power.rs` — Power management plugin
- Modify: `server/src/kde.rs` — Register power plugin
- Modify: `android/lib/screens/remote_desktop_screen.dart` — Power menu button
- Modify: `android/rust/src/api.rs` — `send_power_command()` FFI

**Success Criteria:**
- [ ] Sleep/shutdown/restart commands executed on server
- [ ] Confirmation dialog prevents accidents
- [ ] User notified command succeeded

---

#### F21. Remote Terminal

**Goal:** Basic command execution and terminal emulator within the app.

**Implementation:**
- **Commands:** Send single commands and view stdout/stderr
- **Protocol:** New KDE Connect packet `kdeconnect.linuxlink.exec`
- **Security:** Whitelist of allowed commands in config; require confirmation
- **UI:** Simple input field + scrollable output view
- **History:** Command history with up-arrow recall

**Files:**
- New: `server/src/plugins/exec.rs` — Command execution plugin
- New: `android/lib/screens/terminal_screen.dart` — Terminal UI
- Modify: `android/rust/src/api.rs` — `execute_command()` FFI
- Modify: `server/src/kde.rs` — Register exec plugin
- Modify: `server/src/config.rs` — Command whitelist config

**Success Criteria:**
- [ ] Commands execute and output returned
- [ ] Whitelist enforced on server
- [ ] Long-running commands can be cancelled

---

### S5: Platform Expansion (3 features)

#### F22. Desktop Client (Tauri)

**Goal:** A cross-platform desktop application (Windows, macOS, Linux) to replace the server daemon's CLI.

**Technology:** Tauri v2 (Rust backend + web frontend) or Flutter Desktop

**Implementation:**
- **Backend:** Reuse `linux-link-core` + `linux-link-server` as Tauri commands
- **Frontend:** Rust-based Tauri UI or Flutter web with server API
- **Features:** 
  - System tray with status icon
  - Connection management panel
  - Server start/stop/restart
  - View connected clients
  - Configuration editor
- **Packaging:** AppImage (Linux), DMG (macOS), MSI (Windows)

**Files:**
- New: `desktop/` directory with Tauri project
- New: `desktop/src-tauri/` — Rust backend
- New: `desktop/src/` — Web frontend (React/Svelte/Vanilla)
- Modify: `Cargo.toml` — Add desktop crate to workspace

**Success Criteria:**
- [ ] App runs on all 3 platforms
- [ ] System tray shows connection status
- [ ] Configuration editable from UI

---

#### F23. Localization / i18n

**Goal:** Multi-language support for the Android app.

**Implementation:**
- **Framework:** Flutter's built-in `flutter_localizations` + `intl` package
- **Process:** Extract all UI strings to `.arb` files
- **Languages:** Start with: English, German, French, Spanish, Japanese, Chinese (Simplified)
- **Fallback:** English as default when translation missing

**Files:**
- New: `android/lib/l10n/` — ARB files for each locale
- Modify: `android/pubspec.yaml` — Add `flutter_localizations`
- Modify: `android/lib/main.dart` — Localization config
- Modify (many): Replace hardcoded strings with `AppLocalizations.of(context)!.xxx`

**Success Criteria:**
- [ ] All 6 languages available
- [ ] RTL layout support for Arabic/Hebrew
- [ ] No missing translations (l10n lint passes)

---

#### F24. macOS Server Support

**Goal:** Run the server component on macOS in addition to Linux.

**Implementation:**
- **Screen capture:** `CGDisplayStream` or `SCDisplayStream` (CoreGraphics) via Rust FFI
- **Audio capture:** `AudioUnit` via CoreAudio
- **Input injection:** `CGEvent` API via `core-graphics` crate
- **Clipboard:** `NSPasteboard` via `objc2` crate
- **Notifications:** UserNotifications framework
- **Packaging:** `.app` bundle with `cargo bundle`

**Files:**
- New: `server/src/platform/macos/` — macOS-specific implementations
- Modify: `server/Cargo.toml` — Platform-specific dependencies
- Modify: `core/src/streaming/capture.rs` — macOS capture backend

**Success Criteria:**
- [ ] Screen capture works on macOS (Ventura+)
- [ ] Input injection functional
- [ ] Clipboard sync works

---

### S6: Security Hardening (2 features)

#### F25. Screen Lock Passcode

**Goal:** Protect the streaming session with a passcode to prevent unauthorized access.

**Implementation:**
- **Lock screen:** After connection, show passcode prompt (optional, configurable)
- **Verification:** Local passcode (set in settings) or remote PIN check
- **Timeout:** Auto-lock after N minutes of inactivity
- **State:** Show blurred stream behind lock screen

**Files:**
- New: `android/lib/screens/lock_screen.dart` — Passcode entry UI
- Modify: `android/lib/screens/remote_desktop_screen.dart` — Lock state management
- Modify: `android/lib/screens/settings_screen.dart` — Passcode settings

**Success Criteria:**
- [ ] Passcode prompt shown on connect (if enabled)
- [ ] Auto-lock after inactivity period
- [ ] Wrong passcode count exceeded → disconnect

---

#### F26. Trust on First Use (TOFU) Verification in UI

**Goal:** Visual feedback for TOFU certificate verification during pairing.

**Implementation:**
- **Current state:** TOFU verification exists in core (`TofuVerifier`, `CertManager`) but not surfaced in Flutter
- **UI:** Show certificate fingerprint on first connect
- **Comparison:** Display fingerprint with option to "Accept" or "Reject"
- **Notification:** Alert when a peer's certificate changes (potential MITM)
- **Management:** "Trusted Devices" list in settings with un-trust option

**Files:**
- Modify: `android/rust/src/api.rs` — `get_peer_fingerprint()` FFI
- New: `android/lib/screens/trust_screen.dart` — Certificate verification UI
- Modify: `android/lib/screens/settings_screen.dart` — Trusted devices list
- Modify: `android/lib/screens/connection_screen.dart` — TOFU prompt on first connect

**Success Criteria:**
- [ ] Fingerprint shown on first connection
- [ ] Accept/Reject works
- [ ] Certificate change alerts user

---

### S7: Developer Tooling (3 features)

#### F27. Integration Test Suite for Android

**Goal:** Comprehensive integration tests for the Rust FFI layer.

**Implementation:**
- **Mock server:** `test-server` binary that mimics the real server for client testing
- **Test scenarios:**
  - Connect/disconnect
  - Send/receive clipboard
  - File transfer (small + large)
  - Streaming start/stop
  - RTT measurement
  - Error handling (timeout, disconnect)
- **Coverage:** >80% of FFI functions tested

**Files:**
- New: `android/rust/tests/` — Integration tests
- New: `testing/test_server.rs` — Mock server binary
- Modify: `.github/workflows/ci.yml` — Android Rust test job

**Success Criteria:**
- [ ] All FFI functions tested
- [ ] Tests run in CI
- [ ] No flaky tests

---

#### F28. Benchmarking Suite

**Goal:** Track streaming performance across releases.

**Implementation:**
- **Metrics:**
  - FPS (capture → encode → receive → decode)
  - E2E latency (capture timestamp → render timestamp)
  - Bandwidth usage (bytes per frame, bitrate accuracy)
  - CPU usage (server + client)
  - Memory usage
- **Tools:** `criterion` bench harness for Rust, `benchmark.dart` for Flutter
- **Dashboard:** Generate HTML report with charts
- **Regression guard:** Fail CI if performance drops >10%

**Files:**
- New: `core/benches/` — Criterion benchmarks
- New: `android/test_benchmark/` — Flutter benchmark tests
- New: `scripts/benchmark.sh` — Benchmark runner

**Success Criteria:**
- [ ] Benchmarks run in CI
- [ ] Performance regression detected
- [ ] Report generated

---

#### F29. Flutter Web Prototype

**Goal:** A basic web client to enable remote access from any browser.

**Implementation:**
- **Build:** Compile Flutter web app (`flutter build web`)
- **Transport:** WebSocket bridge (since QUIC not available in browsers)
- **Features (initially):**
  - Peer discovery
  - Clipboard
  - File browsing
  - Screen stream (via WebRTC or MJPEG fallback)
- **Server:** Add WebSocket listener on configurable port

**Files:**
- New: `server/src/bridge/ws.rs` — WebSocket bridge
- Modify: `android/lib/` — Platform-conditional code for web
- New: `web/` — Web-specific configuration

**Success Criteria:**
- [ ] Web client loads in Chrome/Firefox/Safari
- [ ] Clipboard sync works
- [ ] Screen stream renders (even at reduced quality)

---

## 4. Architecture Changes

### Stream Protocol Extension

Current stream protocol uses a single QUIC datagram stream for H.264 frames. Phase 7 extends to multi-stream:

```
QUIC Connection (one per session)
├── Stream 0: Video frames (H.264/HEVC datagrams)
├── Stream 1: Audio packets (Opus datagrams)
├── Stream 2: Input events (bidirectional, reliable)
└── Stream 3: Control messages (bidirectional, reliable)
```

### New Cargo Dependencies

| Crate | Purpose | Workstream |
|-------|---------|------------|
| `audiopus` | Opus audio encoding | S1 |
| `wol` | Wake-on-LAN magic packets | S3 |
| `core-graphics` (macOS) | macOS screen capture | S5 |
| `objc2` (macOS) | macOS FFI bindings | S5 |
| `criterion` | Benchmarking | S7 |

### New Flutter Dependencies

| Package | Purpose | Workstream |
|---------|---------|------------|
| `intl` | i18n/localization | S5 |
| `sqflite` | Local database for history | S4 |
| `path_provider` | Recording file paths | S1 |

---

## 5. Execution Priority

### Phase 7a: Quick Wins (Weeks 1-4)
| Priority | Features | Effort | Impact |
|----------|----------|--------|--------|
| P0 | F9: Pinch-to-zoom & gestures | 1 week | High |
| P0 | F4: Stream quality presets UI | 1 week | High |
| P0 | F8: Stream stats overlay | 3 days | Medium |
| P0 | F16: Bookmark peers | 2 days | Medium |
| P0 | F17: Connection health | 4 days | Medium |

**Total:** ~3 weeks

### Phase 7b: Core Extensions (Weeks 5-12)
| Priority | Features | Effort | Impact |
|----------|----------|--------|--------|
| P1 | F1: Audio streaming | 3 weeks | High |
| P1 | F2: Multi-monitor | 2 weeks | High |
| P1 | F3: HEVC support | 2 weeks | High |
| P1 | F13: Clipboard auto-sync | 1 week | High |
| P1 | F15: Auto-reconnect | 1 week | Medium |

**Total:** ~9 weeks

### Phase 7c: Advanced Features (Weeks 13-20)
| Priority | Features | Effort | Impact |
|----------|----------|--------|--------|
| P2 | F5: Session recording | 2 weeks | Medium |
| P2 | F6: Encoder selection | 1 week | Medium |
| P2 | F10: Gamepad forwarding | 3 weeks | Medium |
| P2 | F14: Wake-on-LAN | 1 week | Medium |
| P2 | F18: Connection history | 1 week | Medium |
| P2 | F20: Power management | 1 week | Medium |
| P2 | F21: Remote terminal | 2 weeks | High |

**Total:** ~11 weeks

### Phase 7d: Platform & Polish (Weeks 21-34)
| Priority | Features | Effort | Impact |
|----------|----------|--------|--------|
| P3 | F7: Stream rotation | 3 days | Low |
| P3 | F11: Shortcuts overlay | 3 days | Low |
| P3 | F12: Drag-and-drop transfer | 1 week | Medium |
| P3 | F19: Notification mirroring | 2 weeks | High |
| P3 | F22: Desktop client | 4 weeks | High |
| P3 | F23: i18n | 2 weeks | Medium |
| P3 | F24: macOS server | 4 weeks | High |
| P3 | F25: Screen lock | 1 week | Medium |
| P3 | F26: TOFU UI | 3 days | Medium |
| P3 | F27: Integration tests | 2 weeks | Low |
| P3 | F28: Benchmarking | 1 week | Low |
| P3 | F29: Flutter web | 3 weeks | Medium |

**Total:** ~20 weeks

---

## 6. Risk Assessment

| Risk | Workstream | Impact | Mitigation |
|------|-----------|--------|------------|
| Audio sync drift | S1 | High | Timestamp-based A/V sync with periodic resync |
| GPU encoder availability | S1 | Medium | Graceful fallback chain for all features |
| Gamepad API fragmentation | S2 | Medium | Abstract behind a controller trait |
| macOS screen capture restrictions | S5 | High | Screen recording permission required; document setup |
| Tauri desktop app complexity | S5 | Medium | Start with minimal viable tray app |
| WebSocket bridge latency | S5 | Medium | Accept higher latency for web; optimize for LAN |
| Localization maintenance burden | S5 | Low | Use Flutter's tooling; rely on community contributions |

---

## 7. Success Criteria

### Quality Gates (All Features)
- [ ] `cargo fmt` — pass
- [ ] `cargo clippy -D warnings` — 0 warnings
- [ ] `cargo test --workspace` — all tests pass
- [ ] `flutter analyze` — no issues
- [ ] `flutter build apk --release` — builds successfully

### Feature-Specific
- [ ] Audio streaming: <200ms latency from capture to playback
- [ ] HEVC: ≥40% bandwidth reduction vs H.264 at same quality
- [ ] Wake-on-LAN: peer wakes within 30 seconds
- [ ] Desktop client: runs on Windows, macOS, Linux
- [ ] 6+ languages localized
- [ ] All FFI functions integration-tested
- [ ] No performance regressions vs Phase 6 baseline

---

## 8. File Map

```
NEW FILES:
core/src/streaming/audio_capture.rs       — PipeWire audio capture
core/src/streaming/audio_encoder.rs       — Opus encoding
core/src/streaming/monitor.rs             — Monitor enumeration
core/src/streaming/encoder_detect.rs      — Hardware encoder detection
core/src/tailscale/wol.rs                 — Wake-on-LAN
server/src/plugins/power.rs               — Power management plugin
server/src/plugins/exec.rs                — Remote exec plugin
server/src/plugins/notifications.rs       — Notification forward to client
server/src/bridge/ws.rs                   — WebSocket bridge
server/src/platform/macos/               — macOS platform support
android/rust/src/audio.rs                 — Audio decode FFI
android/rust/src/recorder.rs              — Session recording FFI
android/rust/tests/                       — Android Rust integration tests
android/lib/l10n/                         — Localization ARB files
android/lib/services/audio_player_service.dart   — Audio playback
android/lib/services/recording_service.dart       — Recording service
android/lib/services/clipboard_sync_service.dart  — Auto-sync
android/lib/services/notification_service.dart    — Notification processing
android/lib/services/history_service.dart         — History persistence
android/lib/providers/bookmarks_provider.dart     — Bookmark state
android/lib/providers/health_provider.dart        — Health monitoring
android/lib/screens/connection_history_screen.dart — History UI
android/lib/screens/terminal_screen.dart          — Terminal UI
android/lib/screens/lock_screen.dart              — Passcode lock screen
android/lib/screens/trust_screen.dart             — Certificate verification
android/lib/widgets/stream_stats_overlay.dart      — Stats overlay
android/lib/widgets/shortcuts_overlay.dart         — Shortcuts overlay
desktop/                                         — Tauri desktop app
core/benches/                                     — Criterion benchmarks
scripts/benchmark.sh                              — Benchmark runner
testing/test_server.rs                            — Mock server

MODIFIED FILES:
core/src/streaming/mod.rs                    — Audio types, Codec enum, presets
core/src/streaming/streamer.rs               — Audio task, monitor switch, dynamic config
core/src/streaming/client.rs                 — Re-connection support
core/src/streaming/encoder.rs                — HEVC + encoder selection
core/src/streaming/capture.rs                — Monitor selector
core/src/streaming/bitrate.rs                — Health integration
core/src/streaming/input_packet.rs           — Gamepad variant
server/src/kde.rs                            — Register new plugins
server/src/config.rs                         — Encoder selection, command whitelist
server/src/service.rs                        — WebSocket bridge
server/src/plugins/notification.rs           — Forward to client
server/src/input_injector.rs                 — Gamepad events
android/rust/src/lib.rs                     — Audio, recording, WOL, power, exec FFI
android/rust/src/api.rs                     — New FFI functions
android/lib/main.dart                        — Localization config, new routes
android/lib/screens/remote_desktop_screen.dart — Major UX updates
android/lib/screens/connection_screen.dart   — Bookmarks, history, WOL, TOFU
android/lib/screens/settings_screen.dart     — New settings
android/lib/screens/file_browser_screen.dart — Drag source
android/lib/services/background_service.dart — Auto-sync, notification start
android/lib/providers/streaming_provider.dart — Reconnect, rotation, health
android/pubspec.yaml                         — New dependencies
.github/workflows/ci.yml                     — Benchmark, test jobs
```

---

## 9. Summary Table

| # | Feature | Workstream | Effort | Priority | Risk | Depends On |
|---|---------|-----------|--------|----------|------|------------|
| F1 | Audio streaming | S1 | 3w | P1 | Medium | Phase 3 |
| F2 | Multi-monitor | S1 | 2w | P1 | Low | Phase 3 |
| F3 | HEVC/H.265 | S1 | 2w | P1 | Medium | Phase 3 |
| F4 | Quality presets UI | S1 | 1w | P0 | Low | Phase 3 |
| F5 | Session recording | S1 | 2w | P2 | Low | F1 |
| F6 | Encoder selection | S1 | 1w | P2 | Medium | Phase 3 |
| F7 | Stream rotation | S1 | 3d | P3 | Low | Phase 3 |
| F8 | Stats overlay | S1 | 3d | P0 | Low | Phase 3 |
| F9 | Pinch-to-zoom | S2 | 1w | P0 | Low | Phase 3 |
| F10 | Gamepad forwarding | S2 | 3w | P2 | Medium | Phase 3 |
| F11 | Shortcuts overlay | S2 | 3d | P3 | Low | Phase 3 |
| F12 | Drag-and-drop transfer | S2 | 1w | P3 | Low | Phase 2 |
| F13 | Clipboard auto-sync | S2 | 1w | P1 | Low | Phase 2 |
| F14 | Wake-on-LAN | S3 | 1w | P2 | Low | Phase 1 |
| F15 | Auto-reconnect | S3 | 1w | P1 | Low | Phase 3 |
| F16 | Bookmark peers | S3 | 2d | P0 | Low | Phase 1 |
| F17 | Connection health | S3 | 4d | P0 | Low | Phase 3 |
| F18 | Connection history | S4 | 1w | P2 | Low | — |
| F19 | Notification mirroring | S4 | 2w | P3 | Medium | Phase 2 |
| F20 | Power management | S4 | 1w | P2 | Low | Phase 2 |
| F21 | Remote terminal | S4 | 2w | P2 | Medium | Phase 2 |
| F22 | Desktop client (Tauri) | S5 | 4w | P3 | High | Phase 1 |
| F23 | Localization | S5 | 2w | P3 | Low | — |
| F24 | macOS server | S5 | 4w | P3 | High | Phase 3 |
| F25 | Screen lock passcode | S6 | 1w | P3 | Low | — |
| F26 | TOFU verification UI | S6 | 3d | P3 | Low | Phase A |
| F27 | Integration tests | S7 | 2w | P3 | Low | — |
| F28 | Benchmarking suite | S7 | 1w | P3 | Low | — |
| F29 | Flutter web prototype | S7 | 3w | P3 | Medium | Phase 4 |

**Legend:** P0=Immediate, P1=Short-term, P2=Medium-term, P3=Long-term

---

## 10. Appendix: Current APK Build

As of Phase 7 kickoff:
- **Debug APK:** 175.8 MB (`app-debug.apk`)
- **Release APK:** 71.7 MB (`app-release.apk`)
- **Flutter:** 3.41.9
- **Rust:** Workspace with core + server + android crates
- **Quality Gates:** All passing (fmt, clippy, test, analyze)
- **Tests:** 88 Rust tests, 0 Flutter tests

---

*Document Version: 1.0*
*Last Updated: May 14, 2026*
*Author: Linux Link Development Team*
