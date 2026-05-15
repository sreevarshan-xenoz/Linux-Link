# Linux Link — Fix Plan

Priorities: **P0** = must fix (broken functionality), **P1** = should fix (design flaw), **P2** = nice to have (polish)

---

## 🔴 P0 — Critical Bugs

### FIX-1: Android control reader drops all server packets
**Files:** `android/rust/src/api.rs`, `android/rust/src/lib.rs`, `android/lib/rust_api_bridge.dart`, `android/lib/services/notification_service.dart`

**Problem:** The reader task in `connect_to_peer()` reads raw lines and discards them. The server sends identity packets and KDE Connect packets (notifications, clipboard, battery), but Android never processes them. PC notifications will never reach the phone.

**Changes:**

1. **`android/rust/src/lib.rs`** — Add a global channel for incoming KDE packets:
```rust
use tokio::sync::broadcast;
pub(crate) static INCOMING_PACKETS: LazyLock<Mutex<Option<broadcast::Sender<String>>>> =
    LazyLock::new(|| Mutex::new(None));
```

2. **`android/rust/src/api.rs` `connect_to_peer()`** — Replace the empty reader loop:
```rust
// Before (lines 147-161): discards everything
tokio::spawn(async move {
    let mut reader = tokio::io::BufReader::new(reader);
    let mut line = String::new();
    while let Ok(n) = reader.read_line(&mut line).await {
        if n == 0 { break; }
        line.clear();
    }
    // ... disconnect handling
});

// After: parse packets and forward
let packet_tx = {
    let mut guard = INCOMING_PACKETS.lock().await;
    let (new_tx, _) = broadcast::channel(128);
    *guard = Some(new_tx.clone());
    new_tx
};
tokio::spawn(async move {
    let mut reader = tokio::io::BufReader::new(reader);
    let mut line = String::new();
    while let Ok(n) = reader.read_line(&mut line).await {
        if n == 0 { break; }
        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() {
            let _ = packet_tx.send(trimmed);
        }
        line.clear();
    }
    // ... disconnect handling
});
```

3. **`android/rust/src/api.rs`** — Add a new FFI function:
```rust
#[frb]
pub async fn poll_incoming_packets() -> Vec<String> {
    let guard = INCOMING_PACKETS.lock().await;
    let Some(tx) = guard.as_ref() else { return vec![] };
    let mut rx = tx.subscribe();
    drop(guard);
    let mut packets = vec![];
    while let Ok(pkt) = rx.try_recv() {
        packets.push(pkt);
        if packets.len() >= 16 { break; }
    }
    packets
}
```

4. **`android/lib/rust_api_bridge.dart`** — Add wrapper + dispatch:
```dart
Future<void> pollPackets() async {
  final packets = await frb.pollIncomingPackets();
  for (final raw in packets) {
    try {
      final json = jsonDecode(raw) as Map<String, dynamic>;
      final type = json['type'] as String?;
      if (type == 'kdeconnect.notification') {
        notificationService.handleNotification(json['body']);
      } else if (type == 'kdeconnect.clipboard') {
        clipboardSyncService.handleRemoteClipboard(json['body']);
      }
      // ... other packet types
    } catch (_) {}
  }
}
```
Add a periodic timer in `remote_desktop_screen.dart` or `main.dart` to call `pollPackets()` every 500ms while connected.

---

### FIX-2: Notification monitor captures go to nowhere
**Files:** `server/src/service.rs`, `server/src/notification_monitor.rs`

**Problem:** Captured notifications are parsed correctly but never forwarded to connected clients. No broadcast mechanism exists.

**Changes:**

1. **`server/src/service.rs`** — Add a global `broadcast::Sender<ForwardedNotification>` and pass it to `handle_connection_with_kde`. When a notification arrives, iterate active connections and send `kdeconnect.notification` packets.

Add a set of active peer senders:
```rust
use std::collections::HashSet;
use tokio::sync::Mutex;
use linux_link_core::protocol::kdeconnect::TcpDeviceSender;

static ACTIVE_PEERS: LazyLock<Mutex<Vec<TcpDeviceSender<OwnedWriteHalf>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));
```

Register sender when connection is established (in `handle_connection_with_kde`), remove on disconnect. Spawn a notification forwarding task:

```rust
let notify_tx = start_notification_monitor();
let mut notify_rx = notify_tx.subscribe();
tokio::spawn(async move {
    while let Ok(notification) = notify_rx.recv().await {
        let packet_json = notification.to_kdeconnect_payload();
        let packet = NetworkPacket::from_wire(&packet_json).unwrap();
        let peers = ACTIVE_PEERS.lock().await;
        for sender in peers.iter() {
            let _ = sender.send_packet(&packet).await;
        }
    }
});
```

---

### FIX-3: Streaming pipeline only uses PipeWire
**Files:** `core/src/streaming/streamer.rs`, `core/src/streaming/mod.rs`

**Problem:** `streamer.rs:150` calls `capture::start_capture()` which is PipeWire-only. On X11, capture fails.

**Changes:**

1. **`core/src/streaming/mod.rs`** — Add re-export:
```rust
#[cfg(feature = "capture")]
pub use capture::start_capture_auto;
```

2. **`core/src/streaming/streamer.rs`** — Change line 150:
```rust
// Before:
let capture_session = capture::start_capture(capture_config, frame_tx, capture_cancel)

// After:
let capture_session = capture::start_capture_auto(capture_config, frame_tx, capture_cancel)
```

---

### FIX-4: CertManager is in-memory only on Android
**Files:** `android/rust/src/api.rs`

**Problem:** CertManager uses `new()` (no persistence). Trusted certs lost on app restart. Trust screen UI exists but is non-functional.

**Changes:**

1. **`android/rust/src/api.rs` `connect_streaming()`** — Replace:
```rust
// Before (line 381-383):
let cert_manager = std::sync::Arc::new(
    linux_link_core::streaming::transport::CertManager::new().map_err(|e| e.to_string())?,
);

// After:
use std::path::PathBuf;
fn cert_dir() -> PathBuf {
    // Android app-specific directory — passed from Flutter or use env
    std::env::var("LINUX_LINK_CERT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("/data/data/com.linux.link"))
                .join("linux-link/certs")
        })
}
let cert_manager = std::sync::Arc::new(
    linux_link_core::streaming::transport::CertManager::load_or_create(&cert_dir())
        .map_err(|e| e.to_string())?,
);
```

2. Add a new FFI to expose trusted devices:
```rust
#[frb]
pub fn get_trusted_peers() -> Vec<String> { /* read cert_manager known_peers */ }
#[frb]
pub fn forget_trusted_peer(label: String) -> Result<(), String> { /* remove + save */ }
```

---

## 🟡 P1 — Design Issues

### FIX-5: Streaming stats return zeros
**Files:** `core/src/streaming/client.rs`, `core/src/streaming/streamer.rs`, `android/rust/src/api.rs`

**Problem:** `get_streaming_stats()` always returns `fps: 0.0`, `bitrate_kbps: 0`, `frame_drops: 0`.

**Changes:**

1. **`core/src/streaming/streamer.rs`** — Track actual metrics in the pipeline (already has counters in Tasks 2 and 3). Expose them through a shared `Arc<Mutex<StreamingStats>>`.

2. **`core/src/streaming/client.rs`** — Forward stats back to caller:
```rust
pub struct StreamingClient {
    // ... existing fields
    pub stats: Arc<Mutex<StreamingStats>>,  // add this
}
```

3. **`android/rust/src/api.rs`** — Read from the stats instead of hardcoding:
```rust
pub fn get_streaming_stats() -> StreamingStatsDto {
    let guard = (*STREAMING_HANDLE).lock().await;
    let Some(handle) = guard.as_ref() else { return StreamingStatsDto::default() };
    let stats = handle.stats.lock().unwrap();
    StreamingStatsDto {
        fps: stats.fps,
        bitrate_kbps: stats.bitrate_kbps,
        e2e_latency_ms: stats.e2e_latency_ms,
        frame_drops: stats.frame_drops,
    }
}
```

---

### FIX-6: Audio streaming is silence
**Files:** `core/src/streaming/streamer.rs`

**Problem:** Audio task sends Opus-encoded silence. No real audio capture.

**Changes:**

This is a larger feature. For now, document it as known limitation. The TODO at line 476 already marks it. The fix would be:
1. Use PipeWire audio loopback (`libspa` audio source) or ALSA `loopback` module
2. Capture PCM frames from the loopback device
3. Feed into existing `AudioEncoder`
4. The transport path already works (audio_rx in client, audio_service.dart on Android)

---

### FIX-7: `StreamingClient::new()` dead code
**Files:** `core/src/streaming/client.rs`

**Changes:**

Either remove `new()` or fix it to not drop the receivers:
```rust
pub fn new(channel_capacity: usize, cert_manager: Arc<CertManager>) ->
    (Self, mpsc::Receiver<EncodedPacket>, mpsc::Receiver<AudioPacket>)
{
    let (frame_tx, frame_rx) = mpsc::channel(channel_capacity);
    let (audio_tx, audio_rx) = mpsc::channel(channel_capacity);
    // ... return receivers too
}
```

---

### FIX-8: `is_streaming_active()` race condition
**Files:** `android/rust/src/api.rs`

**Changes:**

Use a dedicated atomic boolean instead of `try_lock()`:
```rust
pub(crate) static STREAMING_ACTIVE: AtomicBool = AtomicBool::new(false);
// Set true in connect_streaming(), false in stop_streaming()

#[frb(sync)]
pub fn is_streaming_active() -> bool {
    STREAMING_ACTIVE.load(Ordering::Relaxed)
}
```

---

### FIX-9: Device identity is ephemeral
**Files:** `server/src/kde.rs`

**Changes:**

Persist device ID to a file:
```rust
fn host_device_id() -> String {
    let path = state_dir().join("device_id");
    if let Ok(id) = std::fs::read_to_string(&path) {
        if !id.trim().is_empty() { return id.trim().to_string(); }
    }
    let id = uuid::Uuid::new_v4().to_string();
    let _ = std::fs::write(&path, &id);
    id
}
```

---

### FIX-10: Raw TCP helpers in Dart bypass Rust
**Files:** `android/lib/rust_api_bridge.dart`

**Problem:** `sendPowerCommand()`, `executeCommand()`, `getMonitorCount()` open raw TCP from Dart, reimplementing the HELLO handshake. No cert verification, no connection reuse.

**Changes:**

Route these through Rust FFI instead:
- Add `send_power_command(action: String)` → `api.rs`
- Add `execute_remote_command(command: String)` → `api.rs` 
- `get_monitor_count()` already exists in `api.rs`, so remove the Dart duplicate

Each new function uses `ConnectionManager` + reuses `CONTROL_WRITER` when connected.

---

### FIX-11: Clipboard get/send inconsistency
**Files:** `android/rust/src/api.rs`

**Problem:** `get_clipboard()` opens a new connection instead of reusing the existing control channel.

**Changes:**

Modify `get_clipboard()` to reuse `CONTROL_WRITER` if connected, fall back to new connection:
```rust
pub async fn get_clipboard(address: String, port: u16) -> Result<String, String> {
    // Try existing connection first
    if let Some(writer) = (*CONTROL_WRITER).lock().await.as_ref().cloned() {
        let sender = TcpDeviceSender::from_arc(writer);
        // ... send request, read response from existing reader
    } else {
        // Fall back to new connection (existing logic)
    }
}
```

---

## 🟢 P2 — Polish

### FIX-12: Notification monitor URI decoding

**Problem:** D-Bus strings may contain escaped characters.

**Changes:** Add proper string unescaping in `notification_monitor.rs` for the dbus-monitor output format.

---

### FIX-13: mDNS registration error surfacing

**Problem:** `register_service()` failures are logged but invisible to users.

**Changes:** Add a health check or status endpoint. Optionally expose via `linux-link status`.

---

### FIX-14: `receive_frames` timeout documentation

**Problem:** Timeout only applies to first packet.

**Changes:** Update doc comment to clarify semantics.

---

### FIX-15: Consistent error types across plugins

**Problem:** Some plugins use `anyhow::bail!()`, others use `tracing::warn!()` and return `Ok(())`. Inconsistent error handling.

**Changes:** Audit all 9 plugins and standardize on returning `Err` for failures the caller should know about.

---

## ✅ All Fixes Complete (May 15, 2026)

| Fix | Status | Commit |
|-----|--------|--------|
| FIX-3: X11 fallback | ✅ `18bb825` |
| FIX-4: Cert persistence + trust FFI | ✅ `316d0e5` `9486f76` |
| FIX-7: StreamingClient dead code | ✅ `7618b6b` |
| FIX-8: Atomic streaming flag | ✅ `9486f76` |
| FIX-9: Persistent device ID | ✅ `8e8210d` |
| FIX-1: Android packet forwarding | ✅ `9486f76` |
| FIX-2: Notification broadcast | ✅ `a0bfaee` |
| FIX-5: Streaming stats tracking | ✅ `9486f76` |
| FIX-10: Dart TCP → Rust FFI | ✅ `041a832` |
| FIX-11: Clipboard connection reuse | ✅ `cd7362f` |
| FIX-6: PipeWire audio capture | ✅ `b93aa3c` |
| FIX-12: D-Bus URI decoding | ✅ `804de08` |
| FIX-14: receive_frames docs | ✅ `99dc443` |
| FIX-15: Plugin error consistency | ✅ `e3b228e` |
| FRB codegen regeneration | ✅ `9ee3c82` |
| Flutter APK build | ✅ builds clean |

## Effort Summary

| Fix | Effort | Files Changed | Priority |
|-----|--------|---------------|----------|
| FIX-1: Packet forwarding | 3 days | 4 files (Rust + Dart) | **P0** |
| FIX-2: Notification broadcast | 2 days | 2 files (server) | **P0** |
| FIX-3: X11 fallback | 0.5 day | 2 files (core) | **P0** |
| FIX-4: Cert persistence | 1 day | 2 files (Rust) | **P0** |
| FIX-5: Streaming stats | 1 day | 3 files (core + Android) | P1 |
| FIX-6: Audio capture | 5+ days | 1 file (core) | P1 |
| FIX-7: Dead code cleanup | 0.5 day | 1 file | P1 |
| FIX-8: Atomic streaming flag | 0.5 day | 2 files | P1 |
| FIX-9: Persistent device ID | 0.5 day | 1 file | P1 |
| FIX-10: Route Dart TCP → Rust | 2 days | 3 files (Rust + Dart) | P1 |
| FIX-11: Consistent clipboard | 0.5 day | 1 file | P1 |
| FIX-12..15: Polish | 1 day | various | P2 |

**Total P0 effort: ~6.5 days**
**Total P1 effort: ~9.5 days**
**Total P2 effort: ~1 day**

**Recommended order:** FIX-3 → FIX-4 → FIX-7 → FIX-8 → FIX-1 → FIX-2 → FIX-9 → FIX-5 → FIX-11 → FIX-10 → FIX-6 → FIX-12..15
