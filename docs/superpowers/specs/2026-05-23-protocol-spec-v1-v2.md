# Specification: Linux Link Protocol (v1.x & v2.0)

**Date:** 2026-05-23  
**Status:** Draft / Frozen for v2.0 Implementation  
**Version:** 1.1 (v1.x Baseline) / 2.0 (Multiplexed Target)

## 1. Transport & Identity

### 1.1 Transport Layers
*   **v1.x (Current):** 
    *   **Control:** TCP over Port 1716 (Legacy KDE Connect JSON).
    *   **Streaming:** QUIC over Port 4716 (Unidirectional streams).
*   **v2.0 (Target):**
    *   **Unified:** QUIC over Port 4716 only.
    *   **Multiplexing:** Multiple streams (Control, Video, Audio, Input) inside a single QUIC connection.
    *   **ALPN:** `linux-link-v2`

### 1.2 Device Identity
Every device (Host and Client) must have a **stable, persisted UUID**.
*   **Storage:** `~/.config/linux-link/device_id` (Linux) / App Data (Android).
*   **Metadata:** Identity packets must include `deviceId`, `deviceName`, and `protocolVersion`.

---

## 2. Handshake Sequence

### 2.1 TCP Handshake (v1.x Control)
1.  **Client -> Server:** `LINUX_LINK_HELLO 1\n`
2.  **Server -> Client:** `LINUX_LINK_OK 1\n`
3.  **Server -> Client:** `NetworkPacket` (type: `kdeconnect.identity`)
4.  **Client -> Server:** `NetworkPacket` (type: `kdeconnect.identity`)

### 2.2 QUIC Handshake (v2.0 Unified)
1.  **QUIC Connection established** with ALPN `linux-link-v2`.
2.  **TLS Handshake** uses persistent self-signed certificates (TOFU model).
3.  **Stream 0 (Reliable, Bidirectional) opens.**
4.  **Client -> Server (Stream 0):** `IdentityPacket` (Binary/Protobuf - TBD).
5.  **Server -> Client (Stream 0):** `IdentityPacket` + `ServerCapabilities`.

---

## 3. Session Lifecycle

### 3.1 States
*   `Disconnected`: No active socket/connection.
*   `Discovered`: Peer found via mDNS/Tailscale but not connected.
*   `Connecting`: Handshake in progress.
*   `Active`: Heartbeats flowing, streams open.
*   `Stale`: `RTT > 2000ms` or high packet loss. Active but degraded.
*   `Reconnecting`: Socket lost, backoff loop active.
*   `Failed`: Fatal error (Auth rejected, Version mismatch).

### 3.2 Shutdown Semantics
*   **Graceful:** Close Stream 0 with a `Shutdown` packet.
*   **Abrupt:** Peer reset or idle timeout (60s).
*   **Cleanup Order:** 
    1. Stop Capture (Server) / Stop Rendering (Client).
    2. Close unidirectional streams (Video/Audio).
    3. Close control stream.
    4. Terminate QUIC connection.

---

## 4. Stream Model (Multiplexing)

### 4.1 Stream IDs & Kinds
| Stream ID | Type | Kind | Description |
| :--- | :--- | :--- | :--- |
| **0** | Reliable/Bi | Control | Handshake, Config, RPC |
| **1** | Unreliable/Uni | Video | H.264/H.265/AV1 NAL Units |
| **2** | Unreliable/Uni | Audio | Opus Packets |
| **3** | Reliable/Uni | Input | Binary InputPackets (Mouse/Keys) |
| **4+** | Reliable/Uni | Utility | File Transfers, Clipboard |

### 4.2 Framing (Binary Header - 18 Bytes)
All streaming packets (Video/Audio/Input) must start with this header:
*   `[0..8]` **Sequence (u64 LE)**: Monotonic counter for ordering.
*   `[8]` **Stream Kind (u8)**: 0=Video, 1=Audio, 2=Input.
*   `[9]` **Flags (u8)**: Bit 0: IsKeyframe.
*   `[10..18]` **Timestamp (u64 LE)**: Microseconds since session start.

---

## 5. Error & Reconnect Model

### 5.1 Error Codes
*   `2xxx`: Transport (2001: Refused, 2003: Timeout).
*   `3xxx`: Auth (3001: Not Trusted).
*   `5xxx`: Codec/Capture (5002: PW Denied).

### 5.2 Reconnection Rules
1.  **Trigger:** Socket error or timeout.
2.  **Backoff:** Exponential (Base: 1s, Max: 30s) + 10% Jitter.
3.  **Idempotency:** A reconnect attempt must `take()` the existing `StreamingHandle` and await task completion before creating new ones.
4.  **Roaming:** QUIC connection migration is preferred. If IP changes, try to resume the CID. Re-handshake only if CID is invalid.

---

## 6. Backend Support Matrix (Capability Contract)

The system is architected as a set of capability bundles. Support is defined by the intersection of the Compositor and the Backend.

### 6.1 Capability Tiers
*   **Tier 1 (Official):** Fully tested, feature-parity, recommended for production.
*   **Tier 2 (Partial):** Functional but may lack specific optimizations or have minor limitations.
*   **Legacy:** Supported for backward compatibility only; not recommended for new deployments.

### 6.2 Support Matrix

| Category | Component | Backend | Tier | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Compositor** | Wayland (wlroots) | PipeWire + uinput | 1 | Hyprland, Sway (v1.x) |
| | Wayland (KDE) | PipeWire + uinput | 1 | Plasma 6+ |
| | Wayland (GNOME) | PipeWire + enigo | 2 | Mutter restricted uinput |
| | X11 | xcap + enigo | Legacy | XShm capture |
| **Capture** | Video | PipeWire (Portal) | 1 | Zero-copy Wayland |
| | Video | XShm (xcap) | Legacy | Raw buffer pull |
| **Input** | Injection | uinput (Kernel) | 1 | Universal virtual HID |
| | Injection | enigo (X11) | 2 | XTEST extension |
| **Audio** | Capture | PipeWire Loopback | 1 | Native monitor stream |
| | Capture | PulseAudio | 2 | Via PW-Pulse bridge |
| **Network** | Discovery | mDNS (LAN) | 1 | Zero-config local |
| | Discovery | Tailscale | 1 | Global P2P |

---

## 7. Shutdown & Cleanup Mandates

To prevent resource leaks and "zombie" tasks, all components must follow these cleanup rules:

1.  **Explicit Drop Logging:** All major resource owners (`InputInjector`, `CaptureSession`, `StreamingServer`) must log their teardown.
2.  **Task Drainage:** `JoinSet` must be explicitly drained in the shutdown loop.
3.  **FD Integrity:** Kernel resources (uinput, sockets) must be closed immediately on session termination.
4.  **Idempotent Teardown:** Calling `stop()` or dropping a handle multiple times must be safe.
