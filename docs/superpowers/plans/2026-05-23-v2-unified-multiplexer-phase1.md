# Linux Link v2.0: Unified QUIC Multiplexer (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate all communication into a single multiplexed QUIC connection with a persistent control channel and ephemeral media channels.

**Architecture:**
- **ALPN:** `linux-link-v2`
- **Control Channel:** Persistent Bidirectional Stream (Stream 0). Uses 4-byte BE length-prefixed JSON framing.
- **Media Channels:** Ephemeral Unidirectional Streams (or Datagrams).
- **Versioning:** Multi-version range negotiation (min/max).

**Tech Stack:** Rust (quinn, tokio), Flutter (Dart FFI).

---

## File Structure

- **Core (`core/src/protocol/`)**:
  - `v2.rs`: Channel definitions, versioning, and framing logic.
- **Server (`server/src/`)**:
  - `v2_multiplexer.rs`: Server-side connection and stream router.
- **Android (`android/rust/src/`)**:
  - `api.rs`: `connect_v2` implementation.

---

### Task 1: Protocol v2 Fundamentals

**Files:**
- Modify: `core/src/protocol/v2.rs`

- [ ] **Step 1: Define ChannelKind and Versioning**

```rust
pub const ALPN_V2: &[u8] = b"linux-link-v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChannelKind {
    Control = 0, // Reliable Bi-directional
    Video = 1,   // Unreliable Uni-directional
    Audio = 2,   // Unreliable Uni-directional
    Input = 3,   // Reliable Uni-directional
    File = 4,    // Reliable Uni-directional (Ephemeral)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPacketV2 {
    pub device_id: String,
    pub device_name: String,
    pub min_version: u32,
    pub max_version: u32,
    pub capabilities: Vec<String>,
}
```

- [ ] **Step 2: Implement Length-Prefixed Framing**

```rust
pub async fn write_framed_json<T: Serialize>(
    send: &mut quinn::SendStream,
    data: &T,
) -> Result<(), crate::error::LinuxLinkError> {
    let bytes = serde_json::to_vec(data).map_err(|e| crate::error::LinuxLinkError::Serialization {
        format: "JSON",
        detail: e.to_string(),
    })?;
    let len = bytes.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

pub async fn read_framed_json<T: DeserializeOwned>(
    recv: &mut quinn::RecvStream,
) -> Result<T, crate::error::LinuxLinkError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    
    serde_json::from_slice(&buf).map_err(|e| crate::error::LinuxLinkError::Serialization {
        format: "JSON",
        detail: e.to_string(),
    })
}
```

---

### Task 2: Persistent Handshake (Stream 0)

- [ ] **Step 1: Implement Handshake Logic**

```rust
pub async fn perform_v2_handshake(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    local_identity: &IdentityPacketV2,
) -> Result<IdentityPacketV2, crate::error::LinuxLinkError> {
    // 1. Exchange Identities (Framed)
    write_framed_json(send, local_identity).await?;
    let peer_identity = read_framed_json(recv).await?;

    // 2. Version Negotiation
    if peer_identity.max_version < local_identity.min_version || 
       peer_identity.min_version > local_identity.max_version {
        return Err(crate::error::LinuxLinkError::ProtocolError {
            detail: "Incompatible protocol versions".to_string(),
        });
    }

    Ok(peer_identity)
}
```

---

### Task 3: Multiplexer & Flow Control

- [ ] **Step 1: Define Flow Control Policy**
  - **Priority:** Audio > Input > Video.
  - **Congestion:** If `quinn` reports congestion, drop Video frames immediately.
  - **Backpressure:** Limit Video MPSC channel to 2 frames; drop oldest if full.

- [ ] **Step 2: Implement Multiplexer Router**

```rust
async fn handle_v2_session(conn: quinn::Connection) -> Result<()> {
    // 1. Accept Stream 0 for Handshake
    let (mut send0, mut recv0) = conn.accept_bi().await?;
    let peer = perform_v2_handshake(&mut send0, &mut recv0, &local).await?;

    // 2. Enter Multi-Stream Loop
    loop {
        tokio::select! {
            // New Bi-streams (RPC / Control)
            Ok(bi) = conn.accept_bi() => { /* Handle */ }
            // New Uni-streams (Media)
            Ok(uni) = conn.accept_uni() => {
                // Read 1-byte header to identify ChannelKind
                let kind = read_channel_kind(uni).await?;
                spawn_handler(kind, uni);
            }
        }
    }
}
```

---

### Task 4: Execution

- [ ] **Step 1: Commit Phase 1 Foundation**
- [ ] **Step 2: Implement `connect_v2` in Android Rust FFI**
- [ ] **Step 3: Verify end-to-end handshake in logs**
