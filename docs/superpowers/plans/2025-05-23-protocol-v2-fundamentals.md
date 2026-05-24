# Protocol v2 Fundamentals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the core data structures and framing for the Linux Link v2 protocol.

**Architecture:** Define constants, enums, and structs for v2, and implement framed JSON encoding/decoding on top of `quinn` streams.

**Tech Stack:** Rust, `quinn`, `serde`, `serde_json`.

---

### Task 1: Initialize `v2` module and constants

**Files:**
- Create: `core/src/protocol/v2.rs`
- Modify: `core/src/protocol/mod.rs`

- [ ] **Step 1: Create `core/src/protocol/v2.rs` with `ALPN_V2`**

```rust
pub const ALPN_V2: &[u8] = b"linux-link-v2";
```

- [ ] **Step 2: Modify `core/src/protocol/mod.rs` to export `v2`**

```rust
pub mod backoff;
pub mod connection;
pub mod kdeconnect;
pub mod v2; // Add this line

#[cfg(test)]
mod connection_test;
#[cfg(test)]
mod kdeconnect_test;
// ...
```

- [ ] **Step 3: Commit**

```bash
git add core/src/protocol/v2.rs core/src/protocol/mod.rs
git commit -m "feat(protocol): initialize v2 module and ALPN_V2 constant"
```

### Task 2: Implement `ChannelKind` and `IdentityPacketV2`

**Files:**
- Modify: `core/src/protocol/v2.rs`

- [ ] **Step 1: Implement `ChannelKind` enum**

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelKind {
    Control = 0,
    Video = 1,
    Audio = 2,
    Input = 3,
    File = 4,
}
```

- [ ] **Step 2: Implement `IdentityPacketV2` struct**

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityPacketV2 {
    pub device_id: String,
    pub device_name: String,
    pub min_version: u32,
    pub max_version: u32,
    pub capabilities: Vec<String>,
}
```

- [ ] **Step 3: Commit**

```bash
git add core/src/protocol/v2.rs
git commit -m "feat(protocol): add ChannelKind and IdentityPacketV2"
```

### Task 3: Implement Framed JSON Framing (TDD)

**Files:**
- Modify: `core/src/protocol/v2.rs`

- [ ] **Step 1: Write the failing tests for framing**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_framed_json_roundtrip() {
        // We'll use a mock or a way to test this. 
        // Since quinn::SendStream and RecvStream are hard to mock without a real connection,
        // we might need a helper that takes AsyncRead/AsyncWrite if we want pure unit tests,
        // but the requirement specifically says quinn types.
        // I'll assume we can use a helper or test with a real quinn connection if available,
        // but for unit tests, I'll provide a way to test the logic.
    }
}
```

Wait, `quinn::SendStream` and `quinn::RecvStream` don't implement `AsyncRead`/`AsyncWrite` directly in a way that's easy to mock without `quinn` infrastructure. 
However, I can implement the framing logic in a way that takes `AsyncRead` / `AsyncWrite` and then wrap it or just use `quinn`'s methods.
The requirement specifically asks for `quinn::SendStream` and `quinn::RecvStream`.

I'll refine the plan to include tests using `tokio::io::duplex` if I can wrap them, but `quinn` streams are different.
Actually, I'll use a local QUIC connection for testing if possible, or test the logic separately.

Actually, I can just implement the functions and test them using a real (but local) QUIC connection in the test.

- [ ] **Step 1: Write failing test in `core/src/protocol/v2.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct TestData {
        foo: String,
    }

    #[tokio::test]
    async fn test_write_read_framed_json() {
        // This will fail to compile initially because functions aren't defined.
        // I'll need a way to actually run this.
    }
}
```

Actually, let's write the functions first but with `todo!()` to see them fail.

- [ ] **Step 2: Add function signatures with `todo!()`**

```rust
use serde::de::DeserializeOwned;
use crate::error::Result;

pub async fn write_framed_json<T: Serialize>(
    send: &mut quinn::SendStream,
    data: &T,
) -> Result<()> {
    todo!()
}

pub async fn read_framed_json<T: DeserializeOwned>(
    recv: &mut quinn::RecvStream,
) -> Result<T> {
    todo!()
}
```

- [ ] **Step 3: Implement `write_framed_json`**

```rust
pub async fn write_framed_json<T: Serialize>(
    send: &mut quinn::SendStream,
    data: &T,
) -> Result<()> {
    let json = serde_json::to_vec(data)?;
    let len = json.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&json).await?;
    Ok(())
}
```

- [ ] **Step 4: Implement `read_framed_json`**

```rust
pub async fn read_framed_json<T: DeserializeOwned>(
    recv: &mut quinn::RecvStream,
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    
    Ok(serde_json::from_slice(&buf)?)
}
```

- [ ] **Step 5: Add tests that use a local QUIC connection (or duple x if I can wrap them)**

Wait, `quinn` types are concrete. I'll use a local QUIC connection in the test.

- [ ] **Step 6: Run tests**

- [ ] **Step 7: Commit**

```bash
git add core/src/protocol/v2.rs
git commit -m "feat(protocol): implement framed JSON support for v2"
```
