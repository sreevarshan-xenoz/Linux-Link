# Protocol V2 and Broadcast Optimizations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve server performance and reliability by optimizing the notification broadcast loop, preventing task leaks in the v2 multiplexer, and enforcing strict protocol validation.

**Architecture:** 
- Reduce lock contention in `server/src/service.rs` by cloning the active client list before broadcasting.
- Ensure resource cleanup in `server/src/v2_multiplexer.rs` by explicitly aborting the control stream task on session termination.
- Promote stream kind warnings to errors in `server/src/v2_multiplexer.rs` to maintain protocol integrity.

**Tech Stack:** Rust, Tokio, Quinn

---

### Task 1: Optimize Broadcast Loop in `server/src/service.rs`

**Files:**
- Modify: `server/src/service.rs:130-150`

- [ ] **Step 1: Read the file to ensure context**

- [ ] **Step 2: Update the broadcast loop to minimize lock duration**

```rust
                                // Optimized: Clone the list of clients and release the lock immediately
                                // to prevent slow clients from blocking the entire registration system.
                                let clients = {
                                    let clients_guard = ACTIVE_CLIENTS.lock().await;
                                    clients_guard.clone()
                                };
                                
                                let mut dead_clients = Vec::new();
                                for sender in clients.iter() {
                                    if let Err(e) = sender.send_packet(&packet).await {
                                        tracing::debug!("Detected dead client during broadcast: {e}");
                                        dead_clients.push(sender.connection_id().to_string());
                                    }
                                }

                                // Prune dead clients if any were detected
                                if !dead_clients.is_empty() {
                                    let mut clients_guard = ACTIVE_CLIENTS.lock().await;
                                    clients_guard.retain(|c| !dead_clients.contains(&c.connection_id().to_string()));
                                }

                                if !clients.is_empty() {
                                    tracing::debug!("Forwarded notification to {} client(s)", clients.len());
                                }
```

- [ ] **Step 3: Run `cargo check` to verify syntax**

Run: `cargo check -p linux-link-server`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add server/src/service.rs
git commit -m "perf(server): optimize notification broadcast loop to reduce lock contention"
```

### Task 2: Hardened Multiplexer Cleanup and Protocol Enforcement

**Files:**
- Modify: `server/src/v2_multiplexer.rs`

- [ ] **Step 1: Abort control_task on session exit**

In `handle_v2_session`, ensure `control_task.abort()` is called during cleanup.

```rust
        // Main loop to accept new streams
        let mut control_task = control_task;
        loop {
            // ... (existing select loop)
        }

        // Cleanup
        control_task.abort(); // Ensure the control task is terminated immediately
        {
            let mut clients = ACTIVE_CLIENTS.lock().await;
            // ...
```

- [ ] **Step 2: Enforce strict protocol for stream kinds**

Modify `handle_unidirectional_stream` and `handle_bidirectional_stream` to return `ProtocolError`.

```rust
async fn handle_unidirectional_stream(mut recv: RecvStream) -> anyhow::Result<()> {
    // ...
    } else {
        Err(LinuxLinkError::ProtocolError {
            detail: format!("Unknown unidirectional stream kind: {}", kind_raw),
        }.into())
    }
}

async fn handle_bidirectional_stream(_send: SendStream, mut recv: RecvStream) -> anyhow::Result<()> {
    let mut header = [0u8; 1];
    recv.read_exact(&mut header).await?;
    let kind_raw = header[0];

    Err(LinuxLinkError::ProtocolError {
        detail: format!("Unexpected bidirectional stream kind: {}", kind_raw),
    }.into())
}
```

- [ ] **Step 3: Run `cargo check` to verify syntax**

Run: `cargo check -p linux-link-server`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add server/src/v2_multiplexer.rs
git commit -m "fix(server): harden v2 multiplexer cleanup and enforce strict protocol"
```

### Task 3: Verification

- [ ] **Step 1: Run integration tests**

Run: `cargo test`
Expected: PASS
