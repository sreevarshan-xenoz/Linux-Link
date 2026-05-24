# Linux Link v2.0: ChaosProxy & Fairness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the `ChaosProxy` test harness to simulate network degradation (packet loss, latency spikes) and implement the queue bounds defined in the Fairness Contract.

**Architecture:** 
- A new module `core/src/streaming/chaos.rs` providing a `ChaosProxy` that intercepts QUIC datagrams between a mock server and client.
- It will support configuring drop rates and latency delays.
- A new test file `core/tests/chaos_integration.rs` will run the `coffee_shop_wifi` and `elevator_deadzone` scenarios.

**Tech Stack:** Rust (tokio, quinn).

---

### Task 1: Building the ChaosProxy

**Files:**
- Create: `core/src/streaming/chaos.rs`
- Modify: `core/src/streaming/mod.rs` (Export `chaos` if `#[cfg(test)]`)

- [ ] **Step 1: Define ChaosConfig**

```rust
#[derive(Debug, Clone, Default)]
pub struct ChaosConfig {
    pub drop_rate: f64, // 0.0 to 1.0
    pub base_latency_ms: u64,
    pub jitter_ms: u64,
    pub blackhole_duration_ms: Option<u64>,
}
```

- [ ] **Step 2: Implement ChaosProxy**
Create a UDP proxy that sits between two given ports. It receives packets on one port, applies the `ChaosConfig` rules (dropping or delaying), and forwards to the target port.

---

### Task 2: Implementing Bounded Queues & "Latest-Frame-Wins"

**Files:**
- Modify: `core/src/streaming/streamer.rs`

- [ ] **Step 1: Enforce "Latest-Frame-Wins" for Video**
Modify the video `mpsc::channel` creation in `run_pipeline`. Instead of a standard channel, we need a mechanism where if the transport task is slow, the encoder task overwrites the pending frame or drops it, rather than queuing up infinitely. We will use a channel size of 2, and explicitly handle `TrySendError::Full` by dropping.

- [ ] **Step 2: Enforce Coalescing for Input**
Limit the input channel to 16 events.

---

### Task 3: The First Torture Test

**Files:**
- Create: `core/tests/chaos_integration.rs`

- [ ] **Step 1: Write `test_coffee_shop_wifi`**
Setup a local `StreamingServer` and `StreamingClient`. Insert the `ChaosProxy` between them with 10% packet loss and 100ms jitter. Send a stream of input events and video frames. Assert that the session remains `Active` and input events are received within the SLA, even if video frames are dropped by the transport.
