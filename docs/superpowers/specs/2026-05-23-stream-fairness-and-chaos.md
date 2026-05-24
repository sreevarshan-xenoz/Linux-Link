# Specification: Stream Fairness & Protocol Chaos

**Date:** 2026-05-23  
**Status:** Draft / Pending Approval  
**Focus:** Network resilience, queue management, and multiplexing fairness for Linux Link v2.0.

---

## 1. The Stream Fairness Contract

To prevent Head-of-Line (HOL) blocking and ensure the system degrades gracefully under congestion, all channels must adhere to strict queue bounds and drop policies.

### 1.1 Priority Hierarchy & Queue Policy

| Channel (Priority) | Capacity | Drop Strategy | Stale Rule | Explanation |
| :--- | :--- | :--- | :--- | :--- |
| **0 - Control** | Large (1024 msgs) | **Disconnect on Overflow** | Must deliver. | Heartbeats, handshakes. Infinite queues are DoS vectors. Saturated control queue = broken protocol. Disconnect immediately. |
| **1 - Input** | Tiny (16 events) | **Coalesce / Drop Oldest** | Preserve responsiveness. | Mouse motion MUST coalesce to the latest coordinates. Keystrokes/buttons preserve order but drop oldest if flooded. |
| **2 - Audio** | Small (32 frames) | **Drop Oldest** | Short glitch > Delay. | Audio must be continuous, but if buffered too deeply, it desyncs from video. Better to drop a frame and pop/crackle than delay by 1 second. |
| **3 - Video** | Minimal (2 frames) | **Latest-Frame-Wins** | Overwrite instantly. | Video must absorb network pain. If the transport cannot send the current frame before the encoder produces the next, the unsent frame is obliterated. |
| **4 - File/Util** | Bounded (1MB chunks) | **Backpressure** | Yield to higher prio. | File transfers are greedy. They must use QUIC flow control to back off instantly when Control or Media streams need bandwidth. |

### 1.2 Graceful Degradation Ladder
The system must react to congestion in a strict, deterministic hierarchy to preserve interactivity:
1. **Drop unsent Video frames** (Latest-Frame-Wins).
2. **Reduce Video Bitrate** (ABR Fast-Path trigger).
3. **Reduce Target FPS** (Signal capture loop to slow down).
4. **Reduce Capture Resolution** (Downscale before encode).
5. **Pause Video Entirely** (Stream 0 sends `VideoPaused` event).
6. **Preserve Control/Input at all costs.**

### 1.3 Backpressure & Congestion Protocol
- **Encoder Restraint:** If the Video queue is full (2 frames), the `StreamingServer` MUST NOT pull another frame from PipeWire. It must signal the capture loop to yield.
- **Bitrate Guillotine:** If `quinn` reports a congestion event (via `rtt_stats`), the Adaptive Bitrate controller must instantly execute a 40% reduction (Fast-Path), overriding any smoothing window.

---

## 2. Protocol Assertions (The Immune System)

To prevent "zombie" states and parallel brain bugs, the multiplexer must panic (in debug) or immediately disconnect (in release) if these invariants are violated:

1.  **Single Control Stream:** A `quinn::Connection` may only have ONE active Stream 0. A second attempt to open Stream 0 MUST terminate the connection with `LinuxLinkError::ProtocolError`.
2.  **No Zombie Resurrections:** A `SessionStatus::Stale` or `Failed` session MUST NOT process incoming media streams. It may only process heartbeats or reconnect handshakes.
3.  **Strict Typing:** A stream claiming to be `ChannelKind::Input` must only ever receive `InputPacket` binary layouts. Deserialization failure must immediately close that specific stream (not the whole connection).
4.  **No Reconnect Overlap:** The client `_attemptReconnect` lock must guarantee that `start_streaming` cannot be invoked while a previous `reconnectStreaming` future is still pending.

---

## 3. Protocol Torture Scenarios (The Crucible)

These named profiles define the exact network conditions we will inject using the `ChaosProxy` test harness. A failure in any of these scenarios blocks a release.

### 3.1 `coffee_shop_wifi`
- **Condition:** 10% uniform packet loss, 50-150ms jitter.
- **Pass Criteria:** Session remains `Active`. Video degrades visually (bitrate drop) but Input latency remains under 100ms. No stream resets.

### 3.2 `elevator_deadzone`
- **Condition:** 3-second absolute blackhole (0 packets passed up or down), followed by sudden 100% recovery.
- **Pass Criteria:** Session transitions to `Stale` -> `Reconnecting`. Resumes automatically without user intervention in under 5 seconds from recovery. Old video frames are obliterated; first frame upon resume is a fresh Keyframe.

### 3.3 `airport_packet_loss` (Asymmetric)
- **Condition:** 0% upstream loss (Input is fine), 50% downstream loss (Video/Audio destroyed).
- **Pass Criteria:** Server receives all mouse clicks accurately. Server detects downstream congestion and drops video bitrate to minimum. Control stream stays alive.

### 3.4 `reconnect_storm`
- **Condition:** Client attempts 10 simultaneous reconnections within 100ms.
- **Pass Criteria:** Server accepts ONLY the first valid handshake, explicitly rejecting or dropping the others. No "Parallel Brain" state is created. `ACTIVE_CLIENTS` shows exactly 1 connection.

### 3.5 `video_flood` (HOL Blocking & Starvation Test)
- **Condition:** Encoder goes rogue and attempts to push 4K 120FPS uncompressed data.
- **Pass Criteria:** 
  1. `Latest-Frame-Wins` policy engages.
  2. Video stream is violently throttled by `quinn` backpressure. 
  3. **Control and Input streams remain sub-50ms responsive.**
  4. **Runtime Health:** Tokio async runtime remains unblocked. Telemetry task continues to fire exactly every 1.0s without starvation.
  5. Telemetry reports massive "dropped frames" but zero "input delay".

---

## 4. Telemetry Constraints (Do No Harm)

To prevent observability-induced self-harm:
1.  **No Per-Packet Logs in Release:** `trace_packet_stats` MUST be disabled in release builds.
2.  **Rolling Aggregates:** Frame drops, queue depth, and RTT must be aggregated and emitted every 1.0 seconds, not instantly.
3.  **State Change Emphasized:** Log `SessionStatus` changes immediately. Throttle continuous metrics.
