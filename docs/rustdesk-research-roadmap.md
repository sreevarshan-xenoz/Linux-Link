# RustDesk & Friends — Research Findings and Roadmap (R4)

*Produced 2026-09-20 from an adversarially-verified deep-research run (23 sources,
25 claims verified, 21 confirmed, 4 refuted). Every claim below carries its
verification status; anything marked *(unverified)* was not established by the run.*

## 1. How RustDesk actually works

- **Session brokering, not direct connections.** Both sides dial *outward* to a
  rendezvous server (`hbbs`): the controlled side announces an ID + key, the
  controller asks the rendezvous server for that ID, and the two are introduced
  for a direct peer connection. If punching fails, a relay server (`hbbr`)
  carries the traffic instead. This is why RustDesk "just works" behind NATs
  with zero port-forwarding — VNC by contrast always needs a hole punched or
  an SSH tunnel. (3-0, primary vendor docs + `rustdesk-server` source)
- **Auth model:** ID + password (static, or one-time password), plus a
  confirmation dialog on the controlled desktop unless auto-accept is on.
  A public "ID server" is the join point for every client.
- **Codec ladder, not a single codec:** software VP8/VP9 (libvpx), software
  AV1 (libaom), plus H.264/H.265 through a hardware encoder crate (`hwcodec`),
  and it *falls back to VP9-software when hardware encoding fails at runtime*.
  The lesson is architectural: negotiation + a fallback ladder, not codec
  purity. (3-0, verified in `src/server/video_service.rs`)
- **Its transport is NOT QUIC** — custom TCP/UDP protocol over the ID server.
  Our QUIC/iroh choice is a different (and per §3, better-benchmarked) family.
- **Business model note:** the Pro edition sells self-hosted *server* license
  keys layered on the AGPL core — a viable path for us later; Pro-only client
  capabilities were *not researched*, so treat any RustDesk feature list as
  possibly Pro-gated (open question, §7).

## 2. License reality — what we may take from each project

| Project | License | What Linux Link may do |
|---|---|---|
| RustDesk | **AGPL-3.0** | Study/re-implement ideas, protocols, architecture. **No code lifting** without relicensing consequences. |
| Sunshine | **GPL-3.0** (plain GPL, not AGPL) | Same: ideas only. |
| scrcpy | **Apache-2.0** | Code and techniques may be reused directly (attribution + NOTICE). |
| IronRDP (Devolutions) | **MIT OR Apache-2.0** | Code reuse OK. Useful reference for RDP, but we are not an RDP product. |

4 claims, all 3-0 against primary LICENSE files. *(Caveat from the run:
engineering-level analysis, not legal advice — do a license review before
vendoring any Apache/MIT code, and confirm our own project license first.)*
The run **refuted** the popular claim that Apache-2.0's patent grant makes
scrcpy borrowing "patent-safe" in any strong sense (0-3) — don't lean on it.

## 3. The research validates our core bets — with two sobering numbers

- **QUIC was the right transport.** The only published RoQ-vs-WebRTC end-to-end
  study measured RTP-over-QUIC ~90 ms *better* than WebRTC (H.264, Wi-Fi 6/5G,
  XR remote rendering). Cite it as study-scoped; the louder "30%/60% better"
  framing of the same paper was refuted (0-3). → Do NOT rewrite anything toward
  WebRTC.
- **iroh's model is the right WAN architecture** and matches RustDesk's
  pattern with QUIC-native machinery: relay-coordinated simultaneous-open
  hole punching (same 4-tuple exchange), relays as encrypted last resort with
  continuous upgrade-to-direct attempts (DCUtR). We already ship this.
- **Sobering number 1:** production measurements of exactly this technique
  (IPFS/libp2p DCUtR, 4.4M attempts, 85k networks, IMC 2026) show ~70%±7
  punch success *after* rendezvous/prerequisites succeed — i.e. roughly half
  of connection attempts may end up relayed. **Relay must be a first-class,
  good-enough path, not an error state.**
- **Sobering number 2:** TCP and QUIC punching measured equivalent (~70%) —
  no traversal penalty for our transport choice, but also no magic: our WAN
  ceiling is the same physics RustDesk lives with.

## 4. Concrete things to take (re-implemented, never copied)

From **RustDesk** (ideas):
1. Session state visibility: users should always know *how* they are connected
   (direct vs relayed) and be able to act on it — our current "WAN link
   (iroh)" badge is the seed; it does not distinguish punched-direct from
   relayed.
2. One-time-password / temporary-access semantics for remote sessions.
3. The controlled side's consent model (confirm dialog, view-only vs full
   control, kill switch) — see unique features §5.
4. Codec *fallback ladder* discipline: runtime downgrade when an encoder fails,
   negotiated at session start from client-declared capabilities.

From **Sunshine** (ideas):
5. NVENC GPUs get pinned into high-power mode during a session (Adaptive
   P-State is documented to wreck low-latency NVENC; Sunshine ships this
   default-on). Cheap, server-side, hardware-gated.
6. Portal/PipeWire + hardware encode is production-viable (their matrix shows
   XDG portal ✅ with VAAPI/NVENC/Vulkan/software) → re-risk our parked
   R2#3 in-process VAAPI/NVENC work; the blocker is *this box's* VAAPI init,
   not the approach.
7. **wlroots `zwlr_screencopy` as a third capture backend on Hyprland** —
   direct DMABUF frames without the portal grant/session-per-request overhead
   (real portal pain on Hyprland is documented in Sunshine #4662). Hyprland
   implements it; Sway deliberately doesn't, so it's a Hyprland-first path
   alongside portal + X11, not a replacement.
8. `tune=zerolatency` for software x264 is confirmed state-of-the-art — we
   already do exactly this in `encoder_inproc.rs` (validation, not work).

From **scrcpy** (code-level OK, Apache-2.0):
9. Its input-injection UX semantics (SDK-side key event mapping, physical
   keyboard passthrough behavior) are the best-documented Android story; our
   evdev path can borrow the *design* freely, and small helpers literally,
   with attribution.
10. Its "dual clipboard / file push" flows mirror what we already shipped —
    no delta beyond polish.

## 5. Proposed roadmap (R4) — phases, effort, verifiable on this box unless noted

### Phase A — Connection telemetry & relay-first (S–M) — *no device needed for server half*
- **A1 · Link-path reporting.** ✅ **Landed 2026-09-20** (device behavior
  unverified): `ConnectionStats.relayed` (quinn = always direct; iroh = the
  selected path is a relay), surfaced through the bridge's 1 s stats poll as
  `link_state` ("lan" / "wan_direct" / "wan_relayed") in the stats JSON, and
  the `RemoteScreen` WAN badge now reads "WAN · direct" / "WAN · relayed —
  trying direct…" (es/ta strings included); relay↔direct transitions are
  logged once client-side. No new JNI exports.
- **A2 · Session telemetry log.** ✅ **Landed 2026-09-20** (log format
  verified by unit tests; field population pending real sessions):
  `core/src/streaming/session_telemetry.rs` — every `run_pipeline` execution
  is observed by a `SessionRecorder` (transport family + pairing-gate
  deviceId, relay flag sampled every 5 s from `Connection::stats()`, wire
  goodput counted at the transport task, mean RTT) and emits one tab-
  separated `k=v` line through a process-wide sink via an RAII
  `SessionGuard` (Drop-based, so `?`-early-exits are logged too). Outcomes:
  `lan_direct` / `wan_punched` / `wan_relayed` (plus `ever_relayed=true` for
  mid-session punch-through) / `rejected` / `failed`. The server registers a
  sink appending to `$XDG_STATE_HOME/linux-link/streaming_sessions.log`
  (1 MB rotation keeping the newest half) and `linux-link sessions
  [--count N]` prints the outcome tally, the relayed share and the tail.
  Clients (Android bridge) never register a sink → zero cost there; no new
  JNI exports. Accept: after mixed use, log lines distinguish the three
  outcomes. (Sizes our expectations against the §3 ~50/70% reality; honest
  instrumented numbers instead of folklore.)
- **A3 · Relay-quality floor.** When relayed, auto-drop to a conservative
  bitrate/fps preset (relay bandwidth is not ours) and surface a one-tap
  "quality mode" hint. Accept: relayed session starts at preset, user can
  override; direct upgrade re-raises it.

### Phase B — Hyprland-native capture (M) — *testable live on this box*
- **B1 · `zwlr_screencopy` backend.** ✅ **Landed 2026-09-20** (verified live
  on this box's Hyprland — real frame, no portal grant, multi-cycle idle
  loop). New third capture path `core/src/streaming/capture_screencopy.rs`
  (wayland-client + wayland-protocols-wlr behind `capture`; libwayshot
  BSD-2-Clause patterns, no libwayshot dependency): binds
  `zwlr_screencopy_manager_v1` ≥3, `copy_with_damage` with overlay cursor,
  persistent memfd backing + per-frame pool/buffer (the compositor destroys
  the buffer with the frame), ARGB shm repacked to the BGRA pipeline layout
  (YInvert row-flip, stride compaction). Damage-driven VFR + 10 fps idle
  back-off. Auto-selected ahead of the portal on any Wayland session with a
  5 s first-frame handshake; any setup failure (or `LINUX_LINK_SCREENCOPY=0`)
  falls back to the portal path unchanged. Monitor index resolved via
  wl_output geometry vs the xcap enumeration (same space as the picker).
  Remaining ideas from the original bullet (dmabuf zero-copy) deferred —
  shm copies are already the portal path's cost model.
- **B2 · Window-granular screencopy.** Hyprland's screencopy supports
  window-mode capture; wire it to the R3#7 crop path so a window pick
  becomes compositor-crop'd frames (no server-side BGRA crop) — cheaper and
  occlusion-correct. Accept: window stream of an overlapped window shows
  only the window, no software crop rects.
- **B3 · Portal fallback ordering.** Auto (screencopy on Hyprland/wlroots
  that implement it, portal elsewhere, X11 last) + config override.

### Phase C — Encoder ladder & hardware paths (M–L) — *partly box-limited*
- **C1 · Capability negotiation at session start.** Client sends decodable
  set (Android reports MediaCodec caps: H264 always, HEVC/AV1 per device);
  server picks H.264 today's default, HEVC/AV1 when both ends agree. Server:
  `InputPacket`-era config stream gains a codec field (versioned — see D4).
  Client: `H264Decoder.kt` becomes codec-parameterized (mime string + SPS
  handling). Accept: forced-HEVC session round-trips on a device that
  declares it; old clients unaffected (absent field = H.264).
- **C2 · Runtime fallback discipline (RustDesk lesson).** Encoder open
  failure or mid-session encoder stall → rebuild at H.264/software with a
  keyframe, notify client via config channel. Accept: kill VAAPI mid-session
  (test env) → stream continues on x264 within 2 s, HUD notes the switch.
- **C3 · NVENC power pin (idea #5),** gated to sessions with an NVIDIA
  encoder active; document the `nvidia-smi` calls, restore on session end.
- **C4 · Re-open R2#3** (in-process VAAPI/NVENC `AVHWDeviceContext`) on a
  machine where VAAPI initializes — this box can't (see AGENTS); Sunshine's
  matrix says the architecture is sound. Device + desktop gated.

### Phase D — RustDesk-class session UX, re-implemented (S–M each)
- **D1 · View-only & input-lock modes.** ✅ **Landed 2026-09-20** (device
  behavior unverified). New `InputPacket::ViewOnly` (tag 9, 1-byte bool)
  latches a per-session `AtomicBool` in the streaming server's input relay
  (`streamer.rs` monitor task): while set, *every* injectable packet
  (mouse/keyboard/gamepad/text) is dropped **server-side** — control-plane
  packets (keyframe, window crop, further toggles) and video are unaffected,
  so enforcement can't be defeated by a stale client queue. Phone toggle on
  the session bar (amber while on), re-armed automatically after any stream
  rebuild (new pipeline starts interactive). 53 JNI exports.
- **D2 · Desktop-side session consent & tray HUD.** Optional
  "phone is watching" indicator (waybar module doc / `notify-send` on start +
  a `linux-link status` line), and `linux-link kick <device>` to drop a
  session — parity with RustDesk's confirm dialog without a GUI daemon.
- **D3 · One-time access PIN with scope.** `linux-link pair --grant 15m`
  style: a time-boxed, auto-expiring TrustStore entry for one-off support
  sessions (PIN plumbing already exists; this is TTL + a `unpair --after`
  scheduler).
- **D4 · Protocol versioning discipline** (KDE Connect lesson: their
  protocol doc is explicitly *not a spec* and can change without notice).
  Tag our `kdeconnect.linuxlink.*` packets with a `llVersion` field, parse
  defensively (ignore unknown fields — mostly true today), and note the one
  found convention violation: `kdeconnect.notification-reply` uses a hyphen
  where their type regex says `[a-z_]+` — harmless for us, but rename before
  1.0 if we ever ship interop with real KDE Connect phones.

### Phase E — Unique features (the differentiators; our survey found none of
these anywhere — that's the moat)
- **E1 · "Pull window to phone" gesture.** Tap a window chip in the existing
  Workspace HUD → that window becomes the stream (HUD → crop pipeline stitch,
  both already shipped separately); swipe away → back to monitor view. A
  compositor-aware jump-to-context no surveyed project has.
- **E2 · Phone mic → desktop PipeWire source (reverse audio).** scrcpy does
  phone-audio-out; nobody does *mic-in* to the Linux box over our control
  channel. Stream 16k/48k Opus from `AudioRecord` up the existing uni-stream,
  server creates a PipeWire sink (pw-loopback) named "Linux Link Mic".
  Calls-on-PC-from-phone story. (S on the wire — audio path exists both
  directions in the pipeline; M on PipeWire sink plumbing.)
- **E3 · E2E latency probe, compositor-true.** Round-trip the existing e2e
  HUD number with a Hyprland-verified frame stamp: server renders a hidden
  timestamp quads via a transient overlay, phone reads it off the decoded
  surface — measures *display-to-touch-to-display*, not encode-to-decode.
  RustDesk/Sunshine quote encode stats; nobody measures the real loop. (M.)
- **E4 · Blackout-aware privacy shield on desktop.** We already EVIOCGRAB
  locally; add a compositor "shield" — Hyprland invisible-block for the
  grabbed inputs + an optional full-screen "Linux Link session active"
  overlay (layer-shell) so bystanders and the user's own keyboard know.
  Pairs with the blackout mode on the phone for a true pocket-remote story.
- **E5 · Adaptive profile presets per link state** (builds on A1–A3):
  "LAN 60fps", "WAN direct", "WAN relayed" presets adjusting
  resolution/fps/bitrate/codec in one shot, switchable from the HUD.
- **E6 · Foldable/tablet dual-pane** — stream on one half, native trackpad +
  shortcut dock on the other (we own both endpoints; RustDesk's tablet UI is
  a stretched phone layout). (M, device-gated polish.)

### Explicit non-goals (from the research)
- WebRTC stack (QUIC benchmarks at least as well; rewrites buy nothing).
- Copying RustDesk/Sunshine code (AGPL/GPL — ideas only).
- Software AV1 encode on the desktop (their ladder uses it *last*; our
  hardware-first + fallback ladder covers the same ground honestly).
- Public ID/relay server of our own before the telemetry (A2) says we need it
  — iroh's default relays already punch ~half the time.

## 6. Suggested execution order
A1 → A2 → B1 → D1 → A3/E5 → B2 → D3 → C1 → E2 → C2 → D2 → E3 → B3 → D4 →
E1 → C3 → (C4, E4, E6 when hardware allows). Rationale: telemetry and consent
features are cheap trust-builders and unblock honest codec/relay presets;
screencopy is the biggest measurable latency win testable on this box today;
codec ladder comes after negotiation groundwork.

## 7. Open questions the run could not settle
1. How much of RustDesk's UX (address book, permission model, QR pairing) is
   OSS vs Pro-only — determines how much is genuinely "borrowable as an idea
   from public code." *(unresearched)*
2. The real latency/quality delta of `zwlr_screencopy` vs portal on Hyprland —
   B1 is the experiment; expect grant-latency + damage-freshness wins,
   unmeasured. *(unverified)*
3. Whether the ~50% unconditional direct-success number holds for our user
   network mix (CGNAT carriers + corporate NATs) — A2 answers this with our
   own numbers over time.
4. KDE Connect schema stability across releases (their doc is at protocol
   version 8 and self-disclaimed) — D4's versioning is the hedge.

## 8. Source index (key claims)
- rustdesk.com/blog/rustdesk-vs-vnc · github.com/rustdesk/rustdesk (AGPL, codec matrix)
- github.com/rustdesk/rustdesk-server (hbbs/hbbr rendezvous+relay)
- docs.lizardbyte.dev Sunshine advanced_usage + master README (NVENC power, sw_tune, portal matrix, wlroots row) · Sunshine #4662 (Hyprland portal pain)
- github.com/Genymobile/scrcpy LICENSE (Apache-2.0) · github.com/Devolutions/IronRDP (MIT OR Apache-2.0)
- docs.iroh.computer/concepts/nat-traversal · libp2p DCUtR spec · ipfs/camp deep-dive #40
- arXiv:2505.22132 (RoQ vs WebRTC, ~90 ms) · arXiv:2604.12484 / IMC'26 (70%±7 punch success)
- github.com/KDE/kdeconnect-meta protocol.md (non-spec disclaimer, packet envelope, pairing semantics)
