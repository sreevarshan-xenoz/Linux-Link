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
- **A3 · Relay-quality floor.** ✅ **Landed 2026-09-20** (device behavior
  unverified). A relay-guard task (spawns only on the iroh transport family)
  samples `stats().relayed` every 5 s and, while relayed, clamps the encoder
  to `min(configured, 2 Mbit/s)` through the existing bitrate watch channel —
  a mid-session punch-through restores the configured rate automatically.
  `InputPacket::FullQuality` (tag 10) latches a per-session user override;
  the phone shows a one-tap toggle under the "WAN · relaying" badge (rides
  A1's link-state reporting). Accept criteria met: relayed sessions reach the
  preset within the first sample, one-tap override, direct re-raise. E5's
  bitrate axis is covered; fps/resolution/codec presets remain open.

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
- **B2 · Window-granular screencopy.** ✅ **Landed 2026-09-21** (verified
  live on this box's Hyprland — focused window streamed as 918×1020
  compositor-cropped frames from a 1920×1080 output, clean round-trip back).
  Wired to the R3#7 crop path via `hyprland_toplevel_export_v1` (Hyprland's
  actual window-capture protocol — its frame events mirror zwlr's), with a
  u64 window address added to `InputPacket::WindowCrop` (17→25 bytes; 0 =
  legacy software crop, so non-Hyprland servers and every old code path
  behave identically). `window_mode` tells the encode task to skip its BGRA
  crop while compositor frames are live; staging failures/gone handles fall
  back to output frames mid-session without dropping the stream. Accept
  criterion met: window frames come from the compositor, occlusion-correct,
  no software crop applied.
- **B3 · Portal fallback ordering.** ✅ **Landed 2026-09-21** (ordering
  unit-verified; end-to-end backend selection needs a real session).
  `start_capture_auto`'s hard-coded Wayland/X11 branch became a data-driven
  attempt list: a pure `capture_attempts(backend, detected) ->
  Result<Vec<CaptureBackend>>` returns, for `Auto`, `[screencopy, portal]` on
  Wayland (screencopy is present only on wlroots/Hyprland; any pre-first-frame
  setup failure — including `LINUX_LINK_SCREENCOPY=0` — falls to the portal),
  `[x11]` on bare X11, and errors on headless. The runner clones the cheap
  `frame_tx`/`cancel`/`window_rx`/`window_mode` per attempt and returns the
  first backend that opens; only the screencopy attempt consumes the window
  watch/Arc (portal and X11 ignore them). A new `capture_backend` key in
  config.toml (`"auto"` default | `"screencopy"` | `"portal"` | `"x11"`) pins
  the pipeline to a single attempt, so a runtime failure surfaces instead of
  silently switching — the operator escape hatch when screencopy misbehaves.
  Explicit-but-impossible pairs are rejected at selection time (e.g.
  `screencopy` on non-Wayland); `x11` on Wayland is allowed with the
  XWayland-only-root caveat documented, `portal` on X11 is honoured as intent.
  Threaded through `StreamingServer::set_capture_backend` and applied at BOTH
  the LAN (`service.rs`) and WAN (`iroh_endpoint.rs`) construction sites,
  mirroring the existing `set_hevc_allowed` clone-per-connection pattern. 4
  tests (auto ordering per display server, explicit single-pin, impossible
  combos error, config TOML parse + default + unknown-rejects).

### Phase C — Encoder ladder & hardware paths (M–L) — *partly box-limited*
- **C1 · Capability negotiation at session start.** ✅ **Landed 2026-09-21**
  (device behavior unverified). Client announces a decodable-codec bitmask on
  a third pre-pipeline uni-stream `[0xFD, 0x00, caps]` (bit 0 = HEVC; absent
  = legacy H.264-only, so old clients are unaffected); Android reports
  HEVC-decoder presence through the connect/reconnect JNI exports via an
  instantiate-and-release `MediaCodec.createDecoderByType` probe (the
  codec-list `MediaCodecInfo.isDecoder` form C1 first shipped with was
  removed from API 37's android.jar). Server picks H.265 only when the client declares it **and** the
  operator allowed it (`allow_hevc` in config.toml, default off — HEVC encoder
  availability is the box's business); the negotiated codec reaches the
  encoder via the existing `StreamingConfig.codec` field. `H264Decoder.kt` is
  codec-parameterized: MediaCodec configure is deferred to the first keyframe
  and the MIME (`video/avc`/`video/hevc`) is sniffed from its Annex-B NAL
  header (VPS/SPS type + layer byte), so no extra server→client message is
  needed and the codec can never mismatch the actual bitstream. Accept:
  loopback wire round-trip test asserts caps+monitor+deviceId streams
  negotiate an H.265 session; forced-HEVC on a real device pending the
  device-checklist pass.
- **C2 · Runtime fallback discipline (RustDesk lesson).** ✅ **Landed
  2026-09-21** (device behavior unverified). Three layers. (1) Open ladder:
  `SidecarEncoder::verify_startup` feeds black probe frames and reads stdout
  over a 600 ms window — measured on this box, a broken-VAAPI FFmpeg child
  survives a pure exit-poll (the init failure surfaces only when it digests
  its first input frame), so output bytes are the liveness proof; a failed
  hardware rung makes `VideoEncoder::new` degrade to Software + H.264
  (`degrade_to_software`, in-process x264 first, sidecar last). Session
  startup here now *lands* on a working encoder — all 9 previously-failing
  `--ignored` real-encode tests pass through the ladder. (2) Encode-task
  supervisor (`streamer.rs`): sticky `encoder_preferred` config; 5
  consecutive encode Errs or a 2 s/30-frame no-output stall rebuilds the
  software rung once (IDR-first, like every construction); the bottom rung
  gets a 90-error budget, then the session ends cleanly. (3) Client:
  `H264Decoder.kt` re-sniffs MIME at every keyframe — the C1 "codec never
  changes mid-session" assumption is now false — swaps the MediaCodec
  instance on a H.265→H.264 downgrade, and `RemoteScreen` toasts "Desktop
  switched encoder — now H.264" (es/ta included). Honest gap: a *same-codec*
  hw→sw fallback is invisible to the phone (identical bitstream; server log
  is the signal — a status-plane push needs the v2 config channel). The
  original accept line (kill VAAPI mid-session → x264 within 2 s, HUD notes
  the switch) is device-observable; checks in
  docs/device-verification-checklist.md §2.
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
- **D2 · Desktop-side session consent & tray HUD.** ✅ **Landed 2026-09-21**
  (desktop behavior verifiable now; phone-side effect unverified — no
  device). Core: process-global live-session registry
  (`core/src/streaming/sessions.rs`) — `run_pipeline` registers after the
  pairing gate and an RAII handle deregisters on any exit path; `kick()`
  closes the QUIC connection so teardown rides the normal routes (capture,
  encoder children, mic relay all die through the pipeline's own cancel).
  Server: `live_sessions.rs` watcher (1 s tick) mirrors the registry to
  `live_sessions.json` (atomic tmp+rename) for `linux-link status`, raises a
  notify-send "a device is streaming this desktop" per new session (log
  fallback headless — same discipline as the PIN notification), and consumes
  a `kick` request file (`<target>\n<unix-secs>`, ignored when >60 s stale).
  CLI: `linux-link kick <device-id|prefix≥6|peer-IP|all>` (file handoff like
  `pair`'s PIN file — no admin socket to attack; refuses when no pid file
  exists). `status` gained a "Streaming sessions (live)" block. Honest gaps:
  no interactive confirm-on-arrival (RustDesk's dialog would need a GUI
  prompt + accept/reject channel — indicator + kick is the parity we
  promised here), and unannounced legacy clients are only kickable by peer
  IP. Unit tests: registry register/list/deregister, kick prefix rules +
  close-flag, kick-file TTL parsing, JSON↔formatter roundtrip.
- **D3 · One-time access PIN with scope.** ✅ **Landed 2026-09-21**
  (device behavior unverified). `linux-link pair --grant 15m` writes a
  third PIN-file line; pairing with that PIN stores a time-boxed TrustStore
  *grant* (per-device unix expiry) instead of permanent trust. Expiry is
  lazy — grants are filtered out at store load, which every gate
  (TCP/v2/QUIC) performs per check — so there is no scheduler to run or
  crash. Permanent trust can never be demoted by a grant; `unpair` removes
  both. Re-pairing a granted device with a normal PIN promotes it to
  permanent (existing semantics), expiring a grant just blocks *new*
  pairings/sessions — live sessions run to their own end (kick is D2).
- **D4 · Protocol versioning discipline.** ✅ **Landed 2026-09-21** (wire
  format unit-verified; needs a live desktop+phone pair to see a tagged byte
  stream). KDE Connect's doc is a self-disclaimed non-spec, so we version the
  packets **we** own and stay defensive about the rest:
  - **`llVersion` tag.** A new optional top-level `llVersion` field on
    `NetworkPacket`, auto-stamped by `to_wire()` (the single send choke point
    every server + bridge path goes through) on any packet whose type starts
    with `kdeconnect.linuxlink.`, from a new `LL_EXT_VERSION` constant — so no
    construction site has to remember it and KDE Connect's *native* types
    (`kdeconnect.pair`, `kdeconnect.clipboard`, …) stay untagged. It is
    deliberately separate from the KDE identity handshake `protocolVersion`;
    the extension version only bumps for a change to an existing field's
    *meaning* — purely additive fields are forward-compatible by design.
  - **Defensive parse (already true, now asserted).** `body` is an opaque
    `serde_json::Value` and `deny_unknown_fields` is used nowhere, so unknown
    fields — top-level or nested — are ignored; a regression test feeds a
    future-shaped packet (extra `llVersion`, unknown `futureTopLevel`) and
    confirms it still parses with known fields intact.
  - **Convention violation fixed.** `kdeconnect.notification-reply` (hyphen,
    which KDE's `[a-z_]+` type regex rejects) moved to
    `kdeconnect.linuxlink.notification_reply` — a conformant name *and* our own
    namespace, so it now rides the `llVersion` tag too. It was never a real KDE
    Connect type we interoperate with, and both ends ship together (bridge
    send + server plugin + capability string), so there is no compat shim.
  Tests: 4 core (`llVersion` stamped on linuxlink types, native types
  untagged, explicit version preserved, unknown-field tolerance) + 3 server
  (reply round-trip, capability declaration, app-name parse) under the new
  name. No new JNI exports (57); Kotlin side is a doc-comment update.

### Phase E — Unique features (the differentiators; our survey found none of
these anywhere — that's the moat)
- **E1 · "Pull window to phone" gesture.** Tap a window chip in the existing
  Workspace HUD → that window becomes the stream (HUD → crop pipeline stitch,
  both already shipped separately); swipe away → back to monitor view. A
  compositor-aware jump-to-context no surveyed project has.
- **E2 · Phone mic → desktop PipeWire source (reverse audio).** ✅ **Landed
  2026-09-21** (server relay live-verified on this box; phone behavior
  unverified). scrcpy does phone-audio-out; nobody does *mic-in* to the Linux
  box over our channel. New `InputPacket::Mic` (tag 11: `[11, enabled u8,
  len u32 LE, opus]`, strict decode) rides the existing client→server
  uni-stream — one stream per 20 ms Opus frame like every input packet — and
  the stream monitor intercepts it into a bounded (64, drop-on-full) channel
  **before** the view-only drop: mic is session media, not injected input.
  Server `mic_relay.rs` decodes with the new core `AudioDecoder` (opus
  feature) and feeds piped stdin to `pw-loopback -c 1 -m '[[MONO]]' -i
  'node.name=linux_link_mic … media.class=Audio/Source/Virtual'` — float32
  because PipeWire 1.6.8 ignores `audio.format` on stdin-fed nodes (probed
  live); explicit start/stop frames own the node's life, channel-close and
  kill_on_drop are the safety nets, spawn failures retry on a 5 s cooldown.
  Wired for LAN **and** WAN sessions. Phone side: `stream/MicCapture.kt` —
  AudioRecord 48 kHz mono → MediaCodec Opus encoder (32 kbit/s) →
  `RustCore.sendMicOpus`; Rust-side Opus deliberately avoided (the `opus`
  crate's CMake build does not cross-compile under cargo-ndk), so the bridge
  only forwards packets (3 new JNI exports). RECORD_AUDIO + Android 14
  `microphone` FGS type (graceful: only OR-ed into `startForeground` once
  the grant exists). Mic survives view-only; stop button, exit and session
  teardown all remove the desktop source.
- **E3 · E2E latency probe, compositor-true.** ✅ **Landed 2026-09-21**
  (unit-verified; HUD numbers need a device). The literal survey idea —
  server renders a timestamp quad, phone OCRs it off the decoded surface —
  needs eyes + on-device pixel reading; the landed probe gets the *same
  measurement* single-clock, no OCR, no clock sync: every video packet
  header already carries the frame's capture→send age measured on the
  desktop clock (the capture `Instant` survives sidecar + in-proc encoders,
  and on damage-driven backends that instant IS the compositor's copy
  moment), so sample = age + transport RTT/2, EWMA'd in
  `core/src/streaming/client.rs` and reset per session. `linux_link_core…
  client::e2e_estimate_ms()` now feeds the HUD's `e2e` field — replacing
  the old number that was literally just RTT (bridge `get_streaming_stats`
  proxied `rtt_ms`). Honest limits: excludes the phone's decode→panel
  present (unmeasurable from software) and client-side queueing after the
  packet read; the network leg is an RTT/2 estimate, not a timestamped
  one-way. Manual cross-check (film a second device's stopwatch / tap-test)
  lives in the device checklist. Tests: sample math + EWMA seed/smooth/reset.
- **E4 · Blackout-aware privacy shield on desktop.** We already EVIOCGRAB
  locally; add a compositor "shield" — Hyprland invisible-block for the
  grabbed inputs + an optional full-screen "Linux Link session active"
  overlay (layer-shell) so bystanders and the user's own keyboard know.
  Pairs with the blackout mode on the phone for a true pocket-remote story.
- **E5 · Adaptive profile presets per link state** (builds on A1–A3):
  "LAN 60fps", "WAN direct", "WAN relayed" presets adjusting
  resolution/fps/bitrate/codec in one shot, switchable from the HUD.
  *Partial (A3): the WAN-relayed bitrate floor + one-tap override landed;
  fps/resolution/codec preset axes and a preset picker still open.*
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
