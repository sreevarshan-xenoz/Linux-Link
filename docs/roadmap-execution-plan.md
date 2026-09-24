# Linux Link — roadmap execution plan

This is the order, the exit criteria and the gates for the 3000 items in
[roadmap-3000.md](roadmap-3000.md). It contains no feature list — if you want the *what*, read that file.
If you want to know *what to build next, in what order, and what proves it is finished*, read this one.

The organising idea is the one the audit forced: **this project cannot tell whether it is getting better.**
There are 282 Rust tests and zero Kotlin tests, zero percentile/histogram code anywhere in the tree, no
benchmark harness, and `main` has been red at `cargo fmt --check` on every push of the last six. Every
phase below exists to make a claim verifiable before it makes the claim louder.

## 0. Ground rules (these do not lapse)

- Never push. One conventional commit per verified logical change, scope included:
  `fix(core): …`, `feat(android): …`, `docs: …`.
- Docs a change touches (README.md, CONTRIBUTING.md, `docs/`) are updated **in the same commit**.
- AGENTS.md *Current Status* stays accurate and stays at milestone granularity, not function granularity.
- Any new visible string ships in all three locales at once: 161/161/161 en/es/ta, identical key sets.
- Rust gates, both profiles, because the bridge builds `core` with a different feature set:
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo clippy -p linux-link-core --no-default-features --features client -- -D warnings`
  - `cargo test --workspace`; `cargo test -p linux-link-core --features wan` for anything behind `wan`;
    `cargo test -p linux-link-core --features encode` for capture/encode work.
- Kotlin gates: `cd android && ./gradlew assembleDebug lintDebug --offline` at the 18-finding baseline, plus
  `cd android/bridge && cargo ndk -t arm64-v8a -o ../app/src/main/jniLibs build` when the bridge changed.
- Format only files your change touches. `main` carries pre-existing fmt/clippy debt; a wholesale reformat
  buries the diff and seizes the user's parallel edits.
- The working tree routinely carries the user's in-progress edits across `core`/`server`/`bridge`. Never
  revert, stash or reformat work that is not yours; stage files **by name**.
- A ticket from roadmap-3000 is done when its observable is observable: a named test, a number in the
  session record (2167), or a line in `docs/device-verification-checklist.md` that a human can pass or fail.
  "Compiles" is not a done-condition.
- Device-gated UI work is still built and linted on the host and shipped labelled *device-unverified*. Only
  genuinely absent host capability parks a ticket (§14).

## 1. Phase 0 — State truth

The first phase is the synchronisation itself, because a roadmap written against a wrong description of
the tree produces another wrong roadmap. Ids: docs only.

Exit criteria — all five landed 2026-09-24, so Phase 0 is closed and Phase 1 is the live phase:

1. ✅ `README.md` matches the binary: exactly ten `linux-link` verbs
   (`start|stop|status|sessions|list|watch|capabilities|connect|pair|unpair|kick`), install/update/rollback/
   uninstall belong to `scripts/install.sh`, and there is **no** `--config` flag — the server reads
   `$XDG_CONFIG_HOME/linux-link/config.toml`.
2. ✅ `docs/roadmap-2000.md` deleted (superseded docs get deleted, not archived), `docs/roadmap-3000.md` and
   this file committed, and no document links to a file that does not exist.
3. ✅ AGENTS.md *Current Status* states what the tree disagrees about today: CI red at HEAD on
   `cargo fmt --all -- --check`, and the release badge's "feature complete" was aspirational.
4. ✅ (2026-09-24) `core/src/capabilities.rs` is that source: it reads the negotiated
   protocol versions, the transport set, the capture-backend list **and** `Auto`'s order
   (by calling the same `capture_attempts` the capture pipeline calls) and the codec table
   from the constants the wire uses, and reports feature-gated sections as unavailable
   rather than empty. `linux-link capabilities` prints it, `--json` makes it scriptable,
   `--markdown` generates [`capabilities.md`](capabilities.md), and
   `server/tests/capabilities_doc.rs` fails when the committed doc stops matching the build.
   Duplication removed on the way: both ends now build their `IdentityPacketV2` from
   `v2::{V2_MIN_VERSION, V2_MAX_VERSION}` instead of their own `2`/`2`, the
   `linux-link-stream` ALPN exists once as `protocol::ALPN_V1_STREAM` (was four literals),
   and the mic relay's Opus rate/channels moved into `core::streaming::audio`.
5. ✅ (2026-09-24) The owed device verifications are §22 of `docs/device-verification-checklist.md`: the
   `90d92df` journal pass with its exact PASS conditions, the eight open §21 items, §20's two gaps, the
   cellular WAN run, and a list of claims that must *not* be tested because the feature is absent (no Opus
   player, fabricated drops field, dead ABR loss input, uncalled `listRemoteFiles`).

## 2. Phase 1 — Green main, then measurement

**Ids: 2231-2235, 2131-2230, the scaffolding in 2251-2350.** No feature work happens in this phase, and no
later phase may start before it exits — every subsequent exit criterion is phrased as a number, and there
is currently nowhere to put a number.

Work in this order:

1. **2231 — green `main`.** fmt clean at HEAD (measured 2026-09-24: 96 diff hunks over 22 files, 12 in
   `core` and 10 in `server`, plus a working tree where rustfmt aborts on an internal error at
   `server/src/v2_multiplexer.rs:102` — fix that construct first, since it hides every other diff), the
   7-error clippy baseline (`capture.rs`, `capture_x11.rs`, `streamer.rs`) paid down file by file, and
   tests passing on a clean checkout.
   **Done locally 2026-09-24** (2101/2102/2103/2110): fmt clean, `clippy --workspace --all-targets
   -- -D warnings` clean in the default and all four `core` feature profiles, `cargo test --workspace`
   279 passed / 0 failed / 13 ignored. Still open: a clean-checkout rerun of all three, and the pushed
   branch, which stays red until this is pushed — that needs the user.
   Measured on the way: the transport flood test never routed through the chaos proxy it configured, so
   the "sub-300 ms input under 10% loss" contract was asserted against a clean loopback. Routed for
   real, quinn stream priority gives 2.2-3.8 s average input latency (max 6.3 s) at 10% loss and
   delivers every packet — recorded against 146-149 / 2449, with the contract kept as an `#[ignore]`d
   test so the gap stays measurable.
2. **CI matrix, not one job.** Was: one `ubuntu-latest` job running fmt → clippy → release build → test.
   **Landed 2026-09-24** as four jobs — `rust` (fmt, workspace clippy, release build, tests), `profiles`
   (matrix over `client`, `client,wan`, `wan`, `encode`: each clippy profile, with the `wan`/`encode`
   test runs), `android` (bridge clippy on host, the arm64 `.so` via cargo-ndk, then `assembleDebug` +
   `lintDebug`), and `audit` with the `|| echo` removed so a dependency finding can fail the run.
   `release.yml` gained the same audit step *and* the apt dev packages it was missing — without them the
   release job could not link, which is why `v0.1.0` has no CI-built artifact. **Honest status: no job in
   this matrix has executed.** CI can only be green after a push (the user's call), and the Android job in
   particular is written against runner behaviour that has not been observed here, so expect the first run
   to need tuning. It is not "done" until it is green on a push.
3. **Percentiles.** `p50/p90/p99/max` for e2e latency, encode time, decode time, render time, and input
   round-trip (2141-2146), emitted into a per-session record (2167) and retained for comparison (2168).
   This is the highest-leverage hundred ids in the document: without a p99 there is no way to see a
   regression that hurts 5 % of frames, which is exactly the class of bug this project keeps shipping.
   **Landed 2026-09-24** (`5e442e9`, `b3deb18`, `d8b3750`, `7a1623e`, `57094da`, `dba5d9e`, `ff1b526`):
   `core::metrics::Samples` is a bounded reservoir (exact percentiles below capacity, Algorithm R above it,
   count/max always exact) and one session record now carries five tails. `rtt_*` and `enc_*` are the
   desktop's own readings; `dec_*`, `rnd_*` and `e2e_*` are measured on the device and shipped back — the
   client reports raw duration batches (`InputPacket::ClientSamples`, tag 14, plus `LinkFeedback` tag 13 for
   its view of the path) and the *server* folds them through the same `Samples` code, so every tail in one
   line is computed identically and is directly comparable. The phone's half is `H264Decoder.kt` pairing each
   MediaCodec output with the feed that produced it (sound only because the stream is B-frame-free) and
   dropping rather than guessing anything that cannot be paired. Absence is spelled as absence: an
   unmeasured key is omitted from the line and `null` in the JSON, so `key=0` always means measured zero.
   Proven host-side, no device involved: `cargo test -p linux-link-server --test session_record -- --ignored`
   drives a real capture→encode→send→receive session over loopback and asserts the emitted record holds all
   five tails plus `phone_rtt`/`phone_lost`. It caught that a session shorter than the server's 5 s path
   sampler emits no `rtt_*`, no link block and — because the client's readings hang off that same block — no
   `phone_*` either; that is the shape of a connect-and-drop, not a bug to fix here.
   **Open:** `rnd_*` is the rendered-frame *interval*, not panel latency, and `dec_*`/`rnd_*` on a real device
   are still owed (checklist §Transport), as is 2146's input round-trip tail — the record carries `rtt_*` for
   the connection, not a separate input→echo→input measurement.
4. **A pinned benchmark workload plus a committed baseline.** One clip, one desktop state, one link
   condition, run in CI where the hardware allows and skipped-with-reason where it does not; a regression
   is a p95 delta beyond a stated threshold failing the job (2195-2200, with the CI half in 2231-2250).
   **Landed 2026-09-24 for the encode half**: `core::streaming::bench` generates the clip (a pure function
   of frame index — static gradient plus a moving block, so the encoder cannot coast on zero-residual skip
   blocks), `linux-link bench --baseline bench/baselines` grades a run against a committed record and exits
   0/1/3 for pass/regression/not-comparable, and the CI `bench` job turns red only on a real tail move. Two
   baselines are committed from this box (`in-process` p50 7 ms, `in-process-vaapi` p50 4 ms at 720p/5 Mbit).
   **Honest scope:** "one clip" is now true; "one desktop state, one link condition" is not — that half
   needs a live client and a link impairor, which is an on-device run, not a CI step. And a hosted runner
   has no baseline of its own yet, so its first real outcome is `SKIP` naming its host until someone commits
   the artifact the job uploads.
5. **Transport exposure, not transport implementation.** Surface what quinn and iroh already know
   (2151-2170) instead of the old roadmap's plan to "implement" congestion control and path-MTU, which are
   library internals with no application surface.
   **Landed 2026-09-24 for the statistics that exist.** `ConnectionStats` now carries what the connection
   reports — cumulative lost packets/bytes, datagrams and bytes moved, and on quinn the congestion-event
   count, congestion window, discovered path MTU and black-hole count — and the session recorder turns
   that into a `LinkReport` in every record: peak window rather than last (a window that collapsed and is
   still recovering must not read as uncongested), the number of times the selected path's address changed
   (2155), and wall-clock seconds spent riding a relay (2157's "for how long"). The two halves of the old
   plan are resolved the way the libraries allow: path-MTU is already discovered by both stacks and is now
   reported (2151's "where exposed"), and the congestion controller is a `TransportConfig` field
   (quinn's default is CUBIC) — switching it is one line of configuration, not an implementation, and is
   deliberately not switched here because there is no measurement yet saying which tail it would move.
   iroh's connection-level statistics sum bytes across paths and drop the per-path values outright, and the
   per-path accessor is not re-exported, so those four fields are **absent** on a WAN record instead of
   zero — the omission is asserted by a test in each family.
   **Open, with the reason:** 2152 (per-channel stream backlog — nothing counts it today), 2153 (datagram
   queue state, gated on the datagram path in 2491 not existing), 2154's per-path split (one path is all
   either library exposes to us), 2156 (neither reports connection-ID rotation), 2158 (the direct-vs-relay
   delta is now computable from the records, but nothing computes it), 2159 (a failed session is still one
   bucket, not attributed to a layer), 2160 (no live `stats --json`; the counters are historical), 2162
   (the session record has no schema version, unlike the benchmark record, so a shape change is not yet
   detectable in retained history), and 2170 (the phone still cannot see any of this — step 3 built the
   client→server half of that reply, the device→desktop sample batch; 2170 needs the other direction, which
   does not exist yet).

Exit gate:

- `cargo fmt --all -- --check` and both clippy profiles green on a fresh clone of `main`.
- CI green across the matrix, `cargo audit` able to fail.
- One command that produces a session record containing at least p50/p95/p99 for latency, encode, decode.
  **Satisfied 2026-09-24** by `cargo test -p linux-link-server --test session_record -- --ignored --nocapture`:
  it runs a real capture→encode→send→receive session on this box and prints the record, which carries all
  five tails plus the link block. It is a live-capture test, so it is `#[ignore]`d rather than part of CI.
- A committed baseline record, and a CI check that fails if a re-run regresses past the stated threshold.
- `grep -rn "percentile\|p95\|histogram" core/src server/src` returns real code, not nothing.

## 3. Phase 2 — Kill the live defects (U 2051-2130)

Each item here is a wrong behaviour with a known location, which makes this the cheapest quality the
project can buy.

The four that matter most, in order:

- **2051/2052 — the HUD lies.** `frame_drops` is a literal `0` in `android/bridge/src/api.rs`, so the
  session screen asserts a healthy link it never measured. Make it real, or delete the field. Never keep a
  fabricated metric while a real one is pending.
  **Landed 2026-09-24**: it is a measurement now — the holes in the server's per-frame sequence numbers as
  the client's receive loop sees them, which is the only vantage that can know a frame never arrived no
  matter what dropped it (transport backlog trim, reset stream, dead connection). 2052's "delete it
  otherwise" is moot. The number can come back down when an out-of-order frame lands, and the checklist
  says so rather than leaving a tester to read that as a bug.
- **2053 — the ABR controller has no input.** `update_loss(_lost_packets)` in
  `core/src/streaming/bitrate.rs` ignores its argument, so packet loss never moves the bitrate and every
  "adaptive" claim in the README is about a no-op.
  **Landed 2026-09-24**: loss is a term in the live arbiter's ceiling chain now (`LossCeiling` sampled from
  the transport's cumulative counters each 2 s tick), and the README describes the controller that exists
  instead of one that never ran. Two honest residuals: the RTT half of that story was *also* dead
  (`with_adaptive_bitrate` has no callers, so `AdaptiveBitrate` never saw a connection) — removing it is a
  separate change — and the loss response itself is unit-tested only, since proving it needs a link that
  actually drops (checklist §11).
- **2054 — advertised audio that cannot play.** `receiveAudio` has no caller: the phone has no Opus
  playout path, so the desktop audio feature is a UI toggle over a dead wire. Either build 2791 or stop
  advertising the capability.
- **2057/2058 — input that degrades silently.** `KEYCODE_MAP` in `server/src/input_injector.rs:27` covers
  ~26 keys and unmapped codes fall through to `Key::Unicode`; modifiers are absent; the DirectTouch path
  sends move+release with no press. These are the reason "it feels wrong" reports exist at all.

Exit gate: every U id is closed or converted into a named bug with a repro; no reported number in the UI is
produced by anything other than a measurement; the dead-link watchdog's behaviour is asserted by an
automated test rather than a manual kick; the `90d92df` no-churn journal observation is recorded.

## 4. Phase 3 — One control plane, real message classes (Y 2431-2530)

The project currently runs two control planes: a KDE-Connect-style TCP v1 for plugin traffic and QUIC v2
for media. The bridge fix in `90d92df` stopped the reconnect storm by *sharing* a TCP connection — which is
a correct patch for the wrong architecture. Phase 3 retires the wrong architecture.

The normative rule, stated once and enforced in code: **reliability is a property of the message class, not
of the connection.** 2431 declares these classes as an enum; 2432-2450 give each one a policy, a send
budget, and a test.

| Class | Reliability | Ordering | Deadline | Today | Target |
| --- | --- | --- | --- | --- | --- |
| CONTROL | reliable | strict per connection | none — must never be dropped | TCP v1 stream | QUIC reliable stream, one per session |
| INPUT | reliable-ish, latency prioritised | per device, collapse intermediate moves | short: drop stale, never queue | TCP v1, no sequence numbers | reliable stream with seq + release-all on teardown (AA) |
| AUDIO | loss-tolerant | strict within a stream | hard (~100 ms) | QUIC, unmeasured | datagram or `use_datagrams` path with an age-out policy |
| VIDEO | freshness first | none across frames | hard: droppable | one unistream per frame, `use_datagrams` dead config | same, plus explicit partial-frame reset |
| FILES | reliable, resumable | within a file | none, must not starve others | TCP back-connection, 64 KB loop | chunked manifest over QUIC (AC 2851-2863) |
| TELEMETRY | lossy, aggregated | none | yes, discard | log lines + JSON mirror | aggregated in-process, batched out (V) |
| EVENTS | reliable but cancellable | per event | soft | in-memory queue, lost on restart | durable spool with cancel (AC 2920/2921) |

Work order: 2431-2450 (classes as code, budgets, starvation detector) → 2451 (a test that a bulk transfer
cannot add input latency) → 2496 (the written v1 → v2 migration plan, with an explicit "both planes live"
window and the D4 versioning discipline) → then, and only then, freeze or delete the TCP v1 plane.

Exit gate: one connection carries all seven classes with per-class policy visible in the session record;
`use_datagrams` is either used or deleted; the TCP plane is a documented compatibility shim with a stated
end-of-support version, not a second source of truth; a chaos test proves a saturated file transfer leaves
input p95 within a stated budget.

## 5. Phase 4 — Security, consent and auditability (X 2351-2430)

Not polish, and not a sweep: this phase has one dangerous thing to fix and then a shape to build.

- **2351 first.** `server/src/plugins/exec.rs:52-56` runs an arbitrary `sh -c` string. It is gated behind
  pairing (`service.rs:770`), so it is not a remote hole for a stranger — it is a *post-pairing scope
  problem*: any paired phone, or any stolen trust record, gets a shell. Remove `ExecPlugin` from the
  default registry or require per-request desktop confirmation, and gate it behind config. The old
  roadmap's 277-283 describe automation built on this path and **must not be built as written** until this
  lands.
- Then the shape: scoped pairing presets (2369-2370: view-only / control / files / exec-off), a versioned
  trust store (2360), a security event taxonomy and audit log (2401-2402), consent for every privileged
  capability (2351-2360), and the fingerprint surfaced on both ends (2932, which needs 2931's screen to exist
  before it can be honest).

Exit gate: no arbitrary command reachable without an explicit operator opt-in plus a per-request consent;
every privileged action produces an audit record; the trust store can be exported, inspected and revoked
from either end, tested by 2938.

## 6. Phase 5 — Media pipeline completeness (AB 2741-2850)

Ordered by what the user can hear and see, not by what is interesting to build:

1. **2791-2800, the client Opus player.** Nothing in the old G range, and nothing in echo cancellation
   (2806), is definable until the phone can play sound.
2. **ABR that reacts** (2821-2830) — using the loss input wired in Phase 2, with measured thresholds
   replacing the constants, a bandwidth reserve for audio and input (2827, needs 2448), and presets that
   actually change fps and resolution rather than only bitrate, which is what the shipped presets promise
   and do not deliver (2829).
3. **Live reconfiguration** (2746-2750): framerate and resolution as mid-session policy, plus content
   presets (2753) as the honest replacement for the fabricated 437-440.
4. **Quality explanation** (2831, from 2211) so the user knows the link changed instead of blaming the app.

Exit gate: audio audible end to end on a device; a loss-injection chaos run (2304-2306) shows the bitrate
moving within a bounded time-to-recover; the HUD's "why did quality drop" line names the cause; encode
quality benchmark (2756) runs in CI where VAAPI is present and skips with a reason where not.

## 7. Phase 6 — Input fidelity (AA 2651-2740)

Correctness before capability: sequence numbers, an ACK-or-fire-and-forget decision per class, release-all
on disconnect and error, a stuck-key watchdog, and **one shared keymap table** instead of a Kotlin map, a
~26-key server map, and a `KEYCODE_MAP` that silently degrades.

Depends on Phase 3's INPUT class and Phase 2's keycode fix. Exit gate: no input path can leave a key held
after a teardown (test), touch and pointer gestures coexist per 2485's arbitration, desktop control actions
(2584-2600) report whether the desktop actually did the thing rather than whether a key was typed into
nothing, and the per-compositor action matrix (2600) is generated by measurement.

## 8. Phase 7 — Capture, compositor and displays (Z 2531-2650)

`ext-image-copy-capture-v1` is a **capability-detected backend**, not the foundation: the tree already
ships `zwlr_screencopy` (output) and `hyprland_toplevel_export` (window) from R4 B1/B2/B3, and compositor
support for the newer protocol is uneven. Capability detection at runtime, fallback observable and logged,
never a hard dependency.

Order: per-compositor capability table generated at runtime (2531) → image-copy-capture behind it →
window/output policy fixes → **then** virtual displays (2601-2626), last in this phase and explicitly gated
on Phases 1-7 being stable, because a virtual output touches capture, input targeting, monitor selection,
hotplug recovery and power policy at once. On this box the only prototype path is
`hyprctl output create headless`, with known upstream problems (hyprwm/Hyprland#5415 resolution/refresh
control, #12690 black outputs), so the feature ships on a compositor allowlist with a documented
"compositor refused" fallback (2622) and an opt-in flag (2626). Nothing about it may be automatic.

Exit gate: 2531's table is code; a session on each supported compositor reports which backend it got and
why; a virtual output, where created, survives a service restart and a compositor restart, and its absence
is an explained refusal rather than a silent degrade.

## 9. Phase 8 — Files, clipboard and notifications (AC 2851-2930)

Starts with the protocol, because the old I range assumed one that does not exist: manifest, chunking,
offset resume, integrity, cancel, quota, filename policy, tree walk (2851-2863). Everything in the rest of
the block — browser UI, previews, image clipboard, per-app channels — is blocked on those thirteen.

Exit gate: a transfer resumed across a server restart reaches byte-exact completion and proves it in a
test; `listRemoteFiles` (currently dead code with zero call sites) has a working screen; the clipboard has
negotiated types with a conflict rule that is written down; notifications have per-app channels, grouping,
and a delivery receipt; and 2929's soak — 1000 mixed events over a lossy link — passes with nothing
silently dropped.

## 10. Phase 9 — Product surface (AD 2931-2980)

This phase is mostly *exposing* mechanisms that already exist: `list_trusted_peers`,
`forget_trusted_peer` and the computed certificate fingerprint have **no caller**, so device list, revoke
and "verify this host" are one missing screen (2931-2934), not five missing features. Same for the CLI: the
server already performs uinput-first selection, `renderD*` enumeration and a throwaway NVENC encode at
runtime, and no command surfaces any of it (2959 `doctor`).

Exit gate: a user can answer, from either end, "who is trusted, what can they do, when were they last
here, and how do I revoke them"; `linux-link --json` is parseable by scripts; `doctor` reports the real
state of every runtime check the server already makes; and the strings/locale/a11y gates (2980) run in CI
rather than living in discipline.

## 11. Phase 10 — Ecosystem (AE 2981-3000)

Packaging truth and stated deferrals: verifiable AUR checksums instead of `SKIP`, signed release artifacts
with a documented verification step, a supported-distribution matrix written from test results, a threat
model and a privacy data statement. The deferrals (2995-3000) are recorded as ids precisely so they stop
being backlog that looks ready.

## 12. The measurement loop (normative, not a slogan)

`benchmark → telemetry → regression detection → chaos → recovery → release gate`

| Step | Artifact | How it runs | Ids |
| --- | --- | --- | --- |
| Benchmark | pinned clip + desktop state, committed baseline record | `linux-link benchmark` (2963), CI job | 2195-2200, 2963 |
| Telemetry | per-session record with percentiles | emitted at session end, mirrored to `live_sessions.json` | 2141-2170, 2167 |
| Regression detection | p95/p99 delta beyond threshold fails CI | compare against the committed baseline | 2168, 2196, 2221 |
| Chaos | bandwidth cliff, 40 % loss + 200 ms jitter, compositor death, PipeWire restart, Android lifecycle kill | named presets, bounded time-to-recover asserted | 2304-2312 |
| Recovery | reconnect → picture metric, first-frame time, no orphaned state | each chaos preset ends in a recovery assertion | 2835, 2836, 1801-1900 |
| Release gate | `scripts/release-gate.sh`, the same list for CI and humans | blocks `release.yml` | 2341-2350 |

The rule that makes the loop real: **a claim in README or AGENTS.md must name the artifact that measures
it.** If there is no artifact, the claim moves to "unverified" or goes away. That is how `frame_drops: 0`,
"adaptive bitrate" and "desktop audio" all survived review for as long as they did.

## 13. Do-not-build register

Deferred **with an unlock condition**, so deferral is a decision and not a vibe:

| Item | Blocked until | Ids |
| --- | --- | --- |
| AV1 | a target device with AV1 **decode** exists | 2995, 2838-2850 |
| Virtual display / phone-as-monitor | Phases 1-7 exit | 2601-2650, K |
| Plugin marketplace | a stable public ABI + capability negotiation | 2997 |
| Web client | message classes exist as code (Phase 3) | 2998 |
| AI features | fundamentals; no measured need | 2999 |
| Macro/automation epic | session records (2939) + input delivery semantics (AA) | 3000, L |
| Anything extending the "transfer protocol" | 2851-2863 actually designed | old 801-816 |
| Exec-based automation | 2351 landed | old 277-283 |
| Per-section "tests/soak/release gate" trios | deleted as dups of T | 898-900, 998-1000, 1095-1100 |

## 14. Hardware- and device-gated register

These are parked because the capability is physically absent here, not because the work is hard:

- **In-process NVENC** — driver 580.178.04 predates FFmpeg 9's NVENC API-13 requirement. NVENC stays on
  the verified sidecar; any NVENC-specific work is untestable on this box.
- **E6 foldable/tablet dual-pane** — code shipped compile/lint-clean, no foldable attached.
- **AV1 decode** — no target device.
- **iroh cellular WAN** — the phone's cellular was OUT_OF_SERVICE; the tailnet path is device-verified.
- **120 Hz+ pacing and multi-monitor high-DPI mixes** — this desktop is a single 1920x1080 panel @1.25.

Everything else that is merely *unverified on a device* ships: build and lint it on the host, label it
device-unverified, and add the checklist line. Do not park UI work because a phone is not plugged in.

## 15. Device obligations owed right now

1. `90d92df` — confirm in the server journal that the phone holds **one** control connection with no
   per-query churn, and record the baseline reconnect rate.
2. §21 of `docs/device-verification-checklist.md`: Material You on/off, edge-to-edge, the pairing sheet,
   Home empty state, the siren silence dialog, clipboard Clear confirm, the haptics matrix.
3. Task #2: iroh WAN over real cellular.
4. Phase 5's audio player cannot be declared done without a human saying "I heard it".

## 16. Picking the next ticket

Take the lowest-numbered **unblocked** ticket in the current phase. Blocked means a dependency id in the
ticket's own text is not done. When a phase's exit gate is met, commit the docs update that says so *in
the same commit as the last ticket*, then move to the next phase — do not start Phase N+1 while Phase N's
gate is unmet, and do not interleave: the reason this project grew two control planes, a fabricated HUD
metric, and a dead `listRemoteFiles` is that each was started while an earlier one was unfinished.

Cross-phase hard edges worth respecting:

- Phase 1 gates everything after it: no measurement, no exit criteria.
- Phase 3's INPUT class gates Phase 6's delivery semantics.
- Phase 2's loss input (2053) gates Phase 5's ABR work — satisfied 2026-09-24.
- Phase 4's exec scoping gates any automation or productivity item.
- Phase 8's 2851-2863 gates every file-transfer item in the old I range and Phase 3's FILES class.
- Phase 9's 2931-2934 gates Phase 4's fingerprint UX being testable end to end.

## 17. Where the old roadmap's build order went

The previous file's Stages 0-7 and its "current high-leverage priorities" survive here, re-sorted by the
audit's findings: Stage 0 (state truth) → Phase 0; Stage 1 (transport correctness) → Phases 1 and 3;
Stage 2 (media pipeline, including "avoid premature AV1") → Phase 5; Stage 3 (input + desktop) → Phases 6
and 7; Stage 4 (virtual display) → end of Phase 7, gated; Stage 5 (productivity platform) → deferred, 3000;
Stage 6 (ecosystem) → Phases 9 and 10; Stage 7 (hardening) → not a stage, the loop in §12 plus the chaos
ids in 2304-2312. Its architectural principles are adopted unchanged, and the one that mattered most is
the first line of Phase 3.
