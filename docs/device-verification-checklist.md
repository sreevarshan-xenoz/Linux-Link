# Device Verification Checklist

Everything in the Current Status log of `AGENTS.md` says "device behavior
unverified (no device)". This is the ordered battery to run once a real
phone (arm64, Android 8.0+/API 26, debug APK with the bridge `.so`) is
attached to a real desktop. Work top-to-bottom: later sections assume
earlier ones pass. Record failures as `FAIL: <symptom>` next to the box;
each item maps to the commit/feature noted so fixes land in the right
place.

## 0. Prerequisites

- [ ] Desktop: `cargo run -p linux-link-server` (or installed server) on the
      Hyprland machine; FFmpeg + PipeWire + xdg-desktop-portal present.
- [ ] Phone: `adb install -r android/app/build/outputs/apk/debug/app-debug.apk`
      (build it first: `cargo ndk` for the bridge `.so`, then `assembleDebug`).
- [ ] Both on the same Wi-Fi LAN; phone can reach desktop port 1716 (TCP)
      and the QUIC streaming port (default 50000-range per config).
- [ ] Grant the app POST_NOTIFICATIONS when prompted (connect screen).
- [ ] Desktop: user in `input` group (uinput + `/dev/input/event*` read for
      privacy mode) — `groups $USER` should show `input`.
- [ ] Note which items are Hyprland-specific (window picker, workspace HUD,
      monitor geometry) — retest on a plain session if that's a target.

## 1. Connect + pairing gate (Tier 1 #5, Tier-2 #11b)

- [ ] Enter desktop IP + streaming port + control port → "Connect" opens a session.
- [ ] First connection: Pairing sheet auto-opens (pairing_required default true).
- [ ] "Show PIN on desktop" → desktop pops a notify-send PIN → phone confirms "Paired ✓", button flips to "Paired ✓".
- [ ] Second connect to same host: no pairing prompt (persisted both sides).
- [ ] Manual flow: `linux-link pair` on desktop → type 6-digit PIN on phone → paired.
- [ ] Wrong/expired PIN → clear error, retry works.
- [ ] With an *unpaired* second phone: control features (clipboard, monitors) must stay locked out.
- [ ] QUIC gate (v2 + video): before pairing completes, video must not flow — desktop log shows
      "Streaming session rejected: device not paired" (or "Unpaired device … on v2 QUIC") and the
      phone's status chip goes Down; after pairing, video works with no app restart beyond Retry.
- [ ] QUIC gate over WAN (iroh): unpaired dial is rejected the same way (desktop log + no frames).

## 2. Session shell + video (Tier 1 #5, R2#2, R2#5)

- [ ] Video appears within ~1 s; stats HUD shows fps/bitrate/rtt/e2e/drops.
- [ ] FGS notification is present ("Streaming to <ip>"), survives home/swipe-away attempts; its Disconnect action ends the session.
- [ ] Screen-off for 1 min, wake → stream still live (wake lock + keepalive; plan #13).
- [ ] Drop phone far from AP / saturate link → frames stall, then recover; drops counter rises but no permanent freeze (gap-driven keyframe request, R2#5).
- [ ] Status chip: kill the server → "Down: <reason>" chip + Retry rebuilds after restarting the server.
- [ ] R4 B1 screencopy backend (desktop-observable): starting a stream on
      Hyprland must NOT raise the portal screen-share grant dialog; server log shows
      "Starting Wayland screencopy capture (no portal)". If it shows "Screencopy unavailable (…);
      using Wayland/PipeWire portal capture" instead, the reason is in the line — that's the
      fallback working, but note it as a finding. `LINUX_LINK_SCREENCOPY=0` forces the portal path.
- [ ] R4 B1 idle pacing + freshness: keep the desktop static → `src` fps drops to ≤10
      (damage-driven VFR); move a window → back to target fps within a frame or two, no tearing
      or upside-down frames (YInvert handling).
- [ ] R4 B1 multi-monitor: pick monitor N in the picker → log line "Screencopy capture: output at
      (x,y)" shows that monitor's wl_output origin and frames are its size.

## 3. Input paths (R2#4, Tier 1 #2)

- [ ] Direct-touch: tap = left click at the touched point (check `evtest` on desktop for BTN_LEFT, and MT finger down/up on the "Linux Link Virtual Touch" device — axis resolution may need tuning).
- [ ] Drag = finger-down motion; lift = left release.
- [ ] Trackpad mode: pointer moves without jumping to touch point; tap = click; two-finger = scroll.
- [ ] Mode toggle switches behavior live, no session restart.
- [ ] Keyboard: type letters/digits/modifiers via on-screen shortcuts + remote input — check against `evtest`: Super, Alt+Tab, Ctrl+Alt+Del, PrtSc, Esc, Super+1..9 work (ShortcutBar).
- [ ] holdKey/repeat (e.g. hold an arrow key) behaves.
- [ ] R4 D1 view-only: tap "View-only: off" on the session bar → label flips
      ("View-only: on", amber), desktop log shows "View-only mode changed" (enabled=true), and
      EVERY remote input goes dead on the desktop (taps, shortcuts, workspace chips) while video,
      StatsHud, clipboard sync and monitor/window pickers keep working. Toggle back → input restored
      without reconnect. Re-arm check: while view-only is ON, trigger a stream Retry / monitor switch
      (fresh server pipeline starts interactive) — the phone must re-send the latch once the stream
      is Up again; verify input stays blocked across that rebuild.

## 4. Zoom + display mapping (Tier 1 #6, R3#7)

- [ ] Pinch-zoom in direct-touch mode pans/clamps correctly; taps still land on the visible desktop point while zoomed.
- [ ] Trackpad mode: two-finger still scrolls remotely (no zoom capture).
- [ ] Letterbox: on a phone/desktop aspect mismatch, taps map through the letterbox offset (no systematic tap drift).

## 5. Window + monitor streaming (R3#7, Tier-2 #10)

- [ ] Window picker lists Hyprland windows with title/class/workspace/size + "focused" marker.
- [ ] Picking a window: video re-encodes at window size (encoder rebuild), crop tracks the window, taps map to desktop coords via the screen box.
- [ ] Moving the window mid-session: crop follows only after re-pick (known limitation — crop is static rect).
- [ ] "Whole desktop" clears the crop.
- [ ] R4 B2 (Hyprland): pick a window → server log shows "Streaming compositor-cropped window frames"; partly-occluded window streams correctly (occluder NOT in the video), and only the window's pixels are encoded.
- [ ] R4 B2: close the streamed window mid-session → stream keeps running on full-output frames with software crop (warn log "did not stage"; no session drop).
- [ ] R4 B2 (non-Hyprland wlroots, no export global): window pick still works via software crop exactly as pre-B2.
- [ ] Monitor picker lists monitors via xcap; selecting index N streams that monitor's region; reconnect persists the choice per host.
- [ ] Mid-session monitor switch tears down + rebuilds cleanly (no zombie session — bridge "already active" path).

## 6. Workspace HUD + battery (R3#8, Tier-2 #11a)

- [ ] Workspace chips appear under StatsHud; open/close/focus a window on desktop → HUD updates within ~4 s.
- [ ] Tap a chip ≤9 → Super+N injected → workspace switches.
- [ ] Battery chip shows desktop percentage + charging state; matches `upower`.

## 7. Clipboard + files (Tier 1 #4)

- [ ] Copy on phone → desktop clipboard updated within ~4 s; copy on desktop → phone receives.
- [ ] No echo loop (toggle sync off/on, paste both ways repeatedly).
- [ ] History sheet: 20 entries survive app restart; pick restores local + pushes.
- [ ] Share text to the app from any Android app → lands in desktop clipboard, toast "Sent to clipboard."
- [ ] Share a file (EXTRA_STREAM) → appears in desktop `~/Downloads` (server Share plugin pulls over the staged socket).
- [ ] Reboot phone → history + saved hosts survive.

## 8. Notifications + find-my-device (R3#11c, Tier-2 #11)

- [ ] `notify-send -a Test "Hi" "body"` on desktop → phone notification appears (channel "Desktop notifications").
- [ ] Inline reply from the shade → desktop `replies.log` records it, text on desktop clipboard, confirmation popup; originating notification disappears.
- [ ] "Ring PC" → desktop plays sound 30 s (pw-play/paplay path; silent no-op is FAIL here since desktop has audio).
- [ ] Desktop pushes findmydevice ring → phone alarm loops at max volume 30 s (phone in alarm-volume >0; check DoNotDisturb doesn't block USAGE_ALARM).

## 9. Privacy mode + lock (Tier-3 #15)

- [ ] "Privacy: on" → physical keyboard/mouse on desktop stop responding (`evtest`: grabs held), while phone input still flows.
- [ ] Leave session with privacy on → release happens (phone app exit); also verify 10-min TTL auto-release by force-killing the phone app mid-grab.
- [ ] "Lock PC" / session-notification "Lock desktop" → screen locks (loginctl path).
- [ ] Without `input` group: clean error, no crash.

## 10. Audio control (Tier-3 #16)

- [ ] Audio sheet opens with volume %, mute state, sink list (matches `wpctl status`).
- [ ] Slider → desktop volume changes on release; mute switch works; selecting a sink routes default output (verify with `wpctl inspect` + real playback).

## 11. WAN over iroh (R1)

- [ ] On same LAN: identity cached (logcat), status shows LAN.
- [ ] Phone on LTE (Wi-Fi off): dial from cached identity succeeds → badge shows "WAN · punching…" then settles to "WAN · direct" or "WAN · relayed — trying direct…", video + input + keyframe-on-gap all work through relays (R4 A1).
- [ ] Desktop reconnects (restart server) → identity re-announced within 30 s, phone re-dials.
- [ ] Hole punching through a real NAT (relay-free if possible): check `directAddrs` paths get used.
- [ ] After both a LAN and a WAN session: `linux-link sessions` shows one line per session with distinct `outcome=` (`lan_direct` vs `wan_punched`/`wan_relayed`), plausible `rtt_ms`/`kbps`, and `dev=` = the paired deviceId.
- [ ] Relayed → direct upgrade while streaming: badge flips to "WAN · direct" on its own (iroh keeps punching) and the bridge logs "upgraded from relay to direct path" (logcat). Relayed session must stay usable the whole time, not stall on the transition.
- [ ] Relayed session (R4 A3): within ~5 s of the badge reading "relayed", the desktop log shows "Relayed path: clamping encoder bitrate" at cap ≤ 2 Mbit/s, and picture is visibly softer than LAN/direct.
- [ ] Full-quality override (R4 A3): while relaying, the badge area offers "Full quality: off" — tap → log shows "Relay quality override changed enabled=true", bitrate climbs back to configured (`linux-link sessions` kbps over the next session line). Tap again to re-clamp; toggle survives a stream retry (re-arms).
- [ ] Clamp release on punch-through: start relayed (override off), wait for the direct upgrade → log shows "Direct path: restoring configured encoder bitrate" without touching anything.
- [ ] LAN session: the relay-guard never engages (no clamp lines in the log; `stats().relayed` is always false on quinn).

## 12. Roaming (Tier-3 #13 remainder)

- [ ] Mid-stream, toggle Wi-Fi off → phone falls to LTE → within a few seconds status chip shows connecting and a fresh WAN/LAN session comes up (reconnect-on-new-radio, not live migration).
- [ ] Wi-Fi↔LTE ping-pong with 3 s cooldown: flapping radio must not thrash a healthy stream.
- [ ] In PiP: network change must NOT tear the float session (pip guard).

## 13. PiP + multitask (Tier-3 #14, DeX)

- [ ] "PiP" button → chrome hidden, video-only float with correct aspect (matches decoded frame size after first SPS); input goes to system.
- [ ] Expand back → chrome returns, session uninterrupted.
- [ ] DeX/docked or split-screen: session is resizeable, letterboxing recomputes, taps still map correctly.

## 14. Blackout / pocket mode (Tier-3 #15 remainder)

- [ ] "Blackout" → black screen, "double-tap to unlock" hint, screen dimmed; stream continues (watch desktop from another device or check fps in logcat).
- [ ] Screenshot during blackout → blocked (FLAG_SECURE); Recents thumbnail blank/secure.
- [ ] Double-tap or system back unlocks; back never exits the session while blacked out.
- [ ] Entering PiP while blacked-out auto-clears the overlay.
- [ ] Pocket test: with overlay on, phone in pocket should not send spurious input (touch consumed by overlay).

## 15. Language / i18n (Tier-3 #17 remainder)

- [ ] Connect screen shows "Language" button on Android 13+ (absent on 12).
- [ ] Switch system per-app language to Español / தமிழ் → all screens, sheets, FGS notification text localize (telemetry units, key labels, window titles stay as-is by policy).
- [ ] Mid-session language change (if the OS applies live) → no crash; format strings (`%1$s`) render correctly in both locales.

## 16. Long-run / hygiene

- [ ] 1 h continuous session: memory stable (no decoder leak across resolution changes), fps steady, no watchdog kills.
- [ ] Force-stop app mid-stream: desktop auto-releases privacy within TTL, encoder sessions stop (no server-side zombie capture), siren/WoL relays unaffected.
- [ ] Airplane-mode mid-session then back: clean Down chip + retry, no ANR.

## Recording results

Update `AGENTS.md` Current Status (mark verified items / list failures) and
tick plan.md's Tier checkboxes with real device results — items marked
"device behavior unverified" are not done until this file says they are.
