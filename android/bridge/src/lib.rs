//! JNI entry points for the Linux Link Android client.
//!
//! Kotlin side: `dev.linuxlink.android.bridge.RustCore`. Every async API call
//! is bridged with `block_on` on a shared Tokio runtime and returns a JSON
//! envelope string: `{"ok": <value>}` or `{"error": "<message>"}`. Kotlin
//! polls; there is no callback channel yet.

mod api;
mod session;

pub(crate) use session::*;

use jni::JNIEnv;
use jni::objects::{JClass, JIntArray, JObject, JString, ReleaseMode};
use jni::sys::{jboolean, jbyteArray, jfloat, jint, jstring};
use std::sync::LazyLock;

/// Shared Tokio runtime used to `block_on` the async client API.
static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime")
});

/// Wrap a Rust result as the JSON envelope Kotlin expects.
fn envelope<T: serde::Serialize>(result: Result<T, String>) -> String {
    match result {
        Ok(v) => serde_json::json!({ "ok": v }).to_string(),
        Err(msg) => serde_json::json!({ "error": msg }).to_string(),
    }
}

/// Envelope for `Result<(), String>`.
fn envelope_unit(result: Result<(), String>) -> String {
    envelope(result.map(|()| serde_json::Value::Null))
}

fn to_jstring(env: &mut JNIEnv<'_>, json: String) -> jstring {
    match env.new_string(json) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn jstring_to_string(env: &mut JNIEnv<'_>, s: &JString) -> String {
    env.get_string(s)
        .map(|guard| guard.into())
        .unwrap_or_default()
}

/// Proves the Rust -> JNI -> Kotlin wiring works end to end.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeVersion(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    to_jstring(&mut env, api::version())
}

/// Initialize logging and backend state. Idempotent.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeInit(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) {
    api::init_app();
}

/// Set the persistent data directory (certs, trust store).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeSetDataDir(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    path: JString<'_>,
) {
    let path = jstring_to_string(&mut env, &path);
    if !path.is_empty() {
        api::set_data_dir(path);
    }
}

/// Whether LAN (mDNS) discovery is currently active.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeIsDiscoveryActive(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    api::is_discovery_active() as jboolean
}

/// Tailscale availability check: `{"ok": bool}` or `{"error": ...}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeCheckTailscaleStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let json = envelope(RUNTIME.block_on(api::check_tailscale_status()));
    to_jstring(&mut env, json)
}

/// Peer list from Tailscale: `{"ok": [PeerInfoDto, ...]}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeGetPeers(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let json = envelope(RUNTIME.block_on(api::get_peers()));
    to_jstring(&mut env, json)
}

/// Open the KDE Connect control TCP connection. Returns the new connection
/// state (Debug formatting) in the envelope.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeConnectToPeer(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let json = envelope(
        RUNTIME
            .block_on(api::connect_to_peer(address, port as u16))
            .map(|state| format!("{state:?}")),
    );
    to_jstring(&mut env, json)
}

/// Push clipboard content to the remote device.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeSendClipboard(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
    content: JString<'_>,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let content = jstring_to_string(&mut env, &content);
    let json = envelope_unit(RUNTIME.block_on(api::send_clipboard(address, port as u16, content)));
    to_jstring(&mut env, json)
}

/// Pull clipboard content from the remote device.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeGetClipboard(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let json = envelope(RUNTIME.block_on(api::get_clipboard(address, port as u16)));
    to_jstring(&mut env, json)
}

/// Drain pending KDE Connect packets as JSON strings.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativePollIncomingPackets(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let packets = RUNTIME.block_on(api::poll_incoming_packets());
    let json = serde_json::to_string(&packets).unwrap_or_else(|_| "[]".to_string());
    to_jstring(&mut env, json)
}

/// High-level session status as JSON (SessionStatus enum).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeSessionStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let status = api::get_session_status();
    let json = serde_json::to_string(&status).unwrap_or_else(|e| format!(r#"{{"error":"{e}"}}"#));
    to_jstring(&mut env, json)
}

/// Whether a streaming session is currently active.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeIsStreamingActive(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jboolean {
    api::is_streaming_active() as jboolean
}

/// Last measured streaming RTT in microseconds.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeGetStreamingRtt(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jint {
    let rtt_us = api::get_streaming_rtt();
    i32::try_from(rtt_us).unwrap_or(i32::MAX)
}

/// Streaming stats snapshot (fps, bitrate, ...) as JSON.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeGetStreamingStats(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let stats = api::get_streaming_stats();
    let json = serde_json::to_string(&stats).unwrap_or_else(|e| format!(r#"{{"error":"{e}"}}"#));
    to_jstring(&mut env, json)
}

/// Labels of currently trusted server certificates.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeListTrustedPeers(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let peers = api::list_trusted_peers();
    let json = serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string());
    to_jstring(&mut env, json)
}

/// Remove a trusted peer by label. Returns `{"ok": bool}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeForgetTrustedPeer(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    label: JString<'_>,
) -> jstring {
    let label = jstring_to_string(&mut env, &label);
    let json = envelope(Ok(api::forget_trusted_peer(label)));
    to_jstring(&mut env, json)
}

/// Stop the unified v2 connection.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeStopV2(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let json = envelope_unit(RUNTIME.block_on(api::stop_v2()));
    to_jstring(&mut env, json)
}

/// Stop the active streaming session.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeStopStreaming(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jstring {
    let json = envelope_unit(RUNTIME.block_on(api::stop_streaming()));
    to_jstring(&mut env, json)
}

/// Start a QUIC streaming session. `monitor_index` < 0 selects the default.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeConnectStreaming(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
    monitor_index: jint,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let monitor = if monitor_index < 0 {
        None
    } else {
        Some(monitor_index as u32)
    };
    let json =
        envelope_unit(RUNTIME.block_on(api::connect_streaming(address, port as u16, monitor)));
    to_jstring(&mut env, json)
}

/// Reconnect a dropped streaming session with backoff state.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeReconnectStreaming(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
    monitor_index: jint,
    attempt: jint,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let monitor = if monitor_index < 0 {
        None
    } else {
        Some(monitor_index as u32)
    };
    let json = envelope_unit(RUNTIME.block_on(api::reconnect_streaming(
        address,
        port as u16,
        monitor,
        attempt.max(0) as u32,
    )));
    to_jstring(&mut env, json)
}

/// Reset the reconnection backoff (after a successful manual connect).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeResetReconnectBackoff(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) {
    api::reset_reconnect_backoff();
}

/// Connect via the v2 multiplexed QUIC protocol.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeConnectV2(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let json = envelope_unit(RUNTIME.block_on(api::connect_v2(address, port as u16)));
    to_jstring(&mut env, json)
}

/// Drain up to 16 encoded H.264 frames as a binary blob for MediaCodec.
///
/// Wire format (all big-endian):
/// `u32 count`, then per frame `u32 data_len`, `u8 flags` (bit 0 = keyframe),
/// `u64 sequence`, `data_len` bytes of Annex-B NAL data.
/// Returns an empty byte array when no frames are available.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeReceiveFrames(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    timeout_ms: jint,
) -> jbyteArray {
    let frames = RUNTIME.block_on(api::receive_frames(timeout_ms.max(0) as u64));
    let total: usize = frames.iter().map(|f| 17 + f.data.len()).sum();
    let mut buf = Vec::with_capacity(4 + total);
    buf.extend_from_slice(&(frames.len() as u32).to_be_bytes());
    for frame in &frames {
        buf.extend_from_slice(&(frame.data.len() as u32).to_be_bytes());
        buf.push(frame.is_keyframe as u8);
        buf.extend_from_slice(&frame.sequence.to_be_bytes());
        buf.extend_from_slice(&frame.data);
    }
    match env.byte_array_from_slice(&buf) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Drain up to 32 Opus audio packets as a binary blob.
///
/// Wire format: `u32 count`, then per packet `u32 len`, `len` bytes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeReceiveAudio(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    timeout_ms: jint,
) -> jbyteArray {
    let packets = RUNTIME.block_on(api::receive_audio(timeout_ms.max(0) as u64));
    let total: usize = packets.iter().map(|p| 4 + p.len()).sum();
    let mut buf = Vec::with_capacity(4 + total);
    buf.extend_from_slice(&(packets.len() as u32).to_be_bytes());
    for packet in &packets {
        buf.extend_from_slice(&(packet.len() as u32).to_be_bytes());
        buf.extend_from_slice(packet);
    }
    match env.byte_array_from_slice(&buf) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Send a pointer event over the streaming (QUIC) or control channel.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeSendMouseEvent(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
    x: jfloat,
    y: jfloat,
    button: jint,
    is_pressed: jboolean,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let json = envelope_unit(RUNTIME.block_on(api::send_mouse_event(
        address,
        port as u16,
        x,
        y,
        button,
        is_pressed != 0,
    )));
    to_jstring(&mut env, json)
}

/// Send a normalized absolute pointer position (0..=65535 per axis).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeSendMouseAbs(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    x_norm: jint,
    y_norm: jint,
) -> jstring {
    let clamp = |v: jint| v.clamp(0, u16::MAX as i32) as u16;
    let json = envelope_unit(RUNTIME.block_on(api::send_mouse_abs(clamp(x_norm), clamp(y_norm))));
    to_jstring(&mut env, json)
}

/// Send a keyboard event. `key_code` is an Android KeyCode; the bridge maps
/// it to evdev internally. `text` carries the char for UTF-8 input paths.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeSendKeyboardEvent(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
    key_code: jint,
    text: JString<'_>,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let text = jstring_to_string(&mut env, &text);
    let json = envelope_unit(RUNTIME.block_on(api::send_keyboard_event(
        address,
        port as u16,
        key_code,
        text,
    )));
    to_jstring(&mut env, json)
}

/// Send a gamepad state update. `axes` is an IntArray of i16 axis values.
// JNI contracts require taking raw array handles; the JVM guarantees validity.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeSendGamepadEvent(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    axes: jni::sys::jintArray,
    buttons: jint,
) -> jstring {
    let axes = if axes.is_null() {
        Vec::new()
    } else {
        let axes_obj = JIntArray::from(unsafe { JObject::from_raw(axes) });
        match unsafe { env.get_array_elements(&axes_obj, ReleaseMode::CopyBack) } {
            Ok(iter) => iter.iter().map(|&v| v as i16).collect(),
            Err(_) => Vec::new(),
        }
    };
    let json =
        envelope_unit(RUNTIME.block_on(api::send_gamepad_event(axes, buttons.max(0) as u32)));
    to_jstring(&mut env, json)
}

/// Push a local file to the remote device.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeSendFile(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
    file_path: JString<'_>,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let file_path = jstring_to_string(&mut env, &file_path);
    let json = envelope_unit(RUNTIME.block_on(api::send_file(address, port as u16, file_path)));
    to_jstring(&mut env, json)
}

/// List a remote directory: `{"ok": [RemoteFileDto, ...]}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeListRemoteFiles(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
    remote_path: JString<'_>,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let remote_path = jstring_to_string(&mut env, &remote_path);
    let json =
        envelope(RUNTIME.block_on(api::list_remote_files(address, port as u16, remote_path)));
    to_jstring(&mut env, json)
}

/// Enumerate remote monitors: `{"ok": [MonitorInfoDto, ...]}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeGetMonitors(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let json = envelope(RUNTIME.block_on(api::get_monitors(address, port as u16)));
    to_jstring(&mut env, json)
}

/// Number of remote monitors.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeGetMonitorCount(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let json = envelope(RUNTIME.block_on(api::get_monitor_count(address, port as u16)));
    to_jstring(&mut env, json)
}

/// Send a power command (action strings defined by the server protocol).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeSendPowerCommand(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
    action: JString<'_>,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let action = jstring_to_string(&mut env, &action);
    let json =
        envelope_unit(RUNTIME.block_on(api::send_power_command(address, port as u16, action)));
    to_jstring(&mut env, json)
}

/// Execute a shell command remotely; `{"ok": "<stdout>"}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeExecuteRemoteCommand(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    address: JString<'_>,
    port: jint,
    command: JString<'_>,
) -> jstring {
    let address = jstring_to_string(&mut env, &address);
    let command = jstring_to_string(&mut env, &command);
    let json =
        envelope(RUNTIME.block_on(api::execute_remote_command(address, port as u16, command)));
    to_jstring(&mut env, json)
}

/// Send a Wake-on-LAN magic packet.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_linuxlink_android_bridge_RustCore_nativeSendWol(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    mac_address: JString<'_>,
    broadcast_addr: JString<'_>,
) -> jstring {
    let mac_address = jstring_to_string(&mut env, &mac_address);
    let broadcast_addr = jstring_to_string(&mut env, &broadcast_addr);
    let json = envelope_unit(api::send_wol(mac_address, broadcast_addr));
    to_jstring(&mut env, json)
}
