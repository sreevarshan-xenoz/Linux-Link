package dev.linuxlink.android.bridge

import org.json.JSONObject
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Kotlin facade over the Rust JNI bridge (`liblinux_link_android_bridge.so`).
 *
 * Async Rust calls are bridged via `block_on`, so every method here blocks the
 * calling thread; invoke them from a background coroutine/dispatcher, never
 * the main thread. Fallible calls return a JSON envelope `{"ok": ...}` or
 * `{"error": "..."}` which is unwrapped into [Result].
 */
object RustCore {
    init {
        System.loadLibrary("linux_link_android_bridge")
    }

    private external fun nativeVersion(): String
    private external fun nativeInit()
    private external fun nativeSetDataDir(path: String)
    private external fun nativeIsDiscoveryActive(): Boolean
    private external fun nativeCheckTailscaleStatus(): String
    private external fun nativeGetPeers(): String
    private external fun nativeConnectToPeer(address: String, port: Int): String
    private external fun nativeSendClipboard(address: String, port: Int, content: String): String
    private external fun nativeGetClipboard(address: String, port: Int): String
    private external fun nativePollIncomingPackets(): String
    private external fun nativeSessionStatus(): String
    private external fun nativeIsStreamingActive(): Boolean
    private external fun nativeGetStreamingRtt(): Int
    private external fun nativeGetStreamingStats(): String
    private external fun nativeListTrustedPeers(): String
    private external fun nativeForgetTrustedPeer(label: String): String
    private external fun nativeStopV2(): String
    private external fun nativeStopStreaming(): String
    private external fun nativeConnectStreaming(address: String, port: Int, monitorIndex: Int): String
    private external fun nativeReconnectStreaming(
        address: String,
        port: Int,
        monitorIndex: Int,
        attempt: Int,
    ): String

    private external fun nativeResetReconnectBackoff()
    private external fun nativeConnectV2(address: String, port: Int): String
    private external fun nativeReceiveFrames(timeoutMs: Int): ByteArray
    private external fun nativeReceiveAudio(timeoutMs: Int): ByteArray
    private external fun nativeSendMouseEvent(
        address: String,
        port: Int,
        x: Float,
        y: Float,
        button: Int,
        isPressed: Boolean,
    ): String

    private external fun nativeSendKeyboardEvent(
        address: String,
        port: Int,
        keyCode: Int,
        text: String,
    ): String

    private external fun nativeSendGamepadEvent(axes: IntArray, buttons: Int): String
    private external fun nativeSendFile(address: String, port: Int, filePath: String): String
    private external fun nativeListRemoteFiles(address: String, port: Int, remotePath: String): String
    private external fun nativeGetMonitors(address: String, port: Int): String
    private external fun nativeGetMonitorCount(address: String, port: Int): String
    private external fun nativeSendPowerCommand(address: String, port: Int, action: String): String
    private external fun nativeExecuteRemoteCommand(
        address: String,
        port: Int,
        command: String,
    ): String

    private external fun nativeSendWol(macAddress: String, broadcastAddr: String): String

    val version: String
        get() = nativeVersion()

    /** Initialize logging and point the bridge at the app-private data dir. */
    fun start(dataDir: File) {
        nativeInit()
        nativeSetDataDir(dataDir.absolutePath)
    }

    // ---- Session / discovery ----

    val isDiscoveryActive: Boolean
        get() = nativeIsDiscoveryActive()

    fun checkTailscaleStatus(): Result<String> = envelope(nativeCheckTailscaleStatus())

    /** Raw JSON peer list: `[{name, dnsName, ips, ...}]`. */
    fun getPeers(): Result<String> = envelope(nativeGetPeers())

    fun connectToPeer(address: String, port: Int): Result<String> =
        envelope(nativeConnectToPeer(address, port))

    /** One-shot JSON snapshot of the session state machine. */
    fun sessionStatusJson(): String = nativeSessionStatus()

    /** Drain pending KDE Connect packets; each element is a JSON string. */
    fun pollIncomingPackets(): List<String> = parseStringArray(nativePollIncomingPackets())

    // ---- Clipboard ----

    fun sendClipboard(address: String, port: Int, content: String): Result<Unit> =
        envelope(nativeSendClipboard(address, port, content)).map { }

    fun getClipboard(address: String, port: Int): Result<String> =
        envelope(nativeGetClipboard(address, port))

    // ---- Trust store ----

    fun listTrustedPeers(): List<String> = parseStringArray(nativeListTrustedPeers())

    fun forgetTrustedPeer(label: String): Boolean =
        envelope(nativeForgetTrustedPeer(label)).getOrNull()?.toBooleanStrictOrNull() == true

    // ---- Streaming ----

    val isStreamingActive: Boolean
        get() = nativeIsStreamingActive()

    /** Last streaming RTT in microseconds. */
    val streamingRttUs: Int
        get() = nativeGetStreamingRtt()

    /** Parsed streaming stats snapshot including the live QUIC RTT. */
    fun streamingStats(): StreamingStats {
        val obj = JSONObject(nativeGetStreamingStats())
        return StreamingStats(
            fps = obj.optDouble("fps", 0.0),
            bitrateKbps = obj.optLong("bitrate_kbps", 0L),
            e2eLatencyMs = obj.optLong("e2e_latency_ms", 0L),
            frameDrops = obj.optLong("frame_drops", 0L),
            rttUs = nativeGetStreamingRtt().toLong(),
        )
    }

    data class StreamingStats(
        val fps: Double,
        val bitrateKbps: Long,
        val e2eLatencyMs: Long,
        val frameDrops: Long,
        val rttUs: Long,
    ) {
        val rttMs: Long get() = rttUs / 1000
    }

    /** `monitorIndex = -1` selects the server default. */
    fun connectStreaming(address: String, port: Int, monitorIndex: Int = -1): Result<Unit> =
        envelope(nativeConnectStreaming(address, port, monitorIndex)).map { }

    fun reconnectStreaming(address: String, port: Int, attempt: Int, monitorIndex: Int = -1): Result<Unit> =
        envelope(nativeReconnectStreaming(address, port, monitorIndex, attempt)).map { }

    fun resetReconnectBackoff() = nativeResetReconnectBackoff()

    fun connectV2(address: String, port: Int): Result<Unit> =
        envelope(nativeConnectV2(address, port)).map { }

    fun stopStreaming(): Result<Unit> = envelope(nativeStopStreaming()).map { }

    fun stopV2(): Result<Unit> = envelope(nativeStopV2()).map { }

    /**
     * Drain encoded H.264 frames, ready for MediaCodec.
     *
     * Decodes the bridge wire format (big-endian): `u32 count`, then per frame
     * `u32 len`, `u8 flags` (bit 0 = keyframe), `u64 sequence`, `len` NAL bytes.
     */
    fun receiveFrames(timeoutMs: Int = 50): List<EncodedFrame> {
        val buf = ByteBuffer.wrap(nativeReceiveFrames(timeoutMs)).order(ByteOrder.BIG_ENDIAN)
        if (buf.remaining() < 4) return emptyList()
        val count = buf.int
        val frames = ArrayList<EncodedFrame>(count.coerceAtMost(16))
        repeat(count) {
            if (buf.remaining() < 17) return frames
            val len = buf.int
            if (len < 0 || buf.remaining() < 13 + len) return frames
            val flags = buf.get()
            val sequence = buf.long
            val data = ByteArray(len)
            buf.get(data)
            frames += EncodedFrame(data, flags.toInt() and 1 != 0, sequence)
        }
        return frames
    }

    /** Drain Opus audio packets (raw payloads, typically 20 ms @ 48 kHz stereo). */
    fun receiveAudio(timeoutMs: Int = 50): List<ByteArray> {
        val buf = ByteBuffer.wrap(nativeReceiveAudio(timeoutMs)).order(ByteOrder.BIG_ENDIAN)
        if (buf.remaining() < 4) return emptyList()
        val count = buf.int
        val packets = ArrayList<ByteArray>(count.coerceAtMost(32))
        repeat(count) {
            if (buf.remaining() < 4) return packets
            val len = buf.int
            if (len < 0 || buf.remaining() < len) return packets
            val data = ByteArray(len)
            buf.get(data)
            packets += data
        }
        return packets
    }

    // ---- Input ----

    fun sendMouseEvent(
        address: String,
        port: Int,
        x: Float,
        y: Float,
        button: Int,
        isPressed: Boolean,
    ): Result<Unit> = envelope(nativeSendMouseEvent(address, port, x, y, button, isPressed)).map { }

    fun sendKeyboardEvent(address: String, port: Int, keyCode: Int, text: String): Result<Unit> =
        envelope(nativeSendKeyboardEvent(address, port, keyCode, text)).map { }

    /**
     * Tap a key (server sends press+release, one round trip). [keyCode] is an
     * `android.view.KeyEvent.KEYCODE_*`; the bridge maps it to evdev.
     */
    fun tapKey(address: String, port: Int, keyCode: Int): Result<Unit> =
        sendKeyboardEvent(address, port, keyCode, "")

    /** Hold a modifier down / release it (combo building on the server side). */
    fun holdKey(address: String, port: Int, keyCode: Int): Result<Unit> =
        sendKeyboardEvent(address, port, keyCode + MOD_PRESS_OFFSET, "")

    fun releaseKey(address: String, port: Int, keyCode: Int): Result<Unit> =
        sendKeyboardEvent(address, port, keyCode + MOD_RELEASE_OFFSET, "")

    /**
     * Send `modifiers + key` as a combo: press modifiers in order, tap the
     * key, release modifiers in reverse. Modifiers use `KEYCODE_*` constants.
     */
    fun hotkey(address: String, port: Int, key: Int, vararg modifiers: Int): Result<Unit> {
        for (mod in modifiers) {
            holdKey(address, port, mod).onFailure { return Result.failure(it) }
        }
        val tapped = tapKey(address, port, key)
        for (mod in modifiers.reversed()) {
            releaseKey(address, port, mod)
        }
        return tapped
    }

    /** IME/text input path (server injects as Unicode text). */
    fun sendText(address: String, port: Int, text: String): Result<Unit> =
        sendKeyboardEvent(address, port, 0, text)

    fun sendGamepadEvent(axes: IntArray, buttons: Int): Result<Unit> =
        envelope(nativeSendGamepadEvent(axes, buttons)).map { }

    // ---- Files / device control ----

    fun sendFile(address: String, port: Int, filePath: String): Result<Unit> =
        envelope(nativeSendFile(address, port, filePath)).map { }

    fun listRemoteFiles(address: String, port: Int, remotePath: String): Result<String> =
        envelope(nativeListRemoteFiles(address, port, remotePath))

    fun getMonitors(address: String, port: Int): Result<String> =
        envelope(nativeGetMonitors(address, port))

    fun getMonitorCount(address: String, port: Int): Result<String> =
        envelope(nativeGetMonitorCount(address, port))

    fun sendPowerCommand(address: String, port: Int, action: String): Result<Unit> =
        envelope(nativeSendPowerCommand(address, port, action)).map { }

    fun executeRemoteCommand(address: String, port: Int, command: String): Result<String> =
        envelope(nativeExecuteRemoteCommand(address, port, command))

    fun sendWol(macAddress: String, broadcastAddr: String): Result<Unit> =
        envelope(nativeSendWol(macAddress, broadcastAddr)).map { }

    // ---- internals ----

    // Modifier encoding understood by the bridge's send_keyboard_event:
    // keyCode + 50000 = modifier press, keyCode + 100000 = modifier release.
    private const val MOD_PRESS_OFFSET = 50_000
    private const val MOD_RELEASE_OFFSET = 100_000

    /** One Annex-B H.264 access unit plus its keyframe flag and sequence number. */
    data class EncodedFrame(
        val data: ByteArray,
        val isKeyframe: Boolean,
        val sequence: Long,
    ) {
        override fun equals(other: Any?): Boolean =
            this === other ||
                (other is EncodedFrame &&
                    isKeyframe == other.isKeyframe &&
                    sequence == other.sequence &&
                    data.contentEquals(other.data))

        override fun hashCode(): Int =
            (data.contentHashCode() * 31 + isKeyframe.hashCode()) * 31 + sequence.hashCode()
    }

    private fun envelope(json: String): Result<String> = runCatching {
        val obj = JSONObject(json)
        when {
            obj.has("error") -> error(obj.getString("error"))
            else -> obj.opt("ok")?.toString() ?: ""
        }
    }

    private fun parseStringArray(json: String): List<String> = runCatching {
        val arr = org.json.JSONArray(json)
        List(arr.length()) { arr.getString(it) }
    }.getOrDefault(emptyList())
}
