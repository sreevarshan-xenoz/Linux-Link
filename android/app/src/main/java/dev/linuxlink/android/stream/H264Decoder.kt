package dev.linuxlink.android.stream

import android.media.MediaCodec
import android.media.MediaFormat
import android.os.Build
import android.view.Surface
import dev.linuxlink.android.bridge.RustCore
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Low-latency H.264/H.265 decoder that drains encoded access units from the
 * Rust bridge ([RustCore.receiveFrames]) and renders them straight to a
 * [Surface].
 *
 * Runs on a dedicated thread ([start] blocks); stop it by clearing [running]
 * and joining via [RustCore.stopStreaming] on the caller side. The stream is
 * Annex-B NAL units with in-band SPS/PPS (the encoder keyframes carry them),
 * so buffers are fed to MediaCodec as-is; the decoder signals the real format
 * on the first output buffer.
 *
 * R4 C1: the codec is not known at start — the server only upgrades to
 * HEVC when both ends negotiate it — so configuration is deferred to the
 * first keyframe, whose NAL header is sniffed for `video/avc` vs
 * `video/hevc` (`sniffMime`). Frames before the first IDR are dropped (the
 * server always starts a pipeline with an IDR, so this is a few ms at most).
 *
 * [width]/[height] are only the initial guess — window-crop rebuilds the
 * server encoder at the window's resolution mid-session, so when
 * INFO_OUTPUT_FORMAT_CHANGED reports different dimensions the codec is
 * reconfigured and the cached keyframe re-seeds it (the server always emits
 * an IDR as the first packet after a rebuild). The new size is announced via
 * [onVideoSize] so the UI can re-layout.
 *
 * R4 C2: the codec CAN change mid-session — the server's encoder-fallback
 * ladder degrades to software H.264 when a hardware encoder dies — so every
 * keyframe is re-sniffed; on a MIME change the MediaCodec instance is swapped
 * and the fresh keyframe re-seeds it, with [onCodec] notifying the UI.
 */
class H264Decoder(
    private val surface: Surface,
    width: Int,
    height: Int,
    private val onVideoSize: ((Int, Int) -> Unit)? = null,
    private val onCodec: ((String) -> Unit)? = null,
) {
    val running = AtomicBoolean(false)

    private var codec: MediaCodec? = null
    private var configW = width
    private var configH = height
    private var mime = MIME_AVC

    /** Latest keyframe bytes, kept for reconfigure re-seeding. */
    private var lastKeyframe: ByteArray? = null

    /**
     * Configure MediaCodec for real-time, minimum-latency decode.
     *
     * - `KEY_LOW_LATENCY` (API 30+) drops reordering/buffering delay.
     * - `KEY_PRIORITY` real-time requests the fastest scheduling.
     * B-frame-free encoder output (R2#1) is what actually keeps `LOW_LATENCY`
     * honored end to end.
     */
    private fun buildFormat(
        mime: String,
        width: Int,
        height: Int,
    ): MediaFormat {
        val format = MediaFormat.createVideoFormat(mime, width, height)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            format.setInteger(MediaFormat.KEY_LOW_LATENCY, 1)
        }
        // 0 = realtime priority class (highest urgency for the codec scheduler).
        format.setInteger(MediaFormat.KEY_PRIORITY, 0)
        format.setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, MAX_INPUT_SIZE)
        return format
    }

    /**
     * Blocking decode loop. Waits for the first keyframe to learn the codec,
     * configures MediaCodec, then repeatedly pulls a batch of frames and
     * feeds them, rendering every decoded output buffer to the surface
     * immediately.
     */
    fun start() {
        running.set(true)
        var mediaCodec: MediaCodec? = null
        try {
            val bufferInfo = MediaCodec.BufferInfo()
            while (running.get()) {
                val frames = RustCore.receiveFrames(timeoutMs = POLL_TIMEOUT_MS)
                if (frames.isEmpty()) continue
                for (frame in frames) {
                    if (!running.get()) break
                    if (mediaCodec == null) {
                        // Annex-B access-unit sniffing needs a keyframe header.
                        if (!frame.isKeyframe) continue
                        mime = sniffMime(frame.data)
                        mediaCodec = openCodec(mime)
                    } else if (frame.isKeyframe) {
                        // R4 C2: the server's fallback ladder can rebuild
                        // mid-session on a different codec (HEVC → H.264).
                        // Keyframes are the only safe place to notice —
                        // re-sniff and swap if the header disagrees.
                        val sniffed = sniffMime(frame.data)
                        if (sniffed != mime) {
                            val replacement = runCatching { openCodec(sniffed) }.getOrNull()
                            if (replacement != null) {
                                runCatching { mediaCodec.stop() }
                                runCatching { mediaCodec.release() }
                                mediaCodec = replacement
                                mime = sniffed
                                onCodec?.invoke(codecLabel(sniffed))
                            }
                        }
                    }
                    feed(mediaCodec, bufferInfo, frame.data, frame.isKeyframe)
                }
            }
        } finally {
            running.set(false)
            mediaCodec?.let { opened ->
                runCatching { opened.stop() }
                runCatching { opened.release() }
            }
            codec = null
        }
    }

    /** Create + configure + start a decoder instance for [mime] at the
     * current known size. */
    private fun openCodec(mime: String): MediaCodec =
        MediaCodec.createDecoderByType(mime).also {
            it.configure(buildFormat(mime, configW, configH), surface, null, 0)
            it.start()
            codec = it
        }

    fun stop() {
        running.set(false)
    }

    private fun feed(
        codec: MediaCodec,
        info: MediaCodec.BufferInfo,
        data: ByteArray,
        isKeyframe: Boolean,
    ) {
        if (isKeyframe) lastKeyframe = data.copyOf()
        val inIndex = codec.dequeueInputBuffer(INPUT_TIMEOUT_US)
        if (inIndex < 0) return
        val inputBuffer: ByteBuffer = codec.getInputBuffer(inIndex) ?: run {
            codec.queueInputBuffer(inIndex, 0, 0, 0, 0)
            return
        }
        inputBuffer.clear()
        inputBuffer.put(data)
        var flags = 0
        if (isKeyframe) flags = flags or MediaCodec.BUFFER_FLAG_KEY_FRAME
        codec.queueInputBuffer(inIndex, 0, data.size, System.nanoTime() / 1000, flags)

        drain(codec, info)
    }

    private fun drain(
        codec: MediaCodec,
        info: MediaCodec.BufferInfo,
    ) {
        var outIndex = codec.dequeueOutputBuffer(info, 0)
        while (outIndex >= 0) {
            // Render to the surface as soon as a frame is available.
            codec.releaseOutputBuffer(outIndex, true)
            outIndex = codec.dequeueOutputBuffer(info, 0)
        }
        if (outIndex == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED && maybeReconfigure(codec)) {
            return // reconfigure re-fed the stream; resume draining next frame
        }
    }

    /**
     * Reconfigure the codec when the signaled format size differs from what
     * it was configured with. Returns true if a reconfigure happened (the
     * caller must not consume output from the old run).
     */
    private fun maybeReconfigure(codec: MediaCodec): Boolean {
        val format = codec.outputFormat
        val w = format.getInteger(MediaFormat.KEY_WIDTH)
        val h = format.getInteger(MediaFormat.KEY_HEIGHT)
        if (w <= 0 || h <= 0 || (w == configW && h == configH)) return false
        configW = w
        configH = h
        runCatching {
            codec.stop()
            codec.configure(buildFormat(mime, w, h), surface, null, 0)
            codec.start()
        }.onFailure { return true }
        onVideoSize?.invoke(w, h)
        // Re-seed: the decoder needs an IDR to start the new run.
        lastKeyframe?.let { seed ->
            runCatching {
                val inIndex = codec.dequeueInputBuffer(INPUT_TIMEOUT_US)
                if (inIndex >= 0) {
                    codec.getInputBuffer(inIndex)?.let { buf ->
                        buf.clear()
                        buf.put(seed)
                    }
                    codec.queueInputBuffer(
                        inIndex,
                        0,
                        seed.size,
                        System.nanoTime() / 1000,
                        MediaCodec.BUFFER_FLAG_KEY_FRAME,
                    )
                }
            }
        }
        return true
    }

    companion object {
        private const val MIME_AVC = "video/avc"
        private const val MIME_HEVC = "video/hevc"
        private const val MAX_INPUT_SIZE = 4 * 1024 * 1024
        private const val POLL_TIMEOUT_MS = 50
        private const val INPUT_TIMEOUT_US = 10_000L

        /**
         * R4 C1: decide the codec from the first NAL header of an Annex-B
         * keyframe access unit. Our encoders start H.264 keyframes with SPS
         * (nal_unit_type 7 → first byte 0x67) and HEVC keyframes with VPS/SPS
         * (nal_unit_type 32/33 in bits 1..6 → 0x40/0x42, followed by the
         * layer/temporal byte 0x01). Anything unrecognized stays H.264 —
         * the negotiated default.
         */
        fun sniffMime(data: ByteArray): String {
            var i = 0
            while (i < data.size && data[i].toInt() == 0) i++
            // Skip the start-code 0x01 after the zero run (3- or 4-byte code).
            if (i >= data.size || data[i].toInt() != 1) return MIME_AVC
            i++
            if (i + 1 >= data.size) return MIME_AVC
            val b0 = data[i].toInt() and 0xFF
            val b1 = data[i + 1].toInt() and 0xFF
            val hevcType = (b0 shr 1) and 0x3F
            return if ((hevcType == 32 || hevcType == 33) && b1 == 0x01) MIME_HEVC else MIME_AVC
        }

        /** UI-facing codec name for the switch notice (R4 C2). */
        fun codecLabel(mime: String): String = if (mime == MIME_HEVC) "H.265" else "H.264"
    }
}
