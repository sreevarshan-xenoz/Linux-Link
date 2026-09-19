package dev.linuxlink.android.stream

import android.media.MediaCodec
import android.media.MediaFormat
import android.os.Build
import android.view.Surface
import dev.linuxlink.android.bridge.RustCore
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Low-latency H.264 decoder that drains encoded access units from the Rust
 * bridge ([RustCore.receiveFrames]) and renders them straight to a [Surface].
 *
 * Runs on a dedicated thread ([start] blocks); stop it by clearing [running]
 * and joining via [RustCore.stopStreaming] on the caller side. The stream is
 * Annex-B NAL units with in-band SPS/PPS (the encoder keyframes carry them),
 * so buffers are fed to MediaCodec as-is; the decoder signals the real format
 * on the first output buffer.
 */
class H264Decoder(
    private val surface: Surface,
    private val width: Int,
    private val height: Int,
) {
    val running = AtomicBoolean(false)

    private var codec: MediaCodec? = null

    /**
     * Configure MediaCodec for real-time, minimum-latency decode.
     *
     * - `KEY_LOW_LATENCY` (API 30+) drops reordering/buffering delay.
     * - `KEY_PRIORITY` real-time requests the fastest scheduling.
     * B-frame-free encoder output (R2#1) is what actually keeps `LOW_LATENCY`
     * honored end to end.
     */
    private fun buildFormat(): MediaFormat {
        val format = MediaFormat.createVideoFormat(MIME, width, height)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            format.setInteger(MediaFormat.KEY_LOW_LATENCY, 1)
        }
        // 0 = realtime priority class (highest urgency for the codec scheduler).
        format.setInteger(MediaFormat.KEY_PRIORITY, 0)
        format.setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, MAX_INPUT_SIZE)
        return format
    }

    /**
     * Blocking decode loop. Configure the codec, then repeatedly pull a batch
     * of frames and feed them, rendering every decoded output buffer to the
     * surface immediately.
     */
    fun start() {
        val mediaCodec = MediaCodec.createDecoderByType(MIME)
        codec = mediaCodec
        try {
            mediaCodec.configure(buildFormat(), surface, null, 0)
            mediaCodec.start()
            running.set(true)

            val bufferInfo = MediaCodec.BufferInfo()
            while (running.get()) {
                val frames = RustCore.receiveFrames(timeoutMs = POLL_TIMEOUT_MS)
                if (frames.isEmpty()) continue
                for (frame in frames) {
                    if (!running.get()) break
                    feed(mediaCodec, bufferInfo, frame.data, frame.isKeyframe)
                }
            }
        } finally {
            running.set(false)
            runCatching { mediaCodec.stop() }
            runCatching { mediaCodec.release() }
            codec = null
        }
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

    private fun drain(codec: MediaCodec, info: MediaCodec.BufferInfo) {
        var outIndex = codec.dequeueOutputBuffer(info, 0)
        while (outIndex >= 0) {
            // Render to the surface as soon as a frame is available.
            codec.releaseOutputBuffer(outIndex, true)
            outIndex = codec.dequeueOutputBuffer(info, 0)
        }
    }

    companion object {
        private const val MIME = "video/avc"
        private const val MAX_INPUT_SIZE = 4 * 1024 * 1024
        private const val POLL_TIMEOUT_MS = 50
        private const val INPUT_TIMEOUT_US = 10_000L
    }
}
