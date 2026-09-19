package dev.linuxlink.android.stream

import android.os.Build
import android.view.SurfaceView
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import dev.linuxlink.android.bridge.RustCore

/**
 * Remote desktop video surface: connects a streaming session on attach,
 * decodes with [H264Decoder] straight into the [SurfaceView], and tears the
 * session down on dispose.
 *
 * Renders via the SurfaceView overlay path (never ImageReader) so decoded
 * frames go to the display without a GPU copy. On API 31+ the surface
 * declares the panel's native refresh rate so frame presentation aligns with
 * vsync instead of the default 60 Hz voting.
 */
@Composable
fun RemoteDesktopView(
    address: String,
    port: Int,
    width: Int,
    height: Int,
    modifier: Modifier = Modifier,
) {
    val decoderHost = remember { DecoderHost() }

    AndroidView(
        factory = { context ->
            SurfaceView(context).apply {
                holder.addCallback(
                    object : android.view.SurfaceHolder.Callback {
                        override fun surfaceCreated(holder: android.view.SurfaceHolder) {
                            declareFrameRate(holder, display)
                            decoderHost.start(holder.surface, address, port, width, height)
                        }

                        override fun surfaceChanged(
                            holder: android.view.SurfaceHolder,
                            format: Int,
                            width: Int,
                            height: Int,
                        ) {
                        }

                        override fun surfaceDestroyed(holder: android.view.SurfaceHolder) {
                            decoderHost.stop()
                        }
                    },
                )
            }
        },
        modifier = modifier,
    )

    DisposableEffect(Unit) {
        onDispose { decoderHost.stop() }
    }
}

private fun declareFrameRate(holder: android.view.SurfaceHolder, display: android.view.Display?) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
    val surface = holder.surface ?: return
    runCatching {
        val refresh = display?.mode?.refreshRate ?: 0f
        if (refresh > 0f) {
            surface.setFrameRate(refresh, android.view.Surface.FRAME_RATE_COMPATIBILITY_DEFAULT)
        }
    }
}

/** Owns the decoder thread; start/stop are idempotent. */
private class DecoderHost {
    @Volatile
    private var decoder: H264Decoder? = null
    @Volatile
    private var thread: Thread? = null

    fun start(surface: android.view.Surface, address: String, port: Int, width: Int, height: Int) {
        if (thread != null) return
        val active = H264Decoder(surface, width, height)
        decoder = active
        thread = Thread({
            // The Rust bridge blocks, so connect + drain share this thread.
            if (RustCore.connectStreaming(address, port).isSuccess) {
                active.start()
            }
        }, "h264-decode").apply {
            isDaemon = true
            priority = Thread.MAX_PRIORITY
            start()
        }
    }

    fun stop() {
        val active = decoder ?: return
        decoder = null
        active.stop()
        runCatching { RustCore.stopStreaming() }
        thread?.let { t ->
            thread = null
            runCatching { t.join(2000) }
        }
    }
}
