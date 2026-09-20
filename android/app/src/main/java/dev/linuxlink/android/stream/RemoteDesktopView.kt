package dev.linuxlink.android.stream

import android.os.Build
import android.view.SurfaceView
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.viewinterop.AndroidView
import dev.linuxlink.android.bridge.RustCore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlin.math.roundToInt

/**
 * How touch on the video surface is translated into remote input.
 * [DirectTouch] maps the screen 1:1 to the desktop (tap where you see);
 * [Trackpad] is indirect control: drag moves the cursor, tap clicks.
 */
enum class InputMode {
    DirectTouch,
    Trackpad,
}

/**
 * Remote desktop video surface: connects a streaming session on attach,
 * decodes with [H264Decoder] straight into the [SurfaceView], and tears the
 * session down on dispose. A transparent overlay turns touches into input
 * packets according to [inputMode].
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
    inputMode: InputMode = InputMode.DirectTouch,
    modifier: Modifier = Modifier,
) {
    val decoderHost = remember { DecoderHost() }

    Box(modifier) {
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
            modifier = Modifier.matchParentSize(),
        )

        InputOverlay(
            address = address,
            port = port,
            mode = inputMode,
            modifier = Modifier.matchParentSize(),
        )
    }

    DisposableEffect(Unit) {
        onDispose { decoderHost.stop() }
    }
}

/**
 * Full-surface gesture catcher. All sends go through a single-perm
 * dispatcher so packets leave in gesture order (down -> move -> up).
 */
@Composable
private fun InputOverlay(
    address: String,
    port: Int,
    mode: InputMode,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val ordered = remember { Dispatchers.IO.limitedParallelism(1) }

    fun send(block: () -> Unit) = scope.launch(ordered) { block() }

    Box(
        modifier.pointerInput(address to port to mode) {
            fun sendAbs(pos: Offset) {
                val x = RustCore.normalizedCoord(pos.x, size.width)
                val y = RustCore.normalizedCoord(pos.y, size.height)
                send { RustCore.sendMouseAbs(x, y) }
            }

            awaitEachGesture {
                val down = awaitFirstDown(requireUnconsumed = false)
                when (mode) {
                    InputMode.DirectTouch -> {
                        sendAbs(down.position)
                        var done = false
                        while (!done) {
                            val event = awaitPointerEvent()
                            val change = event.changes.firstOrNull { it.pressed }
                            if (change == null) {
                                send { RustCore.sendMouseClick(0, false) }
                                done = true
                            } else {
                                sendAbs(change.position)
                            }
                        }
                    }

                    InputMode.Trackpad -> {
                        var last = down.position
                        var dragged = 0f
                        var pending = Offset.Zero
                        var twoFinger = false
                        var done = false
                        while (!done) {
                            val event = awaitPointerEvent()
                            if (event.changes.size >= 2) twoFinger = true
                            val change = event.changes.firstOrNull { it.pressed }
                            if (change == null) {
                                if (!twoFinger && dragged <= viewConfiguration.touchSlop) {
                                    send {
                                        RustCore.sendMouseClick(0, true)
                                        RustCore.sendMouseClick(0, false)
                                    }
                                }
                                done = true
                                continue
                            }
                            val pos = change.position
                            val delta = pos - last
                            last = pos
                            dragged += delta.getDistance()
                            if (twoFinger) {
                                pending += delta
                                val sx = pending.x.roundToInt()
                                // Finger down == content down == negative wheel.
                                val sy = (-pending.y).roundToInt()
                                if (sx != 0 || sy != 0) {
                                    pending = Offset(pending.x - sx, pending.y + sy)
                                    send {
                                        RustCore.sendMouseEvent(
                                            address,
                                            port,
                                            sx.toFloat(),
                                            sy.toFloat(),
                                            2,
                                            false,
                                        )
                                    }
                                }
                            } else if (dragged > viewConfiguration.touchSlop) {
                                val dx = delta.x.roundToInt()
                                val dy = delta.y.roundToInt()
                                if (dx != 0 || dy != 0) {
                                    send {
                                        RustCore.sendMouseEvent(
                                            address,
                                            port,
                                            dx.toFloat(),
                                            dy.toFloat(),
                                            0,
                                            false,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
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
