package dev.linuxlink.android.stream

import android.os.Build
import android.view.SurfaceView
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.viewinterop.AndroidView
import dev.linuxlink.android.bridge.RustCore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlin.math.hypot
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
 * Pinch-zoom transform over the video surface (Tier 1 #6). The whole desktop
 * fits the viewport at scale 1; zooming in magnifies HiDPI text and
 * [ViewportZoom.toContent] maps viewport touch points back to desktop space so
 * direct-touch still hits what the user sees.
 *
 * Rendering is a graphicsLayer on the SurfaceView, which composes correctly
 * on Android 10+ (API 29); on older devices the surface may not follow the
 * transform cleanly.
 */
private class ViewportZoom {
    var scale by mutableFloatStateOf(1f)
        private set
    var offsetX by mutableFloatStateOf(0f)
        private set
    var offsetY by mutableFloatStateOf(0f)
        private set

    val isZoomed: Boolean get() = scale > 1.01f

    fun applyGesture(zoomDelta: Float, pan: Offset, containerW: Float, containerH: Float) {
        val newScale = (scale * zoomDelta).coerceIn(1f, 8f)
        offsetX = (offsetX + pan.x).coerceIn(containerW * (1f - newScale), 0f)
        offsetY = (offsetY + pan.y).coerceIn(containerH * (1f - newScale), 0f)
        scale = newScale
    }

    fun reset() {
        scale = 1f
        offsetX = 0f
        offsetY = 0f
    }

    /** Viewport point -> desktop point in scale-1 content space. */
    fun toContent(pos: Offset): Offset =
        Offset((pos.x - offsetX) / scale, (pos.y - offsetY) / scale)
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
    val zoom = remember { ViewportZoom() }
    // Pinch-to-zoom only in DirectTouch: Trackpad already owns two-finger
    // gestures for remote scrolling.
    val zoomGesturesEnabled = inputMode == InputMode.DirectTouch

    Box(modifier) {
        Box(
            modifier = Modifier
                .matchParentSize()
                .graphicsLayer {
                    scaleX = zoom.scale
                    scaleY = zoom.scale
                    translationX = zoom.offsetX
                    translationY = zoom.offsetY
                },
        ) {
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
        }

        InputOverlay(
            address = address,
            port = port,
            mode = inputMode,
            zoom = zoom,
            modifier = Modifier
                .matchParentSize()
                .pointerInput(zoomGesturesEnabled) {
                    if (zoomGesturesEnabled) zoomGestureDetector(zoom)
                },
        )
    }

    DisposableEffect(Unit) {
        onDispose { decoderHost.stop() }
    }
}

/**
 * Two-finger pinch + pan. Ignores single-pointer events (those stay input
 * passthrough) and consumes everything while two or more fingers are down.
 */
private suspend fun androidx.compose.ui.input.pointer.PointerInputScope.zoomGestureDetector(
    zoom: ViewportZoom,
) {
    awaitEachGesture {
        var prevCentroid: Offset? = null
        var prevSpan = 0f
        while (true) {
            val event = awaitPointerEvent()
            val pressed = event.changes.filter { it.pressed }
            if (pressed.size >= 2) {
                val centroid = pressed.map { it.position }
                    .reduce { a, b -> Offset((a.x + b.x) / 2f, (a.y + b.y) / 2f) }
                val dx = pressed[0].position.x - pressed[1].position.x
                val dy = pressed[0].position.y - pressed[1].position.y
                val span = hypot(dx, dy)
                val pc = prevCentroid
                if (pc != null && prevSpan > 0f && span > 0f) {
                    zoom.applyGesture(
                        zoomDelta = span / prevSpan,
                        pan = centroid - pc,
                        containerW = size.width.toFloat(),
                        containerH = size.height.toFloat(),
                    )
                }
                prevCentroid = centroid
                prevSpan = span
                pressed.forEach { it.consume() }
            } else if (pressed.isEmpty()) {
                break
            } else {
                // One finger left on the surface: back to passthrough.
                prevCentroid = null
                prevSpan = 0f
            }
        }
    }
}

/**
 * Full-surface gesture catcher. All sends go through a single-perm
 * dispatcher so packets leave in gesture order (down -> move -> up).
 *
 * One-finger gestures drive remote input; a second finger cancels the
 * direct-touch action (it belongs to a pinch-zoom gesture) before anything
 * is sent. Touch positions are mapped through the current [ViewportZoom] so
 * a tap hits the desktop point the user actually sees.
 */
@Composable
private fun InputOverlay(
    address: String,
    port: Int,
    mode: InputMode,
    zoom: ViewportZoom,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val ordered = remember { Dispatchers.IO.limitedParallelism(1) }

    fun send(block: () -> Unit) = scope.launch(ordered) { block() }

    Box(
        modifier.pointerInput(address to port to mode) {
            fun sendAbs(pos: Offset) {
                val content = zoom.toContent(pos)
                val x = RustCore.normalizedCoord(content.x, size.width)
                val y = RustCore.normalizedCoord(content.y, size.height)
                send { RustCore.sendMouseAbs(x, y) }
            }

            awaitEachGesture {
                val down = awaitFirstDown(requireUnconsumed = false)
                when (mode) {
                    InputMode.DirectTouch -> {
                        // Defer the first packet until we know this is a
                        // one-finger gesture, not the start of a pinch.
                        var cancelled = false
                        var lastPos = down.position
                        var done = false
                        while (!done) {
                            val event = awaitPointerEvent()
                            val pressed = event.changes.filter { it.pressed }
                            when {
                                cancelled -> {
                                    if (pressed.isEmpty()) done = true
                                }

                                pressed.size >= 2 -> {
                                    cancelled = true
                                }

                                pressed.isEmpty() -> {
                                    sendAbs(lastPos)
                                    send { RustCore.sendMouseClick(0, false) }
                                    done = true
                                }

                                else -> {
                                    lastPos = pressed.first().position
                                    sendAbs(lastPos)
                                }
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
                            // Divide by zoom so cursor travel matches the
                            // on-screen distance the finger covered.
                            val delta = (pos - last) / zoom.scale
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
