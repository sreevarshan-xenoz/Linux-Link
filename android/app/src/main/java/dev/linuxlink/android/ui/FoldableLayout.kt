package dev.linuxlink.android.ui

import android.app.Activity
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.window.layout.FoldingFeature
import androidx.window.layout.WindowInfoTracker
import androidx.window.layout.WindowLayoutInfo
import dev.linuxlink.android.R
import dev.linuxlink.android.bridge.RustCore
import dev.linuxlink.android.stream.ShortcutBar
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlin.math.roundToInt

/**
 * How a session splits the window when the dual-pane layout is active:
 * [Vertical] = a vertical hinge → left|right columns (stream beside dock);
 * [Horizontal] = a horizontal hinge → top/bottom rows; [None] = no split.
 */
enum class PaneSplit { None, Vertical, Horizontal }

/** User override for the dual-pane layout; [Auto] follows the detected posture. */
enum class PaneMode { Auto, Dual, Single }

/**
 * Observe the device's folding posture and report how the session should split
 * around the hinge. Empty ([PaneSplit.None]) on a phone, on a fold-flat device
 * with no crease, and whenever [WindowInfoTracker] is unavailable — the caller
 * then falls back to a size-based tablet breakpoint.
 */
@Composable
fun rememberFoldingSplit(activity: Activity?): PaneSplit {
    var split by remember { mutableStateOf(PaneSplit.None) }
    LaunchedEffect(activity) {
        val act = activity
        if (act == null) {
            split = PaneSplit.None
            return@LaunchedEffect
        }
        runCatching {
            WindowInfoTracker.getOrCreate(act)
                .windowLayoutInfo(act)
                .collect { info ->
                    val fold = (info as? WindowLayoutInfo)
                        ?.displayFeatures
                        ?.firstOrNull { it is FoldingFeature } as? FoldingFeature
                    split = when (fold?.orientation) {
                        FoldingFeature.Orientation.VERTICAL -> PaneSplit.Vertical
                        FoldingFeature.Orientation.HORIZONTAL -> PaneSplit.Horizontal
                        else -> PaneSplit.None
                    }
                }
        }
            .onFailure { split = PaneSplit.None }
    }
    return split
}

/**
 * Standalone indirect-control surface for the dock pane (R4 E6): a trackpad the
 * user drags on while the desktop is fully visible on the other pane, so the
 * finger never covers the remote view — the problem RustDesk's stretched-phone
 * tablet layout has. Drag moves the cursor (relative motion), a tap clicks,
 * two fingers scroll. Sends go through one ordered dispatcher like the in-view
 * trackpad so packets leave in gesture order.
 */
@Composable
fun TrackpadDock(
    address: String,
    port: Int,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val ordered = remember { Dispatchers.IO.limitedParallelism(1) }
    fun send(block: () -> Unit) = scope.launch(ordered) { block() }

    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.9f),
        tonalElevation = 3.dp,
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                stringResource(R.string.trackpad_hint),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelMedium,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(16.dp),
            )
            Box(
                modifier =
                    Modifier
                        .fillMaxSize()
                        .pointerInput(address to port) {
                            awaitEachGesture {
                                val down = awaitFirstDown(requireUnconsumed = false)
                                var last = down.position
                                var dragged = 0f
                                var twoFinger = false
                                var pending = Offset.Zero
                                while (true) {
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
                                        break
                                    }
                                    val pos = change.position
                                    val delta = pos - last
                                    last = pos
                                    dragged += delta.getDistance()
                                    event.changes.forEach { it.consume() }
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
                        },
            )
        }
    }
}

/** The dock pane: a trackpad filling the pane, with the desktop shortcut bar pinned below it. */
@Composable
fun ControlDock(
    address: String,
    port: Int,
    modifier: Modifier = Modifier,
) {
    Column(modifier) {
        TrackpadDock(address, port, modifier = Modifier.weight(1f).fillMaxWidth())
        ShortcutBar(address, port, modifier = Modifier.fillMaxWidth())
    }
}
