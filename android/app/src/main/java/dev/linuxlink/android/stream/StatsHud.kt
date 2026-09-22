package dev.linuxlink.android.stream

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.linuxlink.android.bridge.RustCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Streaming telemetry HUD overlay (Tier 1 #1): fps / bitrate / RTT /
 * end-to-end latency / frame drops, refreshed on a fixed interval from the
 * Rust core. When an [address]/[controlPort] are given, the desktop's battery
 * is polled slowly alongside (Tier-2 #11). Place on top of [RemoteDesktopView]
 * inside a Box.
 *
 * A [FlowRow], not a plain Row: on a narrow phone in landscape the six items
 * are wider than the screen, and a Row would squash the trailing ones into a
 * one-character-per-line column.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun StatsHud(
    modifier: Modifier = Modifier,
    refreshMs: Long = 500,
    address: String? = null,
    controlPort: Int = 1716,
) {
    var stats by remember { mutableStateOf<RustCore.StreamingStats?>(null) }
    var battery by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(refreshMs) {
        while (true) {
            stats = runCatching { RustCore.streamingStats() }.getOrNull()
            delay(refreshMs)
        }
    }

    LaunchedEffect(address, controlPort) {
        val host = address ?: return@LaunchedEffect
        battery = null
        while (true) {
            battery = withContext(Dispatchers.IO) {
                runCatching {
                    val body = JSONObject(RustCore.getBattery(host, controlPort).getOrThrow())
                    when {
                        body.optBoolean("noBattery") -> null
                        else -> {
                            val charge = body.optInt("currentCharge", -1)
                            if (charge < 0) {
                                null
                            } else {
                                "$charge%" +
                                    if (body.optBoolean("isCharging")) "⚡" else ""
                            }
                        }
                    }
                }.getOrNull()
            }
            delay(15_000)
        }
    }

    val s = stats ?: return
    FlowRow(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(Color.Black.copy(alpha = 0.55f))
            .border(1.dp, Color.White.copy(alpha = 0.14f), RoundedCornerShape(8.dp))
            .padding(horizontal = 10.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
        maxItemsInEachRow = 6,
    ) {
        HudItem("fps", "%.0f".format(s.fps))
        HudItem("kbps", "%,d".format(s.bitrateKbps))
        HudItem("rtt", "${s.rttMs}ms")
        HudItem("e2e", "${s.e2eLatencyMs}ms")
        HudItem("drops", "${s.frameDrops}")
        battery?.let { HudItem("desk", it) }
    }
}

@Composable
private fun HudItem(label: String, value: String) {
    Text(
        text = "$label $value",
        maxLines = 1,
        style = MaterialTheme.typography.labelSmall.copy(
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            color = Color.White,
        ),
    )
}
