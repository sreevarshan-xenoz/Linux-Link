package dev.linuxlink.android.stream

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
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
import kotlinx.coroutines.delay

/**
 * Streaming telemetry HUD overlay (Tier 1 #1): fps / bitrate / RTT /
 * end-to-end latency / frame drops, refreshed on a fixed interval from the
 * Rust core. Place on top of [RemoteDesktopView] inside a Box.
 */
@Composable
fun StatsHud(
    modifier: Modifier = Modifier,
    refreshMs: Long = 500,
) {
    var stats by remember { mutableStateOf<RustCore.StreamingStats?>(null) }

    LaunchedEffect(refreshMs) {
        while (true) {
            stats = runCatching { RustCore.streamingStats() }.getOrNull()
            delay(refreshMs)
        }
    }

    val s = stats ?: return
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(Color.Black.copy(alpha = 0.55f))
            .padding(horizontal = 10.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        HudItem("fps", "%.0f".format(s.fps))
        HudItem("kbps", "%,d".format(s.bitrateKbps))
        HudItem("rtt", "${s.rttMs}ms")
        HudItem("e2e", "${s.e2eLatencyMs}ms")
        HudItem("drops", "${s.frameDrops}")
    }
}

@Composable
private fun HudItem(label: String, value: String) {
    Text(
        text = "$label $value",
        style = MaterialTheme.typography.labelSmall.copy(
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            color = Color.White,
        ),
    )
}
