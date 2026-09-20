package dev.linuxlink.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.linuxlink.android.bridge.RustCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray

/** One desktop monitor as reported by the server's monitors plugin. */
data class DesktopMonitor(
    val index: Int,
    val name: String,
    val width: Int,
    val height: Int,
    val isPrimary: Boolean,
)

fun parseMonitorsPayload(json: String): List<DesktopMonitor> {
    val arr = JSONArray(json)
    return (0 until arr.length()).map { i ->
        val m = arr.getJSONObject(i)
        DesktopMonitor(
            index = m.optInt("index", i),
            name = m.optString("name").ifBlank { "Monitor ${m.optInt("index", i)}" },
            width = m.optInt("width", 0),
            height = m.optInt("height", 0),
            isPrimary = m.optBoolean("is_primary"),
        )
    }
}

/**
 * R3 Tier-2 #10 monitor picker: lists the desktop's monitors; picking one
 * reconnects the stream with that `monitor_index` (the server captures that
 * monitor's region — portal stream by position, X11 grab by monitor rect).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MonitorPickerSheet(
    address: String,
    controlPort: Int,
    selected: Int,
    onDismiss: () -> Unit,
    onPick: (Int) -> Unit,
) {
    var monitors by remember { mutableStateOf<List<DesktopMonitor>?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(address, controlPort) {
        val result =
            withContext(Dispatchers.IO) {
                RustCore.getMonitors(address, controlPort)
            }
        result.fold(
            onSuccess = { json ->
                runCatching { parseMonitorsPayload(json) }
                    .onSuccess { monitors = it }
                    .onFailure { error = "Malformed monitor list" }
            },
            onFailure = { error = it.message ?: "Monitor query failed" },
        )
    }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(modifier = Modifier.padding(horizontal = 16.dp)) {
            Text("Stream a monitor", style = MaterialTheme.typography.titleMedium)
            TextButton(onClick = { onPick(-1) }) {
                val label = if (selected == -1) "Auto — primary (current)" else "Auto — primary"
                Text(label, style = MaterialTheme.typography.bodyMedium)
            }
            HorizontalDivider()
            when {
                error != null ->
                    Text(
                        error!!,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 12.dp),
                    )

                monitors == null ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 24.dp),
                        horizontalArrangement = Arrangement.Center,
                    ) {
                        CircularProgressIndicator()
                    }

                else -> LazyColumn(modifier = Modifier.padding(bottom = 24.dp)) {
                    items(monitors!!, key = { it.index }) { m ->
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onPick(m.index) }
                                .padding(vertical = 10.dp),
                        ) {
                            Text(
                                m.name,
                                style = MaterialTheme.typography.bodyLarge,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                buildString {
                                    append("${m.width}x${m.height}")
                                    if (m.isPrimary) append("  ·  primary")
                                    if (m.index == selected) append("  ·  current")
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        HorizontalDivider()
                    }
                }
            }
        }
    }
}
