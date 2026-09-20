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
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.linuxlink.android.bridge.RustCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/** One desktop output sink as reported by the audio-control plugin. */
data class AudioSink(
    val index: Int,
    val name: String,
    val description: String,
    val isDefault: Boolean,
)

private data class AudioSnapshot(
    val volume: Int,
    val muted: Boolean,
    val sinks: List<AudioSink>,
)

private fun parseSinks(body: JSONObject): List<AudioSink> {
    val arr = body.optJSONArray("sinks") ?: JSONArray()
    return (0 until arr.length()).map { i ->
        val o = arr.getJSONObject(i)
        AudioSink(
            index = o.optInt("index"),
            name = o.optString("name"),
            description = o.optString("description"),
            isDefault = o.optBoolean("isDefault"),
        )
    }
}

/**
 * Desktop audio control (Tier-3 #16): volume + mute for the default output
 * and routing between sinks, over the KDE Connect control channel. The
 * server drives wpctl/pactl; this sheet is a thin remote panel.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AudioControlSheet(
    address: String,
    controlPort: Int,
    onDismiss: () -> Unit,
) {
    var snapshot by remember { mutableStateOf<AudioSnapshot?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var slider by remember { mutableFloatStateOf(0f) }
    val scope = rememberCoroutineScope()

    suspend fun call(body: JSONObject): JSONObject? {
        val result =
            withContext(Dispatchers.IO) {
                RustCore.audioControl(address, controlPort, body.toString())
            }
        return result.fold(
            onSuccess = { json ->
                val obj = JSONObject(json)
                if (obj.optBoolean("ok", true)) {
                    obj
                } else {
                    error = obj.optString("error", "Desktop rejected the request")
                    null
                }
            },
            onFailure = {
                error = it.message ?: "Audio control failed"
                null
            },
        )
    }

    suspend fun refreshAll() {
        val status = call(JSONObject().put("action", "status"))
        val sinks = call(JSONObject().put("action", "sinks"))
        if (status != null && sinks != null) {
            val v = status.optInt("volume", 0)
            snapshot = AudioSnapshot(v, status.optBoolean("muted"), parseSinks(sinks))
            slider = v.toFloat()
        }
    }

    LaunchedEffect(address, controlPort) {
        error = null
        refreshAll()
    }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(modifier = Modifier.padding(horizontal = 16.dp)) {
            Text("Desktop audio", style = MaterialTheme.typography.titleMedium)
            val s = snapshot
            when {
                s == null && error == null ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 24.dp),
                        horizontalArrangement = Arrangement.Center,
                    ) {
                        CircularProgressIndicator()
                    }

                else -> {
                    if (error != null) {
                        Text(
                            error!!,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(vertical = 8.dp),
                        )
                    }
                    if (s != null) {
                        Text(
                            "Volume · ${slider.toInt()}%" +
                                if (s.muted) "  (muted)" else "",
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(top = 8.dp),
                        )
                        Slider(
                            value = slider,
                            onValueChange = { slider = it },
                            valueRange = 0f..100f,
                            onValueChangeFinished = {
                                val v = slider.toInt()
                                error = null
                                scope.launch {
                                    if (
                                        call(
                                            JSONObject()
                                                .put("action", "setVolume")
                                                .put("volume", v),
                                        ) != null
                                    ) {
                                        refreshAll()
                                    }
                                }
                            },
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text("Mute", style = MaterialTheme.typography.bodyMedium)
                            Switch(
                                checked = s.muted,
                                onCheckedChange = { m ->
                                    error = null
                                    scope.launch {
                                        if (
                                            call(
                                                JSONObject()
                                                    .put("action", "setMuted")
                                                    .put("muted", m),
                                            ) != null
                                        ) {
                                            refreshAll()
                                        }
                                    }
                                },
                            )
                        }
                        HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
                        Text(
                            "Output device",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        LazyColumn(modifier = Modifier.padding(bottom = 24.dp)) {
                            items(s.sinks, key = { it.name }) { sink ->
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            error = null
                                            scope.launch {
                                                if (
                                                    call(
                                                        JSONObject()
                                                            .put("action", "selectSink")
                                                            .put("name", sink.name),
                                                    ) != null
                                                ) {
                                                    refreshAll()
                                                }
                                            }
                                        }
                                        .padding(vertical = 10.dp),
                                ) {
                                    Text(
                                        sink.description.ifBlank { sink.name },
                                        style = MaterialTheme.typography.bodyLarge,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    Text(
                                        sink.name + if (sink.isDefault) "  ·  default" else "",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                                HorizontalDivider()
                            }
                        }
                    }
                }
            }
        }
    }
}
