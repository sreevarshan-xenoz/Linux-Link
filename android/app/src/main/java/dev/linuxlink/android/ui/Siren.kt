package dev.linuxlink.android.ui

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.Ringtone
import android.media.RingtoneManager
import android.net.Uri
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import dev.linuxlink.android.bridge.RustCore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

private const val SIREN_POLL_MS = 2_000L
private const val SIREN_RING_MS = 30_000L

/**
 * Find-my-device siren, phone side (R3 Tier-2 #11): while a session is up,
 * poll the bridge latch the control reader sets when the desktop pushes
 * `kdeconnect.findmydevice` `{ring:true}`, and play the alarm tone at full
 * volume for a bounded time so the phone can be found by ear.
 */
@Composable
fun SirenWatcher(context: Context) {
    var tone: Ringtone? by remember { mutableStateOf(null) }
    var stopJob: Job? by remember { mutableStateOf(null) }
    DisposableEffect(context) {
        val scope = CoroutineScope(Dispatchers.Main)
        val job =
            scope.launch {
                while (isActive) {
                    if (RustCore.checkSiren() && tone == null) {
                        tone = ringPhone(context)
                        if (tone != null) {
                            stopJob =
                                scope.launch {
                                    delay(SIREN_RING_MS)
                                    runCatching { tone?.stop() }
                                    tone = null
                                }
                        }
                    }
                    delay(SIREN_POLL_MS)
                }
            }
        onDispose {
            job.cancel()
            stopJob?.cancel()
            runCatching { tone?.stop() }
        }
    }
}

private fun ringPhone(context: Context): Ringtone? {
    val uri: Uri =
        RingtoneManager.getActualDefaultRingtoneUri(context, RingtoneManager.TYPE_ALARM)
            ?: RingtoneManager.getActualDefaultRingtoneUri(context, RingtoneManager.TYPE_RINGTONE)
            ?: return null
    maxAlarmVolume(context)
    val attributes =
        AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_ALARM)
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .build()
    return runCatching {
        val tone = RingtoneManager.getRingtone(context, uri)
        tone.audioAttributes = attributes
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            tone.volume = 1.0f
            tone.isLooping = true
        }
        tone.play()
        tone
    }.getOrNull()
}

private fun maxAlarmVolume(context: Context) {
    runCatching {
        val am = context.getSystemService(Context.AUDIO_SERVICE) as AudioManager
        am.setStreamVolume(
            AudioManager.STREAM_ALARM,
            am.getStreamMaxVolume(AudioManager.STREAM_ALARM),
            0,
        )
    }
}
