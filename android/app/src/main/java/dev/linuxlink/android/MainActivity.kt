package dev.linuxlink.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import dev.linuxlink.android.bridge.RustCore
import dev.linuxlink.android.ui.ConnectScreen
import dev.linuxlink.android.ui.HomeScreen
import dev.linuxlink.android.ui.RemoteScreen

class MainActivity : ComponentActivity() {
    companion object {
        /** Set by the notification's Disconnect action (Tier 1 #5). */
        const val EXTRA_DISCONNECT = "dev.linuxlink.android.DISCONNECT"

        /** Set by the notification's Lock-desktop action (Tier-3 #15). */
        const val EXTRA_LOCK_DESKTOP = "dev.linuxlink.android.LOCK_DESKTOP"
    }

    private val disconnectSignal = mutableIntStateOf(0)

    /** PiP state (Tier-3 #14), read by the composition to hide chrome. */
    private val inPictureInPicture = mutableStateOf(false)

    private val requestNotificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            // Denied is non-fatal: the service still runs, just without a visible notification.
        }

    /** Float the live session over other apps; aspect follows the video. */
    fun enterSessionPictureInPicture(videoWidth: Int, videoHeight: Int) {
        if (videoWidth <= 0 || videoHeight <= 0) {
            enterPictureInPictureMode(
                android.app.PictureInPictureParams.Builder().build(),
            )
            return
        }
        // Android rejects ratios outside [1:2.39, 2.39:1] — clamp both ways.
        val raw = videoWidth.toFloat() / videoHeight.toFloat()
        val ratio = raw.coerceIn(1f / 2.39f, 2.39f)
        enterPictureInPictureMode(
            android.app.PictureInPictureParams.Builder()
                .setAspectRatio(android.util.Rational((ratio * 100).toInt(), 100))
                .build(),
        )
    }

    override fun onPictureInPictureModeChanged(
        isInPictureInPictureMode: Boolean,
        newConfig: android.content.res.Configuration,
    ) {
        super.onPictureInPictureModeChanged(isInPictureInPictureMode, newConfig)
        inPictureInPicture.value = isInPictureInPictureMode
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        RustCore.start(filesDir)
        setContent {
            // Tier-3 #17: `MaterialExpressiveTheme` exists in material3
            // 1.4.0 but is internal — the expressive swap waits for the
            // public API; predictive-back + locale plumbing landed instead.
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    var sessionKey by rememberSaveable { mutableStateOf<String?>(null) }
                    // Home card list vs the add-computer form (UI refresh).
                    var showForm by rememberSaveable { mutableStateOf(false) }

                    LaunchedEffect(Unit) {
                        if (sessionKey == null &&
                            HostStore.autoConnect(this@MainActivity)
                        ) {
                            HostStore.lastHost(this@MainActivity)?.let {
                                sessionKey = "${it.address}|${it.port}|${it.controlPort}"
                            }
                        }
                    }

                    LaunchedEffect(disconnectSignal.intValue) {
                        if (disconnectSignal.intValue > 0) {
                            sessionKey = null
                        }
                    }

                    when (val session = parseSession(sessionKey)) {
                        null -> {
                            if (showForm) {
                                ConnectScreen(
                                    initial = null,
                                    autoConnect = HostStore.autoConnect(this@MainActivity),
                                    onBack = { showForm = false },
                                    onConnect = { address, port, controlPort, rememberHost ->
                                        HostStore.save(
                                            this@MainActivity,
                                            HostStore.Host(address, port, controlPort),
                                        )
                                        HostStore.setAutoConnect(this@MainActivity, rememberHost)
                                        maybeRequestNotificationPermission()
                                        showForm = false
                                        sessionKey = "$address|$port|$controlPort"
                                    },
                                )
                            } else {
                                HomeScreen(
                                    onConnect = { host ->
                                        HostStore.save(this@MainActivity, host)
                                        maybeRequestNotificationPermission()
                                        sessionKey =
                                            "${host.address}|${host.port}|${host.controlPort}"
                                    },
                                    onAdd = { showForm = true },
                                )
                            }
                        }

                        else -> RemoteScreen(
                            address = session.first,
                            port = session.second,
                            controlPort = session.third,
                            inPictureInPicture = inPictureInPicture.value,
                            onExit = { sessionKey = null },
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra(EXTRA_DISCONNECT, false)) {
            Thread { runCatching { RustCore.stopStreaming() } }.start()
            disconnectSignal.intValue += 1
        }
        if (intent.getBooleanExtra(EXTRA_LOCK_DESKTOP, false)) {
            val address = intent.getStringExtra(
                dev.linuxlink.android.service.SessionForegroundService.EXTRA_ADDRESS,
            )
            val controlPort = intent.getIntExtra(
                dev.linuxlink.android.service.SessionForegroundService.EXTRA_CONTROL_PORT,
                HostStore.DEFAULT_CONTROL_PORT,
            )
            if (!address.isNullOrBlank()) {
                Thread {
                    runCatching { RustCore.desktopPrivacy(address, controlPort, "status", lock = true) }
                }.start()
            }
        }
    }

    private fun maybeRequestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}

/** Session state travels as "address|streamingPort|controlPort" so it survives process save/restore. */
private fun parseSession(key: String?): Triple<String, Int, Int>? {
    val parts = key?.split('|') ?: return null
    if (parts.size !in 2..3 || parts[0].isBlank()) return null
    val port = parts[1].toIntOrNull() ?: return null
    val controlPort =
        if (parts.size == 3) {
            parts[2].toIntOrNull() ?: return null
        } else {
            HostStore.DEFAULT_CONTROL_PORT
        }
    return Triple(parts[0], port, controlPort)
}
