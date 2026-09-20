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
import dev.linuxlink.android.ui.RemoteScreen

class MainActivity : ComponentActivity() {
    companion object {
        /** Set by the notification's Disconnect action (Tier 1 #5). */
        const val EXTRA_DISCONNECT = "dev.linuxlink.android.DISCONNECT"
    }

    private val disconnectSignal = mutableIntStateOf(0)

    private val requestNotificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            // Denied is non-fatal: the service still runs, just without a visible notification.
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        RustCore.start(filesDir)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    var sessionKey by rememberSaveable { mutableStateOf<String?>(null) }

                    LaunchedEffect(Unit) {
                        if (sessionKey == null &&
                            HostStore.autoConnect(this@MainActivity)
                        ) {
                            HostStore.lastHost(this@MainActivity)?.let {
                                sessionKey = "${it.address}|${it.port}"
                            }
                        }
                    }

                    LaunchedEffect(disconnectSignal.intValue) {
                        if (disconnectSignal.intValue > 0) {
                            sessionKey = null
                        }
                    }

                    when (val session = parseSession(sessionKey)) {
                        null -> ConnectScreen(
                            initial = HostStore.lastHost(this@MainActivity),
                            autoConnect = HostStore.autoConnect(this@MainActivity),
                        ) { address, port, rememberHost ->
                            HostStore.save(this@MainActivity, HostStore.Host(address, port))
                            HostStore.setAutoConnect(this@MainActivity, rememberHost)
                            maybeRequestNotificationPermission()
                            sessionKey = "$address|$port"
                        }

                        else -> RemoteScreen(
                            address = session.first,
                            port = session.second,
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

/** Session state travels as "address|port" so it survives process save/restore. */
private fun parseSession(key: String?): Pair<String, Int>? {
    val parts = key?.split('|') ?: return null
    if (parts.size != 2 || parts[0].isBlank()) return null
    val port = parts[1].toIntOrNull() ?: return null
    return parts[0] to port
}
