package dev.linuxlink.android.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import dev.linuxlink.android.service.SessionForegroundService
import dev.linuxlink.android.stream.InputMode
import dev.linuxlink.android.stream.RemoteDesktopView
import dev.linuxlink.android.stream.ShortcutBar
import dev.linuxlink.android.stream.StatsHud

/**
 * Live remote-desktop session (Tier 1 #5 shell): video surface + input
 * gestures, stats HUD, shortcut bar, input-mode switch, and the
 * foreground-service + keep-screen-on lifecycle around it.
 */
@Composable
fun RemoteScreen(
    address: String,
    port: Int,
    onExit: () -> Unit,
) {
    val context = LocalContext.current
    var mode by remember { mutableStateOf(InputMode.DirectTouch) }

    DisposableEffect(Unit) {
        val start = Intent(context, SessionForegroundService::class.java).apply {
            action = SessionForegroundService.ACTION_START
            putExtra(SessionForegroundService.EXTRA_ADDRESS, address)
            putExtra(SessionForegroundService.EXTRA_PORT, port)
        }
        context.startForegroundService(start)
        val window = context.findActivity()?.window
        window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        onDispose {
            window?.clearFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            context.stopService(Intent(context, SessionForegroundService::class.java))
        }
    }

    val metrics = remember { context.resources.displayMetrics }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(androidx.compose.ui.graphics.Color.Black),
    ) {
        RemoteDesktopView(
            address = address,
            port = port,
            width = metrics.widthPixels,
            height = metrics.heightPixels,
            inputMode = mode,
            modifier = Modifier.fillMaxSize(),
        )

        StatsHud(
            modifier = Modifier
                .align(Alignment.TopStart)
                .padding(8.dp),
        )

        TextButton(
            onClick = onExit,
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(4.dp),
        ) {
            Text("Exit", color = Color.White)
        }

        Column(modifier = Modifier.align(Alignment.BottomCenter)) {
            Row(modifier = Modifier.padding(bottom = 4.dp)) {
                TextButton(
                    onClick = {
                        mode =
                            if (mode == InputMode.DirectTouch) InputMode.Trackpad else InputMode.DirectTouch
                    },
                ) {
                    val label =
                        if (mode == InputMode.DirectTouch) "Mode: direct touch" else "Mode: trackpad"
                    Text(label, color = Color.White)
                }
            }
            ShortcutBar(
                address = address,
                port = port,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

private tailrec fun Context.findActivity(): Activity? =
    when (this) {
        is Activity -> this
        is ContextWrapper -> baseContext?.findActivity()
        else -> null
    }
