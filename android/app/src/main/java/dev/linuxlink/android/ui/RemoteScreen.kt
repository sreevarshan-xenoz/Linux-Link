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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import dev.linuxlink.android.HostStore
import dev.linuxlink.android.bridge.RustCore
import dev.linuxlink.android.service.SessionForegroundService
import dev.linuxlink.android.stream.InputMode
import dev.linuxlink.android.stream.RemoteDesktopView
import dev.linuxlink.android.stream.ShortcutBar
import dev.linuxlink.android.stream.StatsHud
import dev.linuxlink.android.stream.StreamStatus
import dev.linuxlink.android.stream.StreamTransportKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Live remote-desktop session (Tier 1 #5 shell): video surface + input
 * gestures, stats HUD, shortcut bar, input-mode switch, and the
 * foreground-service + keep-screen-on lifecycle around it.
 */
@Composable
fun RemoteScreen(
    address: String,
    port: Int,
    controlPort: Int,
    inPictureInPicture: Boolean = false,
    onExit: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var mode by remember { mutableStateOf(InputMode.DirectTouch) }
    var clipboardSync by remember { mutableStateOf(true) }
    var showHistory by remember { mutableStateOf(false) }
    // R3#7 single-window streaming: the picked window + the layout box the
    // picker reported (needed to remap direct-touch through the crop).
    var cropWindow by remember { mutableStateOf<DesktopWindow?>(null) }
    var cropScreen by remember { mutableStateOf<IntArray?>(null) }
    var showPicker by remember { mutableStateOf(false) }
    // R3 Tier-2 #10: which desktop monitor to stream (-1 = server default).
    // Toggling `showStream` tears the view down (surfaceDestroyed stops the
    // session) before recreation, so the new connect can't hit the bridge's
    // already-active check on the same address+port.
    var monitorIndex by remember(address) {
        mutableStateOf(HostStore.monitorIndex(context, address))
    }
    var showStream by remember { mutableStateOf(true) }
    var showMonitorPicker by remember { mutableStateOf(false) }
    // Video-link status (LAN/WAN/failed) for the current stream generation.
    var streamStatus by remember {
        mutableStateOf<StreamStatus>(StreamStatus.Connecting)
    }
    // Tier-2 #11b: PIN pairing state. Unpaired sessions open the sheet —
    // with pairing enforced, the control channel only answers the handshake.
    var pairedServerId by remember(address) { mutableStateOf(HostStore.pairedDesktopId(context, address)) }
    var showPairing by remember { mutableStateOf(false) }
    var pairingMessage by remember { mutableStateOf<String?>(null) }
    // Tier-3 #16: desktop audio control sheet (volume/mute/output routing).
    var showAudio by remember { mutableStateOf(false) }
    // Tier-3 #14: decoded video frame size, used to pick the PiP aspect ratio.
    var videoSize by remember { mutableStateOf(androidx.compose.ui.unit.IntSize.Zero) }
    // Tier-3 #15: desktop privacy mode. The server's input grab carries a
    // 10-minute TTL, so an enabled session must keep refreshing it and must
    // release it on exit; a refresh failure means the server auto-released.
    var privacyGrab by remember { mutableStateOf(false) }

    LaunchedEffect(privacyGrab, address) {
        if (!privacyGrab) return@LaunchedEffect
        while (isActive) {
            val ok = withContext(Dispatchers.IO) {
                RustCore.desktopPrivacy(address, controlPort, "grab").isSuccess
            }
            if (!ok) {
                privacyGrab = false
                break
            }
            delay(4 * 60 * 1000)
        }
    }

    DisposableEffect(privacyGrab) {
        onDispose {
            if (privacyGrab) {
                Thread {
                    runCatching { RustCore.desktopPrivacy(address, controlPort, "release") }
                }.start()
            }
        }
    }

    LaunchedEffect(address) {
        val serverId = withContext(Dispatchers.IO) { RustCore.checkPairResult(1L) }
        if (serverId != null) {
            pairedServerId = serverId
            HostStore.savePairedDesktop(context, address, serverId)
        } else if (pairedServerId == null) {
            showPairing = true
        }
    }

    fun retryStream() {
        showStream = false
        streamStatus = StreamStatus.Connecting
        scope.launch {
            withContext(Dispatchers.IO) { RustCore.stopStreaming() }
            showStream = true
        }
    }

    fun switchMonitor(index: Int) {
        showMonitorPicker = false
        if (index == monitorIndex) return
        HostStore.saveMonitorIndex(context, address, index)
        cropWindow = null
        cropScreen = null
        monitorIndex = index
        streamStatus = StreamStatus.Connecting
        showStream = false
        scope.launch {
            withContext(Dispatchers.IO) { RustCore.stopStreaming() }
            showStream = true
        }
    }

    ClipboardSyncEffect(address, controlPort, enabled = clipboardSync)
    SirenWatcher(context)
    DesktopNotificationRelay(address = address, controlPort = controlPort)

    // R1 stage 3: cache the desktop's iroh WAN identity while the control
    // channel is up (the server pushes it on register and re-announces every
    // 30 s), so later sessions can dial it from off-LAN.
    LaunchedEffect(address) {
        var cached: String? = null
        while (isActive) {
            val identity = withContext(Dispatchers.IO) { RustCore.getWanIdentity() }
            if (identity != null && identity != cached) {
                cached = identity
                HostStore.saveWanIdentity(context, address, identity)
            }
            delay(5_000)
        }
    }

    DisposableEffect(Unit) {
        val start = Intent(context, SessionForegroundService::class.java).apply {
            action = SessionForegroundService.ACTION_START
            putExtra(SessionForegroundService.EXTRA_ADDRESS, address)
            putExtra(SessionForegroundService.EXTRA_PORT, port)
            putExtra(SessionForegroundService.EXTRA_CONTROL_PORT, controlPort)
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
        if (showStream) {
            RemoteDesktopView(
                address = address,
                port = port,
                width = metrics.widthPixels,
                height = metrics.heightPixels,
                inputMode = mode,
                mapping = cropWindow?.desktopMapping(cropScreen),
                monitorIndex = monitorIndex,
                onStatus = { streamStatus = it },
                onVideoSizeChanged = { w, h -> videoSize = androidx.compose.ui.unit.IntSize(w, h) },
                modifier = Modifier.fillMaxSize(),
            )
        }

        // Every chrome element is hidden while the activity is in picture-in-picture:
        // the window is thumb-sized and touch input there goes to the system, not us.
        if (!inPictureInPicture) {
            // Connect-status chip: shown until the video link is up (and again
            // if it fails, with the LAN/WAN reasons + a retry). A live WAN link
            // keeps a small badge so the user knows the video is off-LAN.
            val status = streamStatus
            if (status is StreamStatus.Up && status.kind == StreamTransportKind.Wan) {
                Text(
                    "WAN link (iroh)",
                    color = Color.White,
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(top = 4.dp),
                )
            }
            if (status !is StreamStatus.Up) {
                Column(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(horizontal = 32.dp, vertical = 64.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    val label = when (status) {
                        is StreamStatus.Connecting -> "Connecting…"
                        is StreamStatus.Down -> status.reason
                        else -> ""
                    }
                    Text(
                        label,
                        color = Color.White,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier
                            .background(
                                androidx.compose.ui.graphics.Color(0xCC000000),
                                androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
                            )
                            .padding(10.dp),
                    )
                    if (status is StreamStatus.Down) {
                        TextButton(onClick = ::retryStream) {
                            Text("Retry", color = Color.White)
                        }
                    }
                }
            }

            Column(
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(8.dp),
            ) {
                StatsHud(address = address, controlPort = controlPort)
                WorkspaceHud(
                    address = address,
                    port = port,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }

            TextButton(
                onClick = onExit,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(4.dp),
            ) {
                Text("Exit", color = Color.White)
            }
        }

        if (!inPictureInPicture) {
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
                    TextButton(onClick = { clipboardSync = !clipboardSync }) {
                        val label = if (clipboardSync) "Clip: on" else "Clip: off"
                        Text(label, color = Color.White)
                    }
                    TextButton(onClick = { showHistory = true }) {
                        Text("History", color = Color.White)
                    }
                    TextButton(onClick = { showPicker = true }) {
                        val label =
                            if (cropWindow == null) "Window: all" else "Window: ${(cropWindow?.title ?: "").take(18)}"
                        Text(label, color = Color.White)
                    }
                    TextButton(onClick = { showMonitorPicker = true }) {
                        val label =
                            if (monitorIndex == -1) "Monitor: auto" else "Monitor: #$monitorIndex"
                        Text(label, color = Color.White)
                    }
                    TextButton(
                        onClick = {
                            scope.launch(Dispatchers.IO) {
                                RustCore.sendFindMyDevice(address, controlPort)
                            }
                        },
                    ) {
                        Text("Ring PC", color = Color.White)
                    }
                    TextButton(onClick = { showAudio = true }) {
                        Text("Audio", color = Color.White)
                    }
                    TextButton(onClick = { pairingMessage = null; showPairing = true }) {
                        val label = if (pairedServerId == null) "Pair…" else "Paired ✓"
                        Text(label, color = Color.White)
                    }
                    TextButton(
                        onClick = {
                            scope.launch(Dispatchers.IO) {
                                val next = !privacyGrab
                                val result =
                                    RustCore.desktopPrivacy(address, controlPort, if (next) "grab" else "release")
                                withContext(Dispatchers.Main) {
                                    if (result.isSuccess) {
                                        privacyGrab = next
                                    } else {
                                        android.widget.Toast.makeText(
                                            context,
                                            "Privacy: ${result.exceptionOrNull()?.message}",
                                            android.widget.Toast.LENGTH_SHORT,
                                        ).show()
                                    }
                                }
                            }
                        },
                    ) {
                        val label = if (privacyGrab) "Privacy: on" else "Privacy: off"
                        Text(label, color = if (privacyGrab) Color(0xFF80FFB0) else Color.White)
                    }
                    TextButton(
                        onClick = {
                            scope.launch(Dispatchers.IO) {
                                RustCore.desktopPrivacy(address, controlPort, "status", lock = true)
                            }
                        },
                    ) {
                        Text("Lock PC", color = Color.White)
                    }
                    TextButton(
                        onClick = {
                            (context.findActivity() as? dev.linuxlink.android.MainActivity)
                                ?.enterSessionPictureInPicture(
                                    videoSize.width,
                                    videoSize.height,
                                )
                        },
                    ) {
                        Text("PiP", color = Color.White)
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

    if (showHistory) {
        ClipboardHistorySheet(
            onDismiss = { showHistory = false },
            onPick = { text ->
                writeLocalClipboard(context, text)
                scope.launch(Dispatchers.IO) {
                    RustCore.sendClipboard(address, controlPort, text)
                }
                showHistory = false
            },
        )
    }

    if (showMonitorPicker) {
        MonitorPickerSheet(
            address = address,
            controlPort = controlPort,
            selected = monitorIndex,
            onDismiss = { showMonitorPicker = false },
            onPick = { index -> switchMonitor(index) },
        )
    }

    if (showPairing) {
        PairingSheet(
            address = address,
            controlPort = controlPort,
            message = pairingMessage,
            onDismiss = { showPairing = false },
            onPaired = { serverId ->
                pairedServerId = serverId
                HostStore.savePairedDesktop(context, address, serverId)
            },
        )
    }

    if (showAudio) {
        AudioControlSheet(
            address = address,
            controlPort = controlPort,
            onDismiss = { showAudio = false },
        )
    }

    if (showPicker) {
        WindowPickerSheet(
            address = address,
            controlPort = controlPort,
            selected = cropWindow,
            onDismiss = { showPicker = false },
            onPick = { w, screen ->
                // Crop rect is monitor-local capture space; the video is then
                // re-encoded at the window's resolution.
                cropWindow = w
                cropScreen = screen
                scope.launch(Dispatchers.IO) {
                    RustCore.sendWindowCrop(w.localAt[0], w.localAt[1], w.size[0], w.size[1])
                }
                showPicker = false
            },
            onFullDesktop = {
                cropWindow = null
                cropScreen = null
                scope.launch(Dispatchers.IO) { RustCore.clearWindowCrop() }
                showPicker = false
            },
        )
    }
}

private tailrec fun Context.findActivity(): Activity? =
    when (this) {
        is Activity -> this
        is ContextWrapper -> baseContext?.findActivity()
        else -> null
    }
