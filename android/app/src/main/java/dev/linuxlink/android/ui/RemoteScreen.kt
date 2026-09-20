package dev.linuxlink.android.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
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
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dev.linuxlink.android.HostStore
import dev.linuxlink.android.R
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
    // R4 A1: live link path of the video session ("lan" | "wan_direct" |
    // "wan_relayed" | "wan" | "none"), polled from the bridge while up.
    var linkState by remember { mutableStateOf("none") }
    val status = streamStatus
    LaunchedEffect(status) {
        if (status !is StreamStatus.Up || status.kind != StreamTransportKind.Wan) {
            linkState = "none"
            return@LaunchedEffect
        }
        while (isActive) {
            linkState = runCatching { RustCore.streamingStats().linkState }.getOrDefault("wan")
            delay(1_000)
        }
    }
    // Tier-2 #11b: PIN pairing state. Unpaired sessions open the sheet —
    // with pairing enforced, the control channel only answers the handshake.
    var pairedServerId by remember(address) { mutableStateOf(HostStore.pairedDesktopId(context, address)) }
    var showPairing by remember { mutableStateOf(false) }
    var pairingMessage by remember { mutableStateOf<String?>(null) }
    // Tier-3 #16: desktop audio control sheet (volume/mute/output routing).
    var showAudio by remember { mutableStateOf(false) }
    // R4 D1: server-enforced view-only mode — while latched the server drops
    // every injectable input packet from this session, video keeps flowing.
    // The flag is per-session server state, so it is re-armed whenever the
    // stream (re)comes up (retry, monitor switch → fresh pipeline).
    var viewOnly by remember { mutableStateOf(false) }
    var viewOnlyError by remember { mutableStateOf<String?>(null) }
    val viewOnlyErrorMessage =
        viewOnlyError?.let { stringResource(R.string.view_only_error, it) }
    LaunchedEffect(viewOnlyErrorMessage) {
        if (viewOnlyErrorMessage != null) {
            android.widget.Toast
                .makeText(context, viewOnlyErrorMessage, android.widget.Toast.LENGTH_SHORT)
                .show()
            viewOnlyError = null
        }
    }
    LaunchedEffect(status) {
        if (viewOnly && status is StreamStatus.Up) {
            withContext(Dispatchers.IO) { RustCore.setViewOnly(true) }
        }
    }
    // R4 A3: while the video link rides an iroh relay the server clamps the
    // encoder bitrate to a bandwidth-friendly cap; this override opts out.
    // Server-side latch, per-session — re-armed on stream (re)connect like
    // view-only. Meaningless on LAN/direct (the clamp isn't engaged there).
    var fullQuality by remember { mutableStateOf(false) }
    var fullQualityError by remember { mutableStateOf<String?>(null) }
    val fullQualityErrorMessage =
        fullQualityError?.let { stringResource(R.string.full_quality_error, it) }
    LaunchedEffect(fullQualityErrorMessage) {
        if (fullQualityErrorMessage != null) {
            android.widget.Toast
                .makeText(context, fullQualityErrorMessage, android.widget.Toast.LENGTH_SHORT)
                .show()
            fullQualityError = null
        }
    }
    LaunchedEffect(status) {
        if (fullQuality && status is StreamStatus.Up) {
            withContext(Dispatchers.IO) { RustCore.setFullQuality(true) }
        }
    }
    // Tier-3 #14: decoded video frame size, used to pick the PiP aspect ratio.
    var videoSize by remember { mutableStateOf(androidx.compose.ui.unit.IntSize.Zero) }
    // Tier-3 #15: desktop privacy mode. The server's input grab carries a
    // 10-minute TTL, so an enabled session must keep refreshing it and must
    // release it on exit; a refresh failure means the server auto-released.
    var privacyGrab by remember { mutableStateOf(false) }
    // Toast text is resolved during composition (configuration-aware) and
    // fired by this one-shot effect, not from the event callback.
    var privacyError by remember { mutableStateOf<String?>(null) }
    val privacyErrorMessage =
        privacyError?.let { stringResource(R.string.privacy_error, it) }
    LaunchedEffect(privacyErrorMessage) {
        if (privacyErrorMessage != null) {
            android.widget.Toast
                .makeText(context, privacyErrorMessage, android.widget.Toast.LENGTH_SHORT)
                .show()
            privacyError = null
        }
    }

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

    // Tier-3 #15 remainder: phone-side blackout / pocket mode. The session
    // keeps streaming underneath; the phone shows a black, touch-consuming
    // overlay, its window + video surface go secure (no screenshots,
    // Recents, or screen-record leakage), and brightness drops. Double-tap
    // or back unlocks. (True screen-off is not app-possible without key
    // injection; the FGS partial wake lock keeps the link alive if the user
    // powers down the panel themselves.)
    var blackout by remember { mutableStateOf(false) }

    LaunchedEffect(inPictureInPicture) {
        if (inPictureInPicture) blackout = false
    }

    DisposableEffect(blackout) {
        val window = context.findActivity()?.window
        fun applySecure(secure: Boolean) {
            if (window == null) return
            if (secure) {
                window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
            } else {
                window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
            }
            val lp = window.attributes
            lp.screenBrightness = if (secure) 0.01f else -1f
            window.attributes = lp
        }
        applySecure(blackout)
        onDispose { applySecure(false) }
    }

    // Tier-3 #17: system back / predictive back gesture ends the session
    // cleanly (same path as "Exit" → recompose to ConnectScreen → disposal
    // stops streaming) instead of killing the whole activity. Sheets sit
    // above this in the back stack and consume back themselves; in PiP the
    // system gesture closes the float window, so the handler stands down.
    // Tier-3 #15 remainder: while blackout is on, back just uncovers the
    // phone — it must never drop a session the user can't currently see.
    androidx.activity.compose.BackHandler(enabled = !inPictureInPicture) {
        if (blackout) blackout = false else onExit()
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

    // Tier-3 #13 remainder: Wi-Fi↔LTE roaming. quinn's QUIC migration is
    // ready (server accepts a changing source address), but Android pins
    // the endpoint's UDP socket to the network that was default when it
    // was created, so a migrated path can't actually leave the old radio.
    // The reachable fix is a reconnect on the new default network — cheap
    // for us: fresh QUIC handshake + gap-driven keyframe request. Baseline
    // semantics: registerDefaultNetworkCallback fires onAvailable for the
    // *current* network immediately — that one is swallowed; only a
    // *different* later network triggers a rebind. The cooldown keeps a
    // flapping radio from tearing down a healthy stream.
    var lastNetwork by remember { mutableStateOf<Network?>(null) }
    var lastRebindMs by remember { mutableLongStateOf(0L) }
    // The callback lives across recompositions (keyed on address only), so
    // everything it reads must be a live reference, not the value captured
    // at registration.
    val pipNow = rememberUpdatedState(inPictureInPicture)
    DisposableEffect(address) {
        val handler = Handler(Looper.getMainLooper())
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                handler.post {
                    val previous = lastNetwork
                    lastNetwork = network
                    if (previous != null && previous != network &&
                        !pipNow.value &&
                        SystemClock.elapsedRealtime() - lastRebindMs > 3_000
                    ) {
                        lastRebindMs = SystemClock.elapsedRealtime()
                        android.util.Log.i(
                            "RemoteScreen",
                            "default network changed — rebinding stream",
                        )
                        retryStream()
                    }
                }
            }
        }
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        runCatching { cm.registerDefaultNetworkCallback(callback) }
        onDispose {
            handler.removeCallbacksAndMessages(null)
            runCatching { cm.unregisterNetworkCallback(callback) }
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
                secure = blackout,
                modifier = Modifier.fillMaxSize(),
            )
        }

        // Every chrome element is hidden while the activity is in picture-in-picture:
        // the window is thumb-sized and touch input there goes to the system, not us.
        if (!inPictureInPicture) {
            // Connect-status chip: shown until the video link is up (and again
            // if it fails, with the LAN/WAN reasons + a retry). A live WAN link
            // keeps a small badge reporting *how* it is connected (R4 A1) —
            // punched-direct vs relayed, since relayed is a normal first-class
            // state iroh keeps trying to upgrade, not an error.
            if (status is StreamStatus.Up && status.kind == StreamTransportKind.Wan) {
                val label = when (linkState) {
                    "wan_direct" -> stringResource(R.string.wan_link_direct)
                    "wan_relayed" -> stringResource(R.string.wan_link_relayed)
                    else -> stringResource(R.string.wan_link_punching)
                }
                Column(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(top = 4.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        label,
                        color = Color.White,
                        style = MaterialTheme.typography.labelSmall,
                    )
                    // One-tap escape hatch from the server's relay bitrate floor
                    // (R4 A3): relaying is shared bandwidth, but the user may
                    // still want every bit of it.
                    if (linkState == "wan_relayed") {
                        TextButton(
                            onClick = {
                                val next = !fullQuality
                                fullQuality = next
                                scope.launch(Dispatchers.IO) {
                                    RustCore.setFullQuality(next)
                                        .onFailure { fullQualityError = it.message }
                                }
                            },
                        ) {
                            val fqLabel = if (fullQuality) {
                                stringResource(R.string.full_quality_on)
                            } else {
                                stringResource(R.string.full_quality_off)
                            }
                            Text(
                                fqLabel,
                                color = if (fullQuality) Color(0xFFFFC080) else Color.White,
                                style = MaterialTheme.typography.labelSmall,
                            )
                        }
                    }
                }
            }
            if (status !is StreamStatus.Up) {
                Column(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(horizontal = 32.dp, vertical = 64.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    val label = when (status) {
                        is StreamStatus.Connecting -> stringResource(R.string.connecting)
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
                            Text(stringResource(R.string.retry), color = Color.White)
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
                Text(stringResource(R.string.exit), color = Color.White)
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
                            if (mode == InputMode.DirectTouch) {
                                stringResource(R.string.mode_direct_touch)
                            } else {
                                stringResource(R.string.mode_trackpad)
                            }
                        Text(label, color = Color.White)
                    }
                    TextButton(onClick = { clipboardSync = !clipboardSync }) {
                        val label =
                            if (clipboardSync) stringResource(R.string.clip_on) else stringResource(R.string.clip_off)
                        Text(label, color = Color.White)
                    }
                    TextButton(onClick = { showHistory = true }) {
                        Text(stringResource(R.string.history), color = Color.White)
                    }
                    TextButton(onClick = { showPicker = true }) {
                        val label =
                            if (cropWindow == null) {
                                stringResource(R.string.window_all)
                            } else {
                                stringResource(
                                    R.string.window_named,
                                    (cropWindow?.title ?: "").take(18),
                                )
                            }
                        Text(label, color = Color.White)
                    }
                    TextButton(onClick = { showMonitorPicker = true }) {
                        val label =
                            if (monitorIndex == -1) {
                                stringResource(R.string.monitor_auto)
                            } else {
                                stringResource(R.string.monitor_indexed, monitorIndex)
                            }
                        Text(label, color = Color.White)
                    }
                    TextButton(
                        onClick = {
                            scope.launch(Dispatchers.IO) {
                                RustCore.sendFindMyDevice(address, controlPort)
                            }
                        },
                    ) {
                        Text(stringResource(R.string.ring_pc), color = Color.White)
                    }
                    TextButton(onClick = { showAudio = true }) {
                        Text(stringResource(R.string.audio), color = Color.White)
                    }
                    TextButton(onClick = { pairingMessage = null; showPairing = true }) {
                        val label =
                            if (pairedServerId == null) {
                                stringResource(R.string.pair_action)
                            } else {
                                stringResource(R.string.paired)
                            }
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
                                        privacyError = result.exceptionOrNull()?.message
                                    }
                                }
                            }
                        },
                    ) {
                        val label =
                            if (privacyGrab) stringResource(R.string.privacy_on) else stringResource(R.string.privacy_off)
                        Text(label, color = if (privacyGrab) Color(0xFF80FFB0) else Color.White)
                    }
                    TextButton(
                        onClick = {
                            scope.launch(Dispatchers.IO) {
                                val next = !viewOnly
                                val result = RustCore.setViewOnly(next)
                                withContext(Dispatchers.Main) {
                                    if (result.isSuccess) {
                                        viewOnly = next
                                    } else {
                                        viewOnlyError = result.exceptionOrNull()?.message
                                    }
                                }
                            }
                        },
                    ) {
                        val label =
                            if (viewOnly) stringResource(R.string.view_only_on) else stringResource(R.string.view_only_off)
                        Text(label, color = if (viewOnly) Color(0xFFFFC080) else Color.White)
                    }
                    TextButton(
                        onClick = {
                            scope.launch(Dispatchers.IO) {
                                RustCore.desktopPrivacy(address, controlPort, "status", lock = true)
                            }
                        },
                    ) {
                        Text(stringResource(R.string.lock_pc), color = Color.White)
                    }
                    TextButton(onClick = { blackout = true }) {
                        Text(stringResource(R.string.blackout), color = Color.White)
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
                        Text(stringResource(R.string.pip), color = Color.White)
                    }
                }
                ShortcutBar(
                    address = address,
                    port = port,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }

        // Blackout overlay: last child = topmost. Opaque black covers the
        // (already secure) video surface, the tap detector consumes every
        // gesture so nothing reaches the remote input layer, and a
        // double-tap is the unlock.
        if (blackout && !inPictureInPicture) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color.Black)
                    .pointerInput(Unit) {
                        detectTapGestures(onDoubleTap = { blackout = false })
                    },
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    stringResource(R.string.blackout_unlock),
                    color = Color.White.copy(alpha = 0.35f),
                    style = MaterialTheme.typography.bodyMedium,
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
