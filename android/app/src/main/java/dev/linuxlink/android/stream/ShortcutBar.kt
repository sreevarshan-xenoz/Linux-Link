package dev.linuxlink.android.stream

import android.view.KeyEvent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.linuxlink.android.R
import dev.linuxlink.android.bridge.RustCore
import dev.linuxlink.android.ui.rememberLlHaptics
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Desktop shortcut bar (Tier 1 #3): keys a touchscreen cannot produce.
 * C9 groups it into System (Super, window switching, safety screen,
 * screenshots, Esc) and Workspaces (W1–9 — Super+1..9 drives Hyprland
 * workspace switching on the server). Key-cap labels stay literal by
 * design (see the i18n exemption note in strings.xml); only the group
 * captions are localized.
 */
@Composable
fun ShortcutBar(
    address: String,
    port: Int,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.85f),
        tonalElevation = 2.dp,
    ) {
        Row(
            modifier = Modifier
                .horizontalScroll(rememberScrollState())
                .padding(horizontal = 6.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val press = KeyEvent.KEYCODE_META_LEFT
            GroupLabel(stringResource(R.string.shortcut_system))
            Shortcut("Super") { RustCore.tapKey(address, port, press) }
            Shortcut("Alt+Tab") {
                RustCore.hotkey(address, port, KeyEvent.KEYCODE_TAB, KeyEvent.KEYCODE_ALT_LEFT)
            }
            Shortcut("Ctrl+Alt+Del") {
                RustCore.hotkey(
                    address,
                    port,
                    KeyEvent.KEYCODE_FORWARD_DEL,
                    KeyEvent.KEYCODE_CTRL_LEFT,
                    KeyEvent.KEYCODE_ALT_LEFT,
                )
            }
            Shortcut("PrtSc") { RustCore.tapKey(address, port, KeyEvent.KEYCODE_SYSRQ) }
            Shortcut("Esc") { RustCore.tapKey(address, port, KeyEvent.KEYCODE_ESCAPE) }
            Divider()
            GroupLabel(stringResource(R.string.shortcut_workspaces))
            (1..9).forEach { workspace ->
                Shortcut("W$workspace") {
                    RustCore.hotkey(
                        address,
                        port,
                        KeyEvent.KEYCODE_1 + (workspace - 1),
                        press,
                    )
                }
            }
        }
    }
}

@Composable
private fun GroupLabel(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 4.dp),
    )
}

@Composable
private fun Divider() {
    Box(
        modifier = Modifier
            .width(1.dp)
            .height(20.dp)
            .padding(horizontal = 4.dp)
            .background(MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)),
    )
}

@Composable
private fun Shortcut(label: String, action: () -> Result<Unit>) {
    val scope = rememberCoroutineScope()
    val haptics = rememberLlHaptics()
    Box(
        modifier = Modifier
            .height(32.dp)
            .widthIn(min = 32.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(MaterialTheme.colorScheme.onSurface.copy(alpha = 0.08f))
            .clickable {
                haptics.tap()
                scope.launch(Dispatchers.IO) { action() }
            }
            .padding(horizontal = 12.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            label,
            fontSize = 12.sp,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}
