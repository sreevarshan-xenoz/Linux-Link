package dev.linuxlink.android.stream

import android.view.KeyEvent
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.linuxlink.android.bridge.RustCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Desktop shortcut bar (Tier 1 #3): keys a touchscreen cannot produce.
 * Super+1..9 map to Hyprland workspace switching on the server.
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
                .padding(horizontal = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            val press = KeyEvent.KEYCODE_META_LEFT
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
private fun Shortcut(label: String, action: () -> Result<Unit>) {
    val scope = rememberCoroutineScope()
    TextButton(onClick = { scope.launch(Dispatchers.IO) { action() } }) {
        Text(label, fontSize = 12.sp)
    }
}
