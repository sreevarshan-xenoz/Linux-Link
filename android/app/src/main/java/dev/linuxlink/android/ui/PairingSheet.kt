package dev.linuxlink.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import dev.linuxlink.android.HostStore
import dev.linuxlink.android.bridge.RustCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val PIN_WAIT_SECS = 2L

/**
 * PIN pairing sheet (R3 Tier-2 #11b). Two flows: ask the desktop to show a
 * PIN and read it back here, or type a PIN produced by `linux-link pair`.
 * Pairing persists the desktop's deviceId on the phone and marks this
 * connection trusted on the desktop.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairingSheet(
    address: String,
    controlPort: Int,
    message: String?,
    onDismiss: () -> Unit,
    onPaired: (String) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val keyboard = LocalSoftwareKeyboardController.current
    var status by remember { mutableStateOf(message ?: "") }
    var waiting by remember { mutableStateOf(false) }
    var pinEntry by remember { mutableStateOf("") }

    LaunchedEffect(waiting) {
        while (waiting) {
            val serverId = withContext(Dispatchers.IO) { RustCore.checkPairResult(PIN_WAIT_SECS) }
            if (serverId != null) {
                waiting = false
                status = "Paired ✓"
                HostStore.savePairedDesktop(context, address, serverId)
                onPaired(serverId)
                delay(600)
                onDismiss()
                break
            }
        }
    }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Pair with $address", style = MaterialTheme.typography.titleMedium)
            if (status.isNotEmpty()) {
                Text(status, style = MaterialTheme.typography.bodyMedium)
            }
            Button(
                enabled = !waiting,
                onClick = {
                    scope.launch {
                        val result =
                            withContext(Dispatchers.IO) {
                                RustCore.requestPairPin(address, controlPort)
                            }
                        val error = result.exceptionOrNull()?.message
                        status = when (result.getOrNull()) {
                            "pinSent" -> {
                                waiting = true
                                "Read the PIN off the desktop screen…"
                            }
                            "pinReady" ->
                                "A PIN is showing on the desktop (`linux-link pair`) — type it below."
                            else -> error?.let { "Error: $it" } ?: "Desktop did not confirm a PIN."
                        }
                    }
                },
            ) {
                Text(if (waiting) "Waiting for desktop…" else "Show PIN on desktop")
            }
            OutlinedTextField(
                value = pinEntry,
                onValueChange = { pinEntry = it.filter(Char::isDigit).take(6) },
                label = { Text("6-digit PIN") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedButton(
                enabled = pinEntry.length == 6 && !waiting,
                onClick = {
                    keyboard?.hide()
                    val pin = pinEntry
                    scope.launch {
                        val result =
                            withContext(Dispatchers.IO) {
                                RustCore.pairWithPin(address, controlPort, pin)
                            }
                        val serverId = result.getOrNull()
                        if (serverId != null) {
                            status = "Paired ✓"
                            HostStore.savePairedDesktop(context, address, serverId)
                            onPaired(serverId)
                            delay(600)
                            onDismiss()
                        } else {
                            val error = result.exceptionOrNull()?.message
                            status = error?.let { "Error: $it" } ?: "Wrong or expired PIN."
                        }
                    }
                },
            ) {
                Text("Enter PIN from desktop")
            }
            TextButton(
                onClick = {
                    waiting = false
                    onDismiss()
                },
            ) {
                Text("Cancel")
            }
        }
    }
}
