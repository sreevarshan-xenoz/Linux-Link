package dev.linuxlink.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import dev.linuxlink.android.HostStore
import dev.linuxlink.android.bridge.RustCore

/**
 * Landing screen: host address + streaming port, with the auto-connect
 * toggle. Pre-fills the last saved host; connecting is the caller's job
 * (see MainActivity's session state).
 */
@Composable
fun ConnectScreen(
    initial: HostStore.Host?,
    autoConnect: Boolean,
    onConnect: (address: String, port: Int, rememberHost: Boolean) -> Unit,
) {
    var address by rememberSaveable { mutableStateOf(initial?.address.orEmpty()) }
    var port by rememberSaveable { mutableStateOf((initial?.port ?: 4716).toString()) }
    var rememberHost by rememberSaveable { mutableStateOf(autoConnect) }
    val portValue = port.toIntOrNull()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Linux Link", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(24.dp))
        OutlinedTextField(
            value = address,
            onValueChange = { address = it },
            label = { Text("Host address") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = port,
            onValueChange = { input ->
                if (input.all { it.isDigit() } && input.length <= 5) port = input
            },
            label = { Text("Streaming port") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = rememberHost, onCheckedChange = { rememberHost = it })
            Spacer(Modifier.height(0.dp))
            Text("Auto-connect on launch")
        }
        Spacer(Modifier.height(24.dp))
        Button(
            enabled = address.isNotBlank() && portValue != null,
            onClick = { onConnect(address.trim(), portValue ?: return@Button, rememberHost) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Connect")
        }
        Spacer(Modifier.height(16.dp))
        Text(
            "Rust core v${RustCore.version}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
