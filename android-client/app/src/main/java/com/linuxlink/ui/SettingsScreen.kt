package com.linuxlink.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.linuxlink.config.AppConfig

@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    var apiUrl by remember { mutableStateOf(AppConfig.getApiBaseUrl(context)) }
    var connectionTimeout by remember { mutableStateOf(AppConfig.getConnectionTimeout(context).toString()) }
    var readTimeout by remember { mutableStateOf(AppConfig.getReadTimeout(context).toString()) }
    var showSaved by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Settings",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold
        )

        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "Network Configuration",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Medium
                )

                OutlinedTextField(
                    value = apiUrl,
                    onValueChange = { apiUrl = it },
                    label = { Text("API Base URL") },
                    placeholder = { Text("http://192.168.1.100:8000/") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    isError = !AppConfig.isValidUrl(apiUrl)
                )

                if (!AppConfig.isValidUrl(apiUrl)) {
                    Text(
                        text = "Please enter a valid URL (e.g., http://192.168.1.100:8000)",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = connectionTimeout,
                        onValueChange = { connectionTimeout = it },
                        label = { Text("Connection Timeout (s)") },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )

                    OutlinedTextField(
                        value = readTimeout,
                        onValueChange = { readTimeout = it },
                        label = { Text("Read Timeout (s)") },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "About",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Medium
                )

                Text(
                    text = "Linux-Link Mobile Terminal",
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    text = "Version 1.0",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "Secure remote terminal access for your Linux system",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Button(
            onClick = {
                if (AppConfig.isValidUrl(apiUrl)) {
                    AppConfig.setApiBaseUrl(context, AppConfig.normalizeUrl(apiUrl))
                    
                    connectionTimeout.toLongOrNull()?.let { timeout ->
                        if (timeout > 0) AppConfig.setConnectionTimeout(context, timeout)
                    }
                    
                    readTimeout.toLongOrNull()?.let { timeout ->
                        if (timeout > 0) AppConfig.setReadTimeout(context, timeout)
                    }
                    
                    showSaved = true
                }
            },
            enabled = AppConfig.isValidUrl(apiUrl),
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Save Settings")
        }

        if (showSaved) {
            LaunchedEffect(Unit) {
                kotlinx.coroutines.delay(2000)
                showSaved = false
            }
            
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "✓ Settings saved successfully",
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
        
        Text(
            text = "Note: Changes will take effect on the next app restart or after logging out and back in.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
