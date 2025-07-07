package com.linuxlink.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun TerminalScreen() {
    var command by remember { mutableStateOf("") }
    var output by remember { mutableStateOf("Welcome to Linux-Link Terminal\n") }
    var isLoading by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Row(modifier = Modifier.fillMaxWidth()) {
            TextField(
                value = command,
                onValueChange = { command = it },
                label = { Text("Enter command") },
                modifier = Modifier.weight(1f),
                singleLine = true
            )
            Spacer(modifier = Modifier.width(8.dp))
            Button(
                onClick = {
                    if (command.isNotEmpty() && !isLoading) {
                        // Placeholder for command execution
                        output += "\n$ $command\n[output here]"
                        command = ""
                    }
                },
                enabled = !isLoading
            ) {
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp))
                } else {
                    Text("Execute")
                }
            }
        }
        Spacer(modifier = Modifier.height(16.dp))
        Card(
            modifier = Modifier.fillMaxSize()
        ) {
            Text(
                text = output,
                modifier = Modifier.padding(8.dp)
            )
        }
    }
} 