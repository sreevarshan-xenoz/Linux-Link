package com.linuxlink.ui

import android.app.Application
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.linuxlink.viewmodel.TerminalViewModel

@Composable
fun TerminalScreen(app: Application? = null) {
    val context = LocalContext.current
    val terminalViewModel: TerminalViewModel = viewModel(factory = androidx.lifecycle.viewmodel.initializer {
        TerminalViewModel(context.applicationContext as Application)
    })
    val command by terminalViewModel.command.collectAsState()
    val output by terminalViewModel.output.collectAsState()
    val isLoading by terminalViewModel.isLoading.collectAsState()
    val errorMessage by terminalViewModel.errorMessage.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Row(modifier = Modifier.fillMaxWidth()) {
            TextField(
                value = command,
                onValueChange = { terminalViewModel.updateCommand(it) },
                label = { Text("Enter command") },
                modifier = Modifier.weight(1f),
                singleLine = true
            )
            Spacer(modifier = Modifier.width(8.dp))
            Button(
                onClick = { terminalViewModel.executeCommand() },
                enabled = !isLoading && command.isNotEmpty()
            ) {
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp))
                } else {
                    Text("Execute")
                }
            }
        }
        if (errorMessage != null) {
            Text(errorMessage ?: "", color = MaterialTheme.colorScheme.error)
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