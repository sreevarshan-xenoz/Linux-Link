package com.linuxlink.ui

import android.app.Application
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.linuxlink.viewmodel.TerminalViewModel
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.History

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
    val history by terminalViewModel.history.collectAsState()
    var showHistory by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Row(modifier = Modifier.fillMaxWidth()) {
            Box(modifier = Modifier.weight(1f)) {
                TextField(
                    value = command,
                    onValueChange = {
                        terminalViewModel.updateCommand(it)
                        showHistory = it.isNotEmpty() && history.isNotEmpty()
                    },
                    label = { Text("Enter command") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    trailingIcon = {
                        IconButton(
                            onClick = { showHistory = !showHistory }
                        ) {
                            Icon(Icons.Default.History, contentDescription = "Command History")
                        }
                    }
                )
                // Command history dropdown
                if (showHistory) {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 48.dp)
                    ) {
                        Column {
                            history.filter { it.contains(command, ignoreCase = true) }
                                .take(5)
                                .forEach { item ->
                                    Text(
                                        text = item,
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable {
                                                terminalViewModel.updateCommand(item)
                                                showHistory = false
                                            }
                                            .padding(12.dp)
                                    )
                                }
                        }
                    }
                }
            }
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