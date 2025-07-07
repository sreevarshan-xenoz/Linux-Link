package com.linuxlink.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Monitor
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController

@Composable
fun LinuxLinkApp() {
    val navController = rememberNavController()
    Scaffold(
        bottomBar = {
            NavigationBar {
                val items = listOf(
                    NavItem("Terminal", Icons.Default.Computer, "terminal"),
                    NavItem("Monitor", Icons.Default.Monitor, "monitor"),
                    NavItem("Files", Icons.Default.Folder, "files"),
                    NavItem("Voice", Icons.Default.Mic, "voice")
                )
                items.forEach { item ->
                    NavigationBarItem(
                        icon = { Icon(item.icon, contentDescription = item.label) },
                        label = { Text(item.label) },
                        selected = false,
                        onClick = { navController.navigate(item.route) }
                    )
                }
            }
        }
    ) { paddingValues ->
        NavHost(
            navController = navController,
            startDestination = "terminal",
            modifier = Modifier.padding(paddingValues)
        ) {
            composable("terminal") { TerminalScreen() }
            composable("monitor") { MonitorScreen() }
            composable("files") { FilesScreen() }
            composable("voice") { VoiceScreen() }
        }
    }
}

data class NavItem(val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector, val route: String) 