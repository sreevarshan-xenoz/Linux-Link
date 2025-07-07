package com.linuxlink.ui

import android.app.Application
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Monitor
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.linuxlink.security.SecurityManager
import com.linuxlink.viewmodel.LoginViewModel

@Composable
fun LinuxLinkApp(app: Application? = null) {
    val navController = rememberNavController()
    val context = LocalContext.current
    val loginViewModel: LoginViewModel = viewModel(factory = androidx.lifecycle.viewmodel.initializer {
        LoginViewModel(context.applicationContext as Application)
    })
    var isLoggedIn by remember { mutableStateOf(SecurityManager.getToken(context) != null) }

    if (!isLoggedIn) {
        val isLoading by loginViewModel.isLoading.collectAsState()
        val errorMessage by loginViewModel.errorMessage.collectAsState()
        val loginSuccess by loginViewModel.loginSuccess.collectAsState()
        if (loginSuccess) {
            isLoggedIn = true
        } else {
            LoginScreen(
                isLoading = isLoading,
                errorMessage = errorMessage,
                onLogin = { username, password -> loginViewModel.login(username, password) }
            )
        }
    } else {
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
}

data class NavItem(val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector, val route: String) 