package com.linuxlink.ui

import android.app.Application
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.linuxlink.viewmodel.MonitorViewModel

@Composable
fun MonitorScreen(app: Application? = null) {
    val context = LocalContext.current
    val monitorViewModel: MonitorViewModel = viewModel(factory = androidx.lifecycle.viewmodel.initializer {
        MonitorViewModel(context.applicationContext as Application)
    })
    val stats by monitorViewModel.stats.collectAsState()
    val isLoading by monitorViewModel.isLoading.collectAsState()
    val errorMessage by monitorViewModel.errorMessage.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text("System Monitor", style = MaterialTheme.typography.titleLarge)
        Spacer(modifier = Modifier.height(16.dp))
        if (isLoading && stats == null) {
            CircularProgressIndicator()
        } else if (errorMessage != null) {
            Text(errorMessage ?: "", color = MaterialTheme.colorScheme.error)
        } else if (stats != null) {
            val cpu = stats?.cpu as? Map<*, *>
            val memory = stats?.memory as? Map<*, *>
            val disk = stats?.disk as? Map<*, *>
            val uptime = stats?.uptime ?: "--"
            val cpuPercent = (cpu?.get("percent") as? List<*>)?.firstOrNull()?.toString() ?: "--"
            val memPercent = memory?.get("percent")?.toString() ?: "--"
            val diskPercent = disk?.get("percent")?.toString() ?: "--"
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("CPU: $cpuPercent%", style = MaterialTheme.typography.bodyLarge)
                Text("RAM: $memPercent%", style = MaterialTheme.typography.bodyLarge)
                Text("Disk: $diskPercent%", style = MaterialTheme.typography.bodyLarge)
                Text("Uptime: $uptime", style = MaterialTheme.typography.bodyLarge)
            }
        } else {
            Text("No stats available.")
        }
    }
} 