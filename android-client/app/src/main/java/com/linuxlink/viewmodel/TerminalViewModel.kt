package com.linuxlink.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.linuxlink.data.api.ApiService
import com.linuxlink.data.api.CommandRequest
import com.linuxlink.data.api.CommandResponse
import com.linuxlink.security.SecurityManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

class TerminalViewModel(app: Application) : AndroidViewModel(app) {
    private val _command = MutableStateFlow("")
    val command: StateFlow<String> = _command

    private val _output = MutableStateFlow("Welcome to Linux-Link Terminal\n")
    val output: StateFlow<String> = _output

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage

    private val _history = MutableStateFlow<List<String>>(emptyList())
    val history: StateFlow<List<String>> = _history

    private val _shouldLogout = MutableStateFlow(false)
    val shouldLogout: StateFlow<Boolean> = _shouldLogout

    // Hardcoded backend URL for now
    private val api = Retrofit.Builder()
        .baseUrl("http://192.168.1.100:8000/") // Update with your machine's IP
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(ApiService::class.java)

    private val appContext = app.applicationContext

    init {
        loadHistory()
    }

    fun updateCommand(cmd: String) {
        _command.value = cmd
    }

    fun executeCommand() {
        val cmd = _command.value.trim()
        if (cmd.isEmpty()) return
        _isLoading.value = true
        _errorMessage.value = null
        viewModelScope.launch {
            try {
                val token = SecurityManager.getToken(appContext)
                if (token == null) {
                    _errorMessage.value = "Not authenticated."
                    _isLoading.value = false
                    return@launch
                }
                val response = api.executeCommand("Bearer $token", CommandRequest(cmd))
                if (response.isSuccessful && response.body() != null) {
                    val res: CommandResponse = response.body()!!
                    _output.value += "\n$ $cmd\n${res.stdout}${if (res.stderr.isNotBlank()) "\n${res.stderr}" else ""}"
                    addToHistory(cmd)
                } else {
                    when (response.code()) {
                        401, 403 -> {
                            // Token expired or invalid
                            SecurityManager.clearToken(appContext)
                            _shouldLogout.value = true
                            _output.value += "\n$ $cmd\n[Authentication error - please log in again]"
                        }
                        else -> {
                            _output.value += "\n$ $cmd\n[Error: ${response.errorBody()?.string() ?: "Unknown error"}]"
                        }
                    }
                }
            } catch (e: Exception) {
                _output.value += "\n$ $cmd\n[Network error: ${e.localizedMessage}]"
            } finally {
                _isLoading.value = false
                _command.value = ""
            }
        }
    }

    private fun loadHistory() {
        _history.value = SecurityManager.getCommandHistory(appContext)
    }

    private fun addToHistory(cmd: String) {
        val current = _history.value.toMutableList()
        if (cmd.isNotBlank() && (current.isEmpty() || current.first() != cmd)) {
            current.add(0, cmd)
            if (current.size > 50) current.removeLast()
            _history.value = current
            SecurityManager.saveCommandHistory(appContext, current)
        }
    }

    fun resetLogoutFlag() {
        _shouldLogout.value = false
    }
} 