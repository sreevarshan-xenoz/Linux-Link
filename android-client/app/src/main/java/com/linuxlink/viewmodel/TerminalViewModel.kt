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

    // Hardcoded backend URL for now
    private val api = Retrofit.Builder()
        .baseUrl("http://10.0.2.2:8000/")
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(ApiService::class.java)

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
                val token = SecurityManager.getToken(getApplication())
                if (token == null) {
                    _errorMessage.value = "Not authenticated."
                    _isLoading.value = false
                    return@launch
                }
                val response = api.executeCommand("Bearer $token", CommandRequest(cmd))
                if (response.isSuccessful && response.body() != null) {
                    val res: CommandResponse = response.body()!!
                    _output.value += "\n$ $cmd\n${res.stdout}${if (res.stderr.isNotBlank()) "\n${res.stderr}" else ""}"
                } else {
                    _output.value += "\n$ $cmd\n[Error: ${response.errorBody()?.string() ?: "Unknown error"}]"
                }
            } catch (e: Exception) {
                _output.value += "\n$ $cmd\n[Network error: ${e.localizedMessage}]"
            } finally {
                _isLoading.value = false
                _command.value = ""
            }
        }
    }
} 