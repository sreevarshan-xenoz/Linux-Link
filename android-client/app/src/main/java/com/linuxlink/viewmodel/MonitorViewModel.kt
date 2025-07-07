package com.linuxlink.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.linuxlink.data.api.ApiService
import com.linuxlink.data.api.SystemStats
import com.linuxlink.security.SecurityManager
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

class MonitorViewModel(app: Application) : AndroidViewModel(app) {
    private val _stats = MutableStateFlow<SystemStats?>(null)
    val stats: StateFlow<SystemStats?> = _stats

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

    init {
        startAutoRefresh()
    }

    private fun startAutoRefresh() {
        viewModelScope.launch {
            while (true) {
                fetchStats()
                delay(3000) // Refresh every 3 seconds
            }
        }
    }

    fun fetchStats() {
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
                val response = api.getSystemStats("Bearer $token")
                if (response.isSuccessful && response.body() != null) {
                    _stats.value = response.body()
                } else {
                    _errorMessage.value = response.errorBody()?.string() ?: "Failed to fetch stats"
                }
            } catch (e: Exception) {
                _errorMessage.value = e.localizedMessage ?: "Network error"
            } finally {
                _isLoading.value = false
            }
        }
    }
} 