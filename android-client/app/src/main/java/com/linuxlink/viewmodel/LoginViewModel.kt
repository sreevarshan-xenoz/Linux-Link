package com.linuxlink.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.linuxlink.data.api.ApiService
import com.linuxlink.data.api.LoginRequest
import com.linuxlink.security.SecurityManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

class LoginViewModel(app: Application) : AndroidViewModel(app) {
    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage

    private val _loginSuccess = MutableStateFlow(false)
    val loginSuccess: StateFlow<Boolean> = _loginSuccess

    // Hardcoded backend URL for now
    private val api = Retrofit.Builder()
        .baseUrl("http://10.0.2.2:8000/") // Use your backend IP here
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(ApiService::class.java)

    fun login(username: String, password: String) {
        _isLoading.value = true
        _errorMessage.value = null
        viewModelScope.launch {
            try {
                val response = api.login(LoginRequest(username, password))
                if (response.isSuccessful && response.body() != null) {
                    val token = response.body()!!.access_token
                    SecurityManager.saveToken(getApplication(), token)
                    _loginSuccess.value = true
                } else {
                    _errorMessage.value = response.errorBody()?.string() ?: "Login failed"
                }
            } catch (e: Exception) {
                _errorMessage.value = e.localizedMessage ?: "Network error"
            } finally {
                _isLoading.value = false
            }
        }
    }
} 