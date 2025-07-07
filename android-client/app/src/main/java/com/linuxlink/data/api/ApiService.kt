package com.linuxlink.data.api

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST

// Data models

data class LoginRequest(val username: String, val password: String)
data class LoginResponse(val access_token: String, val token_type: String)
data class CommandRequest(val cmd: String, val timeout: Int = 30)
data class CommandResponse(val stdout: String, val stderr: String, val returncode: Int, val command: String)
data class SystemStats(val cpu: Any, val memory: Any, val disk: Any, val network: Any, val timestamp: String, val uptime: String)

data class QuickStatus(
    val system_stats: SystemStatsShort,
    val critical_info: CriticalInfo,
    val timestamp: String
)
data class SystemStatsShort(val cpu_percent: Double, val memory_percent: Double, val disk_percent: Double, val uptime: String)
data class CriticalInfo(val running_services: Int, val recent_errors: List<String>)

interface ApiService {
    @POST("auth/login")
    suspend fun login(@Body credentials: LoginRequest): Response<LoginResponse>

    @POST("exec")
    suspend fun executeCommand(
        @Header("Authorization") token: String,
        @Body command: CommandRequest
    ): Response<CommandResponse>

    @GET("sys/stats")
    suspend fun getSystemStats(
        @Header("Authorization") token: String
    ): Response<SystemStats>

    @GET("sys/quick-status")
    suspend fun getQuickStatus(
        @Header("Authorization") token: String
    ): Response<QuickStatus>
} 