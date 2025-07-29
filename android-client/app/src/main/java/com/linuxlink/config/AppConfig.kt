package com.linuxlink.config

import android.content.Context
import android.content.SharedPreferences
import com.linuxlink.BuildConfig

object AppConfig {
    private const val PREFS_NAME = "linuxlink_config"
    private const val KEY_API_BASE_URL = "api_base_url"
    private const val KEY_CONNECTION_TIMEOUT = "connection_timeout"
    private const val KEY_READ_TIMEOUT = "read_timeout"
    
    // Default values
    private const val DEFAULT_CONNECTION_TIMEOUT = 30L // seconds
    private const val DEFAULT_READ_TIMEOUT = 60L // seconds
    
    fun getApiBaseUrl(context: Context): String {
        val prefs = getPreferences(context)
        return prefs.getString(KEY_API_BASE_URL, BuildConfig.DEFAULT_API_BASE_URL) 
            ?: BuildConfig.DEFAULT_API_BASE_URL
    }
    
    fun setApiBaseUrl(context: Context, url: String) {
        getPreferences(context).edit()
            .putString(KEY_API_BASE_URL, url)
            .apply()
    }
    
    fun getConnectionTimeout(context: Context): Long {
        return getPreferences(context).getLong(KEY_CONNECTION_TIMEOUT, DEFAULT_CONNECTION_TIMEOUT)
    }
    
    fun setConnectionTimeout(context: Context, timeout: Long) {
        getPreferences(context).edit()
            .putLong(KEY_CONNECTION_TIMEOUT, timeout)
            .apply()
    }
    
    fun getReadTimeout(context: Context): Long {
        return getPreferences(context).getLong(KEY_READ_TIMEOUT, DEFAULT_READ_TIMEOUT)
    }
    
    fun setReadTimeout(context: Context, timeout: Long) {
        getPreferences(context).edit()
            .putLong(KEY_READ_TIMEOUT, timeout)
            .apply()
    }
    
    fun isValidUrl(url: String): Boolean {
        return try {
            val cleanUrl = if (!url.startsWith("http://") && !url.startsWith("https://")) {
                "http://$url"
            } else url
            
            val normalizedUrl = if (!cleanUrl.endsWith("/")) "$cleanUrl/" else cleanUrl
            
            // Basic URL validation
            normalizedUrl.matches(Regex("^https?://[\\w.-]+(:[0-9]+)?/?$"))
        } catch (e: Exception) {
            false
        }
    }
    
    fun normalizeUrl(url: String): String {
        val cleanUrl = if (!url.startsWith("http://") && !url.startsWith("https://")) {
            "http://$url"
        } else url
        
        return if (!cleanUrl.endsWith("/")) "$cleanUrl/" else cleanUrl
    }
    
    private fun getPreferences(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }
}
