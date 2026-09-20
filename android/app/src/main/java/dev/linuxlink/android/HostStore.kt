package dev.linuxlink.android

import android.content.Context

/** Last-connected host + auto-connect toggle, persisted for Tier 1 #5. */
object HostStore {
    data class Host(val address: String, val port: Int)

    private const val PREFS = "linux-link-host"
    private const val KEY_ADDRESS = "address"
    private const val KEY_PORT = "port"
    private const val KEY_AUTO = "auto_connect"

    fun lastHost(ctx: Context): Host? {
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val address = prefs.getString(KEY_ADDRESS, null)?.takeIf { it.isNotBlank() } ?: return null
        return Host(address, prefs.getInt(KEY_PORT, 0))
    }

    fun save(ctx: Context, host: Host) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_ADDRESS, host.address)
            .putInt(KEY_PORT, host.port)
            .apply()
    }

    fun autoConnect(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_AUTO, false)

    fun setAutoConnect(ctx: Context, enabled: Boolean) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(KEY_AUTO, enabled)
            .apply()
    }
}
