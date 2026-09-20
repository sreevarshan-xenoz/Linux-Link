package dev.linuxlink.android

import android.content.Context

/** Last-connected host + auto-connect toggle, persisted for Tier 1 #5. */
object HostStore {
    data class Host(val address: String, val port: Int, val controlPort: Int = DEFAULT_CONTROL_PORT)

    const val DEFAULT_CONTROL_PORT = 1716
    const val DEFAULT_STREAMING_PORT = 4716

    private const val PREFS = "linux-link-host"
    private const val KEY_ADDRESS = "address"
    private const val KEY_PORT = "port"
    private const val KEY_CONTROL_PORT = "control_port"
    private const val KEY_AUTO = "auto_connect"

    fun lastHost(ctx: Context): Host? {
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val address = prefs.getString(KEY_ADDRESS, null)?.takeIf { it.isNotBlank() } ?: return null
        return Host(
            address,
            prefs.getInt(KEY_PORT, DEFAULT_STREAMING_PORT),
            prefs.getInt(KEY_CONTROL_PORT, DEFAULT_CONTROL_PORT),
        )
    }

    fun save(ctx: Context, host: Host) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_ADDRESS, host.address)
            .putInt(KEY_PORT, host.port)
            .putInt(KEY_CONTROL_PORT, host.controlPort)
            .apply()
    }

    fun autoConnect(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_AUTO, false)

    fun setAutoConnect(ctx: Context, enabled: Boolean) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(KEY_AUTO, enabled)
            .apply()
    }

    /** Cached iroh WAN identity (`kdeconnect.linuxlink.endpoint` body) per desktop address. */
    fun wanIdentity(ctx: Context, address: String): String? =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString("$KEY_WAN_IDENTITY_PREFIX$address", null)?.takeIf { it.isNotBlank() }

    fun saveWanIdentity(ctx: Context, address: String, identityJson: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("$KEY_WAN_IDENTITY_PREFIX$address", identityJson)
            .apply()
    }

    private const val KEY_WAN_IDENTITY_PREFIX = "wan_identity:"

    /** Selected streaming monitor per desktop (`-1` = server default). */
    fun monitorIndex(ctx: Context, address: String): Int =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getInt("$KEY_MONITOR_PREFIX$address", -1)

    fun saveMonitorIndex(ctx: Context, address: String, index: Int) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putInt("$KEY_MONITOR_PREFIX$address", index)
            .apply()
    }

    private const val KEY_MONITOR_PREFIX = "monitor:"

    /** Device id of the desktop this phone paired with at [address] (Tier-2 #11b). */
    fun pairedDesktopId(ctx: Context, address: String): String? =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString("$KEY_PAIRED_PREFIX$address", null)?.takeIf { it.isNotBlank() }

    fun savePairedDesktop(ctx: Context, address: String, serverId: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("$KEY_PAIRED_PREFIX$address", serverId)
            .apply()
    }

    private const val KEY_PAIRED_PREFIX = "paired_desktop:"
}
