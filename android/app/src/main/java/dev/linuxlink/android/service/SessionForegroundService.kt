package dev.linuxlink.android.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import dev.linuxlink.android.MainActivity
import dev.linuxlink.android.bridge.RustCore

/**
 * Keeps the process alive while a remote-desktop streaming session is up
 * (Tier 1 #5). Started by [dev.linuxlink.android.ui.RemoteScreen] on entry,
 * stopped on exit; the notification offers a Disconnect action that routes
 * back through MainActivity.
 *
 * FGS type choice: `specialUse` with a remote-desktop subtype. The client
 * renders a decoded stream — it captures nothing on-device — so
 * `mediaProjection`'s consent dialog would be semantically wrong and scary;
 * `dataSync`/`connectedDevice` do not match Play policy. The justification
 * lives in the manifest's PROPERTY_SPECIAL_USE_FGS_SUBTYPE property.
 */
class SessionForegroundService : Service() {
    companion object {
        const val ACTION_START = "dev.linuxlink.android.action.START_SESSION"
        const val ACTION_STOP = "dev.linuxlink.android.action.STOP_SESSION"
        const val EXTRA_ADDRESS = "address"
        const val EXTRA_PORT = "port"

        private const val CHANNEL_ID = "linux-link-session"
        private const val NOTIFICATION_ID = 1
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        createChannel()
        val address = intent?.getStringExtra(EXTRA_ADDRESS) ?: "remote host"
        val notification = buildNotification(address)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        return START_NOT_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // UI swiped away: do not leave a live streaming session running.
        Thread { runCatching { RustCore.stopStreaming() } }.start()
        stopSelf()
        super.onTaskRemoved(rootIntent)
    }

    private fun createChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Remote desktop session",
            NotificationManager.IMPORTANCE_LOW,
        )
        channel.setShowBadge(false)
        notificationManager().createNotificationChannel(channel)
    }

    private fun buildNotification(address: String): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val disconnect = PendingIntent.getActivity(
            this,
            1,
            Intent(this, MainActivity::class.java)
                .putExtra(MainActivity.EXTRA_DISCONNECT, true)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setContentTitle("Linux Link")
            .setContentText("Streaming to $address")
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    null,
                    "Disconnect",
                    disconnect,
                ).build(),
            )
            .build()
    }

    private fun notificationManager(): NotificationManager =
        getSystemService(NOTIFICATION_SERVICE) as NotificationManager
}
