package dev.linuxlink.android

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.TextView
import androidx.activity.ComponentActivity
import dev.linuxlink.android.bridge.RustCore
import java.io.File

/**
 * Share target (Tier 1 #4): text shares go to the desktop clipboard, file
 * shares stream to the server's `~/Downloads` over the KDE Connect control
 * channel (same pattern as the server Share plugin, reversed).
 *
 * Requires a saved host ([HostStore]) — the shared item never picks a
 * destination itself.
 */
class ShareActivity : ComponentActivity() {
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        RustCore.start(filesDir)
        status = TextView(this).apply {
            setPadding(48, 96, 48, 48)
            textSize = 16f
        }
        setContentView(status)

        val host = HostStore.lastHost(this)
        if (host == null) {
            status.text = getString(R.string.share_no_host)
            return
        }

        val text =
            if (intent.type == "text/plain") intent.getStringExtra(Intent.EXTRA_TEXT) else null
        val uri = @Suppress("DEPRECATION") intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)

        when {
            uri != null -> sendFile(host, uri)
            !text.isNullOrBlank() -> sendText(host, text)
            else -> status.text = getString(R.string.share_nothing)
        }
    }

    private fun sendText(
        host: HostStore.Host,
        text: String,
    ) {
        status.text = getString(R.string.share_sending_text, host.address)
        Thread {
            val result = RustCore.sendClipboard(host.address, host.controlPort, text)
            runOnUiThread {
                status.text =
                    if (result.isSuccess) {
                        getString(R.string.share_sent_clipboard)
                    } else {
                        getString(R.string.share_failed, result.exceptionOrNull()?.message)
                    }
                finish()
            }
        }.start()
    }

    private fun sendFile(
        host: HostStore.Host,
        uri: Uri,
    ) {
        status.text = getString(R.string.share_preparing, displayName(uri))
        Thread {
            val temp = File(cacheDir, "share/" + displayName(uri))
            temp.parentFile?.mkdirs()
            val result =
                try {
                    contentResolver.openInputStream(uri).use { input ->
                        requireNotNull(input) { "content stream unavailable" }
                        temp.outputStream().use { output -> input.copyTo(output) }
                    }
                    RustCore.sendFile(host.address, host.controlPort, temp.absolutePath)
                } catch (e: Exception) {
                    Result.failure(e)
                } finally {
                    temp.delete()
                }
            runOnUiThread {
                status.text =
                    if (result.isSuccess) {
                        getString(R.string.share_sent_file, temp.name)
                    } else {
                        getString(R.string.share_failed, result.exceptionOrNull()?.message)
                    }
                finish()
            }
        }.start()
    }

    private fun displayName(uri: Uri): String {
        val fromProvider =
            contentResolver
                .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { cursor ->
                    if (cursor.moveToFirst()) cursor.getString(0) else null
                }
        val name = fromProvider ?: uri.lastPathSegment?.substringAfterLast('/') ?: "shared.bin"
        return name.replace(Regex("""[^A-Za-z0-9._ -]"""), "_").ifBlank { "shared.bin" }
    }
}
