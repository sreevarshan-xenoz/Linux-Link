package dev.linuxlink.android.bridge

object RustCore {
    init {
        System.loadLibrary("linux_link_android_bridge")
    }

    private external fun nativeVersion(): String

    val version: String
        get() = nativeVersion()
}
