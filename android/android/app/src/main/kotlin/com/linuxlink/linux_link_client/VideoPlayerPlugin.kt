package com.linuxlink.linux_link_client

import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.Surface
import android.graphics.SurfaceTexture
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.EventChannel
import io.flutter.view.TextureRegistry
import java.nio.ByteBuffer

class VideoPlayerPlugin : FlutterPlugin, MethodChannel.MethodCallHandler, EventChannel.StreamHandler {
    private lateinit var methodChannel: MethodChannel
    private lateinit var eventChannel: EventChannel
    private var eventSink: EventChannel.EventSink? = null
    private var surfaceTexture: SurfaceTexture? = null
    private var surface: Surface? = null
    private var mediaCodec: MediaCodec? = null
    private var textureEntry: TextureRegistry.SurfaceTextureEntry? = null
    private var width: Int = 1920
    private var height: Int = 1080
    private var flutterTextureRegistry: TextureRegistry? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        flutterTextureRegistry = binding.textureRegistry
        
        methodChannel = MethodChannel(binding.binaryMessenger, "com.linuxlink/video_player")
        methodChannel.setMethodCallHandler(this)
        
        eventChannel = EventChannel(binding.binaryMessenger, "com.linuxlink/video_events")
        eventChannel.setStreamHandler(this)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "initialize" -> {
                width = call.argument<Int>("width") ?: 1920
                height = call.argument<Int>("height") ?: 1080
                initializeDecoder(result)
            }
            "feedFrame" -> {
                val data = call.argument<ByteArray>("data")
                feedFrame(data, result)
            }
            "dispose" -> {
                disposeDecoder()
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    private fun initializeDecoder(result: MethodChannel.Result) {
        try {
            // Register a SurfaceTexture with Flutter's texture registry
            textureEntry = flutterTextureRegistry?.createSurfaceTexture()
            surfaceTexture = textureEntry?.surfaceTexture()
            surfaceTexture?.setDefaultBufferSize(width, height)
            surface = Surface(surfaceTexture)

            // Create MediaCodec H.264 decoder
            val format = MediaFormat.createVideoFormat(
                MediaFormat.MIMETYPE_VIDEO_AVC, width, height
            )
            format.setInteger(
                MediaFormat.KEY_COLOR_FORMAT,
                MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface
            )
            
            mediaCodec = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_VIDEO_AVC)
            mediaCodec?.configure(format, surface, null, 0)
            mediaCodec?.start()

            val textureId = textureEntry?.id() ?: -1L
            
            // Notify Flutter of the texture ID
            eventSink?.success(textureId)
            result.success(textureId)
            Log.d("VideoPlayerPlugin", "Decoder initialized: ${width}x${height}, texture=$textureId")
        } catch (e: Exception) {
            Log.e("VideoPlayerPlugin", "Failed to initialize decoder", e)
            result.error("INIT_FAILED", e.message, null)
        }
    }

    private fun feedFrame(data: ByteArray?, result: MethodChannel.Result) {
        if (data == null || data.isEmpty()) {
            result.success(null)
            return
        }

        try {
            val codec = mediaCodec ?: run {
                result.error("NOT_INITIALIZED", "Decoder not initialized", null)
                return
            }

            val inputBufferIndex = codec.dequeueInputBuffer(10000)
            if (inputBufferIndex >= 0) {
                val inputBuffer = codec.getInputBuffer(inputBufferIndex)
                inputBuffer?.clear()
                inputBuffer?.put(data)
                
                val presentationTimeUs = System.nanoTime() / 1000L
                codec.queueInputBuffer(
                    inputBufferIndex, 0, data.size, presentationTimeUs, 0
                )
            }

            // Process output buffers
            processOutputBuffers()
            
            result.success(null)
        } catch (e: Exception) {
            Log.e("VideoPlayerPlugin", "Failed to feed frame", e)
            result.error("FRAME_ERROR", e.message, null)
        }
    }

    private fun processOutputBuffers() {
        val codec = mediaCodec ?: return
        val bufferInfo = MediaCodec.BufferInfo()
        
        var outputBufferIndex = codec.dequeueOutputBuffer(bufferInfo, 0)
        while (outputBufferIndex >= 0) {
            codec.releaseOutputBuffer(outputBufferIndex, true)
            outputBufferIndex = codec.dequeueOutputBuffer(bufferInfo, 0)
        }
    }

    private fun disposeDecoder() {
        try {
            mediaCodec?.stop()
            mediaCodec?.release()
            mediaCodec = null
            surface?.release()
            surface = null
            surfaceTexture?.release()
            surfaceTexture = null
            textureEntry?.release()
            textureEntry = null
            Log.d("VideoPlayerPlugin", "Decoder disposed")
        } catch (e: Exception) {
            Log.e("VideoPlayerPlugin", "Error disposing decoder", e)
        }
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        eventSink = events
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
        disposeDecoder()
    }
}
