package com.linuxlink.linux_link_client

import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioTrack
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.MediaMuxer
import android.os.Build
import android.os.Environment
import android.util.Log
import android.view.Surface
import android.graphics.SurfaceTexture
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.EventChannel
import io.flutter.view.TextureRegistry
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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
    private var mimeType: String? = null
    private var flutterTextureRegistry: TextureRegistry? = null

    // F5: Session Recording state
    private var isRecording = false
    private var mediaMuxer: MediaMuxer? = null
    private var videoTrackIndex = -1
    private var outputFile: File? = null
    private var recordFileStream: FileOutputStream? = null

    // F1: Audio Streaming state
    private var audioTrack: AudioTrack? = null
    private var audioDecoder: MediaCodec? = null
    private var audioSampleRate: Int = 48000
    private var audioChannels: Int = 2
    private var isAudioPlaying = false

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
                mimeType = call.argument<String>("codecType")
                initializeDecoder(result)
            }
            "feedFrame" -> {
                val data = call.argument<ByteArray>("data")
                feedFrame(data, result)
            }
            "dispose" -> {
                stopRecording()
                disposeDecoder()
                result.success(null)
            }
            // F5: Recording methods
            "startRecording" -> {
                startRecording(result)
            }
            "stopRecording" -> {
                stopRecording()
                result.success(outputFile?.absolutePath)
            }
            "feedFrameToRecord" -> {
                val data = call.argument<ByteArray>("data")
                val isKeyframe = call.argument<Boolean>("isKeyframe") ?: false
                feedFrameToRecord(data, isKeyframe)
                result.success(null)
            }
            // F1: Audio Streaming methods
            "startAudio" -> {
                val sampleRate = call.argument<Int>("sampleRate") ?: 48000
                val channels = call.argument<Int>("channels") ?: 2
                startAudio(sampleRate, channels, result)
            }
            "feedAudioPacket" -> {
                val data = call.argument<ByteArray>("data")
                feedAudioPacket(data, result)
            }
            "stopAudio" -> {
                stopAudio()
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

            // Resolve codec MIME type (default: H.264)
            val videoMime = mimeType ?: MediaFormat.MIMETYPE_VIDEO_AVC

            // Create MediaCodec decoder for the detected codec
            val format = MediaFormat.createVideoFormat(videoMime, width, height)
            format.setInteger(
                MediaFormat.KEY_COLOR_FORMAT,
                MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface
            )
            
            mediaCodec = MediaCodec.createDecoderByType(videoMime)
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

    private fun startRecording(result: MethodChannel.Result) {
        try {
            val moviesDir = Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_MOVIES
            )
            val linuxLinkDir = File(moviesDir, "LinuxLink")
            if (!linuxLinkDir.exists()) {
                linuxLinkDir.mkdirs()
            }
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            outputFile = File(linuxLinkDir, "LinuxLink_$timestamp.mp4")
            
            // For simplicity, we write raw H.264 to a file first, then mux on stop
            // Write annex-b format with start codes
            recordFileStream = FileOutputStream(outputFile)
            isRecording = true
            Log.d("VideoPlayerPlugin", "Recording started: ${outputFile?.absolutePath}")
            result.success(outputFile?.absolutePath)
        } catch (e: Exception) {
            Log.e("VideoPlayerPlugin", "Failed to start recording", e)
            result.error("RECORD_START_FAILED", e.message, null)
        }
    }

    private fun stopRecording() {
        if (!isRecording) return
        isRecording = false
        try {
            recordFileStream?.flush()
            recordFileStream?.close()
            recordFileStream = null
            Log.d("VideoPlayerPlugin", "Recording stopped: ${outputFile?.absolutePath}")
        } catch (e: Exception) {
            Log.e("VideoPlayerPlugin", "Error stopping recording", e)
        }
    }

    private fun feedFrameToRecord(data: ByteArray?, isKeyframe: Boolean) {
        if (!isRecording || data == null || data.isEmpty()) return
        try {
            val stream = recordFileStream ?: return
            // Write Annex B start code (0x00 0x00 0x00 0x01)
            stream.write(byteArrayOf(0x00, 0x00, 0x00, 0x01))
            stream.write(data)
        } catch (e: Exception) {
            Log.e("VideoPlayerPlugin", "Error writing frame to recording", e)
        }
    }

    // -----------------------------------------------------------------------
    // F1: Audio Streaming — Opus decode via MediaCodec → AudioTrack playback
    // -----------------------------------------------------------------------

    private fun startAudio(sampleRate: Int, channels: Int, result: MethodChannel.Result) {
        try {
            audioSampleRate = sampleRate
            audioChannels = channels

            // Create AudioTrack for PCM playback
            val channelConfig = if (channels == 1) {
                AudioFormat.CHANNEL_OUT_MONO
            } else {
                AudioFormat.CHANNEL_OUT_STEREO
            }

            val bufferSize = AudioTrack.getMinBufferSize(
                sampleRate,
                channelConfig,
                AudioFormat.ENCODING_PCM_16BIT
            ).coerceAtLeast(64 * 1024) // Minimum 64KB buffer

            val attrs = AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_MEDIA)
                .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                .build()

            val format = AudioFormat.Builder()
                .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                .setSampleRate(sampleRate)
                .setChannelMask(channelConfig)
                .build()

            audioTrack = AudioTrack.Builder()
                .setAudioAttributes(attrs)
                .setAudioFormat(format)
                .setBufferSizeInBytes(bufferSize)
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build()

            audioTrack?.play()

            // Create Opus decoder via MediaCodec (supported since API 21)
            val mimeType = MediaFormat.MIMETYPE_AUDIO_OPUS
            val mediaFormat = MediaFormat.createAudioFormat(mimeType, sampleRate, channels)

            // Opus requires codec-specific data for the ID header
            // See: https://opus-codec.org/docs/opus_in_isobmff.html
            val csd0 = ByteBuffer.allocate(8)
            // OpusHead identifier
            csd0.put("OpusHead".toByteArray())
            // Version 1
            csd0.put(1)
            // Output channel count
            csd0.put(channels.toByte())
            // Pre-skip (2 bytes, little-endian)
            csd0.putShort(312) // 312 samples pre-skip @ 48kHz
            // Input sample rate (4 bytes, little-endian) 48000 Hz
            csd0.putInt(48000)
            // Output gain (2 bytes, little-endian) 0 dB
            csd0.putShort(0)
            // Channel mapping family (1 byte) 0 = RTP mapping
            csd0.put(0)
            csd0.rewind()
            mediaFormat.setByteBuffer("csd-0", csd0)

            audioDecoder = MediaCodec.createDecoderByType(mimeType)
            audioDecoder?.configure(mediaFormat, null, null, 0)
            audioDecoder?.start()

            isAudioPlaying = true
            Log.d("VideoPlayerPlugin", "Audio started: ${sampleRate}Hz, ${channels}ch")
            result.success(null)
        } catch (e: Exception) {
            Log.e("VideoPlayerPlugin", "Failed to start audio", e)
            result.error("AUDIO_START_FAILED", e.message, null)
        }
    }

    private fun feedAudioPacket(data: ByteArray?, result: MethodChannel.Result) {
        if (!isAudioPlaying || data == null || data.isEmpty()) {
            result.success(null)
            return
        }

        try {
            val decoder = audioDecoder ?: run {
                result.error("AUDIO_NOT_INITIALIZED", "Audio decoder not started", null)
                return
            }
            val track = audioTrack ?: run {
                result.error("AUDIO_NOT_INITIALIZED", "AudioTrack not started", null)
                return
            }

            // Feed Opus packet to decoder input
            val inputBufferIndex = decoder.dequeueInputBuffer(10000)
            if (inputBufferIndex >= 0) {
                val inputBuffer = decoder.getInputBuffer(inputBufferIndex)
                inputBuffer?.clear()
                inputBuffer?.put(data)
                val presentationTimeUs = System.nanoTime() / 1000L
                decoder.queueInputBuffer(
                    inputBufferIndex, 0, data.size, presentationTimeUs, 0
                )
            }

            // Drain decoded PCM output to AudioTrack
            val bufferInfo = MediaCodec.BufferInfo()
            var outputBufferIndex = decoder.dequeueOutputBuffer(bufferInfo, 0)
            while (outputBufferIndex >= 0) {
                val outputBuffer = decoder.getOutputBuffer(outputBufferIndex)
                if (outputBuffer != null && bufferInfo.size > 0) {
                    val pcmData = ByteArray(bufferInfo.size)
                    outputBuffer.position(bufferInfo.offset)
                    outputBuffer.get(pcmData, 0, bufferInfo.size)
                    track.write(pcmData, 0, bufferInfo.size)
                }
                decoder.releaseOutputBuffer(outputBufferIndex, false)
                outputBufferIndex = decoder.dequeueOutputBuffer(bufferInfo, 0)
            }

            result.success(null)
        } catch (e: Exception) {
            Log.e("VideoPlayerPlugin", "Audio packet error", e)
            result.error("AUDIO_PACKET_ERROR", e.message, null)
        }
    }

    private fun stopAudio() {
        isAudioPlaying = false
        try {
            audioDecoder?.stop()
            audioDecoder?.release()
            audioDecoder = null
        } catch (e: Exception) {
            Log.e("VideoPlayerPlugin", "Error stopping audio decoder", e)
        }
        try {
            audioTrack?.stop()
            audioTrack?.release()
            audioTrack = null
        } catch (e: Exception) {
            Log.e("VideoPlayerPlugin", "Error stopping AudioTrack", e)
        }
        Log.d("VideoPlayerPlugin", "Audio stopped")
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
        stopRecording()
        stopAudio()
        disposeDecoder()
    }
}
