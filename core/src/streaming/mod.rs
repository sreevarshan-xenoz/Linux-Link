//! Screen capture and streaming module
//!
//! Provides screen capture via PipeWire/XDG Desktop Portal,
//! video encoding via FFmpeg, and QUIC-based streaming transport.

pub mod audio;
pub mod bitrate;
pub mod client;
pub mod encoder_detect;
pub mod input_packet;
pub mod session;
pub mod transport;

// Server-only modules — these require Linux-specific dependencies
#[cfg(feature = "capture")]
pub mod capture;
#[cfg(feature = "capture")]
pub mod capture_x11;
#[cfg(feature = "encode")]
pub mod encoder;
#[cfg(feature = "server")]
pub mod streamer;

pub use audio::{AudioConfig, AudioEncoder, AudioPacket};
pub use bitrate::AdaptiveBitrate;
#[cfg(feature = "capture")]
pub use capture::start_capture_auto;
#[cfg(feature = "capture")]
pub use capture_x11::{check_x11_availability, start_x11_capture};
pub use client::DEFAULT_STREAMING_PORT;
pub use client::StreamingClient;
pub use encoder_detect::{AvailableEncoders, HardwareEncoder, probe_encoders, resolve_encoder};
pub use input_packet::InputPacket;
pub use session::{SessionType, detect_session_type};
#[cfg(feature = "server")]
pub use streamer::StreamingServer;

use serde::{Deserialize, Serialize};

/// Streaming configuration for capture and encoding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingConfig {
    /// Target width in pixels
    pub width: u32,
    /// Target height in pixels
    pub height: u32,
    /// Target frames per second
    pub fps: u32,
    /// Target bitrate in bits per second
    pub bitrate_bps: u32,
    /// Video codec (H.264 or H.265/HEVC)
    pub codec: VideoCodec,
    /// H.264 profile (baseline, main, high)
    pub profile: H264Profile,
    /// Encoder preset (speed vs quality tradeoff)
    pub preset: EncoderPreset,
    /// Hardware encoder selection
    pub hardware_encoder: HardwareEncoder,
    /// Monitor index for multi-monitor support (F2).
    /// 0 = primary monitor.
    pub monitor_index: u32,
}

/// H.264 encoding profile
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum H264Profile {
    Baseline,
    #[default]
    Main,
    High,
}

/// Encoder preset for speed/quality tradeoff
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum EncoderPreset {
    UltraFast,
    SuperFast,
    #[default]
    VeryFast,
    Faster,
    Fast,
    Medium,
    Slow,
}

/// Video codec selection (F3: H.265/HEVC support).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum VideoCodec {
    /// H.264/AVC (widest compatibility)
    #[default]
    H264,
    /// H.265/HEVC (up to 50% bandwidth savings)
    H265,
}

impl VideoCodec {
    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            VideoCodec::H264 => "H.264",
            VideoCodec::H265 => "H.265 (HEVC)",
        }
    }

    /// MIME type for MediaCodec.
    pub fn mime_type(&self) -> &'static str {
        match self {
            VideoCodec::H264 => "video/avc",
            VideoCodec::H265 => "video/hevc",
        }
    }

    /// FFmpeg codec name for encoding.
    pub fn ffmpeg_codec(&self) -> &'static str {
        match self {
            VideoCodec::H264 => "h264",
            VideoCodec::H265 => "hevc",
        }
    }

    /// Bitrate multiplier: H.265 can deliver similar quality at ~50% bitrate.
    pub fn bitrate_multiplier(&self) -> f64 {
        match self {
            VideoCodec::H264 => 1.0,
            VideoCodec::H265 => 0.5,
        }
    }
}

/// User-facing video quality preset with concrete encoding parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum VideoQualityPreset {
    /// 720p, 2 Mbps, veryfast encoder preset
    Low,
    /// 1080p, 5 Mbps, superfast encoder preset
    #[default]
    Balanced,
    /// 1080p, 10 Mbps, medium encoder preset
    High,
}

impl VideoQualityPreset {
    /// Convert to a `StreamingConfig` with appropriate parameters.
    pub fn to_streaming_config(&self) -> StreamingConfig {
        match self {
            VideoQualityPreset::Low => StreamingConfig {
                width: 1280,
                height: 720,
                fps: 30,
                bitrate_bps: 2_000_000,
                preset: EncoderPreset::VeryFast,
                ..StreamingConfig::default()
            },
            VideoQualityPreset::Balanced => StreamingConfig {
                width: 1920,
                height: 1080,
                fps: 60,
                bitrate_bps: 5_000_000,
                preset: EncoderPreset::SuperFast,
                ..StreamingConfig::default()
            },
            VideoQualityPreset::High => StreamingConfig {
                width: 1920,
                height: 1080,
                fps: 60,
                bitrate_bps: 10_000_000,
                preset: EncoderPreset::Medium,
                ..StreamingConfig::default()
            },
        }
    }
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_bps: 8_000_000, // 8 Mbps
            codec: VideoCodec::H264,
            profile: H264Profile::Main,
            preset: EncoderPreset::VeryFast,
            hardware_encoder: HardwareEncoder::Auto,
            monitor_index: 0,
        }
    }
}

/// Runtime statistics for an active streaming session.
#[derive(Debug, Clone, Default)]
pub struct StreamingStats {
    /// Current output framerate in frames per second.
    pub fps: f64,
    /// Current encoder bitrate in kilobits per second.
    pub bitrate_kbps: u64,
    /// End-to-end latency from capture to render in milliseconds.
    pub e2e_latency_ms: u64,
    /// Frames dropped due to channel full.
    pub frame_drops: u64,
}

/// A captured video frame with metadata
#[derive(Debug)]
pub struct VideoFrame {
    /// Raw frame data (BGRA format from PipeWire)
    pub data: Vec<u8>,
    /// Frame width
    pub width: u32,
    /// Frame height
    pub height: u32,
    /// Frame stride (bytes per row)
    pub stride: u32,
    /// Frame timestamp (monotonic clock)
    pub timestamp: std::time::Instant,
}

/// Encoded video packet ready for transmission
#[derive(Debug)]
pub struct EncodedPacket {
    /// Encoded frame data (H.264 NAL units)
    pub data: Vec<u8>,
    /// Whether this is a keyframe
    pub is_keyframe: bool,
    /// Frame timestamp (monotonic clock)
    pub timestamp: std::time::Instant,
    /// Sequence number for ordering
    pub sequence: u64,
}
