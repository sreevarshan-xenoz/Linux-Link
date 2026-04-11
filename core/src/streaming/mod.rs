//! Screen capture and streaming module
//!
//! Provides screen capture via PipeWire/XDG Desktop Portal,
//! video encoding via FFmpeg, and QUIC-based streaming transport.

pub mod bitrate;
pub mod capture;
pub mod client;
pub mod encoder;
pub mod streamer;
pub mod transport;

pub use bitrate::AdaptiveBitrate;
pub use client::StreamingClient;
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
    /// H.264 profile (baseline, main, high)
    pub profile: H264Profile,
    /// Encoder preset (speed vs quality tradeoff)
    pub preset: EncoderPreset,
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
            profile: H264Profile::Main,
            preset: EncoderPreset::VeryFast,
        }
    }
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
