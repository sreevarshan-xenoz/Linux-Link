//! H.264 video encoder using FFmpeg
//!
//! Encodes raw BGRA frames to H.264 NAL units via ffmpeg-sidecar.

use tracing::warn;

use super::{EncodedPacket, EncoderPreset, H264Profile, StreamingConfig, VideoFrame};

/// H.264 encoder wrapper
pub struct VideoEncoder {
    config: StreamingConfig,
    sequence: u64,
    keyframe_interval: u64,
    frames_since_keyframe: u64,
}

impl VideoEncoder {
    /// Create a new encoder with the given configuration
    pub fn new(config: StreamingConfig) -> Self {
        let keyframe_interval = config.fps as u64 * 2; // Keyframe every 2 seconds
        Self {
            config: config.clone(),
            sequence: 0,
            keyframe_interval,
            frames_since_keyframe: 0,
        }
    }

    /// Encode a single raw frame to H.264
    ///
    /// Note: For production use, a persistent encoder that reuses the FFmpeg
    /// process is more efficient than spawning a new process per frame.
    /// This implementation documents the architecture for the streaming pipeline.
    pub fn encode_frame(&mut self, frame: &VideoFrame) -> anyhow::Result<Option<EncodedPacket>> {
        // For real-time streaming, we need a persistent encoder process.
        // The ffmpeg-sidecar approach works best with a long-running process
        // that accepts raw frames via stdin and outputs H.264 via stdout.
        //
        // A full implementation would use:
        // - A persistent FFmpeg process with pipe input/output
        // - Non-blocking I for frame submission and packet retrieval
        // - Proper handling of encoder latency and frame reordering

        self.frames_since_keyframe += 1;
        let is_keyframe = self.frames_since_keyframe >= self.keyframe_interval;

        if is_keyframe {
            self.frames_since_keyframe = 0;
        }

        // TODO: Implement actual encoding with persistent FFmpeg process
        // For now, return the raw frame data as a placeholder packet
        // This allows the streaming pipeline to be tested end-to-end

        warn!("Encoder not fully implemented - returning raw frame data");
        let packet = EncodedPacket {
            data: frame.data.clone(),
            is_keyframe,
            timestamp: frame.timestamp,
            sequence: self.sequence,
        };

        self.sequence += 1;
        Ok(Some(packet))
    }

    /// Get the FFmpeg command line for encoding
    ///
    /// This documents the intended FFmpeg configuration for the streaming pipeline.
    #[allow(dead_code)]
    fn build_ffmpeg_args(&self) -> Vec<String> {
        let profile_str = match self.config.profile {
            H264Profile::Baseline => "baseline".to_string(),
            H264Profile::Main => "main".to_string(),
            H264Profile::High => "high".to_string(),
        };

        let preset_str = match self.config.preset {
            EncoderPreset::UltraFast => "ultrafast".to_string(),
            EncoderPreset::SuperFast => "superfast".to_string(),
            EncoderPreset::VeryFast => "veryfast".to_string(),
            EncoderPreset::Faster => "faster".to_string(),
            EncoderPreset::Fast => "fast".to_string(),
            EncoderPreset::Medium => "medium".to_string(),
            EncoderPreset::Slow => "slow".to_string(),
        };

        // FFmpeg command for encoding raw frames to H.264
        // Input: raw video from stdin (pipe:0)
        // Output: H.264 to stdout (pipe:1)
        vec![
            "-f".to_string(),
            "rawvideo".to_string(),
            "-pix_fmt".to_string(),
            "bgra".to_string(),
            "-s".to_string(),
            format!("{}x{}", self.config.width, self.config.height),
            "-r".to_string(),
            self.config.fps.to_string(),
            "-c:v".to_string(),
            "libx264".to_string(),
            "-profile:v".to_string(),
            profile_str,
            "-preset".to_string(),
            preset_str,
            "-b:v".to_string(),
            format!("{}", self.config.bitrate_bps),
            "-x264-params".to_string(),
            format!("keyint={}:min-keyint=1", self.config.fps * 2),
            "-f".to_string(),
            "h264".to_string(),
            "pipe:1".to_string(),
        ]
    }

    /// Request a keyframe on the next encode
    pub fn request_keyframe(&mut self) {
        self.frames_since_keyframe = self.keyframe_interval;
    }

    /// Get the current sequence number
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Get the encoding configuration
    pub fn config(&self) -> &StreamingConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::capture::create_test_frame;

    #[test]
    fn test_encoder_creation() {
        let config = StreamingConfig::default();
        let encoder = VideoEncoder::new(config);
        assert_eq!(encoder.sequence(), 0);
        assert_eq!(encoder.config().width, 1920);
    }

    #[test]
    fn test_encode_frame_passthrough() {
        let config = StreamingConfig::default();
        let mut encoder = VideoEncoder::new(config);
        let frame = create_test_frame(1920, 1080);

        let packet = encoder.encode_frame(&frame).unwrap();
        assert!(packet.is_some());
        let packet = packet.unwrap();
        assert_eq!(packet.sequence, 0);
        assert!(!packet.data.is_empty());
    }

    #[test]
    fn test_keyframe_interval() {
        let mut config = StreamingConfig::default();
        config.fps = 30;
        let mut encoder = VideoEncoder::new(config);

        // Keyframe every 2 seconds = 60 frames
        assert_eq!(encoder.keyframe_interval, 60);

        // Encode 61 frames and check keyframe flag
        for i in 0..61 {
            let frame = create_test_frame(1920, 1080);
            let packet = encoder.encode_frame(&frame).unwrap().unwrap();
            if i == 59 {
                // 60th frame (index 59) should be keyframe
                assert!(packet.is_keyframe, "Frame {} should be keyframe", i);
            } else if i > 0 && i < 59 {
                assert!(!packet.is_keyframe, "Frame {} should not be keyframe", i);
            }
        }
    }

    #[test]
    fn test_request_keyframe() {
        let config = StreamingConfig::default();
        let mut encoder = VideoEncoder::new(config);

        // Request immediate keyframe
        encoder.request_keyframe();

        let frame = create_test_frame(1920, 1080);
        let packet = encoder.encode_frame(&frame).unwrap().unwrap();
        assert!(packet.is_keyframe, "Requested keyframe should be keyframe");
    }
}
