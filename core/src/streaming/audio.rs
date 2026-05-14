//! Audio capture, encoding, and streaming support (F1: Audio Streaming).
//!
//! Provides:
//! - [`AudioConfig`] — sample rate, channels, bitrate configuration
//! - [`AudioPacket`] — encoded audio data with metadata
//! - [`AudioEncoder`] — Opus encoder wrapping the `opus` crate
//! - Simple PCM buffer types for feeding captured audio

use anyhow::{Context, Result};

/// Audio configuration for capture and encoding.
#[derive(Debug, Clone, Copy)]
pub struct AudioConfig {
    /// Sample rate in Hz (e.g. 48000)
    pub sample_rate: u32,
    /// Number of channels (1 = mono, 2 = stereo)
    pub channels: u16,
    /// Target bitrate in bits per second (e.g. 64000 for 64 kbps)
    pub bitrate_bps: u32,
    /// Frame duration in milliseconds (Opus frame sizes: 2.5, 5, 10, 20, 40, 60)
    pub frame_duration_ms: u32,
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            sample_rate: 48000,
            channels: 2,
            bitrate_bps: 64_000,   // 64 kbps stereo Opus
            frame_duration_ms: 20, // 20 ms frames
        }
    }
}

impl AudioConfig {
    /// Number of PCM samples per frame at the configured frame duration.
    pub fn samples_per_frame(&self) -> usize {
        (self.sample_rate as usize * self.frame_duration_ms as usize) / 1000
    }

    /// Size of a PCM buffer (in bytes) for one frame.
    /// Each sample is 2 bytes (s16le).
    pub fn frame_buffer_size(&self) -> usize {
        self.samples_per_frame() * self.channels as usize * 2
    }
}

/// An encoded audio packet ready for transmission.
#[derive(Debug, Clone)]
pub struct AudioPacket {
    /// Encoded Opus data
    pub data: Vec<u8>,
    /// Sequence number for ordering
    pub sequence: u64,
    /// Timestamp of capture (monotonic clock)
    pub timestamp: std::time::Instant,
    /// Whether this is a codec configuration packet (may be empty)
    pub is_config: bool,
}

/// Opus audio encoder wrapping the `opus` crate.
pub struct AudioEncoder {
    encoder: Option<opus::Encoder>,
    sequence: u64,
    config: AudioConfig,
}

impl AudioEncoder {
    /// Create a new Opus encoder with the given configuration.
    pub fn new(config: AudioConfig) -> Result<Self> {
        let mut encoder = opus::Encoder::new(
            config.sample_rate,
            if config.channels == 1 {
                opus::Channels::Mono
            } else {
                opus::Channels::Stereo
            },
            opus::Application::Audio,
        )
        .context("Failed to create Opus encoder")?;

        // Set bitrate
        encoder
            .set_bitrate(opus::Bitrate::Bits(config.bitrate_bps as i32))
            .context("Failed to set Opus bitrate")?;

        // Enable VBR for variable bitrate (better quality at low bitrate)
        encoder.set_vbr(true).context("Failed to set Opus VBR")?;

        // Enable in-band FEC (forward error correction) for robustness
        encoder
            .set_inband_fec(true)
            .context("Failed to set Opus FEC")?;

        // Set expected packet loss percentage (conservative: 5%)
        encoder
            .set_packet_loss_perc(5)
            .context("Failed to set Opus packet loss")?;

        Ok(Self {
            encoder: Some(encoder),
            sequence: 0,
            config,
        })
    }

    /// Encode a PCM frame into an Opus packet.
    ///
    /// `pcm_data` must be s16le interleaved PCM data at the configured
    /// sample rate and number of channels. The expected size is
    /// `config.frame_buffer_size()`.
    pub fn encode(&mut self, pcm_data: &[i16]) -> Result<Option<AudioPacket>> {
        let encoder = self.encoder.as_mut().context("Encoder has been consumed")?;

        let max_packet_size = 4000; // Opus max packet is 4000 bytes
        let mut output = vec![0u8; max_packet_size];

        let result = encoder.encode(pcm_data, &mut output);
        match result {
            Ok(size) => {
                output.truncate(size);
                let packet = AudioPacket {
                    data: output,
                    sequence: self.sequence,
                    timestamp: std::time::Instant::now(),
                    is_config: false,
                };
                self.sequence += 1;
                Ok(Some(packet))
            }
            Err(ref e) if e.code() == opus::ErrorCode::BufferTooSmall => {
                // Shouldn't happen with 4000 byte buffer
                anyhow::bail!("Opus output buffer too small");
            }
            Err(e) => Err(anyhow::anyhow!("Opus encode error: {e:?}")),
        }
    }

    /// Encode a silence frame (for gaps in capture).
    pub fn encode_silence(&mut self) -> Result<Option<AudioPacket>> {
        let frame_samples = self.config.samples_per_frame();
        let silence = vec![0i16; frame_samples * self.config.channels as usize];
        self.encode(&silence)
    }

    /// Get the current configuration.
    pub fn config(&self) -> &AudioConfig {
        &self.config
    }

    /// Reset the sequence counter (useful on stream reconnect).
    pub fn reset_sequence(&mut self) {
        self.sequence = 0;
    }
}

impl Drop for AudioEncoder {
    fn drop(&mut self) {
        // opus::Encoder is automatically cleaned up on drop
        self.encoder.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_config_default() {
        let config = AudioConfig::default();
        assert_eq!(config.sample_rate, 48000);
        assert_eq!(config.channels, 2);
        assert_eq!(config.bitrate_bps, 64_000);
        assert_eq!(config.frame_duration_ms, 20);
    }

    #[test]
    fn test_audio_config_frame_sizes() {
        let config = AudioConfig::default();
        // 48000 Hz * 20ms = 960 samples per frame
        assert_eq!(config.samples_per_frame(), 960);
        // 960 samples * 2 channels * 2 bytes = 3840 bytes per frame
        assert_eq!(config.frame_buffer_size(), 3840);
    }

    #[test]
    fn test_audio_encoder_create() {
        let config = AudioConfig::default();
        let encoder = AudioEncoder::new(config);
        assert!(encoder.is_ok());
    }

    #[test]
    fn test_audio_encoder_encode_silence() {
        let config = AudioConfig::default();
        let mut encoder = AudioEncoder::new(config).unwrap();

        // Encode a silence frame
        let frame_samples = encoder.config().samples_per_frame();
        let silence = vec![0i16; frame_samples * encoder.config().channels as usize];
        let result = encoder.encode(&silence).unwrap();

        assert!(result.is_some());
        let packet = result.unwrap();
        assert!(!packet.data.is_empty());
        assert!(!packet.is_config);
        assert_eq!(packet.sequence, 0);
    }

    #[test]
    fn test_audio_encoder_sequence_increment() {
        let config = AudioConfig::default();
        let mut encoder = AudioEncoder::new(config).unwrap();

        let frame_samples = encoder.config().samples_per_frame();
        let silence = vec![0i16; frame_samples * encoder.config().channels as usize];

        let first = encoder.encode(&silence).unwrap().unwrap();
        assert_eq!(first.sequence, 0);

        let second = encoder.encode(&silence).unwrap().unwrap();
        assert_eq!(second.sequence, 1);

        let third = encoder.encode(&silence).unwrap().unwrap();
        assert_eq!(third.sequence, 2);
    }

    #[test]
    fn test_encode_silence_method() {
        let config = AudioConfig::default();
        let mut encoder = AudioEncoder::new(config).unwrap();
        let result = encoder.encode_silence().unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_reset_sequence() {
        let config = AudioConfig::default();
        let mut encoder = AudioEncoder::new(config).unwrap();

        let frame_samples = encoder.config().samples_per_frame();
        let silence = vec![0i16; frame_samples * encoder.config().channels as usize];

        encoder.encode(&silence).unwrap().unwrap();
        encoder.encode(&silence).unwrap().unwrap();

        encoder.reset_sequence();
        let after = encoder.encode(&silence).unwrap().unwrap();
        assert_eq!(after.sequence, 0);
    }

    #[test]
    fn test_mono_config() {
        let config = AudioConfig {
            channels: 1,
            ..AudioConfig::default()
        };
        assert_eq!(config.samples_per_frame(), 960);
        // 960 samples * 1 channel * 2 bytes = 1920 bytes
        assert_eq!(config.frame_buffer_size(), 1920);

        let encoder = AudioEncoder::new(config);
        assert!(encoder.is_ok());
    }
}
