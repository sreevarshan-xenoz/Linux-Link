//! H.264 video encoder using FFmpeg
//!
//! Encodes raw BGRA frames to H.264 NAL units via a persistent FFmpeg sidecar process.
//! Frames are submitted via stdin (pipe:0) and encoded packets are read from stdout (pipe:1).

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::io::AsRawFd;
use std::process::{ChildStderr, ChildStdin, ChildStdout};
use std::time::Instant;

use ffmpeg_sidecar::child::FfmpegChild;
use ffmpeg_sidecar::command::FfmpegCommand;
use tracing::{debug, error, info, trace, warn};

use super::{EncodedPacket, EncoderPreset, H264Profile, StreamingConfig, VideoFrame};

/// Set a file descriptor to non-blocking mode.
fn set_nonblocking(stream: &impl AsRawFd) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Magic bytes for H.264 NAL unit start codes.
const START_CODE_4: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
const START_CODE_3: [u8; 3] = [0x00, 0x00, 0x01];

/// NAL unit type for IDR (instantaneous decoder refresh / keyframe).
const NAL_TYPE_IDR: u8 = 5;

/// Mask to extract NAL unit type from the first byte.
const NAL_TYPE_MASK: u8 = 0x1F;

/// H.264 encoder wrapper using a persistent FFmpeg sidecar process.
///
/// The encoder spawns a single long-running FFmpeg process on creation.
/// Raw BGRA frames are written to stdin and H.264 NAL units are read from stdout.
pub struct VideoEncoder {
    config: StreamingConfig,
    sequence: u64,
    keyframe_interval: u64,
    frames_since_keyframe: u64,
    /// The FFmpeg child process.
    process: FfmpegChild,
    /// Stdin pipe for submitting raw frames. Wrapped in Option for clean shutdown.
    stdin: Option<ChildStdin>,
    /// Stdout pipe for reading encoded packets.
    stdout: ChildStdout,
    /// Stderr reader for FFmpeg log messages (consumed in background).
    stderr: BufReader<ChildStderr>,
    /// Accumulated output buffer from stdout.
    output_buffer: Vec<u8>,
}

impl VideoEncoder {
    /// Create a new encoder with the given configuration.
    ///
    /// Spawns a persistent FFmpeg process that accepts raw BGRA frames on stdin
    /// and outputs H.264 NAL units on stdout.
    pub fn new(config: StreamingConfig) -> anyhow::Result<Self> {
        let keyframe_interval = config.fps as u64 * 2; // Keyframe every 2 seconds

        let args = build_ffmpeg_args(&config, keyframe_interval);
        debug!(
            "Spawning FFmpeg encoder: {}x{}@{}fps, profile={:?}, preset={:?}, bitrate={}",
            config.width,
            config.height,
            config.fps,
            config.profile,
            config.preset,
            config.bitrate_bps
        );
        trace!("FFmpeg args: {:?}", args);

        let mut command = FfmpegCommand::new();
        for arg in &args {
            command.arg(arg);
        }

        let mut process = command
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn FFmpeg process: {}", e))?;

        let stdin = process
            .take_stdin()
            .ok_or_else(|| anyhow::anyhow!("FFmpeg stdin not available"))?;

        let stdout = process
            .take_stdout()
            .ok_or_else(|| anyhow::anyhow!("FFmpeg stdout not available"))?;

        let stderr = process
            .take_stderr()
            .ok_or_else(|| anyhow::anyhow!("FFmpeg stderr not available"))?;

        // Set stdout and stderr to non-blocking mode so we can read without blocking
        set_nonblocking(&stdout)
            .map_err(|e| anyhow::anyhow!("Failed to set FFmpeg stdout to non-blocking: {}", e))?;
        set_nonblocking(&stderr)
            .map_err(|e| anyhow::anyhow!("Failed to set FFmpeg stderr to non-blocking: {}", e))?;

        info!("FFmpeg encoder process spawned successfully");

        Ok(Self {
            config: config.clone(),
            sequence: 0,
            keyframe_interval,
            frames_since_keyframe: 0,
            process,
            stdin: Some(stdin),
            stdout,
            stderr: BufReader::new(stderr),
            output_buffer: Vec::with_capacity(64 * 1024), // 64 KB initial capacity
        })
    }

    /// Encode a single raw frame to H.264.
    ///
    /// Writes the frame data to FFmpeg stdin and reads any available encoded
    /// packets from stdout. Returns `None` if no output is ready yet (encoder latency).
    pub fn encode_frame(&mut self, frame: &VideoFrame) -> anyhow::Result<Option<EncodedPacket>> {
        self.frames_since_keyframe += 1;
        let is_keyframe_requested = self.frames_since_keyframe >= self.keyframe_interval;

        if is_keyframe_requested {
            self.frames_since_keyframe = 0;
        }

        let frame_sequence = self.sequence;

        let stdin = self.stdin.as_mut().expect("stdin closed");
        stdin.write_all(&frame.data).map_err(|e| {
            error!("Failed to write frame to FFmpeg stdin: {}", e);
            anyhow::anyhow!("FFmpeg stdin write error: {}", e)
        })?;

        stdin.flush().map_err(|e| {
            error!("Failed to flush FFmpeg stdin: {}", e);
            anyhow::anyhow!("FFmpeg stdin flush error: {}", e)
        })?;

        trace!(
            "Submitted frame #{} to FFmpeg ({} bytes)",
            frame_sequence,
            frame.data.len()
        );

        self.sequence += 1;

        // Read any available encoded output from stdout (non-blocking)
        self.read_available_output()?;

        // Parse the output buffer into NAL-delimited packets
        if let Some(packet_data) = self.extract_next_packet() {
            let is_keyframe = is_keyframe_requested || detect_keyframe(&packet_data);

            let packet = EncodedPacket {
                data: packet_data,
                is_keyframe,
                timestamp: frame.timestamp,
                sequence: frame_sequence,
            };

            trace!(
                "Encoded packet for frame #{}: {} bytes, keyframe={}",
                frame_sequence,
                packet.data.len(),
                packet.is_keyframe
            );

            return Ok(Some(packet));
        }

        // No output ready yet — FFmpeg may have internal buffering latency
        trace!(
            "No encoded output ready for frame #{} (encoder latency)",
            frame_sequence
        );
        Ok(None)
    }

    /// Drain remaining output from the FFmpeg process.
    ///
    /// Reads all available data from stdout and returns any complete packets.
    pub fn drain(&mut self) -> anyhow::Result<Vec<EncodedPacket>> {
        let mut packets = Vec::new();

        // Read all remaining stdout data
        self.read_all_output()?;

        // Extract all complete packets from the buffer
        while let Some(packet_data) = self.extract_next_packet() {
            let is_keyframe = detect_keyframe(&packet_data);
            let packet = EncodedPacket {
                data: packet_data,
                is_keyframe,
                timestamp: Instant::now(),
                sequence: self.sequence,
            };
            self.sequence += 1;
            packets.push(packet);
        }

        debug!("Drained {} remaining packets from encoder", packets.len());
        Ok(packets)
    }

    /// Request a keyframe on the next encode.
    pub fn request_keyframe(&mut self) {
        self.frames_since_keyframe = self.keyframe_interval;
    }

    /// Get the current sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Get the encoding configuration.
    pub fn config(&self) -> &StreamingConfig {
        &self.config
    }

    /// Read available data from FFmpeg stdout without blocking.
    fn read_available_output(&mut self) -> anyhow::Result<()> {
        // Also consume any stderr messages to prevent pipe buffer fill-up
        self.consume_stderr();

        let mut buf = [0u8; 8192];
        loop {
            match self.stdout.read(&mut buf) {
                Ok(0) => {
                    // EOF — process may have exited
                    debug!("FFmpeg stdout returned EOF");
                    break;
                }
                Ok(n) => {
                    self.output_buffer.extend_from_slice(&buf[..n]);
                    trace!(
                        "Read {} bytes from FFmpeg stdout (total buffer: {})",
                        n,
                        self.output_buffer.len()
                    );
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No more data available right now
                    break;
                }
                Err(e) => {
                    // Other errors may indicate process issues.
                    error!("Error reading from FFmpeg stdout: {}", e);
                    return Err(anyhow::anyhow!("FFmpeg stdout read error: {}", e));
                }
            }
        }
        Ok(())
    }

    /// Consume available stderr messages from FFmpeg.
    fn consume_stderr(&mut self) {
        let mut line = String::new();
        loop {
            line.clear();
            match self.stderr.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        // FFmpeg writes warnings/errors to stderr
                        if trimmed.contains("[error]") || trimmed.contains("[fatal]") {
                            error!("[ffmpeg] {}", trimmed);
                        } else if trimmed.contains("[warning]") {
                            warn!("[ffmpeg] {}", trimmed);
                        } else {
                            debug!("[ffmpeg] {}", trimmed);
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    break;
                }
                Err(e) => {
                    trace!("FFmpeg stderr read error (non-critical): {}", e);
                    break;
                }
            }
        }
    }

    /// Read all remaining output from FFmpeg stdout.
    fn read_all_output(&mut self) -> anyhow::Result<()> {
        self.consume_stderr();
        let mut buf = [0u8; 8192];
        loop {
            match self.stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    self.output_buffer.extend_from_slice(&buf[..n]);
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    break;
                }
                Err(e) => {
                    warn!("Error draining FFmpeg stdout: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Extract the next complete H.264 packet from the output buffer.
    ///
    /// H.264 NAL units are delimited by start codes. This function finds
    /// the first complete NAL unit (or group of NAL units) and removes
    /// it from the buffer, returning the raw data.
    fn extract_next_packet(&mut self) -> Option<Vec<u8>> {
        if self.output_buffer.is_empty() {
            return None;
        }

        // Find the first start code in the buffer
        let first_start = find_start_code(&self.output_buffer, 0)?;

        // Find the next start code after the first one
        let second_start = find_start_code(&self.output_buffer, first_start.0 + first_start.1);

        if let Some((second_pos, _)) = second_start {
            // We have a complete NAL unit (or group) from first_start to second_pos
            let packet_data = self.output_buffer[first_start.0..second_pos].to_vec();
            self.output_buffer.drain(..second_pos);
            Some(packet_data)
        } else {
            // Check if we have enough data for at least a start code + NAL header
            let remaining = &self.output_buffer[first_start.0 + first_start.1..];
            if remaining.len() >= 2 {
                // We have at least the start code and NAL header — extract what we have
                // This handles the case where FFmpeg outputs a single NAL unit at EOF
                let packet_data = self.output_buffer[first_start.0..].to_vec();
                self.output_buffer.clear();
                Some(packet_data)
            } else {
                // Not enough data yet — wait for more output
                None
            }
        }
    }
}

impl Drop for VideoEncoder {
    fn drop(&mut self) {
        info!("Shutting down FFmpeg encoder process");

        // Close stdin to signal FFmpeg that no more input is coming
        if let Some(mut stdin) = self.stdin.take() {
            if let Err(e) = stdin.flush() {
                trace!("FFmpeg stdin flush on drop (expected): {}", e);
            }
            drop(stdin); // closes the pipe
        }

        // Try to drain remaining output before killing
        if let Err(e) = self.read_all_output() {
            trace!("FFmpeg drain on drop (expected): {}", e);
        }

        // Terminate the process
        match self.process.as_inner_mut().try_wait() {
            Ok(Some(status)) => {
                debug!("FFmpeg process already exited: {:?}", status);
            }
            Ok(None) => {
                // Try graceful shutdown first
                let _ = self.process.quit();
                // Then force kill if still running
                if let Err(e) = self.process.kill() {
                    warn!("Failed to kill FFmpeg process on drop: {}", e);
                } else {
                    debug!("FFmpeg process killed");
                }
                // Reap the process
                let _ = self.process.wait();
            }
            Err(e) => {
                warn!("Error checking FFmpeg process status on drop: {}", e);
            }
        }
    }
}

/// Detect if the encoded data contains an IDR (keyframe) NAL unit.
///
/// Scans for start codes and checks if any following NAL unit has type 5.
fn detect_keyframe(data: &[u8]) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        if let Some((start_pos, start_len)) = find_start_code(data, pos) {
            let nal_header_pos = start_pos + start_len;
            if nal_header_pos < data.len() {
                let nal_byte = data[nal_header_pos];
                let nal_type = nal_byte & NAL_TYPE_MASK;
                if nal_type == NAL_TYPE_IDR {
                    trace!("Detected IDR (keyframe) NAL unit at offset {}", start_pos);
                    return true;
                }
            }
            pos = nal_header_pos;
        } else {
            break;
        }
    }
    false
}

/// Find the next H.264 start code in the data starting from the given position.
///
/// Returns `Some((position, length))` where position is the offset of the start
/// code and length is either 4 (for 00 00 00 01) or 3 (for 00 00 01).
/// Returns `None` if no start code is found.
fn find_start_code(data: &[u8], from: usize) -> Option<(usize, usize)> {
    if from >= data.len() || from + 2 >= data.len() {
        return None;
    }

    let slice = &data[from..];

    // Look for 4-byte start code: 0x00 0x00 0x00 0x01
    if slice.len() >= 4 && slice[0..4] == START_CODE_4 {
        return Some((from, 4));
    }

    // Look for 3-byte start code: 0x00 0x00 0x01
    if slice.len() >= 3 && slice[0..3] == START_CODE_3 {
        return Some((from, 3));
    }

    // Scan forward for the next start code
    // We look for the pattern 0x00 0x00 0x01 or 0x00 0x00 0x00 0x01
    for i in 1..=slice.len().saturating_sub(3) {
        if slice[i..i + 3] == START_CODE_3 {
            // Check if this is actually a 4-byte start code
            if i > 0 && slice[i - 1] == 0x00 {
                return Some((from + i - 1, 4));
            }
            return Some((from + i, 3));
        }
    }

    None
}

/// Build the FFmpeg command-line arguments for encoding.
///
/// Input: raw BGRA frames via stdin (pipe:0)
/// Output: H.264 NAL units via stdout (pipe:1)
fn build_ffmpeg_args(config: &StreamingConfig, keyframe_interval: u64) -> Vec<String> {
    let profile_str = match config.profile {
        H264Profile::Baseline => "baseline".to_string(),
        H264Profile::Main => "main".to_string(),
        H264Profile::High => "high".to_string(),
    };

    let preset_str = match config.preset {
        EncoderPreset::UltraFast => "ultrafast".to_string(),
        EncoderPreset::SuperFast => "superfast".to_string(),
        EncoderPreset::VeryFast => "veryfast".to_string(),
        EncoderPreset::Faster => "faster".to_string(),
        EncoderPreset::Fast => "fast".to_string(),
        EncoderPreset::Medium => "medium".to_string(),
        EncoderPreset::Slow => "slow".to_string(),
    };

    vec![
        // Suppress banner and informational output to stderr
        "-hide_banner".to_string(),
        "-loglevel".to_string(),
        "warning".to_string(),
        // Input format: raw BGRA video from stdin
        "-f".to_string(),
        "rawvideo".to_string(),
        "-pix_fmt".to_string(),
        "bgra".to_string(),
        "-s".to_string(),
        format!("{}x{}", config.width, config.height),
        "-r".to_string(),
        config.fps.to_string(),
        "-i".to_string(),
        "pipe:0".to_string(),
        // Output encoding: H.264 via libx264
        "-c:v".to_string(),
        "libx264".to_string(),
        "-profile:v".to_string(),
        profile_str,
        "-preset".to_string(),
        preset_str,
        "-b:v".to_string(),
        format!("{}", config.bitrate_bps),
        // Convert from BGRA (4:4:4) to yuv420p (4:2:0) which all H.264 profiles support
        "-pix_fmt".to_string(),
        "yuv420p".to_string(),
        "-x264-params".to_string(),
        format!("keyint={}:min-keyint=1", keyframe_interval),
        // Reduce encoder latency for real-time streaming
        "-tune".to_string(),
        "zerolatency".to_string(),
        // Output format: raw H.264 bitstream to stdout
        "-f".to_string(),
        "h264".to_string(),
        "pipe:1".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_start_code_4_byte() {
        let data = [0x00, 0x00, 0x00, 0x01, 0x67, 0x42];
        let result = find_start_code(&data, 0);
        assert!(result.is_some());
        let (pos, len) = result.unwrap();
        assert_eq!(pos, 0);
        assert_eq!(len, 4);
    }

    #[test]
    fn test_find_start_code_3_byte() {
        let data = [0x00, 0x00, 0x01, 0x67, 0x42];
        let result = find_start_code(&data, 0);
        assert!(result.is_some());
        let (pos, len) = result.unwrap();
        assert_eq!(pos, 0);
        assert_eq!(len, 3);
    }

    #[test]
    fn test_find_start_code_not_found() {
        let data = [0x67, 0x42, 0x00, 0x01];
        let result = find_start_code(&data, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_start_code_at_offset() {
        let data = [0x67, 0x00, 0x00, 0x00, 0x01, 0x65];
        let result = find_start_code(&data, 1);
        assert!(result.is_some());
        let (pos, len) = result.unwrap();
        assert_eq!(pos, 1);
        assert_eq!(len, 4);
    }

    #[test]
    fn test_detect_keyframe_idr() {
        // 4-byte start code + NAL type 5 (IDR)
        let data = [0x00, 0x00, 0x00, 0x01, 0x65, 0x00, 0xFF];
        assert!(detect_keyframe(&data));
    }

    #[test]
    fn test_detect_keyframe_non_idr() {
        // 4-byte start code + NAL type 7 (SPS) — not an IDR
        let data = [0x00, 0x00, 0x00, 0x01, 0x67, 0x00, 0xFF];
        assert!(!detect_keyframe(&data));
    }

    #[test]
    fn test_detect_keyframe_3_byte_start_code() {
        // 3-byte start code + NAL type 5 (IDR)
        let data = [0x00, 0x00, 0x01, 0x65, 0x00, 0xFF];
        assert!(detect_keyframe(&data));
    }

    #[test]
    fn test_detect_keyframe_multiple_nals() {
        // SPS (type 7) followed by IDR (type 5)
        let data = [
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x0A, // SPS
            0x00, 0x00, 0x00, 0x01, 0x65, 0x00, 0xFF, // IDR
        ];
        assert!(detect_keyframe(&data));
    }

    #[test]
    fn test_detect_keyframe_no_start_code() {
        let data = [0x65, 0x00, 0xFF];
        assert!(!detect_keyframe(&data));
    }

    #[test]
    fn test_build_ffmpeg_args() {
        let config = StreamingConfig {
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_bps: 5_000_000,
            profile: H264Profile::Baseline,
            preset: EncoderPreset::UltraFast,
        };
        let args = build_ffmpeg_args(&config, 60);

        // Verify key arguments are present
        assert!(args.contains(&"rawvideo".to_string()));
        assert!(args.contains(&"bgra".to_string()));
        assert!(args.contains(&"1920x1080".to_string()));
        assert!(args.contains(&"30".to_string()));
        assert!(args.contains(&"pipe:0".to_string()));
        assert!(args.contains(&"libx264".to_string()));
        assert!(args.contains(&"baseline".to_string()));
        assert!(args.contains(&"ultrafast".to_string()));
        assert!(args.contains(&"5000000".to_string()));
        assert!(args.contains(&"pipe:1".to_string()));
        assert!(args.contains(&"keyint=60:min-keyint=1".to_string()));
    }

    #[test]
    fn test_build_ffmpeg_args_high_profile() {
        let config = StreamingConfig {
            width: 1280,
            height: 720,
            fps: 60,
            bitrate_bps: 8_000_000,
            profile: H264Profile::High,
            preset: EncoderPreset::Medium,
        };
        let args = build_ffmpeg_args(&config, 120);

        assert!(args.contains(&"high".to_string()));
        assert!(args.contains(&"medium".to_string()));
        assert!(args.contains(&"1280x720".to_string()));
        assert!(args.contains(&"60".to_string()));
    }

    // Tests that require FFmpeg to be installed on the system.
    // Run with: cargo test -- --ignored

    #[test]
    #[ignore]
    fn test_encoder_spawn_and_encode() {
        let config = StreamingConfig {
            width: 320,
            height: 240,
            fps: 30,
            bitrate_bps: 1_000_000,
            profile: H264Profile::Baseline,
            preset: EncoderPreset::UltraFast,
        };

        let mut encoder = VideoEncoder::new(config).expect("FFmpeg should be installed");

        // Create a test frame (320x240 BGRA)
        let stride = 320 * 4;
        let data = vec![0u8; (stride * 240) as usize];
        let frame = VideoFrame {
            data,
            width: 320,
            height: 240,
            stride,
            timestamp: Instant::now(),
        };

        // Encode several frames — first few may be None due to encoder latency
        let mut encoded_count = 0;
        for frame_idx in 0..30 {
            let result = encoder.encode_frame(&frame).unwrap();
            if let Some(packet) = result {
                assert!(
                    !packet.data.is_empty(),
                    "Packet {} should have data",
                    encoded_count
                );
                // Sequence should match the frame index that was submitted
                assert_eq!(
                    packet.sequence, frame_idx as u64,
                    "Packet sequence should match frame index"
                );
                debug!(
                    "Frame {} -> packet #{}: {} bytes, keyframe={}",
                    frame_idx,
                    packet.sequence,
                    packet.data.len(),
                    packet.is_keyframe
                );
                encoded_count += 1;
            }
        }

        assert!(
            encoded_count > 0,
            "Should have produced at least one encoded packet"
        );

        // Sequence should have advanced for all 30 encode calls
        assert_eq!(encoder.sequence(), 30);
    }

    #[test]
    #[ignore]
    fn test_encoder_drain() {
        let config = StreamingConfig {
            width: 320,
            height: 240,
            fps: 30,
            bitrate_bps: 1_000_000,
            profile: H264Profile::Baseline,
            preset: EncoderPreset::UltraFast,
        };

        let mut encoder = VideoEncoder::new(config).expect("FFmpeg should be installed");

        // Submit a few frames
        let stride = 320 * 4;
        let data = vec![0u8; (stride * 240) as usize];
        let frame = VideoFrame {
            data,
            width: 320,
            height: 240,
            stride,
            timestamp: Instant::now(),
        };

        for _ in 0..10 {
            let _ = encoder.encode_frame(&frame);
        }

        // Drain remaining packets
        let packets = encoder.drain().unwrap();
        // Drain should not panic and should return whatever is buffered
        debug!("Drained {} packets", packets.len());
    }

    #[test]
    #[ignore]
    fn test_encoder_keyframe_interval() {
        let mut config = StreamingConfig {
            width: 320,
            height: 240,
            fps: 30,
            bitrate_bps: 1_000_000,
            profile: H264Profile::Baseline,
            preset: EncoderPreset::UltraFast,
        };
        config.fps = 30;

        let mut encoder = VideoEncoder::new(config).expect("FFmpeg should be installed");

        let stride = 320 * 4;
        let data = vec![0u8; (stride * 240) as usize];
        let frame = VideoFrame {
            data,
            width: 320,
            height: 240,
            stride,
            timestamp: Instant::now(),
        };

        // Encode enough frames to trigger the keyframe interval (2 seconds = 60 frames)
        let mut keyframe_count = 0;
        for _ in 0..90 {
            if let Some(packet) = encoder.encode_frame(&frame).unwrap()
                && packet.is_keyframe
            {
                keyframe_count += 1;
            }
        }

        // Should have seen at least one keyframe within 90 frames
        assert!(
            keyframe_count > 0,
            "Should have produced at least one keyframe in 90 frames"
        );
    }

    #[test]
    #[ignore]
    fn test_encoder_request_keyframe() {
        let config = StreamingConfig {
            width: 320,
            height: 240,
            fps: 30,
            bitrate_bps: 1_000_000,
            profile: H264Profile::Baseline,
            preset: EncoderPreset::UltraFast,
        };

        let mut encoder = VideoEncoder::new(config).expect("FFmpeg should be installed");

        let stride = 320 * 4;
        let data = vec![0u8; (stride * 240) as usize];
        let frame = VideoFrame {
            data,
            width: 320,
            height: 240,
            stride,
            timestamp: Instant::now(),
        };

        // Encode a few frames then request a keyframe
        for _ in 0..5 {
            let _ = encoder.encode_frame(&frame);
        }

        encoder.request_keyframe();

        // Next encoded packet should be a keyframe
        if let Some(packet) = encoder.encode_frame(&frame).unwrap() {
            assert!(
                packet.is_keyframe,
                "Packet after request_keyframe should be a keyframe"
            );
        }
    }

    #[test]
    #[ignore]
    fn test_encoder_drop_cleans_up_process() {
        let config = StreamingConfig {
            width: 320,
            height: 240,
            fps: 30,
            bitrate_bps: 1_000_000,
            profile: H264Profile::Baseline,
            preset: EncoderPreset::UltraFast,
        };

        let mut encoder = VideoEncoder::new(config).expect("FFmpeg should be installed");

        // Encode a frame to ensure process is running
        let stride = 320 * 4;
        let data = vec![0u8; (stride * 240) as usize];
        let frame = VideoFrame {
            data,
            width: 320,
            height: 240,
            stride,
            timestamp: Instant::now(),
        };
        let _ = encoder.encode_frame(&frame);

        // Drop should clean up without panicking
        drop(encoder);
    }
}
