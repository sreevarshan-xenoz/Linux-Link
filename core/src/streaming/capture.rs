//! PipeWire screen capture via XDG Desktop Portal
//!
//! Uses ashpd to request screen capture from the compositor
//! and receives frames via PipeWire memory-mapped buffers.

use anyhow::{Context, Result};
use ashpd::desktop::screencast::{Screencast, SelectSourcesOptions, SourceType};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[cfg(test)]
use std::time::Instant;

use super::{StreamingConfig, VideoFrame};

/// Screen capture session
pub struct CaptureSession {
    _config: StreamingConfig,
    _frame_tx: mpsc::Sender<VideoFrame>,
    running: bool,
}

impl CaptureSession {
    /// Create a new capture session
    pub fn new(config: StreamingConfig, frame_tx: mpsc::Sender<VideoFrame>) -> Self {
        Self {
            _config: config,
            _frame_tx: frame_tx,
            running: false,
        }
    }

    /// Start capturing screens
    pub async fn start(&mut self) -> Result<()> {
        let config = self.config();
        info!(
            "Starting screen capture: {}x{}@{}fps",
            config.width, config.height, config.fps
        );

        let screencast = Screencast::new()
            .await
            .context("Failed to create Screencast")?;

        // Request screen capture session
        debug!("Requesting screen capture from portal...");
        let session = screencast
            .create_session(Default::default())
            .await
            .context("Failed to create capture session")?;

        // Set up sources (monitor capture)
        let source_types = ashpd::enumflags2::BitFlags::from(SourceType::Monitor);
        screencast
            .select_sources(
                &session,
                SelectSourcesOptions::default()
                    .set_sources(Some(source_types))
                    .set_multiple(Some(true)),
            )
            .await
            .context("Failed to select sources")?;

        // Start capture and get PipeWire node ID
        debug!("Starting capture and waiting for PipeWire stream...");
        let response = screencast
            .start(&session, None, Default::default())
            .await
            .context("Failed to start capture")?;

        let streams = response
            .response()
            .context("No response from capture start")?;

        for stream in streams.streams().iter() {
            let node_id = stream.pipe_wire_node_id();
            let size = stream.size().unwrap_or((0, 0));
            info!(
                "Capturing stream: node_id={}, size={}x{}",
                node_id, size.0, size.1
            );

            // In a full implementation, we would:
            // 1. Set up a PipeWire client using the `pipewire` crate
            // 2. Connect to the PipeWire node
            // 3. Receive frames and send them through frame_tx
            //
            // For now, this is a scaffold that documents the intended architecture.
            // The actual PipeWire integration requires a running Wayland session
            // and is tested separately.

            warn!(
                "PipeWire stream available but full capture integration requires runtime session"
            );
        }

        self.running = true;
        Ok(())
    }

    /// Stop capturing
    pub fn stop(&mut self) {
        info!("Stopping screen capture");
        self.running = false;
    }

    /// Check if capture is running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get the capture configuration
    pub fn config(&self) -> &StreamingConfig {
        &self._config
    }
}

/// Check if screen capture is available on this system
pub async fn check_availability() -> Result<bool> {
    // Check if XDG Desktop Portal is running
    let portal_available =
        std::env::var("XDG_CURRENT_DESKTOP").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();

    if !portal_available {
        debug!("XDG Desktop Portal not available - no WAYLAND_DISPLAY or XDG_CURRENT_DESKTOP");
    }

    Ok(portal_available)
}

/// Create a test frame for development/testing
#[cfg(test)]
pub fn create_test_frame(width: u32, height: u32) -> VideoFrame {
    let stride = width * 4; // BGRA = 4 bytes per pixel
    let data = vec![0u8; (stride * height) as usize];

    VideoFrame {
        data,
        width,
        height,
        stride,
        timestamp: Instant::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_frame() {
        let frame = create_test_frame(1920, 1080);
        assert_eq!(frame.width, 1920);
        assert_eq!(frame.height, 1080);
        assert_eq!(frame.stride, 1920 * 4);
        assert_eq!(frame.data.len(), (1920 * 4 * 1080) as usize);
    }

    #[test]
    fn test_streaming_config_default() {
        let config = StreamingConfig::default();
        assert_eq!(config.width, 1920);
        assert_eq!(config.height, 1080);
        assert_eq!(config.fps, 60);
    }
}
