//! PipeWire screen capture via XDG Desktop Portal
//!
//! Uses ashpd to request screen capture from the compositor
//! and receives frames via PipeWire memory-mapped buffers.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ashpd::desktop::screencast::{Screencast, SelectSourcesOptions, SourceType};
use pipewire::stream::StreamFlags;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use super::{StreamingConfig, VideoFrame};

/// SPA_PARAM_Format property ID (from SPA param type enum).
const SPA_PARAM_FORMAT: u32 = 0;

/// Shared state between the PipeWire thread and stream callbacks.
struct StreamUserData {
    frame_tx: mpsc::Sender<VideoFrame>,
    cancel: CancellationToken,
    /// Actual negotiated width (updated by param_changed callback).
    width: AtomicU32,
    /// Actual negotiated height (updated by param_changed callback).
    height: AtomicU32,
    /// Frame counter for logging.
    frame_count: AtomicU64,
}

/// PipeWire frame capture session.
///
/// Manages the lifetime of the background PipeWire thread.
/// When dropped, the capture task is cancelled and cleaned up.
pub struct CaptureSession {
    config: StreamingConfig,
    cancel: CancellationToken,
}

impl CaptureSession {
    /// Create a new capture session.
    fn new(config: StreamingConfig, cancel: CancellationToken) -> Self {
        Self { config, cancel }
    }

    /// Get the capture configuration.
    pub fn config(&self) -> &StreamingConfig {
        &self.config
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        info!("CaptureSession dropped, cancelling capture");
        self.cancel.cancel();
    }
}

/// Start PipeWire screen capture.
///
/// This function:
/// 1. Creates an XDG Portal screencast session
/// 2. Extracts the PipeWire node ID from the portal response
/// 3. Spawns a background PipeWire client thread that receives frames
/// 4. Sends frames through the provided `mpsc::Sender<VideoFrame>` channel
/// 5. Returns a [`CaptureSession`] that manages the capture lifetime
///
/// The capture runs continuously until `cancel` is triggered or the portal
/// session ends.
pub async fn start_capture(
    config: StreamingConfig,
    frame_tx: mpsc::Sender<VideoFrame>,
    cancel: CancellationToken,
) -> Result<CaptureSession> {
    info!(
        "Starting screen capture: {}x{}@{}fps",
        config.width, config.height, config.fps
    );

    // Step 1: Create XDG Portal screencast session (with timeout to handle missing portal backends)
    let screencast = tokio::time::timeout(
        Duration::from_secs(10),
        Screencast::new(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Screencast portal unavailable (timeout after 10s) — is xdg-desktop-portal running?"))?
    .context("Failed to create Screencast portal")?;

    debug!("Creating screencast session...");
    let session = tokio::time::timeout(
        Duration::from_secs(10),
        screencast.create_session(Default::default()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Portal request timed out — is xdg-desktop-portal running?"))?
    .context("Failed to create capture session")?;

    // Step 2: Select sources (monitor capture)
    let source_types = ashpd::enumflags2::BitFlags::from(SourceType::Monitor);
    tokio::time::timeout(
        Duration::from_secs(10),
        screencast.select_sources(
            &session,
            SelectSourcesOptions::default()
                .set_sources(Some(source_types))
                .set_multiple(Some(true)),
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Portal request timed out — is xdg-desktop-portal running?"))?
    .context("Failed to select sources")?;

    // Step 3: Start capture and get PipeWire node ID
    debug!("Starting capture and waiting for PipeWire stream...");
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        screencast.start(&session, None, Default::default()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Portal request timed out — is xdg-desktop-portal running?"))?
    .context("Failed to start capture")?;

    let streams = response
        .response()
        .context("No response from capture start")?;

    // Step 4: Find the first available stream and extract its node ID
    let mut node_id = None;
    for stream in streams.streams().iter() {
        let nid = stream.pipe_wire_node_id();
        let size = stream.size().unwrap_or((0, 0));
        info!(
            "Capturing stream: node_id={}, size={}x{}",
            nid, size.0, size.1
        );
        if node_id.is_none() {
            node_id = Some(nid);
        }
    }

    let node_id = node_id.context("No PipeWire stream available from screencast session")?;

    // Clone config for the capture thread
    let thread_config = config.clone();

    // Step 5: Spawn the PipeWire capture thread
    let pw_cancel = cancel.clone();
    std::thread::Builder::new()
        .name("pipewire-capture".into())
        .spawn(move || {
            if let Err(e) = run_pipewire_capture(node_id, &thread_config, frame_tx, pw_cancel) {
                error!("PipeWire capture thread exited with error: {e}");
            } else {
                info!("PipeWire capture thread exited normally");
            }
        })
        .context("Failed to spawn PipeWire capture thread")?;

    Ok(CaptureSession::new(config, cancel))
}

/// Run the PipeWire capture loop in a dedicated thread.
fn run_pipewire_capture(
    node_id: u32,
    config: &StreamingConfig,
    frame_tx: mpsc::Sender<VideoFrame>,
    cancel: CancellationToken,
) -> Result<()> {
    info!("PipeWire capture thread started, connecting to node {node_id}");

    // Initialize PipeWire
    pipewire::init();

    // Create the main loop (event loop)
    let mainloop = pipewire::main_loop::MainLoopBox::new(None)
        .context("Failed to create PipeWire main loop")?;

    // Create the context
    let context = pipewire::context::ContextBox::new(mainloop.loop_(), None)
        .context("Failed to create PipeWire context")?;

    // Connect to the PipeWire daemon
    let core = context
        .connect(None)
        .context("Failed to connect to PipeWire daemon")?;

    // Create stream properties for video capture.
    // The stream properties guide the format negotiation.
    // We don't pass explicit format params to connect(); instead,
    // we learn the negotiated format from the param_changed callback.
    let stream_props = pipewire::properties::properties! {
        *pipewire::keys::MEDIA_TYPE => "Video",
        *pipewire::keys::MEDIA_CATEGORY => "Capture",
        *pipewire::keys::MEDIA_ROLE => "Screen",
    };

    // Create the stream
    let stream = pipewire::stream::StreamBox::new(&core, "linux-link-capture", stream_props)
        .context("Failed to create PipeWire stream")?;

    // Set up shared state for callbacks
    let user_data = StreamUserData {
        frame_tx,
        cancel: cancel.clone(),
        width: AtomicU32::new(config.width),
        height: AtomicU32::new(config.height),
        frame_count: AtomicU64::new(0),
    };

    // Create local listener with param_changed and process callbacks
    let _listener = stream
        .add_local_listener_with_user_data(user_data)
        .param_changed(|_stream, ud, id, param| {
            on_param_changed(id, param, ud);
        })
        .process(|stream, ud| {
            on_process(stream, ud);
        })
        .register()
        .context("Failed to register stream listener")?;

    // Connect the stream to the specific PipeWire node.
    // We pass an empty params array -- the format will be negotiated
    // automatically based on stream properties and server capabilities.
    // The actual format is learned via the param_changed callback.
    let mut params: [&libspa::pod::Pod; 0] = [];
    stream
        .connect(
            libspa::utils::Direction::Input,
            Some(node_id),
            StreamFlags::AUTOCONNECT | StreamFlags::MAP_BUFFERS,
            &mut params,
        )
        .with_context(|| format!("Failed to connect stream to node {node_id}"))?;

    // Activate the stream to start receiving frames
    stream
        .set_active(true)
        .context("Failed to activate stream")?;

    info!("PipeWire stream connected and active, entering main loop");

    // Run the main loop until cancellation
    loop {
        mainloop.loop_().iterate(Duration::from_millis(100));
        if cancel.is_cancelled() {
            info!("Cancellation received, exiting PipeWire main loop");
            break;
        }
    }

    info!("PipeWire capture thread shutting down");

    // Clean up
    let _ = stream.set_active(false);
    let _ = stream.disconnect();

    Ok(())
}

/// Handle the param_changed callback to learn the negotiated video format.
fn on_param_changed(id: u32, param: Option<&libspa::pod::Pod>, user_data: &StreamUserData) {
    if id != SPA_PARAM_FORMAT {
        return;
    }

    let Some(param) = param else {
        debug!("param_changed: format removed");
        return;
    };

    // Parse the negotiated format
    let mut video_info = libspa::param::video::VideoInfoRaw::new();
    if video_info.parse(param).is_err() {
        warn!("Failed to parse video format from param_changed");
        return;
    }

    let format = video_info.format();
    let size = video_info.size();
    let framerate = video_info.framerate();

    info!(
        "Negotiated video format: {:?}, {}x{}@{}/{}fps",
        format, size.width, size.height, framerate.num, framerate.denom
    );

    // Update the actual dimensions for frame capture
    user_data.width.store(size.width, Ordering::Relaxed);
    user_data.height.store(size.height, Ordering::Relaxed);
}

/// Handle the process callback -- dequeue frames and send them through the channel.
fn on_process(stream: &pipewire::stream::Stream, user_data: &StreamUserData) {
    // Dequeue an available buffer
    let mut buffer = match stream.dequeue_buffer() {
        Some(b) => b,
        None => {
            trace!("No buffer available in process callback");
            return;
        }
    };

    // Access the buffer data
    let datas = buffer.datas_mut();
    if datas.is_empty() {
        warn!("Buffer has no data planes");
        return;
    }

    let data = &mut datas[0];

    // Get chunk info first (size and stride)
    let (size, stride) = {
        let chunk = data.chunk();
        (chunk.size() as usize, chunk.stride())
    };
    if size == 0 {
        return;
    }

    // Then get the data slice
    let Some(data_slice) = data.data() else {
        trace!("Buffer data pointer is null");
        return;
    };

    if data_slice.is_empty() {
        return;
    }

    // Get the actual negotiated dimensions
    let width = user_data.width.load(Ordering::Relaxed);
    let height = user_data.height.load(Ordering::Relaxed);

    // Copy the frame data (cap at actual data slice length)
    let frame_data = data_slice[..size.min(data_slice.len())].to_vec();

    // Update frame counter
    let count = user_data.frame_count.fetch_add(1, Ordering::Relaxed);

    if count.is_multiple_of(30) {
        debug!("Captured frame #{count}: size={size}B, {width}x{height}, stride={stride}");
    }

    let frame = VideoFrame {
        data: frame_data,
        width,
        height,
        stride: stride as u32,
        timestamp: Instant::now(),
    };

    // Send the frame through the channel.
    // Use blocking_send since we're on a PipeWire thread, not a tokio runtime.
    if user_data.frame_tx.blocking_send(frame).is_err() {
        // Channel closed -- receiver dropped, stop capturing.
        debug!("Frame channel closed, cancelling capture");
        user_data.cancel.cancel();
    }
}

/// Check if screen capture is available on this system
pub async fn check_availability() -> Result<bool> {
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
