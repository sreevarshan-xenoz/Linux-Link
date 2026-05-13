//! PipeWire screen capture via XDG Desktop Portal
//!
//! Uses ashpd to request screen capture from the compositor
//! and receives frames via PipeWire memory-mapped buffers.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
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
    let screencast = tokio::time::timeout(Duration::from_secs(10), Screencast::new())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Screencast portal unavailable (timeout after 10s) — is xdg-desktop-portal running?"
            )
        })?
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

/// Which display server is currently running
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayServer {
    /// Wayland compositor (via XDG Desktop Portal / PipeWire)
    Wayland,
    /// X11 server (via XDG Desktop Portal or direct X11)
    X11,
    /// No display server detected
    None,
}

/// Detect the active display server from environment variables.
pub fn detect_display_server() -> DisplayServer {
    // Wayland is indicated by WAYLAND_DISPLAY being set
    if std::env::var("WAYLAND_DISPLAY").is_ok() {
        debug!("Detected Wayland display server");
        return DisplayServer::Wayland;
    }

    // X11 is indicated by DISPLAY being set
    if std::env::var("DISPLAY").is_ok() {
        debug!("Detected X11 display server");
        return DisplayServer::X11;
    }

    // XDG_CURRENT_DESKTOP may indicate a desktop environment
    // Check if we're on a headless system or SSH without X forwarding
    if std::env::var("XDG_CURRENT_DESKTOP").is_ok() {
        // This could be a pure Wayland session without WAYLAND_DISPLAY set explicitly
        debug!("Desktop environment detected via XDG_CURRENT_DESKTOP, assuming Wayland");
        return DisplayServer::Wayland;
    }

    warn!("No display server detected (neither WAYLAND_DISPLAY nor DISPLAY is set)");
    DisplayServer::None
}

/// Check if screen capture is available on this system
pub async fn check_availability() -> Result<bool> {
    match detect_display_server() {
        DisplayServer::Wayland => {
            // Check PipeWire portal availability by trying to create a session
            let available = try_portal_available().await;
            if available {
                info!("Screen capture available via PipeWire/XDP");
            } else {
                warn!("Wayland detected but XDG Desktop Portal not available");
            }
            Ok(available)
        }
        DisplayServer::X11 => {
            // Check X11 availability — try connecting to the display
            let x11_available = check_x11_available();
            if x11_available {
                info!("Screen capture available via X11");
            } else {
                warn!("X11 detected but display connection failed");
            }
            Ok(x11_available)
        }
        DisplayServer::None => {
            debug!("Screen capture not available — no display server");
            Ok(false)
        }
    }
}

/// Quick check whether PipeWire portal is available (lightweight probe).
async fn try_portal_available() -> bool {
    // Try creating a screencast session — if it fails, portal isn't available
    match Screencast::new().await {
        Ok(screencast) => match screencast.create_session(Default::default()).await {
            Ok(_session) => true,
            Err(e) => {
                debug!("Portal session creation failed: {e}");
                false
            }
        },
        Err(e) => {
            debug!("Portal unavailable: {e}");
            false
        }
    }
}

/// Quick check whether X11 display is accessible.
fn check_x11_available() -> bool {
    use x11rb::rust_connection::RustConnection;

    match RustConnection::connect(None) {
        Ok((_conn, _screen_num)) => true,
        Err(e) => {
            debug!("X11 connection failed: {e}");
            false
        }
    }
}

/// Auto-detect display server and start the appropriate capture method.
///
/// Tries PipeWire/XDP first for Wayland, then falls back to X11 if applicable.
pub async fn start_capture_auto(
    config: StreamingConfig,
    frame_tx: mpsc::Sender<VideoFrame>,
    cancel: CancellationToken,
) -> Result<CaptureSession> {
    match detect_display_server() {
        DisplayServer::Wayland => {
            info!("Starting Wayland/PipeWire capture");
            start_capture(config, frame_tx, cancel).await
        }
        DisplayServer::X11 => {
            info!("Starting X11 capture");
            start_x11_capture(config, frame_tx, cancel).await
        }
        DisplayServer::None => {
            bail!("No display server detected — cannot start capture");
        }
    }
}

// ---------------------------------------------------------------------------
// X11 screen capture (fallback when PipeWire portal isn't available)
// ---------------------------------------------------------------------------

/// Start X11 screen capture using X GetImage for screen capture.
///
/// This is a fallback when PipeWire/Portal isn't available (e.g., bare X11
/// sessions without a working portal). For Wayland, use the PipeWire path via
/// `start_capture()`.
async fn start_x11_capture(
    config: StreamingConfig,
    frame_tx: mpsc::Sender<VideoFrame>,
    cancel: CancellationToken,
) -> Result<CaptureSession> {
    use x11rb::connection::Connection;
    use x11rb::rust_connection::RustConnection;

    info!("Starting X11 screen capture");

    let (conn, screen_num) =
        RustConnection::connect(None).context("Failed to connect to X11 display")?;
    let screen = &conn.setup().roots[screen_num];
    let root = screen.root;

    // Get the actual screen dimensions
    let screen_width = screen.width_in_pixels as u32;
    let screen_height = screen.height_in_pixels as u32;
    info!("X11 screen: {}x{}", screen_width, screen_height);

    // Determine capture width/height (use config if <= screen, otherwise screen)
    let cap_width = config.width.min(screen_width);
    let cap_height = config.height.min(screen_height);

    // Spawn the capture loop on a blocking thread
    let cap_cancel = cancel.clone();
    std::thread::Builder::new()
        .name("x11-capture".into())
        .spawn(move || {
            if let Err(e) = run_x11_capture_loop(
                conn, root, cap_width, cap_height, config.fps, frame_tx, cap_cancel,
            ) {
                error!("X11 capture thread exited with error: {e}");
            }
        })
        .context("Failed to spawn X11 capture thread")?;

    Ok(CaptureSession::new(config, cancel))
}

/// Run the X11 capture loop, sending frames through the channel.
fn run_x11_capture_loop(
    conn: x11rb::rust_connection::RustConnection,
    root: u32,
    width: u32,
    height: u32,
    fps: u32,
    frame_tx: mpsc::Sender<VideoFrame>,
    cancel: CancellationToken,
) -> Result<()> {
    use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat};

    let frame_interval = Duration::from_micros(1_000_000 / fps as u64);
    let mut frame_count = 0u64;

    loop {
        if cancel.is_cancelled() {
            info!("X11 capture cancelled");
            break;
        }

        let frame_start = Instant::now();

        // Capture the screen using GetImage
        let result = conn.get_image(
            ImageFormat::Z_PIXMAP,
            root,
            0, // x offset
            0, // y offset
            width as u16,
            height as u16,
            !0, // plane mask (all planes)
        );

        match result {
            Ok(cookie) => match cookie.reply() {
                Ok(reply) => {
                    let frame_data = reply.data.to_vec();
                    let stride = width * 4;

                    frame_count += 1;
                    if frame_count.is_multiple_of(30) {
                        debug!("X11 capture: frame #{}, {}x{}", frame_count, width, height);
                    }

                    let frame = VideoFrame {
                        data: frame_data,
                        width,
                        height,
                        stride,
                        timestamp: Instant::now(),
                    };

                    if frame_tx.blocking_send(frame).is_err() {
                        debug!("Frame channel closed, stopping capture");
                        break;
                    }

                    // Maintain target framerate
                    let elapsed = frame_start.elapsed();
                    if elapsed < frame_interval {
                        std::thread::sleep(frame_interval - elapsed);
                    }
                }
                Err(e) => {
                    error!("X11 GetImage reply error: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                }
            },
            Err(e) => {
                error!("X11 GetImage request error: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    info!("X11 capture thread shut down after {} frames", frame_count);
    Ok(())
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
