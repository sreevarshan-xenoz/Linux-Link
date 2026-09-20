//! R4 B1 — direct wlroots screen capture (`zwlr_screencopy_manager_v1`).
//!
//! Hyprland (and every wlroots compositor) implements this protocol itself,
//! so a screencopy client captures **without the xdg-desktop-portal grant
//! dialog** the PipeWire path requires — the Sunshine-style native wlroots
//! mode. Frames arrive as compositor-rendered ARGB/XRGB shm buffers, which
//! is exactly the BGRA layout the encoder pipeline consumes, and damage
//! events make the loop genuinely variable-rate (no memcmp needed, unlike
//! the X11 path).
//!
//! Protocol patterns follow `libwayshot` (BSD-2-Clause, as vendored for
//! xcap's Wayland backend). Fallback is explicit: every setup failure —
//! no Wayland display, no/old global (non-wlroots compositors), unsupported
//! buffer — returns `Err` before any frame flows, and
//! [`crate::streaming::capture::start_capture_auto`] then uses the portal
//! path unchanged. Set `LINUX_LINK_SCREENCOPY=0` to force the portal even
//! on wlroots.

use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering as AtomicOrdering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::sync::mpsc as tokio_mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use wayland_client::globals::{GlobalList, GlobalListContents, registry_queue_init};
use wayland_client::protocol::wl_buffer::WlBuffer;
use wayland_client::protocol::wl_output::{self, WlOutput};
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::protocol::wl_shm::{self, WlShm};
use wayland_client::protocol::wl_shm_pool::WlShmPool;
use wayland_client::{Connection, Dispatch, EventQueue, Proxy, QueueHandle, WEnum};
use wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_frame_v1::{
    self, ZwlrScreencopyFrameV1,
};
use wayland_protocols_wlr::screencopy::v1::client::zwlr_screencopy_manager_v1::ZwlrScreencopyManagerV1;

use super::capture::CaptureSession;
use super::{StreamingConfig, VideoFrame};

/// Request rate for a static screen: the compositor still fills the shm
/// buffer, but an undamaged `ready` costs no encode.
const IDLE_FPS: u64 = 10;
/// Socket poll slice — bounds cancellation latency while waiting on events.
const POLL_TICK: Duration = Duration::from_millis(100);
/// Time the caller waits for the first successful frame before falling back
/// to the portal path (the capture thread aborts via the cancel token).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Output geometry (wl_output global coordinates) shared per bound output.
#[derive(Default)]
struct OutputPos {
    x: AtomicI32,
    y: AtomicI32,
}

/// Progress of one screencopy request, filled by `Dispatch` for the frame.
#[derive(Default)]
struct FramePhase {
    /// (width, height, stride, format) from the compositor's `buffer` event.
    buffer: Option<(u32, u32, u32, wl_shm::Format)>,
    y_invert: bool,
    damaged: bool,
    done: bool,
    failed: bool,
}

type FrameSlot = Arc<Mutex<FramePhase>>;

struct WlState;

impl Dispatch<WlRegistry, GlobalListContents> for WlState {
    fn event(
        _state: &mut Self,
        _proxy: &WlRegistry,
        _event: <WlRegistry as Proxy>::Event,
        _data: &GlobalListContents,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlOutput, Arc<OutputPos>> for WlState {
    fn event(
        _state: &mut Self,
        _proxy: &WlOutput,
        event: <WlOutput as Proxy>::Event,
        data: &Arc<OutputPos>,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let wl_output::Event::Geometry { x, y, .. } = event {
            data.x.store(x, AtomicOrdering::Relaxed);
            data.y.store(y, AtomicOrdering::Relaxed);
        }
    }
}

impl Dispatch<ZwlrScreencopyManagerV1, ()> for WlState {
    fn event(
        _state: &mut Self,
        _proxy: &ZwlrScreencopyManagerV1,
        _event: <ZwlrScreencopyManagerV1 as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZwlrScreencopyFrameV1, FrameSlot> for WlState {
    fn event(
        _state: &mut Self,
        _proxy: &ZwlrScreencopyFrameV1,
        event: <ZwlrScreencopyFrameV1 as Proxy>::Event,
        data: &FrameSlot,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        use zwlr_screencopy_frame_v1::Event;
        let mut phase = data.lock().unwrap();
        match event {
            Event::Buffer {
                format,
                width,
                height,
                stride,
            } => {
                if let WEnum::Value(format) = format {
                    phase.buffer = Some((width, height, stride, format));
                } else {
                    phase.failed = true;
                }
            }
            Event::Flags {
                // YInvert means the shm copy must be flipped vertically
                // when repacked into pipeline coordinates.
                flags: WEnum::Value(zwlr_screencopy_frame_v1::Flags::YInvert),
            } => phase.y_invert = true,
            Event::Damage { .. } => phase.damaged = true,
            Event::Ready { .. } => phase.done = true,
            Event::Failed => phase.failed = true,
            // DMA-BUF-only frames are not supported by this backend; shm
            // support is announced by `buffer`, so absence + dmabuf means
            // "fail over to the portal path".
            Event::LinuxDmabuf { .. } => {
                if phase.buffer.is_none() {
                    phase.failed = true;
                }
            }
            Event::BufferDone => {}
            _ => {}
        }
    }
}

impl Dispatch<WlShm, ()> for WlState {
    fn event(
        _state: &mut Self,
        _proxy: &WlShm,
        _event: <WlShm as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlShmPool, ()> for WlState {
    fn event(
        _state: &mut Self,
        _proxy: &WlShmPool,
        _event: <WlShmPool as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlBuffer, ()> for WlState {
    fn event(
        _state: &mut Self,
        _proxy: &WlBuffer,
        _event: <WlBuffer as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

/// Start wlroots screencopy capture of one output.
///
/// Spawns the capture thread and returns only after its **first frame** has
/// been grabbed successfully (so callers can fall back to the portal on any
/// setup failure: no display, no global, no output, unsupported buffer).
pub fn start_screencopy_capture(
    config: StreamingConfig,
    frame_tx: tokio_mpsc::Sender<VideoFrame>,
    cancel: CancellationToken,
) -> Result<CaptureSession> {
    if std::env::var("LINUX_LINK_SCREENCOPY")
        .map(|v| v == "0")
        .unwrap_or(false)
    {
        bail!("screencopy backend disabled via LINUX_LINK_SCREENCOPY=0");
    }

    let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();
    let thread_config = config.clone();
    let thread_cancel = cancel.clone();
    std::thread::Builder::new()
        .name("screencopy-capture".into())
        .spawn(move || {
            if let Err(e) =
                run_capture_loop(thread_config, frame_tx, thread_cancel, ready_tx.clone())
            {
                let _ = ready_tx.send(Err(e));
            }
        })
        .context("Failed to spawn screencopy capture thread")?;

    match ready_rx.recv_timeout(HANDSHAKE_TIMEOUT) {
        Ok(Ok(())) => Ok(CaptureSession::new(config, cancel.clone())),
        Ok(Err(e)) => {
            cancel.cancel();
            Err(e)
        }
        Err(_) => {
            cancel.cancel();
            bail!("screencopy first-frame handshake timed out");
        }
    }
}

fn run_capture_loop(
    config: StreamingConfig,
    frame_tx: tokio_mpsc::Sender<VideoFrame>,
    cancel: CancellationToken,
    ready_tx: Sender<Result<()>>,
) -> Result<()> {
    let conn = Connection::connect_to_env().context("no Wayland display")?;
    let (globals, mut queue) =
        registry_queue_init::<WlState>(&conn).context("wayland registry init failed")?;
    let qh = queue.handle();

    let Ok(shm): Result<WlShm, _> = globals.bind(&qh, 1..=1, ()) else {
        bail!("no wl_shm global");
    };
    // Version 3 gives damage events (since 2) and buffer_done (since 3);
    // older compositors (including Hyprland < 0.30) fall back to the portal.
    let Ok(manager): Result<ZwlrScreencopyManagerV1, _> = globals.bind(&qh, 3..=3, ()) else {
        bail!("compositor does not advertise zwlr_screencopy_manager_v1 >= 3");
    };

    let outputs = bind_outputs(&globals, &qh)?;
    let mut state = WlState;
    let (output, pos) = pick_output(
        &conn,
        &mut queue,
        &mut state,
        &outputs,
        config.monitor_index,
    )?;

    info!(
        "Screencopy capture: output at ({},{}), no portal grant",
        pos.0, pos.1
    );
    let mut shm_buf: Option<ShmBuffer> = None;
    let mut idle = false;
    let mut first = true;

    loop {
        if cancel.is_cancelled() {
            info!("Screencopy capture cancelled");
            break;
        }
        let cycle_start = Instant::now();

        let slot: FrameSlot = Arc::new(Mutex::new(FramePhase::default()));
        // overlay_cursor = 1: desktop parity with the portal path, which
        // shares with the system cursor composited in.
        let frame = manager.capture_output(1, &output, &qh, slot.clone());

        // Stage 1: the compositor announces the shm layout (or fails).
        pump_until(&conn, &mut queue, &mut state, &cancel, || {
            let p = slot.lock().unwrap();
            p.buffer.is_some() || p.done || p.failed
        })?;
        let meta = {
            let p = slot.lock().unwrap();
            if p.failed || p.buffer.is_none() {
                bail!("compositor rejected the shm capture (unsupported buffer format?)");
            }
            p.buffer.unwrap()
        };
        let (w, h, stride, format) = meta;
        if !matches!(format, wl_shm::Format::Argb8888 | wl_shm::Format::Xrgb8888) {
            bail!("unsupported screencopy shm format {format:?}");
        }

        // (Re)allocate the backing pixels only when geometry drifts; the
        // pool/buffer objects must be fresh per frame (the compositor
        // destroys the buffer once the copy completes).
        let reusable = shm_buf
            .as_ref()
            .is_some_and(|f| f.matches(w, h, stride, format));
        if !reusable {
            shm_buf = Some(ShmBuffer::new(w, h, stride, format)?);
        }
        let fb = shm_buf.as_ref().unwrap();
        let (pool, buffer) = fb.attach(&shm, &qh);
        frame.copy_with_damage(&buffer);

        // Stage 2: wait for ready/failed.
        pump_until(&conn, &mut queue, &mut state, &cancel, || {
            let p = slot.lock().unwrap();
            p.done || p.failed
        })?;
        let (inverted, damaged, failed) = {
            let p = slot.lock().unwrap();
            (p.y_invert, p.damaged, p.failed)
        };
        buffer.destroy();
        pool.destroy();
        frame.destroy();
        if failed {
            bail!("screencopy frame copy failed (compositor busy?)");
        }

        // The first frame ships regardless of reported damage: a static
        // screen's initial capture may arrive undamaged, and the pipeline
        // needs a starting frame.
        let emit = first || damaged;
        if first {
            let _ = ready_tx.send(Ok(()));
            first = false;
        }

        if emit {
            if idle {
                debug!(
                    "Screencopy: screen active, resuming {} fps pacing",
                    config.fps
                );
                idle = false;
            }
            let data = fb.repack(inverted, w, h, stride);
            let frame = VideoFrame {
                data,
                width: w,
                height: h,
                stride: w * 4,
                timestamp: Instant::now(),
            };
            match frame_tx.try_send(frame) {
                Ok(()) => {}
                Err(tokio_mpsc::error::TrySendError::Full(_)) => {
                    // Encoder backlog: the next request re-grabs fresh
                    // pixels, so dropping is the correct newest-only move.
                }
                Err(tokio_mpsc::error::TrySendError::Closed(_)) => {
                    debug!("Frame channel closed, stopping screencopy capture");
                    break;
                }
            }
        } else if !idle {
            info!("Screencopy: screen static, dropping to {IDLE_FPS} fps idle pacing");
            idle = true;
        }

        let target_period = if idle {
            Duration::from_micros(1_000_000 / IDLE_FPS.min(config.fps as u64))
        } else {
            Duration::from_micros(1_000_000 / config.fps as u64)
        };
        let elapsed = cycle_start.elapsed();
        if elapsed < target_period {
            std::thread::sleep(target_period - elapsed);
        }
    }

    Ok(())
}

/// Bind every advertised `wl_output` global (registry order, stable across
/// a session; mode switches surface as frame failures we bail on, matching
/// the other capture paths' behavior).
fn bind_outputs(
    globals: &GlobalList,
    qh: &QueueHandle<WlState>,
) -> Result<Vec<(WlOutput, Arc<OutputPos>)>> {
    let registry = globals.registry();
    let mut outputs = Vec::new();
    globals.contents().with_list(|list| {
        for global in list {
            if global.interface == "wl_output" {
                let pos = Arc::<OutputPos>::default();
                let version = global.version.min(4);
                let out: WlOutput = registry.bind(global.name, version, qh, pos.clone());
                outputs.push((out, pos));
            }
        }
    });
    Ok(outputs)
}

/// Map `monitor_index` onto an output: origin match against the xcap
/// enumeration first (same coordinate space the portal path matched), then
/// positional index, then the first output. Returns the output plus its
/// geometry for logging.
fn pick_output(
    conn: &Connection,
    queue: &mut EventQueue<WlState>,
    state: &mut WlState,
    outputs: &[(WlOutput, Arc<OutputPos>)],
    monitor_index: u32,
) -> Result<(WlOutput, (i32, i32))> {
    // Geometry arrives as events after bind; drain briefly to collect them.
    pump_brief(conn, queue, state);

    if outputs.is_empty() {
        bail!("compositor advertised no wl_output globals");
    }
    let want = monitor_rect_physical(monitor_index);
    let chosen = if let Some((x, y)) = want
        && let Some(i) = outputs.iter().position(|(_, p)| {
            p.x.load(AtomicOrdering::Relaxed) == x && p.y.load(AtomicOrdering::Relaxed) == y
        }) {
        i
    } else if (monitor_index as usize) < outputs.len() {
        monitor_index as usize
    } else {
        0
    };
    let (out, pos) = &outputs[chosen];
    Ok((
        out.clone(),
        (
            pos.x.load(AtomicOrdering::Relaxed),
            pos.y.load(AtomicOrdering::Relaxed),
        ),
    ))
}

fn monitor_rect_physical(index: u32) -> Option<(i32, i32)> {
    let monitors = xcap::Monitor::all().ok()?;
    let monitor = monitors.get(index as usize)?;
    Some((monitor.x().ok()?, monitor.y().ok()?))
}

/// Drain pending events for a bounded time (used post-bind to collect
/// one-shot state like `wl_output.geometry`).
fn pump_brief(conn: &Connection, queue: &mut EventQueue<WlState>, state: &mut WlState) {
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        let _ = queue.dispatch_pending(state);
        let _ = queue.flush();
        if let Some(guard) = conn.prepare_read() {
            poll_fd(guard.connection_fd().as_raw_fd(), Duration::from_millis(20));
            let _ = guard.read();
        } else {
            break;
        }
    }
    let _ = queue.dispatch_pending(state);
}

/// Drain wayland events (with a cancel-aware poll slice) until `done`.
fn pump_until<F>(
    conn: &Connection,
    queue: &mut EventQueue<WlState>,
    state: &mut WlState,
    cancel: &CancellationToken,
    done: F,
) -> Result<()>
where
    F: Fn() -> bool,
{
    loop {
        queue.dispatch_pending(state)?;
        if done() {
            return Ok(());
        }
        if cancel.is_cancelled() {
            bail!("capture cancelled while waiting for compositor events");
        }
        queue.flush()?;
        // prepare_read() returns None when events are already buffered —
        // in that case loop straight back into dispatch_pending.
        if let Some(guard) = conn.prepare_read() {
            poll_fd(guard.connection_fd().as_raw_fd(), POLL_TICK);
            // Errors (WouldBlock on timeout) just re-enter the loop.
            let _ = guard.read();
        }
    }
}

fn poll_fd(fd: i32, timeout: Duration) {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: one valid pollfd, correct nfds.
    unsafe { libc::poll(&mut pfd, 1, ms) };
}

/// Copy shm pixels into a tightly packed BGRA frame, flipping rows when the
/// compositor requested y-inversion. ARGB8888 memory (little-endian) is
/// already B,G,R,A — no byte shuffling needed for our BGRA pipeline.
fn repack_shm(src: &[u8], invert: bool, w: u32, h: u32, stride: u32) -> Vec<u8> {
    let row = (w as usize) * 4;
    let rows = h as usize;
    let stride = stride as usize;
    let mut out = vec![0u8; row * rows];
    for y in 0..rows {
        let src_y = if invert { rows - 1 - y } else { y };
        let from = src_y * stride;
        if from + row > src.len() {
            break; // defensive: short buffer, keep the zero tail
        }
        out[y * row..y * row + row].copy_from_slice(&src[from..from + row]);
    }
    out
}

/// Persistent shm backing (memfd + mmap) reused across captures until the
/// geometry changes. The `wl_shm_pool`/`wl_buffer` objects are per-frame:
/// the protocol requires the client to destroy the buffer after the copy
/// (the compositor destroys it together with the frame otherwise), so
/// [`ShmBuffer::attach`] mints fresh ones each cycle.
struct ShmBuffer {
    _fd: OwnedFd,
    ptr: *mut u8,
    len: usize,
    width: u32,
    height: u32,
    stride: u32,
    format: wl_shm::Format,
}

impl ShmBuffer {
    fn new(width: u32, height: u32, stride: u32, format: wl_shm::Format) -> Result<Self> {
        let len = (stride as usize) * (height as usize);
        let fd = make_memfd(len as u64)?;
        // SAFETY: fresh memfd of `len` bytes, MAP_SHARED, read-only.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            bail!(
                "mmap of capture buffer failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(Self {
            _fd: fd,
            ptr: ptr as *mut u8,
            len,
            width,
            height,
            stride,
            format,
        })
    }

    /// Wrap the backing fd in a fresh pool + buffer for one capture.
    fn attach(&self, shm: &WlShm, qh: &QueueHandle<WlState>) -> (WlShmPool, WlBuffer) {
        let pool = shm.create_pool(self._fd.as_fd(), self.len as i32, qh, ());
        let buffer = pool.create_buffer(
            0,
            self.width as i32,
            self.height as i32,
            self.stride as i32,
            self.format,
            qh,
            (),
        );
        (pool, buffer)
    }

    fn matches(&self, w: u32, h: u32, stride: u32, format: wl_shm::Format) -> bool {
        self.width == w && self.height == h && self.stride == stride && self.format == format
    }

    /// Copy the shm pixels into a tightly packed BGRA frame (see [`repack_shm`]).
    fn repack(&self, invert: bool, w: u32, h: u32, stride: u32) -> Vec<u8> {
        // SAFETY: the mmap covers stride*height, and the compositor wrote
        // the full buffer before signaling ready.
        let src = unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) };
        repack_shm(src, invert, w, h, stride)
    }
}

impl Drop for ShmBuffer {
    fn drop(&mut self) {
        // SAFETY: ptr came from a successful mmap of length len above.
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

fn make_memfd(len: u64) -> Result<OwnedFd> {
    let name = std::ffi::CString::new("linux-link-screencopy").unwrap();
    // SAFETY: plain memfd_create; fd checked below.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: ftruncate on a valid memfd.
    if unsafe { libc::ftruncate(fd.as_raw_fd(), len as i64) } != 0 {
        bail!(
            "ftruncate capture buffer: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repack_compacts_stride_and_flips_on_invert() {
        // 2x2 frame, stride 12 (row = 8 useful + 4 padding bytes).
        let stride = 12usize;
        let mut src = vec![0u8; stride * 2];
        src[0..4].copy_from_slice(&[1, 1, 1, 255]); // row0 px0
        src[4..8].copy_from_slice(&[2, 2, 2, 255]); // row0 px1
        src[stride..stride + 4].copy_from_slice(&[3, 3, 3, 255]); // row1 px0
        src[stride + 4..stride + 8].copy_from_slice(&[4, 4, 4, 255]);
        let out = repack_shm(&src, false, 2, 2, stride as u32);
        assert_eq!(&out[0..8], &[1, 1, 1, 255, 2, 2, 2, 255]);
        assert_eq!(&out[8..16], &[3, 3, 3, 255, 4, 4, 4, 255]);
        let flipped = repack_shm(&src, true, 2, 2, stride as u32);
        assert_eq!(&flipped[0..8], &[3, 3, 3, 255, 4, 4, 4, 255]);
        assert_eq!(&flipped[8..16], &[1, 1, 1, 255, 2, 2, 2, 255]);
    }

    /// Real capture against the running compositor (developer machines).
    /// Headless CI has no Wayland display — start_screencopy_capture then
    /// errors during setup and the test skips, mirroring the live Hyprland
    /// IPC tests' pattern.
    #[test]
    fn screencopy_grabs_a_real_frame() {
        let (tx, mut rx) = tokio_mpsc::channel::<VideoFrame>(2);
        let cancel = CancellationToken::new();
        let config = StreamingConfig::default();
        let session = match start_screencopy_capture(config, tx, cancel.clone()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping: no wlroots screencopy available here: {e:#}");
                return;
            }
        };
        let frame = rx
            .blocking_recv()
            .expect("handshake completed but no frame arrived");
        assert!(frame.width > 0 && frame.height > 0);
        assert_eq!(frame.data.len(), (frame.stride * frame.height) as usize);
        // Let the idle loop run several capture cycles on the *reused*
        // backing with freshly attached pool/buffer each frame. A protocol
        // violation (e.g. reusing a compositor-destroyed wl_buffer) errors
        // the Wayland connection, which drops the sender -> Disconnected.
        std::thread::sleep(Duration::from_millis(1200));
        assert!(
            !matches!(
                rx.try_recv(),
                Err(tokio_mpsc::error::TryRecvError::Disconnected)
            ),
            "capture thread died after the first frame (per-frame buffer lifecycle?)"
        );
        drop(session); // cancels via Drop
        // A live capture thread would still hold the token uncalled;
        // session Drop must have cancelled it.
        std::thread::sleep(Duration::from_millis(300));
        assert!(cancel.is_cancelled());
    }
}
