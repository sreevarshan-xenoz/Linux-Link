#![allow(unexpected_cfgs, reason = "flutter_rust_bridge uses frb_expand cfg")]

pub mod api;
mod frb_generated; /* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */

use std::sync::{Arc, LazyLock};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;

// Initialize logging for Android
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize the Linux Link backend (internal, called from api::init_app)
pub(crate) fn init_app_impl() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    flutter_rust_bridge::setup_default_user_utils();
}

/// Maximum number of H.264 frames to drain per `receive_frames` call.
pub(crate) const MAX_FRAMES_PER_RECEIVE: usize = 16;

/// Global handle for the active control connection writer.
pub(crate) static CONTROL_WRITER: LazyLock<Mutex<Option<Arc<Mutex<OwnedWriteHalf>>>>> =
    LazyLock::new(|| Mutex::new(None));

/// Global handle for the active control connection state.
pub(crate) static CONNECTION_STATE: LazyLock<Mutex<api::ConnectionState>> =
    LazyLock::new(|| Mutex::new(api::ConnectionState::Disconnected));

/// Last known RTT in microseconds, updated by the streaming stats task.
pub(crate) static STREAMING_RTT_US: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Global handle for the active streaming client session.
pub(crate) static STREAMING_HANDLE: LazyLock<Mutex<Option<StreamingHandle>>> =
    LazyLock::new(|| Mutex::new(None));

/// Holds the live streaming client and its packet receiver.
pub(crate) struct StreamingHandle {
    /// Token that can be used to cancel the receive loop.
    pub(crate) cancel: tokio_util::sync::CancellationToken,
    /// JoinHandle of the background `client.start()` task.
    pub(crate) task: tokio::task::JoinHandle<()>,
    /// JoinHandle of the background RTT polling task.
    pub(crate) rtt_task: tokio::task::JoinHandle<()>,
    /// Receiver so the consumer (Flutter) can receive packets.
    #[allow(dead_code)]
    pub(crate) packet_rx: tokio::sync::mpsc::Receiver<linux_link_core::streaming::EncodedPacket>,
}

/// Update the global streaming RTT value (called from the stats task).
pub(crate) fn update_streaming_rtt(rtt_us: u64) {
    STREAMING_RTT_US.store(rtt_us, std::sync::atomic::Ordering::Relaxed);
}
