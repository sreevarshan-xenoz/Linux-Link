#![allow(unexpected_cfgs, reason = "flutter_rust_bridge uses frb_expand cfg")]

pub mod api;
mod frb_generated; /* AUTO INJECTED BY flutter_rust_bridge. This line may not be accurate, and you can change it according to your needs. */

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, LazyLock};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::broadcast;
use tokio::sync::Mutex as TokioMutex;

// Initialize logging for Android
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize the Linux Link backend (internal, called from api::init_app)
pub(crate) fn init_app_impl() {
    static DONE: std::sync::Once = std::sync::Once::new();
    DONE.call_once(|| {
        let _ = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
        flutter_rust_bridge::setup_default_user_utils();
    });
}

/// Maximum number of H.264 frames to drain per `receive_frames` call.
pub(crate) const MAX_FRAMES_PER_RECEIVE: usize = 16;

/// Maximum number of audio packets to drain per `receive_audio` call.
pub(crate) const MAX_AUDIO_PACKETS_PER_RECEIVE: usize = 32;

/// Global handle for the active control connection writer.
pub(crate) static CONTROL_WRITER: LazyLock<TokioMutex<Option<Arc<TokioMutex<OwnedWriteHalf>>>>> =
    LazyLock::new(|| TokioMutex::new(None));

/// Global handle for the active control connection state.
pub(crate) static CONNECTION_STATE: LazyLock<TokioMutex<api::ConnectionState>> =
    LazyLock::new(|| TokioMutex::new(api::ConnectionState::Disconnected));

/// Persistent device identity for the Android client.
pub(crate) static DEVICE_IDENTITY: LazyLock<std::sync::Mutex<Option<linux_link_core::protocol::kdeconnect::DeviceIdentity>>> =
    LazyLock::new(|| std::sync::Mutex::new(None));

/// mDNS discovery service status flag.
pub(crate) static MDNS_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Exponential backoff state for reconnection.
pub(crate) static RECONNECT_BACKOFF: LazyLock<std::sync::Mutex<linux_link_core::protocol::backoff::ExponentialBackoff>> =
    LazyLock::new(|| std::sync::Mutex::new(linux_link_core::protocol::backoff::ExponentialBackoff::default()));

/// High-level session status for reconnection state machine.
pub(crate) static SESSION_STATUS: LazyLock<std::sync::Mutex<api::SessionStatus>> =
    LazyLock::new(|| std::sync::Mutex::new(api::SessionStatus::Disconnected));

/// Last known RTT in microseconds, updated by the streaming stats task.
pub(crate) static STREAMING_RTT_US: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Atomic flag indicating whether streaming is active (avoids try_lock race).
pub(crate) static STREAMING_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Streaming metrics for stats display.
pub(crate) static STREAMING_FRAME_COUNT: AtomicU64 = AtomicU64::new(0);
pub(crate) static STREAMING_BYTE_COUNT: AtomicU64 = AtomicU64::new(0);
pub(crate) static STREAMING_START_TIME: LazyLock<std::sync::Mutex<Option<std::time::Instant>>> =
    LazyLock::new(|| std::sync::Mutex::new(None));

/// Global handle for the active streaming client session.
pub(crate) static STREAMING_HANDLE: LazyLock<TokioMutex<Option<StreamingHandle>>> =
    LazyLock::new(|| TokioMutex::new(None));

/// Global handle for the active v2 unified connection.
pub(crate) static V2_HANDLE: LazyLock<TokioMutex<Option<V2Handle>>> =
    LazyLock::new(|| TokioMutex::new(None));

/// Persistent cert directory set from Flutter (std Mutex for sync access).
pub(crate) static CERT_DIR: LazyLock<std::sync::Mutex<Option<PathBuf>>> =
    LazyLock::new(|| std::sync::Mutex::new(None));

/// Currently active CertManager for trust management UI.
pub(crate) static CERT_MANAGER: LazyLock<std::sync::Mutex<Option<Arc<linux_link_core::streaming::transport::CertManager>>>> =
    LazyLock::new(|| std::sync::Mutex::new(None));

/// Broadcast channel for incoming KDE Connect packets from the control connection.
/// Flutter polls these via `poll_incoming_packets`.
pub(crate) static INCOMING_PACKETS: LazyLock<TokioMutex<Option<broadcast::Sender<String>>>> =
    LazyLock::new(|| TokioMutex::new(None));

/// Holds the live streaming client and its packet receiver.
pub(crate) struct StreamingHandle {
    pub(crate) address: String,
    pub(crate) port: u16,
    /// Token that can be used to cancel the receive loop.
    pub(crate) cancel: tokio_util::sync::CancellationToken,
    /// JoinHandle of the background `client.start()` task.
    pub(crate) task: tokio::task::JoinHandle<()>,
    /// JoinHandle of the background RTT polling task.
    pub(crate) rtt_task: tokio::task::JoinHandle<()>,
    /// Receiver so the consumer (Flutter) can receive packets.
    #[allow(dead_code)]
    pub(crate) packet_rx: tokio::sync::mpsc::Receiver<linux_link_core::streaming::EncodedPacket>,
    /// Receiver for decoded audio packets (F1: Audio Streaming).
    #[allow(dead_code)]
    pub(crate) audio_rx: tokio::sync::mpsc::Receiver<linux_link_core::streaming::AudioPacket>,
    /// The QUIC connection, kept alive for sending input events.
    pub(crate) connection: quinn::Connection,
}

/// Holds the unified v2 connection and its persistent control streams.
pub(crate) struct V2Handle {
    pub(crate) connection: quinn::Connection,
    pub(crate) control_send: Arc<TokioMutex<quinn::SendStream>>,
    pub(crate) task: tokio::task::JoinHandle<()>,
}

/// Update the global streaming RTT value (called from the stats task).
pub(crate) fn update_streaming_rtt(rtt_us: u64) {
    STREAMING_RTT_US.store(rtt_us, std::sync::atomic::Ordering::Relaxed);
}
