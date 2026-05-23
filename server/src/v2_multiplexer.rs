use anyhow::Context;
use quinn::{Connection, ConnectionError, RecvStream, SendStream};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, info_span, warn, Instrument};

use linux_link_core::error::LinuxLinkError;
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, PluginRegistry};
use linux_link_core::protocol::v2::{
    perform_v2_handshake, read_framed_json, write_framed_json, ChannelKind, IdentityPacketV2,
};

/// Handles a v2 multiplexed QUIC session.
/// 
/// This involves the initial v2 handshake on Stream 0, followed by a loop
/// that accepts new unidirectional and bidirectional streams for various
/// features (video, audio, input, etc.).
pub async fn handle_v2_session(
    conn: Connection,
    local_identity: IdentityPacketV2,
    registry: Arc<PluginRegistry>,
) -> anyhow::Result<()> {
    let peer_addr = conn.remote_address();
    let session_id = uuid::Uuid::new_v4().to_string();

    let span = info_span!(
        "v2_session",
        session = %session_id,
        peer = ?peer_addr,
        proto = "v2"
    );

    async move {
        info!("New v2 session established");

        // Step 1: Accept the first bidirectional stream for handshake
        let (mut send0, mut recv0) = conn
            .accept_bi()
            .await
            .context("failed to accept handshake stream")?;

        let peer_identity = perform_v2_handshake(&mut send0, &mut recv0, &local_identity).await?;

        tracing::Span::current().record("peer_id", &peer_identity.device_id);
        info!(
            "Handshake successful with {} ({})",
            peer_identity.device_name, peer_identity.device_id
        );

        // Wrap Stream 0 for use with existing v1 plugins (control channel)
        let sender = Arc::new(QuicDeviceSender::new(
            send0,
            peer_identity.device_id.clone(),
            session_id.clone(),
        ));

        // Main loop to accept new streams and read from control stream
        loop {
            tokio::select! {
                uni = conn.accept_uni() => {
                    match uni {
                        Ok(recv) => {
                            tokio::spawn(handle_unidirectional_stream(recv).instrument(info_span!("uni_stream")));
                        }
                        Err(e) => {
                            handle_conn_error(e);
                            break;
                        }
                    }
                }
                bi = conn.accept_bi() => {
                    match bi {
                        Ok((send, recv)) => {
                            tokio::spawn(handle_bidirectional_stream(send, recv).instrument(info_span!("bi_stream")));
                        }
                        Err(e) => {
                            handle_conn_error(e);
                            break;
                        }
                    }
                }
                // Read legacy KDE Connect packets over the v2 control stream (Stream 0)
                packet = read_framed_json::<NetworkPacket>(&mut recv0) => {
                    match packet {
                        Ok(p) => {
                             let packet_type = p.packet_type.clone();
                             let packet_span = tracing::debug_span!("packet", type = %packet_type);
                             let registry = Arc::clone(&registry);
                             let sender = Arc::clone(&sender);
                             
                             tokio::spawn(async move {
                                 debug!("Processing v1-over-v2 control packet");
                                 if let Err(e) = registry.dispatch_packet(&p, &*sender).await {
                                     warn!("Packet dispatch failed: {}", e);
                                 }
                             }.instrument(packet_span));
                        }
                        Err(e) => {
                            warn!("Error reading from control stream: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        info!("v2 session ended");
        Ok(())
    }
    .instrument(span)
    .await
}

fn handle_conn_error(e: ConnectionError) {
    match e {
        ConnectionError::ApplicationClosed(close) => {
            info!("Session closed by peer: {:?}", close);
        }
        ConnectionError::LocallyClosed => {
            debug!("Session closed locally");
        }
        _ => {
            warn!("Connection error: {}", e);
        }
    }
}

async fn handle_unidirectional_stream(mut recv: RecvStream) -> anyhow::Result<()> {
    let mut header = [0u8; 1];
    recv.read_exact(&mut header).await?;
    let kind_raw = header[0];

    // Map raw byte to ChannelKind if possible
    match kind_raw {
        k if k == ChannelKind::Video as u8 => {
            debug!("Incoming Video stream (unidirectional)");
            // TODO: Route to video decoder/player
        }
        k if k == ChannelKind::Audio as u8 => {
            debug!("Incoming Audio stream (unidirectional)");
            // TODO: Route to audio player
        }
        _ => {
            warn!("Unknown unidirectional stream kind: {}", kind_raw);
        }
    }

    Ok(())
}

async fn handle_bidirectional_stream(_send: SendStream, mut recv: RecvStream) -> anyhow::Result<()> {
    let mut header = [0u8; 1];
    recv.read_exact(&mut header).await?;
    let kind_raw = header[0];

    match kind_raw {
        k if k == ChannelKind::Input as u8 => {
            debug!("Incoming Input stream (bidirectional)");
            // TODO: Handle low-latency input packets
        }
        k if k == ChannelKind::File as u8 => {
            debug!("Incoming File transfer stream (bidirectional)");
            // TODO: Handle file transfer
        }
        _ => {
            warn!("Unknown bidirectional stream kind: {}", kind_raw);
        }
    }

    Ok(())
}

/// DeviceSender implementation that uses a QUIC SendStream with v2 framing.
struct QuicDeviceSender {
    send: Arc<Mutex<SendStream>>,
    device_id: String,
    connection_id: String,
}

impl QuicDeviceSender {
    fn new(send: SendStream, device_id: String, connection_id: String) -> Self {
        Self {
            send: Arc::new(Mutex::new(send)),
            device_id,
            connection_id,
        }
    }
}

#[async_trait::async_trait]
impl DeviceSender for QuicDeviceSender {
    fn device_id(&self) -> &str {
        &self.device_id
    }

    fn connection_id(&self) -> &str {
        &self.connection_id
    }

    async fn send_packet(&self, packet: &NetworkPacket) -> std::result::Result<(), LinuxLinkError> {
        let mut guard = self.send.lock().await;
        write_framed_json(&mut *guard, packet).await?;
        Ok(())
    }
}
