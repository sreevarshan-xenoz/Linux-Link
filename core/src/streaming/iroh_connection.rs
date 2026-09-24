//! iroh (noq) implementation of the streaming connection traits (R1 stage 2).
//!
//! iroh 1.x speaks `noq`, whose connection/stream types are unrelated to
//! quinn 0.11 (see `spike/iroh/README.md`), but the operations noq exposes
//! mirror quinn's closely enough that the [`Connection`] abstraction maps
//! one-to-one: same `open_uni`/`accept_uni` shapes, same `write_all` +
//! sync `finish`, and the same `ConnectionError` taxonomy — so close
//! classification is a structural copy of the quinn arm.
//!
//! Behind the `wan` feature: the Android bridge and the default build must
//! not pull iroh into the graph. The v2 multiplexer path additionally needs
//! `open_bi` and datagrams, which the trait does not model yet; only v1
//! streaming can ride this connection today.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use iroh::endpoint::presets::Minimal;
use iroh::endpoint::{
    ClosedStream, ConnectionError as NoqError, PathId, ReadError, ReadExactError, ReadToEndError,
    RecvStream, SendStream, WriteError,
};
use iroh::{Endpoint, EndpointAddr, RelayMode};

use super::connection::{
    Connection, ConnectionError, ConnectionStats, InStream, OutStream, SharedConnection,
    TransportFamily,
};
use super::transport::StreamTransportConfig;

/// Classify an iroh/noq connection error — identical taxonomy to quinn.
fn classify_conn_error(e: NoqError) -> ConnectionError {
    use NoqError::*;
    match e {
        ApplicationClosed(_) | ConnectionClosed(_) | Reset | TimedOut | LocallyClosed => {
            ConnectionError::Closed
        }
        other => ConnectionError::Other(other.to_string()),
    }
}

/// [`Connection`] over an iroh endpoint connection — the WAN arm next to
/// [`super::QuinnConnection`]'s LAN default.
#[derive(Debug, Clone)]
pub struct IrohConnection {
    inner: iroh::endpoint::Connection,
}

impl IrohConnection {
    pub fn new(connection: iroh::endpoint::Connection) -> Self {
        Self { inner: connection }
    }

    /// Share into the boxed trait object the pipeline expects.
    pub fn shared(connection: iroh::endpoint::Connection) -> SharedConnection {
        Arc::new(Self::new(connection))
    }

    /// Escape hatch for iroh-native plumbing (endpoint close, datagrams,
    /// connection-level close with an error code).
    pub fn inner(&self) -> &iroh::endpoint::Connection {
        &self.inner
    }
}

impl From<iroh::endpoint::Connection> for IrohConnection {
    fn from(connection: iroh::endpoint::Connection) -> Self {
        Self::new(connection)
    }
}

#[async_trait]
impl Connection for IrohConnection {
    async fn open_uni(&self) -> Result<Box<dyn OutStream>, ConnectionError> {
        self.inner
            .open_uni()
            .await
            .map(|s| Box::new(IrohSendStream { inner: s }) as Box<dyn OutStream>)
            .map_err(classify_conn_error)
    }

    async fn accept_uni(&self) -> Result<Box<dyn InStream>, ConnectionError> {
        self.inner
            .accept_uni()
            .await
            .map(|s| Box::new(IrohRecvStream { inner: s }) as Box<dyn InStream>)
            .map_err(classify_conn_error)
    }

    fn remote_address(&self) -> SocketAddr {
        // Established iroh connections expose their network paths, not a
        // single socket address. The selected direct path (if any) is the
        // quinn-equivalent "peer"; relay/custom paths have no IP to report
        // (the pipeline only logs this — a proper transport-address type
        // lands with the WAN dialing wiring).
        let unspecified = SocketAddr::from(([0, 0, 0, 0], 0));
        let paths = self.inner.paths();
        paths
            .iter()
            .find(|p| p.is_selected() && p.is_ip())
            .or_else(|| paths.iter().find(|p| p.is_ip()))
            .map(|p| match p.remote_addr() {
                iroh::TransportAddr::Ip(addr) => *addr,
                _ => unspecified,
            })
            .unwrap_or(unspecified)
    }

    fn stats(&self) -> ConnectionStats {
        // noq keeps RTT per path; path 0 is the initial path every
        // connection has. None (no samples yet) reads as zero, like quinn's
        // fresh-connection value.
        //
        // `relayed` mirrors iroh's path selection: DCUtR keeps trying to
        // punch a direct path while traffic rides the relay, so this flips
        // false on its own once punching succeeds — callers surface it as
        // "relayed — trying direct…", never as a dead end.
        let relayed = self
            .inner
            .paths()
            .iter()
            .any(|p| p.is_selected() && p.is_relay());
        // noq's connection-level stats are an aggregate over every open path,
        // and the aggregation deliberately discards rtt, cwnd and MTU (they
        // have no meaning summed across paths) while iroh does not re-export
        // the per-path accessor. Reporting them as `None` is what makes a WAN
        // record comparable against a LAN one: a zero here would look like a
        // healthy, uncongested path.
        let s = self.inner.stats();
        ConnectionStats {
            rtt: self.inner.rtt(PathId::ZERO).unwrap_or(Duration::ZERO),
            lost_packets: s.lost_packets,
            lost_bytes: s.lost_bytes,
            datagrams_sent: s.udp_tx.datagrams,
            datagrams_received: s.udp_rx.datagrams,
            bytes_sent: s.udp_tx.bytes,
            bytes_received: s.udp_rx.bytes,
            congestion_events: None,
            cwnd_bytes: None,
            path_mtu: None,
            black_holes_detected: None,
            relayed,
        }
    }

    fn transport_family(&self) -> TransportFamily {
        TransportFamily::Iroh
    }

    fn close(&self, error_code: u32, reason: &[u8]) {
        self.inner
            .close(iroh::endpoint::VarInt::from_u32(error_code), reason);
    }
}

/// Client-side WAN dial (R1 stage 3).
///
/// Owns the ephemeral iroh `Endpoint` for the life of the session: iroh
/// aborts its socket task with an error if an `Endpoint` is dropped while
/// live, so callers must `close()` the dial (or at least keep the endpoint
/// alive until the connection ends). The identity the phone learned from the
/// server's `kdeconnect.linuxlink.endpoint` announcement is reassembled here
/// from its string parts — relays are dial-reachable fallbacks, direct
/// addresses the LAN/Tailscale-routable set.
pub struct IrohDial {
    endpoint: Endpoint,
    raw: iroh::endpoint::Connection,
    connection: SharedConnection,
}

impl IrohDial {
    /// Dial a server from its announced identity parts.
    ///
    /// `use_relays` selects n0 relay assistance (hole punching); `false`
    /// restricts the dial to the direct addresses — loopback tests and
    /// air-gapped direct paths.
    pub async fn dial(
        endpoint_id: &str,
        relay_urls: &[String],
        direct_addrs: &[String],
        use_relays: bool,
        timeout: Duration,
    ) -> Result<Self> {
        let id: iroh::EndpointId = endpoint_id.parse().context("invalid iroh EndpointId")?;
        let mut addr = EndpointAddr::new(id);
        for url in relay_urls {
            let url = url
                .parse()
                .with_context(|| format!("invalid relay url: {url}"))?;
            addr = addr.with_relay_url(url);
        }
        for a in direct_addrs {
            let a: SocketAddr = a
                .parse()
                .with_context(|| format!("invalid direct address: {a}"))?;
            addr = addr.with_ip_addr(a);
        }

        let alpn = StreamTransportConfig::default().alpn;
        let endpoint = Endpoint::builder(Minimal)
            .alpns(vec![alpn.clone()])
            .relay_mode(if use_relays {
                RelayMode::Default
            } else {
                RelayMode::Disabled
            })
            .bind_addr(SocketAddr::from(([0, 0, 0, 0], 0)))
            .context("iroh bind_addr rejected wildcard socket addr")?
            .bind()
            .await
            .context("iroh client endpoint bind failed")?;

        let raw = tokio::time::timeout(timeout, endpoint.connect(addr, &alpn))
            .await
            .context("iroh dial timed out")?
            .context("iroh dial failed")?;

        Ok(Self {
            endpoint,
            connection: IrohConnection::shared(raw.clone()),
            raw,
        })
    }

    /// The trait handle `StreamingClient::attach` adopts.
    pub fn connection(&self) -> SharedConnection {
        self.connection.clone()
    }

    /// Gracefully close the connection and the endpoint. Mandatory before
    /// drop to avoid iroh's dropped-live-endpoint error log.
    pub async fn close(self) {
        self.raw
            .close(iroh::endpoint::VarInt::from_u32(0), b"session end");
        self.endpoint.close().await;
    }
}

struct IrohSendStream {
    inner: SendStream,
}

#[async_trait]
impl OutStream for IrohSendStream {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), ConnectionError> {
        self.inner.write_all(data).await.map_err(|e| match e {
            WriteError::ConnectionLost(e) => classify_conn_error(e),
            WriteError::ClosedStream => ConnectionError::Closed,
            other => ConnectionError::Other(other.to_string()),
        })
    }

    fn finish(&mut self) -> Result<(), ConnectionError> {
        // Same contract as quinn 0.11: ClosedStream means the stream (and
        // effectively the session for our one-packet-per-stream use) is done.
        self.inner
            .finish()
            .map_err(|_: ClosedStream| ConnectionError::Closed)
    }
}

struct IrohRecvStream {
    inner: RecvStream,
}

#[async_trait]
impl InStream for IrohRecvStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ConnectionError> {
        self.inner.read_exact(buf).await.map_err(|e| match e {
            ReadExactError::ReadError(ReadError::ConnectionLost(e)) => classify_conn_error(e),
            other => ConnectionError::Other(other.to_string()),
        })
    }

    async fn read_to_end(&mut self, limit: usize) -> Result<Vec<u8>, ConnectionError> {
        self.inner.read_to_end(limit).await.map_err(|e| match e {
            ReadToEndError::Read(ReadError::ConnectionLost(e)) => classify_conn_error(e),
            ReadToEndError::Read(other) => ConnectionError::Other(other.to_string()),
            ReadToEndError::TooLong => ConnectionError::Other("stream exceeds limit".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::transport::StreamTransportConfig;
    use iroh::endpoint::VarInt;

    /// Loopback iroh endpoint with relays/DNS disabled — the spike's
    /// zero-infrastructure setup, dialing the direct `EndpointAddr` only.
    async fn bind_loopback_endpoint(alpn: &[u8]) -> (iroh::endpoint::Endpoint, SocketAddr) {
        use iroh::RelayMode;
        use iroh::endpoint::Endpoint;
        use iroh::endpoint::presets::Minimal;
        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        // The spike dials an explicitly-bound port; reserve one the same way.
        let port = {
            let sock = std::net::UdpSocket::bind(addr).unwrap();
            sock.local_addr().unwrap().port()
        };
        let addr = SocketAddr::new(addr.ip(), port);
        let endpoint = Endpoint::builder(Minimal)
            .alpns(vec![alpn.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind_addr(addr)
            .expect("bind_addr")
            .bind()
            .await
            .expect("endpoint bind");
        (endpoint, addr)
    }

    /// Same exercise as `connection::tests::quinn_connection_roundtrip`,
    /// over iroh's noq connection: uni round-trip through the traits and
    /// graceful close surfacing as `ConnectionError::Closed`.
    #[tokio::test]
    async fn iroh_connection_roundtrip() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let alpn = StreamTransportConfig::default().alpn;
        let (server, server_addr) = bind_loopback_endpoint(&alpn).await;
        let (client, _) = bind_loopback_endpoint(&alpn).await;

        let accept = {
            let server = server.clone();
            tokio::spawn(async move {
                let incoming = server.accept().await.expect("incoming");
                let conn = incoming.accept().expect("reject").await.expect("handshake");
                IrohConnection::shared(conn)
            })
        };

        let raw_client = client
            .connect(server.addr(), &alpn)
            .await
            .expect("dial loopback");
        let client_q = IrohConnection::new(raw_client);
        let client_conn: SharedConnection = Arc::new(client_q.clone());
        let server_conn: SharedConnection = accept.await.expect("accept task");

        assert_eq!(
            client_q.remote_address(),
            server_addr,
            "direct loopback connection reports the dialed socket address"
        );
        assert!(
            !client_q.stats().relayed && !server_conn.stats().relayed,
            "relay-less loopback traffic is direct"
        );
        let stats = client_q.stats();
        assert!(
            stats.bytes_sent > 0 && stats.datagrams_sent > 0,
            "the aggregate counters do fill in: {stats:?}"
        );
        assert_eq!(
            (stats.cwnd_bytes, stats.path_mtu, stats.congestion_events),
            (None, None, None),
            "iroh's connection-level stats throw the per-path fields away, and a \
             WAN record must say so rather than report a healthy-looking zero"
        );

        let payload = tokio::join!(
            async {
                let mut reader = server_conn.accept_uni().await.expect("accept_uni");
                let mut head = [0u8; 6];
                reader.read_exact(&mut head).await.expect("read_exact");
                let mut body = reader.read_to_end(64).await.expect("read_to_end");
                let mut all = head.to_vec();
                all.append(&mut body);
                all
            },
            async {
                let mut writer = client_conn.open_uni().await.expect("open_uni");
                writer.write_all(b"hello ").await.expect("write 1");
                writer.write_all(b"stream").await.expect("write 2");
                writer.finish().expect("finish");
            },
        )
        .0;
        assert_eq!(payload, b"hello stream");

        // Same exercise over the client dial path: reassemble the announced
        // identity strings into an `EndpointAddr`, dial with relays off, and
        // round-trip a stream pair through the traits. (The server handle is
        // held open — dropping the last iroh Connection handle closes the
        // connection, unlike quinn.)
        {
            let accept2 = {
                let server = server.clone();
                tokio::spawn(async move {
                    let incoming = server.accept().await.expect("incoming 2");
                    let conn = incoming
                        .accept()
                        .expect("reject 2")
                        .await
                        .expect("handshake 2");
                    IrohConnection::shared(conn)
                })
            };
            let dial = IrohDial::dial(
                &server.id().to_string(),
                &[],
                &[server_addr.to_string()],
                false,
                Duration::from_secs(10),
            )
            .await
            .expect("loopback dial over direct addr");
            let dialed = dial.connection();
            let server2 = accept2.await.expect("accept task 2");

            let echoed = tokio::join!(
                async {
                    let mut r = server2.accept_uni().await.expect("server accept_uni");
                    let data = r.read_to_end(64 * 1024).await.expect("server read");
                    let mut s = server2.open_uni().await.expect("server open_uni");
                    s.write_all(&data).await.expect("server echo");
                    s.finish().expect("server finish");
                },
                async {
                    let mut w = dialed.open_uni().await.expect("client open_uni");
                    w.write_all(b"over the wan").await.expect("client write");
                    w.finish().expect("client finish");
                    let mut r = dialed.accept_uni().await.expect("client accept_uni");
                    r.read_to_end(1024).await.expect("client read")
                },
            )
            .1;
            assert_eq!(echoed, b"over the wan");

            drop(server2);
            dial.close().await;
        }

        // Close surfaces as ConnectionError::Closed on the accept loop —
        // the sentinel every streaming receive task breaks on.
        client_q.inner().close(VarInt::from_u32(0), b"bye");
        match tokio::time::timeout(Duration::from_secs(5), server_conn.accept_uni()).await {
            Ok(Err(ConnectionError::Closed)) => {}
            Ok(Ok(_)) => panic!("unexpected stream after close"),
            Ok(Err(other)) => panic!("expected Closed from accept_uni, got {other}"),
            Err(_) => panic!("accept_uni hung after close"),
        }

        // iroh lesson from the spike: dropping a live endpoint aborts its
        // socket task with an ERROR log — close both explicitly.
        client.close().await;
        server.close().await;
    }
}
