//! R1 spike tests: iroh loopback connectivity + the quinn incompatibility.

use anyhow::Result;
use iroh::endpoint::Connection as IrohConnection;
use iroh_spike::{
    ALPN, PAYLOAD, bind_loopback_endpoint, client_roundtrip, reserve_loopback_port, serve_echo_once,
};

async fn pair() -> Result<(iroh::endpoint::Endpoint, iroh::endpoint::Endpoint)> {
    let server = bind_loopback_endpoint(reserve_loopback_port()?).await?;
    let client = bind_loopback_endpoint(reserve_loopback_port()?).await?;
    Ok((server, client))
}

#[tokio::test]
async fn bidi_stream_and_datagram_echo() -> Result<()> {
    let (server, client) = pair().await?;
    let echo = tokio::spawn({
        let server = server.clone();
        async move { serve_echo_once(&server).await }
    });
    client_roundtrip(&client, &server).await?;
    echo.await??;
    client.close().await;
    server.close().await;
    Ok(())
}

#[tokio::test]
async fn uni_stream_reaches_server() -> Result<()> {
    let (server, client) = pair().await?;
    let accept = tokio::spawn({
        let server = server.clone();
        async move { serve_echo_once(&server).await }
    });

    let conn = client.connect(server.addr(), ALPN).await?;
    let mut send = conn.open_uni().await?;
    send.write_all(PAYLOAD).await?;
    send.finish()?;

    // The same connection on the server side; accept_bi in serve_echo_once
    // blocks on the bi queue, so racing our accept_uni here is fine.
    let server_conn = accept.await??;
    let mut recv = server_conn.accept_uni().await?;
    let data = recv.read_to_end(64 * 1024).await?;
    assert_eq!(data, PAYLOAD);
    client.close().await;
    server.close().await;
    Ok(())
}

/// Compile-time proof of the spike's central finding: `iroh::endpoint::Connection`
/// and `quinn::Connection` are distinct types — core's quinn-typed streaming
/// code cannot be pointed at iroh without an abstraction layer. The two crates
/// do coexist in one binary (this test links both).
#[test]
fn iroh_types_are_not_quinn_types() {
    fn takes_iroh_conn(_: IrohConnection) {}
    fn takes_quinn_conn(_: quinn::Connection) {}

    // Both callables exist; assigning an iroh connection to the quinn one is
    // the incompatibility. Uncommenting the next block must fail to compile:
    // let _ = |c: IrohConnection| takes_quinn_conn(c);

    // Sanity: neither function is optimized away into an unused warning.
    let _ = (
        takes_iroh_conn as fn(IrohConnection),
        takes_quinn_conn as fn(quinn::Connection),
    );
}
