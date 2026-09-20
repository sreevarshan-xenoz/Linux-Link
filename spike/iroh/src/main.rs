//! Runnable demo: two relay-less iroh endpoints on loopback, one full
//! stream+datagram echo round-trip. Exits non-zero if anything fails.

use anyhow::Result;
use iroh_spike::{
    bind_loopback_endpoint, client_roundtrip, reserve_loopback_port, serve_echo_once,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let server = bind_loopback_endpoint(reserve_loopback_port()?).await?;
    let client = bind_loopback_endpoint(reserve_loopback_port()?).await?;

    println!("server endpoint: {:?}", server.addr());
    println!("client endpoint: {:?}", client.addr());

    let echo = tokio::spawn({
        let server = server.clone();
        async move { serve_echo_once(&server).await }
    });
    client_roundtrip(&client, &server).await?;
    echo.await??;

    // Dropping an Endpoint without closing it aborts its socket task ungracefully.
    client.close().await;
    server.close().await;

    println!("round-trip OK: bidi stream + datagram echoed over iroh (noq QUIC), relays disabled");
    Ok(())
}
