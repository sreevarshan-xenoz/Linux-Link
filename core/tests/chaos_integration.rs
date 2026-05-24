use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use linux_link_core::streaming::chaos::proxy::{ChaosProxy, ChaosConfig};

#[tokio::test]
async fn test_coffee_shop_wifi() {
    let server_addr: SocketAddr = "127.0.0.1:4716".parse().unwrap();
    let proxy_addr: SocketAddr = "127.0.0.1:4717".parse().unwrap();
    
    // 1. Setup dummy server
    let server_socket = UdpSocket::bind(server_addr).await.expect("Failed to bind server socket");
    let received_count = Arc::new(AtomicUsize::new(0));
    let received_count_clone = received_count.clone();
    
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        while let Ok((_len, _src)) = server_socket.recv_from(&mut buf).await {
            received_count_clone.fetch_add(1, Ordering::SeqCst);
        }
    });

    // 2. Setup ChaosProxy
    let config = ChaosConfig::coffee_shop_wifi(); // 10% drop rate, latency, jitter
    let proxy = ChaosProxy::new("127.0.0.1:4717", "127.0.0.1:4716", config).await.expect("Failed to create ChaosProxy");
    
    tokio::spawn(async move {
        let _ = proxy.run().await;
    });

    // 3. Wait 1s for proxy to start
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 4. Send 100 datagrams
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("Failed to bind client socket");
    let payload = b"hello chaos";
    for _ in 0..100 {
        client_socket.send_to(payload, proxy_addr).await.expect("Failed to send datagram");
        // small delay to prevent UDP buffer overflow and allow latency/jitter to apply well
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // 5. Wait for packets to arrive (accounting for latency and jitter)
    tokio::time::sleep(Duration::from_secs(2)).await;

    let total_received = received_count.load(Ordering::SeqCst);
    println!("Total received: {}", total_received);
    
    // With 10% drop rate, we expect roughly 90.
    // Assert it's > 60 and < 100 to tolerate RNG variance but confirm drops occurred.
    assert!(total_received > 60, "Received too few packets: {}", total_received);
    assert!(total_received < 100, "Received all packets, no drops occurred!");
}
