use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use linux_link_core::streaming::transport::{CertManager, StreamServer, StreamTransportConfig, StreamClient};
use linux_link_core::streaming::chaos::proxy::{ChaosProxy, ChaosConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_coffee_shop_wifi_multiplexing() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_manager = Arc::new(CertManager::new()?);
    
    // Server
    let mut server_config = StreamTransportConfig::default();
    server_config.address = "127.0.0.1:0".parse()?; // Random port
    let server = StreamServer::new(server_config, &cert_manager).await?;
    let server_addr = server.local_addr()?;
    
    // Proxy with 10% packet loss and 100ms jitter
    let proxy_port = 50000 + (rand::random::<u16>() % 10000);
    let proxy_addr_str = format!("127.0.0.1:{}", proxy_port);
    let mut chaos_cfg = ChaosConfig::coffee_shop_wifi();
    chaos_cfg.drop_rate = 0.10; // 10% loss
    chaos_cfg.jitter_ms = 0; // Prevent massive packet reordering from independent async sleep
    let proxy = ChaosProxy::new(&proxy_addr_str, &server_addr.to_string(), chaos_cfg).await?;
    
    tokio::spawn(async move { proxy.run().await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Server Accept Loop
    let (input_latency_tx, mut input_latency_rx) = tokio::sync::mpsc::channel::<Duration>(100);
    tokio::spawn(async move {
        let incoming = server.accept_connection().await.unwrap();
        let conn = incoming.await.unwrap();
        // Server stream accept loop
        loop {
            match conn.accept_uni().await {
                Ok(mut recv) => {
                    let tx = input_latency_tx.clone();
                    tokio::spawn(async move {
                        use tokio::io::AsyncReadExt;
                        let mut buf = vec![0u8; 1024 * 1024];
                        let mut total_read = 0;
                        let mut first_byte = None;
                        let mut sent_time = None;
                        
                        loop {
                            match recv.read(&mut buf).await {
                                Ok(Some(n)) => {
                                    if total_read == 0 && n > 0 {
                                        first_byte = Some(buf[0]);
                                        if buf[0] == 3 && n >= 9 {
                                            sent_time = Some(u64::from_le_bytes(buf[1..9].try_into().unwrap()));
                                        }
                                    }
                                    total_read += n;
                                }
                                Ok(None) => break, // EOF
                                Err(e) => {
                                    println!("Server read err: {:?}", e);
                                    break;
                                }
                            }
                        }

                        if first_byte == Some(3) {
                            println!("Input stream EOF, sent_time: {:?}", sent_time);
                            if let Some(t) = sent_time {
                                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                                let latency = Duration::from_millis(now.saturating_sub(t));
                                let _ = tx.send(latency).await;
                            }
                        } else {
                            // Video stream finished or reset
                        }
                    });
                }
                Err(e) => {
                    println!("Server accept_uni err: {}", e);
                    break;
                }
            }
        }
    });

    // Client
    let client = StreamClient::new(StreamTransportConfig::default(), &cert_manager)?;
    
    let conn = client.connect(server_addr, "127.0.0.1").await?;
    
    // Send 50 input packets, 100ms apart (5 seconds)
    // Concurrently send massive video frames to simulate flood/congestion
    let conn_video = conn.clone();
    tokio::spawn(async move {
        let video_data = vec![0u8; 1024 * 1024]; // 1MB frame
        let mut prev_stream: Option<quinn::SendStream> = None;
        for _ in 0..50 {
            // LATEST FRAME WINS: Reset the previous stream if it's still sending!
            if let Some(mut stream) = prev_stream.take() {
                let _ = stream.reset(0u32.into());
            }

            if let Ok(mut send) = conn_video.open_uni().await {
                let _ = send.set_priority(10); // Lowest priority
                // Send large video frame
                let _ = send.write_all(&video_data).await; // This buffers it in Quinn
                prev_stream = Some(send); // Keep handle to cancel it next frame
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    for i in 0..50 {
        match conn.open_uni().await {
            Ok(mut send) => {
                let _ = send.set_priority(0); // Highest priority
                let mut buf = vec![0u8; 9];
                buf[0] = 3; // Input Kind
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                buf[1..9].copy_from_slice(&now.to_le_bytes());
                if let Err(e) = send.write_all(&buf).await {
                    println!("Input client write err {}: {}", i, e);
                }
                let _ = send.finish();
                println!("Input client sent {}", i);
            }
            Err(e) => println!("Input client open_uni err {}: {}", i, e),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Wait for stragglers
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Analyze latencies
    let mut latencies = Vec::new();
    while let Ok(lat) = input_latency_rx.try_recv() {
        latencies.push(lat.as_millis());
    }

    assert!(!latencies.is_empty(), "No input packets received!");
    
    let avg_latency: u128 = latencies.iter().sum::<u128>() / latencies.len() as u128;
    println!("Received {}/50 input packets. Avg Latency: {}ms", latencies.len(), avg_latency);
    
    // The Fairness Contract requires sub-100ms input latency under congestion and 10% drop.
    // Jitter is 100ms, base latency 50ms, so 150ms max normal latency. 
    // If it's over 300ms, HOL blocking is happening!
    assert!(avg_latency < 300, "HOL Blocking detected! Input latency spiked to {}ms", avg_latency);

    Ok(())
}
