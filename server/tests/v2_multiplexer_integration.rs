use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use uuid::Uuid;

use linux_link_core::streaming::transport::{CertManager, StreamClient, StreamServer, StreamTransportConfig};
use linux_link_core::protocol::v2::{ALPN_V2, IdentityPacketV2, perform_v2_handshake};
use linux_link_core::protocol::kdeconnect::PluginRegistry;

// We need to access handle_v2_session and ACTIVE_CLIENTS
use linux_link_server::v2_multiplexer::handle_v2_session;
use linux_link_server::service::ACTIVE_CLIENTS;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_reconnect_storm_kills_stale_sessions() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_manager = Arc::new(CertManager::new()?);
    let registry = Arc::new(PluginRegistry::new());
    
    // Server
    let mut server_config = StreamTransportConfig::default();
    server_config.address = "127.0.0.1:0".parse()?;
    server_config.alpn = ALPN_V2.to_vec();
    let server = StreamServer::new(server_config, &cert_manager).await?;
    let server_addr = server.local_addr()?;
    
    // Server loop calling handle_v2_session directly
    let registry_clone = registry.clone();
    tokio::spawn(async move {
        while let Some(incoming) = server.accept_connection().await {
            let conn = incoming.await.unwrap();
            let registry_c = registry_clone.clone();
            tokio::spawn(async move {
                let local_identity = IdentityPacketV2 {
                    device_id: "server-test-id".to_string(),
                    device_name: "Mock Server".to_string(),
                    min_version: 1,
                    max_version: 1,
                    capabilities: vec![],
                };
                let _ = handle_v2_session(conn, local_identity, registry_c).await;
            });
        }
    });

    // Clear active clients list to ensure clean state
    {
        let mut clients = ACTIVE_CLIENTS.lock().await;
        clients.clear();
    }

    // Client Storm!
    let mut handles = Vec::new();
    for _ in 0..10 {
        let cert_mgr = cert_manager.clone();
        
        let handle = tokio::spawn(async move {
            let mut client_config = StreamTransportConfig::default();
            client_config.alpn = ALPN_V2.to_vec();
            let client = StreamClient::new(client_config, &cert_mgr).unwrap();
            
            if let Ok(conn) = client.connect(server_addr, "127.0.0.1").await {
                if let Ok((mut send0, mut recv0)) = conn.open_bi().await {
                    let local_id = IdentityPacketV2 {
                        device_id: "storm-client-id".to_string(), // SAME ID for all
                        device_name: "Storm Client".to_string(),
                        min_version: 1,
                        max_version: 1,
                        capabilities: vec![],
                    };
                    
                    if perform_v2_handshake(&mut send0, &mut recv0, &local_id).await.is_ok() {
                        // Keep connection alive for a while so they overlap
                        tokio::time::sleep(Duration::from_millis(1000)).await;
                    }
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all handshakes to theoretically complete and overlap
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check ACTIVE_CLIENTS. Even though 10 clients connected and are holding
    // their connection open, only 1 should be in the active list!
    {
        let clients = ACTIVE_CLIENTS.lock().await;
        assert_eq!(clients.len(), 1, "Reconnect storm failed! Found {} parallel brains", clients.len());
    }

    // Wait for all to finish
    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}
