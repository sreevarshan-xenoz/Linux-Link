pub mod proxy {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::sync::RwLock;
    use tracing::{debug, info};
    use rand::Rng;

    #[derive(Debug, Clone)]
    pub struct ChaosConfig {
        pub drop_rate: f64, // 0.0 to 1.0
        pub base_latency_ms: u64,
        pub jitter_ms: u64,
        pub blackhole_duration_ms: Option<u64>,
        pub start_time: std::time::Instant,
    }

    impl Default for ChaosConfig {
        fn default() -> Self {
            Self {
                drop_rate: 0.0,
                base_latency_ms: 0,
                jitter_ms: 0,
                blackhole_duration_ms: None,
                start_time: std::time::Instant::now(),
            }
        }
    }

    impl ChaosConfig {
        pub fn coffee_shop_wifi() -> Self {
            Self {
                drop_rate: 0.10, // 10% packet loss
                base_latency_ms: 50,
                jitter_ms: 100,
                blackhole_duration_ms: None,
                start_time: std::time::Instant::now(),
            }
        }

        pub fn elevator_deadzone() -> Self {
            Self {
                drop_rate: 0.0,
                base_latency_ms: 20,
                jitter_ms: 10,
                blackhole_duration_ms: Some(3000), // 3-second absolute blackhole
                start_time: std::time::Instant::now(),
            }
        }

        pub fn should_drop(&self) -> bool {
            // Check blackhole
            if let Some(dur) = self.blackhole_duration_ms {
                let elapsed = self.start_time.elapsed().as_millis() as u64;
                if elapsed > 1000 && elapsed < (1000 + dur) {
                    return true;
                }
            }

            if self.drop_rate <= 0.0 {
                return false;
            }
            
            let mut rng = rand::thread_rng();
            rng.gen_bool(self.drop_rate)
        }

        pub fn calculate_delay(&self) -> Duration {
            if self.base_latency_ms == 0 && self.jitter_ms == 0 {
                return Duration::from_millis(0);
            }
            
            let mut delay = self.base_latency_ms;
            if self.jitter_ms > 0 {
                let mut rng = rand::thread_rng();
                let jitter = rng.gen_range(0..self.jitter_ms);
                delay += jitter;
            }
            Duration::from_millis(delay)
        }
    }

    /// A simple UDP proxy that injects chaos (latency, drops) between a client and server.
    pub struct ChaosProxy {
        listen_addr: SocketAddr,
        target_addr: SocketAddr,
        config: Arc<RwLock<ChaosConfig>>,
        cancel: tokio_util::sync::CancellationToken,
    }

    impl ChaosProxy {
        pub async fn new(listen_addr: &str, target_addr: &str, config: ChaosConfig) -> anyhow::Result<Self> {
            let listen_addr: SocketAddr = listen_addr.parse()?;
            let target_addr: SocketAddr = target_addr.parse()?;
            Ok(Self {
                listen_addr,
                target_addr,
                config: Arc::new(RwLock::new(config)),
                cancel: tokio_util::sync::CancellationToken::new(),
            })
        }

        pub fn update_config(&self, config: ChaosConfig) {
            let config_clone = self.config.clone();
            tokio::spawn(async move {
                let mut guard = config_clone.write().await;
                *guard = config;
            });
        }

        pub fn stop(&self) {
            self.cancel.cancel();
        }

        pub async fn run(&self) -> anyhow::Result<()> {
            let socket = UdpSocket::bind(self.listen_addr).await?;
            let socket = Arc::new(socket);
            
            // Map of client addresses to their dedicated forwarder sockets
            let clients: Arc<RwLock<std::collections::HashMap<SocketAddr, (Arc<UdpSocket>, tokio::sync::mpsc::UnboundedSender<(tokio::time::Instant, Vec<u8>)>)>>> = 
                Arc::new(RwLock::new(std::collections::HashMap::new()));

            info!("ChaosProxy listening on {} -> forwarding to {}", self.listen_addr, self.target_addr);

            let mut buf = vec![0u8; 65535];
            let cancel = self.cancel.clone();

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        info!("ChaosProxy shutting down");
                        break;
                    }
                    res = socket.recv_from(&mut buf) => {
                        let (len, src_addr) = match res {
                            Ok(x) => x,
                            Err(e) => {
                                debug!("ChaosProxy read error: {}", e);
                                continue;
                            }
                        };

                        let data = buf[..len].to_vec();
                        let config = self.config.read().await.clone();

                        if config.should_drop() {
                            continue; // Drop packet
                        }

                        let delay = config.calculate_delay();
                        let target = self.target_addr;
                        let clients_ref = clients.clone();
                        let server_sock = socket.clone();

                        tokio::spawn(async move {
                            if delay.as_millis() > 0 {
                                tokio::time::sleep(delay).await;
                            }

                            // Ensure we have a proxy socket for this client to receive return traffic
                            let fwd_sock = {
                                let c_guard = clients_ref.read().await;
                                if let Some((s, _)) = c_guard.get(&src_addr) {
                                    s.clone()
                                } else {
                                    drop(c_guard);
                                    let mut c_guard = clients_ref.write().await;
                                    if let Some((s, _)) = c_guard.get(&src_addr) {
                                        s.clone()
                                    } else {
                                        // Create a new socket to talk to the server on behalf of this client
                                        let s = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
                                        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
                                        c_guard.insert(src_addr, (s.clone(), tx));
                                        
                                        // Spawn a task to listen for return traffic from the server
                                        let s_clone = s.clone();
                                        let mut ret_buf = vec![0u8; 65535];
                                        let server_sock_clone = server_sock.clone();
                                        tokio::spawn(async move {
                                            loop {
                                                if let Ok((n, _)) = s_clone.recv_from(&mut ret_buf).await {
                                                    let _ = server_sock_clone.send_to(&ret_buf[..n], src_addr).await;
                                                } else {
                                                    break;
                                                }
                                            }
                                        });

                                        // Spawn a task to send forwarded traffic in order
                                        let s_clone2 = s.clone();
                                        let target_clone = target;
                                        tokio::spawn(async move {
                                            while let Some((deliver_at, data)) = rx.recv().await {
                                                tokio::time::sleep_until(deliver_at.into()).await;
                                                let _ = s_clone2.send_to(&data, target_clone).await;
                                            }
                                        });

                                        s
                                    }
                                }
                            };
                            
                            // Queue packet for ordered delivery
                            let c_guard = clients_ref.read().await;
                            if let Some((_, tx)) = c_guard.get(&src_addr) {
                                let deliver_at = tokio::time::Instant::now() + delay;
                                let _ = tx.send((deliver_at, data));
                            }
                        });
                    }
                }
            }
            Ok(())
        }
    }
}
