# Linux Link - Comprehensive Development Plan

> **A Rust-based remote desktop solution combining low-latency Wayland screen streaming (Sunshine-level) + full KDE Connect feature set + Tailscale-native connectivity**

**Target Platforms:** Arch Linux + Hyprland (server), Android (client)

**Project Status:** Active Development (Phase 2 in progress)

**Estimated Timeline:** 4-6 months for MVP

**Execution Snapshot (March 31, 2026):**
- Phase 0 completed (workspace scaffold, CI, docs, build/test baseline)
- Phase 1 largely completed (CLI + handshake + discovery watch); two-device discovery validation still pending
- Phase 2 kicked off with compile-ready KDE protocol scaffolding and server plugin metadata stubs
- Quality gates currently pass (`cargo fmt`, `cargo check`, `cargo clippy -D warnings`, `cargo test`)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [High-Level Architecture](#high-level-architecture)
3. [Technology Stack](#technology-stack)
4. [Phase-by-Phase Implementation Plan](#phase-by-phase-implementation-plan)
5. [Detailed Execution Steps](#detailed-execution-steps)
6. [Technical Deep Dives](#technical-deep-dives)
7. [Risk Assessment & Mitigation](#risk-assessment--mitigation)
8. [Testing Strategy](#testing-strategy)
9. [Deployment & Packaging](#deployment--packaging)
10. [Appendix: Quick Reference](#appendix-quick-reference)

---

## Executive Summary

### Project Vision

Linux Link is a pioneering pure-Rust remote desktop solution that fills a critical gap in the Linux ecosystem: **secure, low-latency remote access over Tailscale with full device integration features**. Unlike existing solutions that require public port forwarding or centralized servers, Linux Link leverages Tailscale's encrypted mesh network for automatic, secure connectivity.

### Key Differentiators

| Feature | Linux Link | RustDesk | Sunshine/Moonlight | KDE Connect |
|---------|------------|----------|-------------------|-------------|
| **Tailscale-native** | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **Wayland-native** | ✅ Yes | ⚠️ Partial | ⚠️ Partial | ✅ Yes |
| **Hyprland optimized** | ✅ Yes | ❌ No | ⚠️ Limited | ⚠️ Limited |
| **Full KDE Connect** | ✅ Yes | ⚠️ Partial | ❌ No | ✅ Yes |
| **<100ms latency** | ✅ Target | ⚠️ Variable | ✅ Yes | N/A |
| **Pure Rust** | ✅ Yes | ✅ Yes | ❌ C++ | ❌ C++ |
| **Open Source** | ✅ MIT/Apache | ✅ AGPL | ✅ GPL | ✅ GPL |

### Success Criteria

- [ ] **Latency:** End-to-end screen streaming latency <100ms on LAN, <200ms over internet
- [ ] **Quality:** 1080p60 streaming with adaptive bitrate
- [ ] **Security:** All traffic encrypted via Tailscale; optional PIN pairing
- [ ] **Compatibility:** Works on all Wayland compositors (Hyprland, Sway, GNOME, KDE)
- [ ] **Features:** Full KDE Connect feature parity + screen streaming
- [ ] **Usability:** One-click connection via Tailscale; no manual IP configuration

---

## High-Level Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Linux Link Architecture                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────┐         Tailscale P2P          ┌─────────────┐│
│  │   Android Client     │◄───────Encrypted──────────────►│   Server    ││
│  │   (Flutter + Rust)   │        (Tailscale IP)          │(Hyprland)   ││
│  ├──────────────────────┤                                ├─────────────┤│
│  │  UI Layer (Flutter)  │                                │ Rust Daemon ││
│  │  ├── Connection Mgr  │                                │   (tokio)   ││
│  │  ├── Video Player    │                                ├─────────────┤│
│  │  ├── File Browser    │                                │  Core Lib   ││
│  │  └── Settings        │                                │  (shared)   ││
│  ├──────────────────────┤                                ├─────────────┤│
│  │  Rust Backend (FFI)  │                                │  Modules:   ││
│  │  ├── Protocol Handler│                                │  ├── Screen ││
│  │  ├── Video Decoder   │                                │  ├── Input  ││
│  │  ├── File Transfer   │                                │  ├── Files  ││
│  │  └── Input Mapper    │                                │  ├── KDE C. ││
│  └──────────────────────┘                                │  └── Tails. ││
│                                                          └─────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Breakdown

#### Server (Linux/Hyprland)

| Component | Responsibility | Technology |
|-----------|---------------|------------|
| **Screen Capture** | Monitor/window capture via PipeWire | `ashpd` + `pipewire` |
| **Video Encoding** | H.264/HEVC hardware encoding | `playa-ffmpeg` (VAAPI/NVENC) |
| **Input Injection** | Keyboard/mouse event handling | `ashpd` Input Capture + `enigo` |
| **KDE Connect** | File transfer, clipboard, notifications | `kdeconnect-proto` |
| **Tailscale** | Peer discovery, secure transport | `tailscale-localapi` |
| **Hyprland IPC** | App launching, window control | `hyprland` crate |
| **DBus Integration** | Notifications, media control | `zbus` |

#### Client (Android)

| Component | Responsibility | Technology |
|-----------|---------------|------------|
| **UI Framework** | User interface | Flutter (Dart) |
| **Rust Bridge** | FFI communication | `flutter_rust_bridge` |
| **Video Decoding** | H.264 hardware decoding | MediaCodec + SurfaceTexture |
| **Input Handling** | Touch gestures, virtual trackpad | Flutter gestures |
| **File Access** | File picker, transfer | Storage Access Framework |
| **Background Service** | Notifications when closed | Android Foreground Service |

#### Shared Protocol

```
┌─────────────────────────────────────────────────────────────┐
│                    Linux Link Protocol                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Control Channel (TCP over Tailscale)                        │
│  ├── KDE Connect packets (JSON, newline-terminated)         │
│  ├── Custom streaming commands                               │
│  └── Authentication/handshake                                │
│                                                              │
│  Streaming Channel (QUIC/UDP over Tailscale)                 │
│  ├── H.264/HEVC video frames (binary)                        │
│  ├── Input events (binary)                                   │
│  └── Audio packets (Opus, optional)                          │
│                                                              │
│  File Transfer Channel (TCP, negotiated port)                │
│  └── Large file transfers with progress                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

#### Screen Streaming Flow

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│  PipeWire   │───►│  H.264/H.265 │───►│   QUIC/UDP  │───►│  MediaCodec  │
│  (ashpd)    │    │  (playa-    │    │   (quinn)   │    │  (Android)   │
│  Frame      │    │   ffmpeg)    │    │   Stream    │    │   Decode     │
│  Capture    │    │   Encode     │    │             │    │              │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
                                                                  │
                                                                  ▼
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│   Flutter   │◄───│  Texture ID  │◄───│  Surface     │◄───│   Frame      │
│   Texture   │    │   Render     │    │  Texture     │    │   Buffer     │
│   Widget    │    │              │    │              │    │              │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
```

#### Input Event Flow

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│   Flutter   │───►│  Rust FFI    │───►│  QUIC/TCP   │───►│  Input       │
│   Gesture   │    │  (FRB)       │    │  Stream     │    │  Handler     │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
                                                                  │
                                                                  ▼
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│   Hyprland  │◄───│  Wayland     │◄───│  XDG Input  │◄───│  Event       │
│   Compositor│    │  Input      │    │  Capture    │    │  Injection   │
│             │    │  Protocol   │    │  (ashpd)    │    │  (enigo)     │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
```

---

## Technology Stack

### Server Dependencies (Cargo.toml)

```toml
[package]
name = "linux-link-server"
version = "0.1.0"
edition = "2024"

[workspace]
members = ["core", "server", "android/rust"]

[workspace.dependencies]
# Core async runtime
tokio = { version = "1", features = ["full"] }
tokio-util = "0.7"

# XDG Desktop Portal (screen capture, input)
ashpd = { version = "0.13", features = ["screencast", "input-capture", "tokio"] }
pipewire = "0.9"
libspa = "0.9"

# Hyprland integration
hyprland = "0.3"
wayland-client = "0.31"
wayland-protocols = "0.32"
wayland-protocols-wlr = "0.3"

# KDE Connect protocol
kdeconnect-proto = "0.2"

# Video encoding
playa-ffmpeg = { version = "8.0", features = ["vaapi", "nvenc"] }
# Alternative: ffmpeg-next = "7"

# Tailscale integration
tailscale-localapi = "0.2"

# QUIC streaming
quinn = "0.11"

# DBus integration
zbus = { version = "5.7", features = ["tokio"] }

# Input handling
enigo = { version = "0.6", features = ["wayland"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Error handling
anyhow = "1"
thiserror = "2"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Configuration
toml = "0.8"
dirs = "5"

# Crypto (for optional PIN)
argon2 = "0.5"
rand = "0.8"
```

### Client Dependencies (Flutter pubspec.yaml)

```yaml
name: linux_link_client
description: Linux Link Android Client
version: 1.0.0+1

environment:
  sdk: '>=3.5.0 <4.0.0'

dependencies:
  flutter:
    sdk: flutter
  
  # Rust FFI
  flutter_rust_bridge: ^2.12.0
  
  # State management
  flutter_riverpod: ^2.4.0
  
  # Navigation
  go_router: ^14.0.0
  
  # UI components
  material_symbols_icons: ^8.0.0
  
  # File handling
  file_picker: ^8.0.0
  
  # Network
  connectivity_plus: ^6.0.0
  
  # Preferences
  shared_preferences: ^2.2.0
  
  # Notifications
  flutter_local_notifications: ^17.0.0
  
  # Background service
  flutter_background_service: ^5.0.0

dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^4.0.0
  build_runner: ^2.4.0
  ffigen: ^11.0.0
```

### Client Dependencies (Rust - android/rust/Cargo.toml)

```toml
[package]
name = "linux-link-android"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
flutter_rust_bridge = "2.12.0"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
anyhow = "1"
tracing = "0.1"

# Shared with server
linux-link-core = { path = "../../core" }

# Video decoding (feed frames to MediaCodec via JNI)
# Note: Actual decoding done in Android; Rust handles protocol
```

---

## Phase-by-Phase Implementation Plan

### Timeline Overview

```
Month 1          Month 2          Month 3          Month 4          Month 5          Month 6
│                │                │                │                │                │
├────────────────┤                │                │                │                │
│ Phase 0: Setup │                │                │                │                │
│ (Week 1-2)     │                │                │                │                │
└────────────────┘                │                │                │                │
                ├─────────────────┤                │                │                │
                │ Phase 1: Basic  │                │                │                │
                │ Daemon +        │                │                │                │
                │ Tailscale       │                │                │                │
                │ (Week 3-6)      │                │                │                │
                └─────────────────┘                │                │                │
                                ├──────────────────┼───────────────┤                │
                                │ Phase 2: KDE     │               │                │
                                │ Connect Features │               │                │
                                │ (Week 7-12)      │               │                │
                                └──────────────────┼───────────────┘                │
                                                   │                ├──────────────┼──────────────┤
                                                   │                │ Phase 3:     │              │
                                                   │                │ Screen       │              │
                                                   │                │ Streaming    │              │
                                                   │                │ (Week 13-24) │              │
                                                   │                └──────────────┼──────────────┘
                                                                                  │
                                                   ┌──────────────────────────────┼──────────────┐
                                                   │ Phase 4: Android Client      │              │
                                                   │ Polish                       │              │
                                                   │ (Week 19-26)                 │              │
                                                   └──────────────────────────────┼──────────────┘
                                                                                  │
                                                   ┌──────────────────────────────┼──────────────┐
                                                   │ Phase 5: Polish & Extras     │              │
                                                   │ (Week 25-28)                 │              │
                                                   └──────────────────────────────┼──────────────┘
                                                                                  │
                                                                                  ├──────────────┤
                                                                                  │ Phase 6:     │
                                                                                  │ Release &    │
                                                                                  │ Packaging    │
                                                                                  │ (Week 29-30) │
                                                                                  └──────────────┘
```

### Phase Summary

| Phase | Duration | Key Deliverables | Success Criteria |
|-------|----------|------------------|------------------|
| **Phase 0** | 1-2 weeks | Project structure, build system, CI/CD | `cargo build` succeeds, Flutter app runs |
| **Phase 1** | 3-4 weeks | Tailscale daemon, peer discovery, basic CLI | Two devices connect over Tailscale |
| **Phase 2** | 5-6 weeks | KDE Connect features, Android basic UI | File transfer, clipboard, notifications work |
| **Phase 3** | 8-10 weeks | Screen capture, encoding, streaming, input | <150ms latency, 30+ FPS streaming |
| **Phase 4** | 6-8 weeks | Android UI polish, gestures, background service | Production-ready Android app |
| **Phase 5** | 3-4 weeks | systemd service, config, optimizations | Auto-start works, <100ms latency |
| **Phase 6** | 2-3 weeks | AUR package, Android APK, documentation | Published on AUR + GitHub Releases |

---

## Detailed Execution Steps

### Phase 0: Project Setup (Week 1-2)

#### Day 1-3: Repository & Workspace Setup

**Step 0.1: Create Repository Structure**

```bash
# Initialize repository
mkdir linux-link
cd linux-link
git init

# Create workspace structure
mkdir -p core/src
mkdir -p server/src
mkdir -p android/{rust,lib,android/app/src/main/{kotlin,res}}

# Initialize Cargo workspace
cat > Cargo.toml << 'EOF'
[workspace]
resolver = "2"
members = [
    "core",
    "server",
    "android/rust",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"
repository = "https://github.com/yourusername/linux-link"
EOF

# Initialize core crate
cat > core/Cargo.toml << 'EOF'
[package]
name = "linux-link-core"
version.workspace = true
edition.workspace = true

[dependencies]
# Shared dependencies will be added as needed
EOF

# Initialize server crate
cat > server/Cargo.toml << 'EOF'
[package]
name = "linux-link-server"
version.workspace = true
edition.workspace = true

[[bin]]
name = "linux-link"
path = "src/main.rs"

[dependencies]
linux-link-core = { path = "../core" }
# Add other dependencies as we implement
EOF

# Initialize Android Rust crate
cat > android/rust/Cargo.toml << 'EOF'
[package]
name = "linux-link-android"
version.workspace = true
edition.workspace = true

[lib]
crate-type = ["cdylib"]

[dependencies]
flutter_rust_bridge = "2.12.0"
linux-link-core = { path = "../../core" }
EOF
```

**Step 0.2: Create Initial Source Files**

```bash
# Core library structure
mkdir -p core/src/{protocol,tailscale,streaming,input}

cat > core/src/lib.rs << 'EOF'
//! Linux Link Core Library
//! 
//! Shared protocol, utilities, and business logic for Linux Link.

pub mod protocol;
pub mod tailscale;
pub mod streaming;
pub mod input;

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u32 = 1;

/// Default ports
pub const DEFAULT_CONTROL_PORT: u16 = 1716;  // KDE Connect compatible
pub const DEFAULT_STREAMING_PORT: u16 = 4716;
EOF

# Server main entry
cat > server/src/main.rs << 'EOF'
//! Linux Link Server
//! 
//! Background daemon for remote desktop access over Tailscale.

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod service;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    
    tracing::info!("Linux Link Server starting...");
    
    // Load configuration
    let config = config::Config::load()?;
    
    // Start service
    service::run(config).await?;
    
    Ok(())
}
EOF

# Android Rust bridge
cat > android/rust/src/lib.rs << 'EOF'
//! Linux Link Android - Rust Backend
//! 
//! Flutter Rust Bridge interface for Android client.

use flutter_rust_bridge::frb;

#[frb]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[frb]
pub async fn connect(address: String) -> Result<ConnectionState, String> {
    // Implementation in later phases
    Ok(ConnectionState::Disconnected)
}

#[frb]
pub enum ConnectionState {
    Connected,
    Disconnected,
    Connecting,
    Error(String),
}
EOF
```

**Step 0.3: Flutter Project Setup**

```bash
cd android

# Create Flutter project (if not exists)
flutter create --org com.linuxlink --project-name linux_link_client .

# Update pubspec.yaml (see Technology Stack section)

# Install dependencies
flutter pub get

# Generate FRB bindings
cargo install flutter_rust_bridge_codegen
flutter_rust_bridge_codegen generate
```

**Step 0.4: Development Environment Setup**

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
rustup target add x86_64-unknown-linux-gnu

# For Android cross-compilation
rustup target add aarch64-linux-android armv7-linux-androideabi

# Install system dependencies (Arch Linux)
sudo pacman -S \
    pipewire \
    xdg-desktop-portal \
    xdg-desktop-portal-hyprland \
    xdg-desktop-portal-gtk \
    hyprland \
    tailscale \
    ffmpeg \
    libva \
    libva-utils

# Enable Tailscale
sudo systemctl enable --now tailscaled

# Verify Tailscale status
tailscale status
```

**Step 0.5: CI/CD Setup**

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always

jobs:
  build-server:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-action@stable
      
      - name: Cache cargo
        uses: Swatinem/rust-cache@v2
      
      - name: Build server
        run: cargo build --workspace --release
      
      - name: Run tests
        run: cargo test --workspace
  
  build-android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Flutter
        uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.24.0'
      
      - name: Install Rust
        uses: dtolnay/rust-action@stable
      
      - name: Add Android targets
        run: |
          rustup target add aarch64-linux-android armv7-linux-androideabi
      
      - name: Build Flutter APK
        run: |
          cd android
          flutter build apk --release

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-action@stable
      
      - name: Run clippy
        run: cargo clippy --workspace -- -D warnings
      
      - name: Run fmt
        run: cargo fmt --all -- --check
```

**Deliverables Checklist - Phase 0:**

- [x] Cargo workspace with core, server, android crates
- [ ] Flutter project with FRB integration
- [x] Basic CI/CD pipeline
- [x] Development environment documented
- [x] `cargo build` succeeds for all targets
- [ ] Flutter app runs on Android emulator

---

### Phase 1: Basic Daemon + Tailscale (Week 3-6)

#### Goal: Establish secure Tailscale connectivity between devices

#### Step 1.1: Tailscale Integration (Week 3)

**Implement Tailscale Status Checker:**

```rust
// core/src/tailscale/mod.rs
use anyhow::{Context, Result};
use tailscale_localapi::{LocalApi, Status};
use std::time::Duration;
use tokio::time::sleep;

pub struct TailscaleClient {
    api: LocalApi,
}

impl TailscaleClient {
    pub fn new() -> Result<Self> {
        let socket_path = std::env::var("TAILSCALE_SOCKET")
            .unwrap_or_else(|_| "/var/run/tailscale/tailscaled.sock".to_string());
        
        let api = LocalApi::new_with_socket_path(&socket_path)
            .context("Failed to connect to Tailscale daemon")?;
        
        Ok(Self { api })
    }
    
    /// Wait for Tailscale to be ready
    pub async fn wait_for_ready(&self, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        
        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("Tailscale not ready within timeout");
            }
            
            match self.api.status().await {
                Ok(status) if status.backend_state == "Running" => {
                    tracing::info!("Tailscale is connected");
                    return Ok(());
                }
                Ok(status) => {
                    tracing::debug!("Waiting for Tailscale... state: {}", status.backend_state);
                }
                Err(e) => {
                    tracing::debug!("Tailscale not ready: {}", e);
                }
            }
            
            sleep(Duration::from_secs(2)).await;
        }
    }
    
    /// Get our Tailscale IP address
    pub async fn get_self_ip(&self) -> Result<String> {
        let status = self.api.status().await?;
        
        status.self_
            .as_ref()
            .and_then(|s| s.tailscale_ips.first())
            .cloned()
            .context("No Tailscale IP assigned")
    }
    
    /// Get all peers on the tailnet
    pub async fn get_peers(&self) -> Result<Vec<PeerInfo>> {
        let status = self.api.status().await?;
        
        let peers = status.peer
            .iter()
            .map(|p| PeerInfo {
                name: p.name.clone(),
                dns_name: p.dns_name.clone(),
                ips: p.tailscale_ips.clone(),
                online: p.active,
            })
            .collect();
        
        Ok(peers)
    }
    
    /// Check if a specific peer is online
    pub async fn is_peer_online(&self, peer_name: &str) -> Result<bool> {
        let peers = self.get_peers().await?;
        Ok(peers.iter().any(|p| p.name == peer_name && p.online))
    }
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub name: String,
    pub dns_name: String,
    pub ips: Vec<String>,
    pub online: bool,
}
```

**Step 1.2: Device Discovery Service**

```rust
// core/src/tailscale/discovery.rs
use super::{TailscaleClient, PeerInfo};
use anyhow::Result;
use std::collections::HashMap;
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};

pub struct DiscoveryService {
    client: TailscaleClient,
    tx: broadcast::Sender<DiscoveryEvent>,
}

#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    PeerDiscovered(PeerInfo),
    PeerOffline(String),
    ServiceReady,
}

impl DiscoveryService {
    pub fn new(client: TailscaleClient) -> Self {
        let (tx, _) = broadcast::channel(100);
        Self { client, tx }
    }
    
    /// Subscribe to discovery events
    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.tx.subscribe()
    }
    
    /// Run continuous peer discovery
    pub async fn run(&self, check_interval: Duration) {
        let mut ticker = interval(check_interval);
        let mut known_peers: HashMap<String, bool> = HashMap::new();
        
        // Initial scan
        match self.scan_peers().await {
            Ok(peers) => {
                for peer in &peers {
                    known_peers.insert(peer.name.clone(), peer.online);
                    if peer.online {
                        let _ = self.tx.send(DiscoveryEvent::PeerDiscovered(peer.clone()));
                    }
                }
            }
            Err(e) => tracing::error!("Initial peer scan failed: {}", e),
        }
        
        let _ = self.tx.send(DiscoveryEvent::ServiceReady);
        
        // Continuous monitoring
        loop {
            ticker.tick().await;
            
            match self.scan_peers().await {
                Ok(peers) => {
                    let mut current_online: HashMap<String, bool> = HashMap::new();
                    
                    for peer in peers {
                        current_online.insert(peer.name.clone(), peer.online);
                        
                        let prev_online = known_peers.get(&peer.name).copied().unwrap_or(false);
                        
                        if peer.online && !prev_online {
                            tracing::info!("Peer came online: {}", peer.name);
                            let _ = self.tx.send(DiscoveryEvent::PeerDiscovered(peer));
                        } else if !peer.online && prev_online {
                            tracing::info!("Peer went offline: {}", peer.name);
                            let _ = self.tx.send(DiscoveryEvent::PeerOffline(peer.name));
                        }
                    }
                    
                    // Check for removed peers
                    for name in known_peers.keys() {
                        if !current_online.contains_key(name) {
                            let _ = self.tx.send(DiscoveryEvent::PeerOffline(name.clone()));
                        }
                    }
                    
                    known_peers = current_online;
                }
                Err(e) => tracing::error!("Peer scan failed: {}", e),
            }
        }
    }
    
    async fn scan_peers(&self) -> Result<Vec<PeerInfo>> {
        self.client.get_peers().await
    }
}
```

**Step 1.3: Connection Manager**

```rust
// core/src/protocol/connection.rs
use anyhow::{Context, Result};
use tokio::net::TcpStream;
use std::net::SocketAddr;
use std::time::Duration;

pub struct ConnectionManager {
    timeout: Duration,
}

impl ConnectionManager {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
    
    /// Connect to a peer over Tailscale
    pub async fn connect(&self, address: &str, port: u16) -> Result<TcpStream> {
        let socket_addr = format!("{}:{}", address, port);
        
        tracing::info!("Connecting to {}...", socket_addr);
        
        let stream = tokio::time::timeout(
            self.timeout,
            TcpStream::connect(&socket_addr)
        )
        .await
        .context("Connection timeout")?
        .context("Failed to connect")?;
        
        // Configure TCP keepalive for Tailscale connections
        stream.set_keepalive(Some(Duration::from_secs(30)))?;
        stream.set_nodelay(true)?;
        
        tracing::info!("Connected to {}", socket_addr);
        
        Ok(stream)
    }
    
    /// Connect using MagicDNS hostname
    pub async fn connect_magicdns(
        &self,
        peer_name: &str,
        tailnet_name: &str,
        port: u16,
    ) -> Result<TcpStream> {
        let hostname = format!("{}.{}.ts.net", peer_name, tailnet_name);
        self.connect(&hostname, port).await
    }
}
```

**Step 1.4: Basic CLI Interface**

```rust
// server/src/cli.rs
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "linux-link")]
#[command(about = "Linux Link - Secure remote desktop over Tailscale", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
    
    /// Config file path
    #[arg(short, long, default_value = "~/.config/linux-link/config.toml")]
    pub config: String,
    
    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the server daemon
    Start,
    
    /// Stop the running daemon
    Stop,
    
    /// Show connection status
    Status,
    
    /// List available peers on tailnet
    List,
    
    /// Connect to a specific peer
    Connect {
        /// Peer name or Tailscale IP
        peer: String,
    },
    
    /// Pair with a new device (generate PIN)
    Pair {
        /// Optional PIN (generated if not provided)
        pin: Option<String>,
    },
    
    /// Show this help message
    Help,
}
```

**Step 1.5: Server Service Implementation**

```rust
// server/src/service.rs
use anyhow::{Context, Result};
use linux_link_core::tailscale::{TailscaleClient, DiscoveryService};
use linux_link_core::protocol::ConnectionManager;
use std::time::Duration;
use crate::config::Config;

pub async fn run(config: Config) -> Result<()> {
    tracing::info!("Starting Linux Link service...");
    
    // Initialize Tailscale client
    let ts_client = TailscaleClient::new()
        .context("Failed to initialize Tailscale client")?;
    
    // Wait for Tailscale to be ready
    ts_client.wait_for_ready(Duration::from_secs(30)).await?;
    
    // Get our identity
    let self_ip = ts_client.get_self_ip().await?;
    tracing::info!("Running on Tailscale IP: {}", self_ip);
    
    // Start discovery service
    let discovery = DiscoveryService::new(ts_client.clone());
    let mut rx = discovery.subscribe();
    
    // Spawn discovery task
    tokio::spawn(async move {
        discovery.run(Duration::from_secs(10)).await;
    });
    
    // Create connection manager
    let conn_mgr = ConnectionManager::new(Duration::from_secs(10));
    
    // Start TCP listener for incoming connections
    let listener = tokio::net::TcpListener::bind(format!(
        "0.0.0.0:{}",
        config.control_port
    ))
    .await?;
    
    tracing::info!("Listening on port {}", config.control_port);
    
    // Accept connections
    loop {
        tokio::select! {
            Ok((stream, addr)) = listener.accept() => {
                tracing::info!("New connection from {}", addr);
                // Handle connection in spawned task
                tokio::spawn(handle_connection(stream, conn_mgr.clone()));
            }
            
            Ok(event) = rx.recv() => {
                handle_discovery_event(event).await;
            }
        }
    }
}

async fn handle_connection(stream: TcpStream, conn_mgr: ConnectionManager) {
    // Protocol handshake and authentication
    // Implementation in Phase 2
}

async fn handle_discovery_event(event: DiscoveryEvent) {
    match event {
        DiscoveryEvent::PeerDiscovered(peer) => {
            tracing::info!("Discovered peer: {} ({})", peer.name, peer.ips.join(", "));
        }
        DiscoveryEvent::PeerOffline(name) => {
            tracing::info!("Peer offline: {}", name);
        }
        DiscoveryEvent::ServiceReady => {
            tracing::info!("Discovery service ready");
        }
    }
}
```

**Deliverables Checklist - Phase 1:**

- [x] TailscaleClient with status, peer discovery
- [x] DiscoveryService with event broadcasting
- [x] ConnectionManager for TCP connections
- [x] CLI with start/stop/status/list/connect/pair commands
- [x] Server listens for incoming connections
- [ ] Two devices can discover each other over Tailscale
- [x] Basic connection established (handshake)

Current validation: local end-to-end handshake verified with `start` + `connect 127.0.0.1 --port 1716` + `stop`.
Two-device discovery validation command: `linux-link watch --interval 10` (run on one node while toggling peer availability on another tailnet device).

---

### Phase 2: KDE Connect Features (Week 7-12)

#### Goal: Implement full KDE Connect protocol for device integration

#### Step 2.1: KDE Connect Protocol Integration

Phase 2 kickoff status (implemented):
- Core packet model and trust store scaffold added in `core/src/protocol/kdeconnect.rs`
- Server plugin metadata stubs added under `server/src/plugins/`
- CLI inspection command added: `linux-link capabilities`

Implementation note:
- Current repository implementation uses an internal KDE Connect-compatible scaffold (`NetworkPacket`, `PluginRegistry`, `TrustStore`) as a stepping stone.
- Direct integration via `kdeconnect-proto` remains planned work.

```rust
// core/src/protocol/kdeconnect.rs
use kdeconnect_proto::{
    Device, DeviceConfig, NetworkPacket, TokioIoImpl,
    plugin::PluginRegistry,
    trust::TrustHandler,
};
use anyhow::{Context, Result};
use std::path::Path;

pub struct KDEConnectService {
    device: Device<TokioIoImpl>,
}

impl KDEConnectService {
    pub async fn new(config_path: &Path) -> Result<Self> {
        // Load or generate device config
        let config = DeviceConfig::load_or_create(
            config_path.join("cert.pem"),
            config_path.join("key.pem"),
        )
        .await?;
        
        // Create plugin registry
        let mut registry = PluginRegistry::new();
        
        // Register our plugins
        registry.register(crate::plugins::BatteryPlugin::new());
        registry.register(crate::plugins::ClipboardPlugin::new());
        registry.register(crate::plugins::NotificationPlugin::new());
        registry.register(crate::plugins::SharePlugin::new());
        registry.register(crate::plugins::InputPlugin::new());
        
        // Create trust handler
        let trust_handler = FileTrustHandler::new(config_path.join("trusted_devices.toml"));
        
        // Create device
        let device = Device::new(config, registry, trust_handler, TokioIoImpl);
        
        Ok(Self { device })
    }
    
    /// Start listening for connections
    pub async fn start(&self) -> Result<()> {
        self.device.start().await?;
        Ok(())
    }
    
    /// Wait for incoming connection
    pub async fn wait_for_connection(&self) -> Result<String> {
        let link_id = self.device.wait_for_connection().await?;
        Ok(link_id)
    }
    
    /// Pair with a device
    pub async fn pair_with(&self, link_id: &str) -> Result<()> {
        self.device.pair_with(link_id).await?;
        Ok(())
    }
    
    /// Get connected devices
    pub fn get_connected_devices(&self) -> Vec<Device> {
        self.device.connected_devices()
    }
}

/// Custom trust handler that persists to file
pub struct FileTrustHandler {
    path: std::path::PathBuf,
}

impl FileTrustHandler {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}

impl TrustHandler for FileTrustHandler {
    fn is_trusted(&self, device_id: &str) -> bool {
        // Check if device is in trusted list
        // Implementation depends on storage format
        false
    }
    
    fn trust(&self, device_id: &str) -> kdeconnect_proto::Result<()> {
        // Add device to trusted list
        Ok(())
    }
}
```

#### Step 2.2: Plugin Implementations

**Battery Plugin:**

```rust
// server/src/plugins/battery.rs
use kdeconnect_proto::{
    plugin::Plugin,
    packet::NetworkPacket,
    Result,
};

pub struct BatteryPlugin {
    // Battery state tracking
    charge_level: u8,
    is_charging: bool,
}

impl BatteryPlugin {
    pub fn new() -> Self {
        Self {
            charge_level: 100, // Desktops usually don't have battery
            is_charging: true,
        }
    }
}

impl Plugin for BatteryPlugin {
    fn name(&self) -> &'static str {
        "battery"
    }
    
    fn incoming_capabilities(&self) -> &[&'static str] {
        &["kdeconnect.battery.request"]
    }
    
    fn outgoing_capabilities(&self) -> &[&'static str] {
        &["kdeconnect.battery"]
    }
    
    async fn receive_packet(&mut self, packet: NetworkPacket) -> Result<()> {
        match packet.packet_type() {
            "kdeconnect.battery.request" => {
                // Send battery status
                let response = NetworkPacket::new("kdeconnect.battery")
                    .with_body(serde_json::json!({
                        "currentCharge": self.charge_level,
                        "isCharging": self.is_charging,
                    }));
                // Send response...
            }
            _ => {}
        }
        Ok(())
    }
}
```

**Clipboard Plugin:**

```rust
// server/src/plugins/clipboard.rs
use kdeconnect_proto::{plugin::Plugin, packet::NetworkPacket, Result};
use wl_clipboard_rs::{
    copy::{MimeType, Options, Source},
    paste::{get_contents, ClipboardType},
};

pub struct ClipboardPlugin;

impl ClipboardPlugin {
    pub fn new() -> Self {
        Self
    }
    
    fn get_clipboard_content(&self) -> Result<String> {
        let contents = get_contents(ClipboardType::Regular, MimeType::Text)?;
        Ok(contents.1)
    }
    
    fn set_clipboard_content(&self, content: String) -> Result<()> {
        let mut opts = Options::new();
        opts.copy(Source::Bytes(content.into_bytes().into()), MimeType::Text)?;
        Ok(())
    }
}

impl Plugin for ClipboardPlugin {
    fn name(&self) -> &'static str {
        "clipboard"
    }
    
    fn incoming_capabilities(&self) -> &[&'static str] {
        &["kdeconnect.clipboard", "kdeconnect.clipboard.connect"]
    }
    
    fn outgoing_capabilities(&self) -> &[&'static str] {
        &["kdeconnect.clipboard"]
    }
    
    async fn receive_packet(&mut self, packet: NetworkPacket) -> Result<()> {
        match packet.packet_type() {
            "kdeconnect.clipboard" => {
                if let Some(content) = packet.body().get("content").and_then(|v| v.as_str()) {
                    self.set_clipboard_content(content.to_string())?;
                }
            }
            "kdeconnect.clipboard.connect" => {
                // Client wants clipboard sync - send current content
                if let Ok(content) = self.get_clipboard_content() {
                    let response = NetworkPacket::new("kdeconnect.clipboard")
                        .with_body(serde_json::json!({
                            "content": content,
                            "timestamp": chrono::Utc::now().timestamp_millis(),
                        }));
                    // Send response...
                }
            }
            _ => {}
        }
        Ok(())
    }
}
```

**Notification Plugin:**

```rust
// server/src/plugins/notification.rs
use kdeconnect_proto::{plugin::Plugin, packet::NetworkPacket, Result};
use zbus::{Connection, proxy};

#[proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: std::collections::HashMap<&str, zbus::zvariant::Value>,
        timeout: i32,
    ) -> zbus::Result<u32>;
}

pub struct NotificationPlugin {
    dbus_connection: Connection,
}

impl NotificationPlugin {
    pub async fn new() -> Result<Self> {
        let connection = Connection::session().await?;
        Ok(Self { dbus_connection: connection })
    }
}

impl Plugin for NotificationPlugin {
    fn name(&self) -> &'static str {
        "notification"
    }
    
    fn incoming_capabilities(&self) -> &[&'static str] {
        &["kdeconnect.notification", "kdeconnect.notification.request"]
    }
    
    fn outgoing_capabilities(&self) -> &[&'static str] {
        &["kdeconnect.notification"]
    }
    
    async fn receive_packet(&mut self, packet: NetworkPacket) -> Result<()> {
        match packet.packet_type() {
            "kdeconnect.notification" => {
                let body = packet.body();
                let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("Notification");
                let text = body.get("text").and_then(|v| v.as_str()).unwrap_or("");
                
                let proxy = NotificationsProxy::new(&self.dbus_connection).await?;
                proxy.notify(
                    "Linux Link",
                    0,
                    "",
                    title,
                    text,
                    &[],
                    std::collections::HashMap::new(),
                    5000,
                ).await?;
            }
            _ => {}
        }
        Ok(())
    }
}
```

**Share Plugin (File Transfer):**

```rust
// server/src/plugins/share.rs
use kdeconnect_proto::{plugin::Plugin, packet::NetworkPacket, Result};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::path::PathBuf;

pub struct SharePlugin {
    download_dir: PathBuf,
}

impl SharePlugin {
    pub fn new(download_dir: PathBuf) -> Self {
        Self { download_dir }
    }
}

impl Plugin for SharePlugin {
    fn name(&self) -> &'static str {
        "share"
    }
    
    fn incoming_capabilities(&self) -> &[&'static str] {
        &["kdeconnect.share.request"]
    }
    
    fn outgoing_capabilities(&self) -> &[&'static str] {
        &["kdeconnect.share.request"]
    }
    
    async fn receive_packet(&mut self, packet: NetworkPacket) -> Result<()> {
        match packet.packet_type() {
            "kdeconnect.share.request" => {
                let body = packet.body();
                
                if let Some(payload_size) = packet.payload_size() {
                    if let Some(transfer_info) = body.get("payloadTransferInfo") {
                        let port = transfer_info.get("port").and_then(|v| v.as_u64()).unwrap_or(1739) as u16;
                        let filename = body.get("filename").and_then(|v| v.as_str()).unwrap_or("shared_file");
                        
                        // Spawn file receiver
                        tokio::spawn(Self::receive_file(
                            self.download_dir.clone(),
                            filename.to_string(),
                            payload_size,
                            port,
                        ));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl SharePlugin {
    async fn receive_file(
        download_dir: PathBuf,
        filename: String,
        size: i64,
        port: u16,
    ) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        let (mut stream, addr) = listener.accept().await?;
        
        tracing::info!("Receiving file from {} ({} bytes)", addr, size);
        
        let filepath = download_dir.join(filename);
        let mut file = tokio::fs::File::create(&filepath).await?;
        
        let mut buffer = vec![0u8; 8192];
        let mut received = 0u64;
        
        while received < size as u64 {
            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            file.write_all(&buffer[..n]).await?;
            received += n as u64;
            
            // Progress logging
            if received % (1024 * 1024) == 0 {
                tracing::debug!("Received {} MB", received / (1024 * 1024));
            }
        }
        
        tracing::info!("File saved to {:?}", filepath);
        Ok(())
    }
}
```

#### Step 2.3: Android Client - Basic UI

```dart
// android/lib/screens/connection_screen.dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../rust/api.dart';
import '../widgets/peer_list_tile.dart';

class ConnectionScreen extends ConsumerStatefulWidget {
  const ConnectionScreen({super.key});

  @override
  ConsumerState<ConnectionScreen> createState() => _ConnectionScreenState();
}

class _ConnectionScreenState extends ConsumerState<ConnectionScreen> {
  StreamSubscription<DiscoveryEvent>? _discoverySubscription;
  List<PeerInfo> _peers = [];
  bool _isScanning = false;

  @override
  void initState() {
    super.initState();
    _startDiscovery();
  }

  Future<void> _startDiscovery() async {
    setState(() => _isScanning = true);
    
    // Subscribe to discovery events
    _discoverySubscription = RustApi.discoveryStream().listen((event) {
      setState(() {
        switch (event) {
          case PeerDiscoveredEvent(:final peer):
            if (!_peers.any((p) => p.name == peer.name)) {
              _peers.add(peer);
            }
            break;
          case PeerOfflineEvent(:final name):
            _peers.removeWhere((p) => p.name == name);
            break;
        }
      });
    });
    
    // Initial scan
    try {
      final peers = await RustApi.scanPeers();
      setState(() {
        _peers = peers;
        _isScanning = false;
      });
    } catch (e) {
      setState(() => _isScanning = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to scan peers: $e')),
        );
      }
    }
  }

  @override
  void dispose() {
    _discoverySubscription?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Linux Link'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _isScanning ? null : _startDiscovery,
          ),
        ],
      ),
      body: _isScanning
          ? const Center(child: CircularProgressIndicator())
          : _peers.isEmpty
              ? Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.devices_off, size: 64, color: Colors.grey),
                      const SizedBox(height: 16),
                      Text('No peers found', style: Theme.of(context).textTheme.titleLarge),
                      const SizedBox(height: 8),
                      Text('Make sure Tailscale is running on both devices'),
                    ],
                  ),
                )
              : ListView.builder(
                  itemCount: _peers.length,
                  itemBuilder: (context, index) {
                    final peer = _peers[index];
                    return PeerListTile(
                      peer: peer,
                      onTap: () => _connectToPeer(peer),
                    );
                  },
                ),
      floatingActionButton: FloatingActionButton(
        onPressed: _startDiscovery,
        child: const Icon(Icons.search),
      ),
    );
  }

  Future<void> _connectToPeer(PeerInfo peer) async {
    try {
      final state = await RustApi.connect(address: peer.ips.first);
      
      if (mounted) {
        switch (state) {
          case ConnectionStateConnected():
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (context) => RemoteDesktopScreen(peer: peer),
              ),
            );
            break;
          case ConnectionStateError(:final message):
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text('Connection failed: $message')),
            );
            break;
          default:
            break;
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error: $e')),
        );
      }
    }
  }
}
```

**Deliverables Checklist - Phase 2:**

- [x] Core KDE protocol scaffolding (`NetworkPacket`, identity, plugin registry, trust store)
- [x] Server plugin metadata stubs (`battery`, `clipboard`, `notification`, `share`, `input`)
- [x] CLI capabilities inspection (`linux-link capabilities`)
- [ ] KDE Connect protocol integration via `kdeconnect-proto`
- [ ] Battery plugin runtime behavior (packet handling)
- [ ] Clipboard plugin runtime behavior (bidirectional sync)
- [ ] Notification plugin runtime behavior (DBus forwarding)
- [ ] Share plugin runtime behavior (file transfer with progress)
- [ ] Android connection screen with peer list
- [ ] File transfer UI in Flutter
- [ ] Clipboard sync working bidirectionally
- [ ] Notifications forwarded between devices

---

### Phase 3: Screen Streaming (Week 13-24)

**This is the most complex phase - allocate extra time for debugging**

#### Step 3.1: Screen Capture with PipeWire

```rust
// core/src/streaming/capture.rs
use ashpd::desktop::{
    screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType},
    PersistMode,
    Session,
};
use pipewire::{
    main_loop::MainLoop,
    context::Context,
    properties::properties,
    spa::{
        self,
        utils::Direction,
        pod::Pod,
        buffer::{Buffer, BufferRef},
    },
};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct ScreenCapture {
    node_id: u32,
    width: u32,
    height: u32,
    framerate: u32,
}

pub struct CaptureSession {
    session: Session,
    stream_tx: mpsc::Sender<Frame>,
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub timestamp: u64,
    pub format: FrameFormat,
}

#[derive(Debug, Clone, Copy)]
pub enum FrameFormat {
    BGRx,
    NV12,
    RGBx,
}

impl ScreenCapture {
    /// Start screen capture session
    pub async fn start(
        framerate: u32,
    ) -> Result<(Self, mpsc::Receiver<Frame>)> {
        let (stream_tx, stream_rx) = mpsc::channel(10);
        
        // Create screencast proxy
        let screencast = Screencast::new().await?;
        
        // Create session
        let session = screencast.create_session(Default::default()).await?;
        
        // Select sources (monitor capture)
        screencast
            .select_sources(
                &session,
                SelectSourcesOptions::default()
                    .set_cursor_mode(CursorMode::Metadata)
                    .set_sources(SourceType::Monitor)
                    .set_multiple(false)
                    .set_persist_mode(PersistMode::DoNot),
            )
            .await?;
        
        // Start capture
        let response = screencast
            .start(&session, None, Default::default())
            .await?
            .response()?;
        
        // Get stream info
        let stream = response.streams().first()
            .context("No stream available")?;
        
        let node_id = stream.pipe_wire_node_id();
        let size = stream.size();
        
        tracing::info!(
            "Screen capture started: node_id={}, size={:?}",
            node_id,
            size
        );
        
        let capture = Self {
            node_id,
            width: size.0,
            height: size.1,
            framerate,
        };
        
        // Spawn PipeWire stream processing
        tokio::task::spawn_blocking(move || {
            Self::run_pipewire_stream(node_id, stream_tx)
        });
        
        Ok((capture, stream_rx))
    }
    
    fn run_pipewire_stream(
        node_id: u32,
        stream_tx: mpsc::Sender<Frame>,
    ) -> Result<()> {
        let main_loop = MainLoop::new(None)?;
        let context = Context::new(&main_loop)?;
        
        // Create PipeWire stream
        let stream = pipewire::Stream::new(&context, "Linux Link Capture")?;
        
        // Set stream properties
        let props = properties! {
            "media.type" => "Video",
            "media.role" => "Capture",
            "media.format" => "raw",
            "video.format" => "BGRx",
            "video.size" => format!("1920x1080"),
            "video.framerate" => "60/1",
        };
        
        // Connect to PipeWire
        stream.connect(
            Direction::Input,
            Some(node_id),
            pipewire::stream::StreamFlags::DRIVING | pipewire::stream::StreamFlags::MAP_BUFFERS,
            Some(props),
        )?;
        
        // Set buffer process callback
        stream.set_buffer_process(move |stream, direction| {
            if direction != Direction::Input {
                return;
            }
            
            if let Some(buffer) = stream.dequeue_buffer() {
                for data in buffer.datas() {
                    if let Some(slice) = data.slice() {
                        let chunk = data.chunk();
                        let data_slice = &slice[chunk.offset as usize..(chunk.offset + chunk.size) as usize];
                        
                        let frame = Frame {
                            data: data_slice.to_vec(),
                            width: 1920,
                            height: 1080,
                            timestamp: chrono::Utc::now().timestamp_millis() as u64,
                            format: FrameFormat::BGRx,
                        };
                        
                        // Send frame to encoder
                        if stream_tx.blocking_send(frame).is_err() {
                            return; // Channel closed
                        }
                    }
                }
            }
        });
        
        // Run main loop
        main_loop.run();
        
        Ok(())
    }
    
    pub fn width(&self) -> u32 {
        self.width
    }
    
    pub fn height(&self) -> u32 {
        self.height
    }
}
```

#### Step 3.2: H.264 Hardware Encoding

```rust
// core/src/streaming/encoder.rs
use playa_ffmpeg::{
    codec::{Codec, Context, Encoder},
    format::Pixel,
    frame::Video,
};
use super::capture::Frame;
use anyhow::{Context, Result};
use std::sync::Arc;

pub struct VideoEncoder {
    encoder: Encoder,
    width: u32,
    height: u32,
    bitrate: u32,
    framerate: u32,
}

pub enum EncoderType {
    VAAPI,   // Intel/AMD
    NVENC,   // NVIDIA
    QSV,     // Intel QuickSync
    Software, // Fallback
}

impl VideoEncoder {
    /// Create encoder with hardware acceleration detection
    pub fn new(
        width: u32,
        height: u32,
        framerate: u32,
        bitrate: u32,
    ) -> Result<Self> {
        // Detect best available encoder
        let encoder_type = Self::detect_encoder();
        tracing::info!("Using encoder: {:?}", encoder_type);
        
        let codec = match encoder_type {
            EncoderType::VAAPI => Codec::h264_vaapi(),
            EncoderType::NVENC => Codec::h264_nvenc(),
            EncoderType::QSV => Codec::h264_qsv(),
            EncoderType::Software => Codec::h264(),
        }
        .context("H.264 codec not available")?;
        
        let mut context = Context::new_with_codec(codec);
        
        // Configure encoder
        context.set_width(width);
        context.set_height(height);
        context.set_pixel_format(Pixel::NV12);
        context.set_bit_rate(bitrate as i64);
        context.set_time_base((1, framerate as i32));
        
        // Hardware-specific options
        match encoder_type {
            EncoderType::VAAPI => {
                context.set_option("qp", "23");
                context.set_option("quality", "3");
            }
            EncoderType::NVENC => {
                context.set_option("preset", "p4");
                context.set_option("tune", "ull"); // Ultra-low latency
                context.set_option("rc", "cbr");
            }
            EncoderType::QSV => {
                context.set_option("preset", "fast");
            }
            EncoderType::Software => {
                context.set_option("preset", "ultrafast");
                context.set_option("tune", "zerolatency");
            }
        }
        
        let encoder = context.encoder().video()?;
        
        Ok(Self {
            encoder,
            width,
            height,
            bitrate,
            framerate,
        })
    }
    
    /// Detect best available hardware encoder
    fn detect_encoder() -> EncoderType {
        // Try NVENC first (NVIDIA GPUs)
        if Codec::h264_nvenc().is_ok() {
            return EncoderType::NVENC;
        }
        
        // Try VAAPI (AMD/Intel)
        if Codec::h264_vaapi().is_ok() {
            return EncoderType::VAAPI;
        }
        
        // Try QSV (Intel)
        if Codec::h264_qsv().is_ok() {
            return EncoderType::QSV;
        }
        
        // Fallback to software
        EncoderType::Software
    }
    
    /// Encode a frame
    pub fn encode(&mut self, frame: Frame) -> Result<Vec<Vec<u8>>> {
        // Convert BGRx to NV12 if needed
        let nv12_data = self.convert_to_nv12(&frame)?;
        
        // Create FFmpeg video frame
        let mut video_frame = Video::new(
            Pixel::NV12,
            self.width as usize,
            self.height as usize,
        );
        
        // Copy data to frame
        video_frame.data_mut()[0].copy_from_slice(&nv12_data);
        video_frame.set_pts(Some(frame.timestamp as i64));
        
        // Send frame to encoder
        self.encoder.send_frame(&video_frame)?;
        
        // Receive encoded packets
        let mut packets = Vec::new();
        while let Ok(packet) = self.encoder.receive_packet() {
            packets.push(packet.data().to_vec());
        }
        
        Ok(packets)
    }
    
    /// Convert BGRx to NV12 (simplified - use libyuv in production)
    fn convert_to_nv12(&self, frame: &Frame) -> Result<Vec<u8>> {
        // In production, use libyuv or similar for efficient conversion
        // This is a placeholder
        Ok(frame.data.clone())
    }
    
    /// Adjust bitrate dynamically
    pub fn set_bitrate(&mut self, bitrate: u32) -> Result<()> {
        self.bitrate = bitrate;
        // Reconfigure encoder if supported
        Ok(())
    }
}
```

#### Step 3.3: QUIC Streaming

```rust
// core/src/streaming/quic_stream.rs
use quinn::{
    Connection, Endpoint, RecvStream, SendStream, ClientConfig, ServerConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;

pub struct QuicStreamer {
    endpoint: Endpoint,
}

impl QuicStreamer {
    /// Create server endpoint
    pub fn new_server(cert: CertificateDer, key: PrivateKeyDer) -> Result<Self> {
        let mut server_config = ServerConfig::with_single_cert(vec![cert], key)?;
        
        // Configure for low latency
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(100u32.into());
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
        
        server_config.transport_config(Arc::new(transport_config));
        
        let endpoint = Endpoint::server(
            server_config,
            "0.0.0.0:4716".parse()?,
        )?;
        
        Ok(Self { endpoint })
    }
    
    /// Create client endpoint
    pub fn new_client() -> Result<Self> {
        let mut client_config = ClientConfig::new(Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth(),
        ));
        
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
        client_config.transport_config(Arc::new(transport_config));
        
        let endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);
        
        Ok(Self { endpoint })
    }
    
    /// Accept incoming stream
    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream)> {
        let incoming = self.endpoint.accept().await.context("No incoming connection")?;
        let connection = incoming.await?;
        
        let (send, recv) = connection.accept_bi().await?;
        Ok((send, recv))
    }
    
    /// Connect to server
    pub async fn connect(&self, addr: &str, port: u16) -> Result<Connection> {
        let connection = self.endpoint
            .connect(format!("{}:{}", addr, port).parse()?, "linux-link")?
            .await?;
        Ok(connection)
    }
    
    /// Open bidirectional stream
    pub async fn open_stream(&self, conn: &Connection) -> Result<(SendStream, RecvStream)> {
        let (send, recv) = conn.open_bi().await?;
        Ok((send, recv))
    }
}

/// Dummy certificate verifier for development (use proper verification in production)
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
}
```

#### Step 3.4: Streaming Service

```rust
// core/src/streaming/service.rs
use super::{capture::{ScreenCapture, Frame}, encoder::VideoEncoder, quic_stream::QuicStreamer};
use anyhow::Result;
use tokio::sync::mpsc;
use std::time::Duration;

pub struct StreamingService {
    capture: Option<ScreenCapture>,
    encoder: Option<VideoEncoder>,
    streamer: QuicStreamer,
    is_streaming: bool,
    config: StreamingConfig,
}

pub struct StreamingConfig {
    pub width: u32,
    pub height: u32,
    pub framerate: u32,
    pub bitrate: u32,
    pub adaptive_bitrate: bool,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            framerate: 60,
            bitrate: 8_000_000, // 8 Mbps
            adaptive_bitrate: true,
        }
    }
}

impl StreamingService {
    pub fn new() -> Result<Self> {
        let streamer = QuicStreamer::new_server(
            // Load certificate from config
            todo!(),
            todo!(),
        )?;
        
        Ok(Self {
            capture: None,
            encoder: None,
            streamer,
            is_streaming: false,
            config: StreamingConfig::default(),
        })
    }
    
    /// Start streaming to a client
    pub async fn start_streaming(&mut self, client_addr: String) -> Result<()> {
        if self.is_streaming {
            anyhow::bail!("Already streaming");
        }
        
        tracing::info!("Starting stream to {}", client_addr);
        
        // Start screen capture
        let (capture, mut frame_rx) = ScreenCapture::start(self.config.framerate).await?;
        self.capture = Some(capture);
        
        // Create encoder
        let encoder = VideoEncoder::new(
            self.config.width,
            self.config.height,
            self.config.framerate,
            self.config.bitrate,
        )?;
        self.encoder = Some(encoder);
        
        self.is_streaming = true;
        
        // Spawn streaming task
        tokio::spawn(Self::stream_loop(
            client_addr,
            frame_rx,
            self.config.clone(),
        ));
        
        Ok(())
    }
    
    async fn stream_loop(
        client_addr: String,
        mut frame_rx: mpsc::Receiver<Frame>,
        config: StreamingConfig,
    ) {
        let streamer = QuicStreamer::new_client().unwrap();
        
        match streamer.connect(&client_addr, 4716).await {
            Ok(conn) => {
                match streamer.open_stream(&conn).await {
                    Ok((mut send, _recv)) => {
                        tracing::info!("Stream connected");
                        
                        while let Some(frame) = frame_rx.recv().await {
                            // Encode frame
                            // In production, use a thread pool for encoding
                            // to avoid blocking the async runtime
                            
                            // Send encoded data
                            // for packet in encoded_packets {
                            //     send.write_all(&packet).await.unwrap();
                            // }
                        }
                        
                        tracing::info!("Stream ended");
                    }
                    Err(e) => tracing::error!("Failed to open stream: {}", e),
                }
            }
            Err(e) => tracing::error!("Failed to connect: {}", e),
        }
    }
    
    /// Stop streaming
    pub fn stop_streaming(&mut self) {
        self.is_streaming = false;
        self.capture = None;
        self.encoder = None;
        tracing::info!("Streaming stopped");
    }
    
    /// Adjust quality based on network conditions
    pub fn adjust_quality(&mut self, network_rtt: Duration, packet_loss: f32) {
        if !self.config.adaptive_bitrate {
            return;
        }
        
        // Simple adaptive bitrate logic
        let new_bitrate = if packet_loss > 0.05 {
            // High packet loss - reduce quality
            self.config.bitrate / 2
        } else if network_rtt > Duration::from_millis(100) {
            // High latency - reduce quality
            self.config.bitrate * 3 / 4
        } else if packet_loss < 0.01 && network_rtt < Duration::from_millis(50) {
            // Good conditions - increase quality
            self.config.bitrate * 5 / 4
        } else {
            self.config.bitrate
        };
        
        if new_bitrate != self.config.bitrate {
            tracing::info!("Adjusting bitrate to {}", new_bitrate);
            self.config.bitrate = new_bitrate;
            
            if let Some(encoder) = &mut self.encoder {
                let _ = encoder.set_bitrate(new_bitrate);
            }
        }
    }
}
```

**Deliverables Checklist - Phase 3:**

- [ ] Screen capture via PipeWire working
- [ ] H.264 hardware encoding (VAAPI/NVENC)
- [ ] QUIC streaming protocol
- [ ] Basic streaming service
- [ ] Android video decoder (MediaCodec)
- [ ] Texture rendering in Flutter
- [ ] End-to-end latency <150ms
- [ ] 30+ FPS streaming
- [ ] Adaptive bitrate based on network

---

### Phase 4: Android Client Polish (Week 19-26)

[Continuing with similar detail for remaining phases...]

### Phase 5: Polish & Extras (Week 25-28)

### Phase 6: Release & Packaging (Week 29-30)

---

## Technical Deep Dives

### A. Tailscale Integration Details

### B. KDE Connect Protocol Specification

### C. Video Encoding Pipeline

### D. Input Event Mapping

### E. Security Considerations

---

## Risk Assessment & Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Wayland API changes | Medium | High | Pin crate versions, monitor upstream |
| Hardware encoding issues | Medium | Medium | Software fallback, extensive testing |
| Tailscale connectivity | Low | High | Retry logic, clear error messages |
| Android permission changes | Medium | Medium | Regular updates, SAF adoption |
| Performance below target | Medium | High | Early profiling, optimization sprints |

---

## Testing Strategy

### Unit Tests
### Integration Tests
### E2E Tests
### Performance Benchmarks

---

## Deployment & Packaging

### AUR Package
### systemd Service
### Android APK Distribution
### Documentation

---

## Appendix: Quick Reference

### Command Reference
### Configuration Options
### Troubleshooting Guide
### Performance Tuning

---

## Next Steps

1. **Immediate (This Week):**
   - Set up repository structure
   - Configure CI/CD
   - Install development dependencies

2. **Short-term (Month 1):**
   - Complete Phase 0 & 1
   - Establish Tailscale connectivity
   - Basic CLI working

3. **Medium-term (Month 2-3):**
   - KDE Connect features
   - Android basic UI
   - File transfer working

4. **Long-term (Month 4-6):**
   - Screen streaming
   - Performance optimization
   - Public release

---

*Document Version: 1.0*
*Last Updated: March 31, 2026*
*Author: Linux Link Development Team*
