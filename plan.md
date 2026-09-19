# Linux Link - Comprehensive Development Plan

> **A Rust-based remote desktop solution combining low-latency Wayland screen streaming (Sunshine-level) + full KDE Connect feature set + Tailscale-native connectivity**

**Target Platforms:** Arch Linux + Hyprland (server), Android (client)

**Project Status:** Active Development (server/core through Phase 6 complete; Android client migrated from Flutter to native Kotlin — scaffold + JNI bridge in place, API port in progress)

**Estimated Timeline:** 4-6 months for MVP

**Execution Snapshot (April 2026):**
- Phase 0 completed (workspace scaffold, CI, docs, build/test baseline)
- Phase 1 completed (CLI + handshake + discovery watch + two-device discovery)
- Phase 2 completed (KDE protocol runtime, all 5 plugins with real behavior, KDE Connect TCP packet loop)
- Phase 3 completed (full streaming pipeline: PipeWire capture → persistent FFmpeg encoder → QUIC transport → adaptive bitrate; 50+ integration tests)
- Phase 4 completed (Android client: Flutter UI + Rust FFI + MediaCodec video decoding + background service + all 4 screens wired)
- Phase 5 completed (systemd service, config extension, remote file browsing, latency optimization, config.toml.example)
- Phase 6 completed (CHANGELOG, GitHub Release workflow, AUR packaging, man page, install script, CONTRIBUTING.md, CI expansion)
- **Phase A (Post-Phase Additions):**
  - ✅ A1 — X11 screen capture fallback (Wayland/X11 auto-detection, `x11rb` GetImage)
  - ✅ A2 — LAN mDNS discovery fallback (`mdns-sd`, polling-based peer discovery for local networks)
  - ✅ A3 — Structured error types (`LinuxLinkError` enum with 15 variants, `From` impls)
  - ✅ A4 — E2E encryption with TOFU certificate management (`CertManager`, `TofuVerifier`, persistent identity + known peers)
- Quality gates pass (`cargo fmt`, `cargo check`, `cargo clippy -D warnings`, `cargo test` — 66 tests)

**Client Migration (September 2026):**
- Android client switched from Flutter to native Kotlin (2026-09-19): the entire Flutter app (`android/lib`, `android/rust`, pubspec) was deleted and replaced with a Compose-based Kotlin scaffold (`android/app`).
- Rust side of the bridge is now `android/bridge` — a `cdylib` JNI crate exposing `dev.linuxlink.android.bridge.RustCore` (currently a version-echo proof of wiring; session/streaming/input API is being ported on top of it).
- Sections below that describe Flutter, `flutter_rust_bridge`, `android/rust`, or Dart are historical records from the April 2026 plan; live status is in AGENTS.md.

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
│  │  (Kotlin + Rust JNI)  │        (Tailscale IP)          │(Hyprland)   ││
│  ├──────────────────────┤                                ├─────────────┤│
│  │  UI Layer (Compose)  │                                │ Rust Daemon ││
│  │  ├── Connection Mgr  │                                │   (tokio)   ││
│  │  ├── Video Player    │                                ├─────────────┤│
│  │  ├── File Browser    │                                │  Core Lib   ││
│  │  └── Settings        │                                │  (shared)   ││
│  ├──────────────────────┤                                ├─────────────┤│
│  │  Rust Backend (JNI)  │                                │  Modules:   ││
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
| **UI Framework** | User interface | Kotlin + Jetpack Compose |
| **Rust Bridge** | FFI communication | JNI (`jni` crate, `android/bridge` cdylib) |
| **Video Decoding** | H.264 hardware decoding | MediaCodec + SurfaceView |
| **Input Handling** | Touch gestures, virtual trackpad | Compose pointer/gesture API |
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
│  Compose    │◄───│  SurfaceView │◄───│  Surface     │◄───│   Frame      │
│  AndroidView│    │  (MediaCodec)│    │  Texture     │    │   Buffer     │
│             │    │              │    │              │    │              │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
```

#### Input Event Flow

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│  Compose    │───►│  Rust via    │───►│  QUIC/TCP   │───►│  Input       │
│  Gestures   │    │  JNI         │    │  Stream     │    │  Handler     │
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
members = ["core", "server", "android/bridge"]

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

### Client Dependencies (Android — Gradle Kotlin DSL)

```kotlin
// android/app/build.gradle.kts (abridged)
android {
    namespace = "dev.linuxlink.android"
    compileSdk = 36
    defaultConfig {
        applicationId = "dev.linuxlink.android"
        minSdk = 26
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.08.00")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.11.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    // state / navigation / background service — added as the API port lands
}
```

### Client Dependencies (Rust — android/bridge/Cargo.toml)

```toml
[package]
name = "linux-link-android-bridge"

[lib]
crate-type = ["cdylib"]

[dependencies]
# Shared with server, client feature only
linux-link-core = { path = "../../core", default-features = false, features = ["client"] }
jni = "0.21"
anyhow.workspace = true
tokio.workspace = true
tracing.workspace = true

# Video decoding is done on the Android side (MediaCodec);
# the Rust bridge handles protocol/transport and feeds frames.
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
| **Phase 0** | 1-2 weeks | Project structure, build system, CI/CD | `cargo build` succeeds, Android app runs |
| **Phase 1** | 3-4 weeks | Tailscale daemon, peer discovery, basic CLI | Two devices connect over Tailscale |
| **Phase 2** | 5-6 weeks | KDE Connect features, Android basic UI | File transfer, clipboard, notifications work |
| **Phase 3** | 8-10 weeks | Screen capture, encoding, streaming, input | <150ms latency, 30+ FPS streaming |
| **Phase 4** | 6-8 weeks | Android UI polish, gestures, background service | Production-ready Android app |
| **Phase 5** | 3-4 weeks | systemd service, config, optimizations | Auto-start works, <100ms latency |
| **Phase 6** | 2-3 weeks | AUR package, Android APK, documentation | Published on AUR + GitHub Releases |

---

## Detailed Execution Steps

> **Historical record (April 2026).** The step-by-step commands, code samples and checklists below reflect the original Flutter-based client plan. On 2026-09-19 the client was migrated to native Kotlin + a JNI bridge (`android/app`, `android/bridge`); Flutter-specific steps (`flutter create`, `flutter_rust_bridge_codegen`, `android/rust`, Dart samples) are kept as history and are no longer the way to build the client. See AGENTS.md "Current Status" for the live picture.

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

**Status: COMPLETE (April 3, 2026)**

The KDE Connect protocol runtime is fully implemented with an internal scaffold — no external `kdeconnect-proto` dependency needed for MVP.

**Implemented architecture:**

| Component | Location | Description |
|-----------|----------|-------------|
| `NetworkPacket` | `core/src/protocol/kdeconnect.rs` | Serde-based JSON packet model with `to_wire()` / `from_wire()` for newline-terminated transport |
| `DeviceIdentity` | `core/src/protocol/kdeconnect.rs` | Device metadata (name, type, capabilities) serialized as `kdeconnect.identity` packet |
| `Plugin` trait | `core/src/protocol/kdeconnect.rs` | Async trait with `handle_packet(&self, packet, sender)` — plugins reply via `DeviceSender` |
| `DeviceSender` / `TcpDeviceSender` | `core/src/protocol/kdeconnect.rs` | Per-connection sender wrapping `Arc<Mutex<WriteHalf>>` for concurrent plugin replies |
| `PluginRegistry` | `core/src/protocol/kdeconnect.rs` | Capability-indexed registry with `dispatch_packet()` routing + `clone_for_dispatch()` |
| `TrustStore` | `core/src/protocol/kdeconnect.rs` | Persisted trusted-device list (JSON file) with `trust_device()` / `untrust_device()` |
| `KdeConnectService` | `core/src/protocol/kdeconnect.rs` | Facade assembling identity + registry + trust store |
| `build_default_service()` | `server/src/kde.rs` | Constructs service with all 5 plugins registered |

**Connection handler (`server/src/service.rs`):**

```
TCP Connection
    │
    ▼
┌─────────────────────────┐
│ 1. LINUX_LINK_HELLO     │  ← Custom handshake (8s timeout)
│    → LINUX_LINK_OK      │
├─────────────────────────┤
│ 2. Send identity packet │  ← kdeconnect.identity (JSON)
├─────────────────────────┤
│ 3. Packet loop          │  ← Read lines, parse NetworkPacket,
│    dispatch → plugins   │    route via PluginRegistry::dispatch_packet()
│    (30s idle timeout)   │
└─────────────────────────┘
```

#### Step 2.2: Plugin Implementations

**Status: COMPLETE — all 5 plugins have runtime behavior**

**Battery Plugin (`server/src/plugins/battery.rs`):**
- Handles `kdeconnect.battery.request` → responds with `kdeconnect.battery`
- Reads real battery data via `gdbus` querying UPower's DisplayDevice
- Falls back to 100% / isCharging=true for desktops without batteries

**Clipboard Plugin (`server/src/plugins/clipboard.rs`):**
- Handles `kdeconnect.clipboard` → sets local clipboard
- Handles `kdeconnect.clipboard.connect` → sends current clipboard to peer
- Uses `wl-clipboard` (Wayland native) with `xclip` fallback (X11 compat)

**Notification Plugin (`server/src/plugins/notification.rs`):**
- Handles `kdeconnect.notification` → shows desktop notification via `notify-send`
- Handles `kdeconnect.notification.request` → acknowledges support
- Extracts title, text, and app name from packet body

**Share Plugin (`server/src/plugins/share.rs`):**
- Handles `kdeconnect.share.request` with `payloadTransferInfo` → binds port, receives file over TCP in background task
- Handles `kdeconnect.share.request` with `url` → logs URL and sends notification
- Saves files to `~/Downloads` (or `dirs::download_dir()`)
- Streams in 64KB chunks with progress logging

**Input Plugin (`server/src/plugins/input.rs`):**
- Handles `kdeconnect.mousepad.request` → mouse movement, button press/release, text typing, special keys
- Handles `kdeconnect.presenter` → play/pause/next/previous via key simulation
- Uses `xdotool` for all input injection
- Responds with `kdeconnect.mousepad.echo`

**Plugin runtime summary:**

| Plugin | Packet Types Handled | System Integration | Reply Sent |
|--------|---------------------|-------------------|------------|
| Battery | `kdeconnect.battery.request` | UPower via `gdbus` | `kdeconnect.battery` |
| Clipboard | `kdeconnect.clipboard`, `.connect` | `wl-clipboard` / `xclip` | `kdeconnect.clipboard` |
| Notification | `kdeconnect.notification`, `.request` | `notify-send` | (none) |
| Share | `kdeconnect.share.request` | TCP listener + `~/Downloads` | `kdeconnect.notification` (URL) |
| Input | `kdeconnect.mousepad.request`, `kdeconnect.presenter` | `xdotool` | `kdeconnect.mousepad.echo` |

#### Step 2.3: Android Client - Basic UI
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
- [x] KDE Connect protocol runtime (packet parsing, wire format, dispatch loop)
- [x] `Plugin` trait with async `handle_packet` + `DeviceSender` abstraction
- [x] `TcpDeviceSender` for per-connection packet replies
- [x] `PluginRegistry::dispatch_packet()` routing packets to registered plugins
- [x] Battery plugin runtime (UPower via `gdbus`, fallback to 100%)
- [x] Clipboard plugin runtime (bidirectional sync via `wl-clipboard` / `xclip`)
- [x] Notification plugin runtime (desktop notifications via `notify-send`)
- [x] Share plugin runtime (file transfer over TCP, URL sharing)
- [x] Input plugin runtime (mouse/keyboard via `xdotool`, presenter remote)
- [ ] Android connection screen with peer list (Kotlin client — pending bridge API port)
- [ ] File transfer UI in Kotlin client (pending bridge API port)
- [x] End-to-end KDE Connect packet exchange validated between two devices

---

### Phase 3: Screen Streaming (Week 13-24)

**Status: COMPLETE (April 8, 2026)**

#### ✅ Completed: Full Streaming Pipeline

The streaming pipeline is fully implemented with all core components integrated into a coordinated multi-task runtime.

**What's Implemented:**

| Component | File | Status | Notes |
|-----------|------|--------|-------|
| **Module Structure** | `core/src/streaming/mod.rs` | ✅ Complete | `StreamingConfig`, `VideoFrame`, `EncodedPacket` types with H264 profiles and encoder presets; re-exports `StreamingServer`, `StreamingClient`, `AdaptiveBitrate` |
| **PipeWire Capture** | `core/src/streaming/capture.rs` | ✅ Complete | XDG Portal screencast session + PipeWire stream with `on_process` callback, BGRA frame reception, `CancellationToken` lifecycle, `CaptureSession` struct |
| **H.264 Encoder** | `core/src/streaming/encoder.rs` | ✅ Complete | Persistent FFmpeg sidecar process, stdin/stdout non-blocking I/O (via `libc::fcntl`), NAL start code parsing, IDR keyframe detection, `drain()` and `Drop` cleanup |
| **QUIC Transport** | `core/src/streaming/transport.rs` | ✅ Complete | `pub PacketHeader` (17-byte binary), `StreamServer`/`StreamClient` with quinn, `send_packets`/`receive_packets`, `NoVerifier` cert bypass |
| **Streaming Loop** | `core/src/streaming/streamer.rs` | ✅ Complete | `StreamingServer` with 5 concurrent tokio tasks: capture, encode, QUIC transport, connection monitor, adaptive bitrate monitor |
| **Adaptive Bitrate** | `core/src/streaming/bitrate.rs` | ✅ Complete | RTT-based congestion detection, smoothed history (10-sample window), 25% decrease on congestion, 10% increase on good conditions, 3 presets (LAN/internet/low-bandwidth) |
| **Input Injection** | `server/src/input_injector.rs` | ✅ Complete | Native enigo replacing xdotool: mouse, keyboard, scroll, text input |
| **Input Plugin** | `server/src/plugins/input.rs` | ✅ Complete | Lazy-initialized injector, KDE mousepad/presenter protocol via enigo |
| **Integration Tests** | All streaming modules | ✅ 50 tests | 47 core (7 bitrate + 2 capture + 11 encoder + 10 NAL/keyframe + 4 streamer + 2 transport + 11 KDE plugins) + 3 server (input_injector) |

**Dependencies Added:**
- `ashpd` 0.13 — XDG Desktop Portal for screen capture
- `pipewire` 0.9 + `libspa` 0.9 — PipeWire client for frame reception
- `ffmpeg-sidecar` 2.5 — FFmpeg binary wrapper for persistent encoding
- `quinn` 0.11 — QUIC transport for streaming
- `rcgen` 0.14 — Self-signed certificate generation
- `rustls` 0.23 — TLS implementation
- `enigo` 0.6 — Native input injection (replaces xdotool)
- `libc` 0.2 — Non-blocking I/O via `fcntl`
- `tokio-util` 0.7 — `CancellationToken`

**Quality Gates:**
- `cargo fmt`: ✅ Pass
- `cargo clippy -D warnings`: ✅ Pass
- `cargo test`: ✅ 50 tests pass (47 core + 3 server)
- `cargo check --workspace`: ✅ Clean compilation

**Architecture Decisions Made:**
1. **ffmpeg-sidecar over playa-ffmpeg** — playa-ffmpeg had enum compatibility issues with system FFmpeg 8.0; sidecar wraps binary directly
2. **Lazy input injector initialization** — `InputPlugin::new()` no longer returns `Result`; injector created on first use to avoid startup failures on headless systems
3. **Self-signed certs for QUIC** — Production should use Tailscale identity; `NoVerifier` allows local testing without CA setup
4. **Datagram mode for streaming** — `StreamTransportConfig::use_datagrams = true` for lower latency over reliability
5. **5-task concurrent pipeline** — Capture, encode, transport, connection monitor, and adaptive bitrate run as independent tokio tasks coordinated via mpsc channels
6. **Non-blocking FFmpeg I/O** — `libc::fcntl(O_NONBLOCK)` on stdout/stderr prevents blocking when encoder has internal latency

#### 📋 Phase 3 Deliverables Checklist (Updated)

**Completed:**
- [x] Streaming module structure (`core/src/streaming/`)
- [x] PipeWire frame capture (XDG Portal session + PipeWire stream with BGRA frame callbacks)
- [x] Persistent FFmpeg encoder (sidecar process, stdin/stdout, NAL keyframe detection)
- [x] QUIC transport layer with TLS and binary packet header
- [x] Streaming loop integration (`StreamingServer` with 5 concurrent tasks)
- [x] Adaptive bitrate controller (RTT monitoring, congestion detection, 3 presets)
- [x] Native input injection via enigo (replaces xdotool)
- [x] 50 integration tests across streaming + KDE plugins

**Remaining (runtime validation):**
- [ ] End-to-end streaming test on live Wayland session (requires Hyprland + PipeWire running)
- [ ] Latency measurement and optimization (<150ms target)
- [ ] FPS benchmarking (30+ FPS target)
- [ ] Android video decoder (MediaCodec) — Phase 4
- [ ] Video surface rendering on Android (MediaCodec + SurfaceView via Kotlin bridge) — Phase 4

#### 📚 Implementation Reference

The streaming module is implemented in `core/src/streaming/` with five submodules:
- **capture.rs** — `CaptureSession` with ashpd XDG Portal + PipeWire stream callbacks
- **encoder.rs** — `VideoEncoder` with persistent FfmpegChild, non-blocking I/O, NAL parsing
- **streamer.rs** — `StreamingServer` with 5-task pipeline, `StreamingClient`, `AdaptiveBitrateMonitor`
- **transport.rs** — `StreamServer`/`StreamClient` with quinn, `PacketHeader` binary protocol
- **bitrate.rs** — `AdaptiveBitrate` with RTT smoothing, congestion detection, profile presets

Input injection uses enigo in `server/src/input_injector.rs` — replaces all xdotool subprocess calls.

Full code documentation with Rustdoc comments is available in the source files.

---

### Phase 4: Android Client Polish (Week 19-26)

**Status: IN PROGRESS — client migrated from Flutter to native Kotlin (September 2026)**

#### Historical: Flutter-era completion (April 2026)

By April 2026 the Flutter client was feature-complete in scaffold form: 4 screens (Connection/Remote Desktop/Files/Settings) with GoRouter + Riverpod, an FRB-based Rust API in `android/rust` (clipboard, file transfer, mouse/keyboard input, streaming stubs), a MediaCodec decoding plugin, and a foreground service. All of this was deleted on 2026-09-19 in favor of a native Kotlin client (recoverable from git at `4bf3c73`). The Flutter-era feature list remains the design reference for the Kotlin port.

#### Current: Kotlin scaffold + JNI bridge

| Component | Location | Status | Notes |
|-----------|----------|--------|-------|
| **App Scaffold** | `android/app/` | ✅ Complete | Gradle Kotlin DSL (AGP 9.4.0, Kotlin 2.3.20), Compose Material 3, `MainActivity`, manifest, `minSdk 26` |
| **Rust Bridge** | `android/bridge/` | ✅ Wired | `cdylib` JNI crate; `dev.linuxlink.android.bridge.RustCore.nativeVersion()` proves Rust→JNI→Kotlin path |
| **Connection Screen (peer list)** | — | ⬜ Pending | Port alongside bridge session API |
| **Remote Desktop Screen** | — | ⬜ Pending | Compose gestures → JNI → QUIC input stream; MediaCodec via SurfaceView |
| **File Browser Screen** | — | ⬜ Pending | SAF picker + KDE Share protocol via bridge |
| **Settings Screen** | — | ⬜ Pending | Tailscale toggle, quality, input mode |
| **Background Service** | — | ⬜ Pending | Android foreground service + notification |
| **Bridge API (clipboard/files/input/streaming)** | `android/bridge/src/` | ⬜ Pending | Replaces Flutter-era `android/rust` FRB surface |

**Quality Gates (Rust side):**
- `cargo fmt` / `cargo check --workspace`: ✅
- `cargo clippy -D warnings`: ✅ in both default and `client` feature profiles
- `cargo test`: ✅ (see AGENTS.md Current Status for count)
- Kotlin side: ✅ Verified on host (JDK 21, SDK Platform 37, NDK 29, Gradle 9.7.1 wrapper; `assembleDebug` succeeds, bridge `.so` packaged in the APK)

**Remaining Work:**
- [x] Gradle wrapper generated and `./gradlew assembleDebug` verified on host
- [ ] Port session lifecycle (connect/discover/trust) into the bridge over `linux-link-core` (`client` feature)
- [ ] Frame delivery: QUIC client → JNI → MediaCodec SurfaceView
- [ ] Input events: Compose gestures → JNI → streaming channel
- [ ] Clipboard, file transfer, notification plugins end-to-end from Android
- [ ] Full E2E testing on Android device against a live Hyprland + PipeWire server

### Phase 5: Polish & Extras (Week 25-28)

**Status: COMPLETE ✅**

**Quality Gates:**
- `cargo fmt`: ✅ Pass
- `cargo clippy -D warnings`: ✅ Pass (0 warnings across workspace)
- `cargo test`: ✅ 66 tests pass (63 core + 3 server)
- `cargo check --workspace`: ✅ Clean compilation

**Completed:**
- [x] Code review fixes (I1: timeout-based recv, I2: mounted guards, I4: error logging, I5: stop confirmation, S6: remove redundant atomic)
- [x] Configuration extension (streaming_port, log_level, video_quality with VideoQualityPreset)
- [x] systemd service with installation documentation
- [x] Remote file browsing (server plugin with path sanitization + FFI + UI; Flutter UI removed in Kotlin migration — Android side pending)
- [x] Latency optimization (StreamingStats struct, encoder preset mapping via VideoQualityPreset)
- [x] config.toml.example with all documented defaults

**Remaining (requires live hardware):**
- [x] `./gradlew assembleDebug` verification (done on host, 2026-09-19)
- [ ] E2E latency measurement on live system (requires Hyprland + PipeWire server running)

### Phase 6: Release & Packaging (Week 29-30)

**Status: COMPLETE ✅**

- [x] CHANGELOG.md with Unreleased section
- [x] GitHub Release workflow (binary builds + checksums + draft release)
- [x] AUR packaging (PKGBUILD + install script)
- [x] CI expansion (cargo audit, Flutter analyze — Flutter lint job removed in Kotlin migration)
- [x] Man page (linux-link.1)
- [x] Install script (scripts/install.sh)
- [x] CONTRIBUTING.md

**Remaining (manual action required):**
- [ ] First release tagged and published (requires manual release workflow trigger)

---

## Improvement Roadmap (September 2026 research)

Candidate pool for Phase 7+, ranked by impact-per-effort. These are proposals from a research pass (2026-09-19), not committed scope.

### R1. Connectivity — direct P2P without a Tailscale hard requirement

Today the server requires Tailscale and connects via its IPs. Research conclusion: adopt **iroh 1.x** (1.0 stable June 2026, v1.2.x current) as the default WAN transport.

| Change | Effort | Rationale |
|--------|--------|-----------|
| Replace raw quinn WAN path with an iroh endpoint (QUIC end-to-end, built-in hole punching via their quinn fork) | Medium | Bidirectional dial/punch that plain quinn lacks; works on Android through the JNI bridge |
| Demote Tailscale to an optional *candidate address*, keep mDNS for LAN | Low | Removes the install prerequisite without losing the mesh users |
| Self-host one `iroh-relay` for symmetric-CGNAT/corporate fallback | Low ops / Med | Punching succeeds on ~80-85% of home-NAT pairs; relay must exist in the design for the rest (RustDesk's hbbs/hbbr model proves this) |
| PIN/QR pairing: iroh node-id (32-byte key) doubles as identity + address, bound to the existing TOFU cert | Medium | Moonlight has zero remote-access story (manual port forwarding); this beats both Moonlight and plain RustDesk UX |
| Android: QUIC connection migration keeps Wi-Fi↔LTE a path change, not a reconnect; `connectedDevice`/`specialUse` foreground service, WorkManager backoff resume | Medium | Kills the "app died in Doze" class of bugs |

**Dead ends avoided:** DIY quinn hole punching, `hole-punch-connect` (dead, 2023), `tsnet` rust binding (dead), standalone DERP (needs a tailscaled/headscale coordination plane), libp2p dcutr (QUIC punching still rough, imports whole swarm stack), WebRTC (SCTP head-of-line; throws away the datagram video path) — reconsider WebRTC only if worst-case symmetric NATs must be traversed without hosting a relay.

### R2. Streaming pipeline — latency & quality

Ranked by impact-per-effort against the current pipeline (portal capture → FFmpeg child process → QUIC datagrams → MediaCodec). Target: Sunshine-class sub-50ms end-to-end.

| # | Upgrade | Impact / Effort | Expected gain |
|---|---------|-----------------|---------------|
| 1 | **Encoder low-latency flags now** (`tune=zerolatency`, `bf=0`, CBR + tiny VBV, `slices=4`, no lookahead; NVENC `llhp`, VAAPI `vbr_latency`) | High / Low | 5–15 ms, no architecture change |
| 2 | **Android decode/render tuning**: `KEY_LOW_LATENCY=1` + `KEY_PRIORITY=0` (realtime), decode straight to SurfaceView (never ImageReader), `Surface.setFrameRate` to display mode | High / Low | 5–15 ms touch-to-photon |
| 3 | **In-process encode via `ffmpeg-next` (9.0.0)**, dropping the FFmpeg child-process stdio pipe; frames stay GPU-resident with `hevc_vaapi`/`h264_nvenc` | High / Med | 3–8 ms + lower jitter |
| 4 | **Input path**: dedicated QUIC stream/socket with its own congestion control so input never queues behind video; host-side injection via **`/dev/uinput` absolute-coordinate virtual device** (Sunshine's approach; the `uinput` crate is dead — write thin bindings with `nix`) | High / Med | 10–30 ms perceived under load |
| 5 | **Transport hardening**: quinn 0.11 pluggable CC (BBR present but experimental — A/B vs CUBIC/NewReno), keep one frame ≈ one datagram set, send-only-newest + request IDR on gap. Skip FEC: QUIC datagrams already discard, Rust FEC crates are unproven (low ROI) | Med / Low-Med | jitter/tail-latency |
| 6 | **VFR capture pacing**: drive from compositor vsync/damage events; encode a static screen at 5–15 fps instead of fixed 60 | Med / Med | big CPU/GPU/queue relief when idle |
| 7 | **Zero-copy capture — bypass the portal on Hyprland**: ScreenCast portal delivers shm buffers after conversion (dmabuf-through-portal open since portal-wlr #9); the 2026 path is `ext-image-copy-capture-v1` (standardized, Hyprland-supported) with direct dmabuf `vaImport`. Tradeoff: portal-permission UX vs no-permission capture is a *product decision*. Watch `lamco-wayland` crates (active, tiny adoption); `ashpd` 0.13 and `pipewire` 0.10 are healthy | High / High | 4–10 ms at 1440p+ |

**Codec call:** keep HEVC default. Android AV1 hw decode is flagship-mainstream by 2026 but patchy mid-range, and SVT-AV1 software encode is latency-hostile; add `av1_nvenc` only as an RTX-40+ preset. Dirty-region encoding: dead end on Wayland (full frames only). Cursor prediction: skip (host cursor is already in the video).

**Caveat on #3/intra-refresh:** it removes periodic IDRs — keep a forced recovery point (CRI) or Android mid-stream join/recovery breaks.

### R3. Android client features

**Tier 1 — quick wins (the "1.0 remote desktop" batch):**
1. Latency/FPS/bitrate stats HUD overlay (MediaCodec callbacks + QUIC RTT → Compose overlay)
2. Touch input modes: direct-touch / trackpad (relative mouse) / mouse-direct — the most-loved RustDesk/Moonlight affordance
3. Shortcut key bar: Super, Ctrl+Alt+Del equivalent, Alt+Tab, **Super+1..9 Hyprland workspace switch**, screenshot
4. Clipboard UX: sync toggle, phone-side history sheet, share-URI → file plugin (KDE Connect pattern)
5. Auto-connect to last host + connect/disconnect/lock actions in the foreground-service notification — decide the Android 14 FGS type early (`specialUse` justification vs `mediaProjection` consent dialog)
6. Pinch-zoom + display scaling for HiDPI desktops

**Tier 2 — differentiators:**
7. **Hyprland window/workspace picker + single-window streaming** (server queries `$HYPRLAND_INSTANCE_SIGNATURE` IPC: `j/clients`, `j/activewindow`, `.socket2.sock` events; feed window geometry as encoder crop) — a moat feature: Sunshine has no per-window Linux capture
8. Workspace state HUD (push `activewindow` events over the control stream; click-to-switch)
9. Gamepad passthrough: Android InputDevice (USB/BT controller) → serialize → server `uinput`/`evdev` virtual Xbox360/DS4 (Moonlight's killer feature; rank by audience)
10. Per-monitor selection (portal already provides monitor streams). HDR: skip
11. KDE Connect parity: notification reply from phone, find-my-phone siren, battery in client HUD, PIN pairing dialog
12. Wake-on-LAN from WAN via an always-on LAN relay peer (broadcast can't cross the wire; Tailscale's own WoL guidance is the same pattern)

**Tier 3 — epics:**
13. Seamless roaming hardening (QUIC migration + keepalive/Doze strategy)
14. PiP remote-desktop window + DeX/docked mode
15. Privacy modes: lock local screen + block local input while remote (both directions)
16. Audio device routing + volume sync via Hyprland IPC (`dispatch setvolume`)
17. Compose polish: predictive back, Material 3 expressive, per-app language (2026 Play table stakes)

**Suggested order:** R2#1-2 (encoder flags + MediaCodec tuning — days, pure config) → Tier 1 batch → R1 connectivity (iroh spike) → window picker (R3#7-8) → then gamepad vs KDE-parity/WoL depending on target audience.

### Sources (R1/R2/R3)

- iroh: [crates.io/iroh](https://crates.io/crates/iroh), [iroh-relay](https://crates.io/crates/iroh-relay), [why we forked Quinn](https://www.iroh.computer/blog/why-we-forked-quinn), [iroh vs libp2p](https://www.iroh.computer/blog/comparing-iroh-and-libp2p)
- NAT/QUIC punching: [Implementing NAT Hole Punching with QUIC](https://arxiv.org/abs/2408.01791), [2025 decentralized NAT traversal measurement](https://arxiv.org/html/2510.27500v1)
- Prior art: [RustDesk self-host docs](https://rustdesk.com/docs/en/self-host/), [Moonlight setup/port-forwarding](https://natchecker.com/blog/moonlight-port-forwarding), [Tailscale DERP reference](https://tailscale.com/docs/reference/derp-servers), [Tailscale WoL relay](https://tailscale.com/blog/wake-on-lan-tailscale-upsnap)
- Client features: [Hyprland IPC wiki](https://wiki.hyprland.org/0.41.2/IPC/), [Moonlight Android](https://github.com/moonlight-stream/moonlight-android), [RustDesk remote control on Android](https://rustdesk.com/blog/rustdesk-remote-control-android-ios), [Android 14 foreground service types](https://developer.android.com/about/versions/14/changes/fgs-types-required)
- Streaming: [Sunshine advanced-usage/optimization docs](https://docs.lizardbyte.dev/projects/sunshine/v0.23.1/about/advanced_usage.html), [AOSP low-latency decoding](https://source.android.com/docs/core/media/low-latency-media), [LiveVideo10ms](https://github.com/Consti10/LiveVideo10ms), [xdg-desktop-portal-wlr dmabuf #9](https://github.com/emersion/xdg-desktop-portal-wlr/issues/9), [Sunshine Hyprland portal issues #4662](https://github.com/LizardByte/Sunshine/issues/4662), [quinn congestion-control API](https://docs.rs/quinn-proto/latest/quinn_proto/congestion/index.html), [Cloudflare UDP GSO for QUIC](https://blog.cloudflare.com/accelerating-udp-packet-transmission-for-quic/)

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

*Document Version: 1.1*
*Last Updated: September 19, 2026 (Kotlin client migration)*
*Author: Linux Link Development Team*
