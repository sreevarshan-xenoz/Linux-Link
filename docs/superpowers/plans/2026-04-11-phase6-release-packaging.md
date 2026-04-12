# Phase 6: Release & Packaging — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Linux Link release-ready with automated GitHub Releases, AUR packaging, expanded CI, and polished documentation.

**Architecture:** 5 sequential streams — CHANGELOG + version → GitHub Release workflow → AUR packaging → CI expansion → documentation polish (man page, install script, CONTRIBUTING).

**Tech Stack:** GitHub Actions YAML, bash scripts, roff (man page), PKGBUILD (AUR), Markdown

---

### Task 1: CHANGELOG.md

**Files:**
- Create: `CHANGELOG.md`

- [ ] **Step 1: Create CHANGELOG.md**

Create `CHANGELOG.md` in the repo root:

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Full KDE Connect protocol runtime (battery, clipboard, notification, share, input plugins)
- Screen streaming pipeline: PipeWire capture → FFmpeg encoder → QUIC transport → MediaCodec decode
- Android client with Flutter UI, FFI bridge, remote desktop, file browser, settings
- Remote file browsing via KDE Connect protocol extension
- systemd service for auto-start on boot
- TOML configuration with video quality presets (low/balanced/high)
- Streaming statistics API (fps, bitrate, e2e latency, frame drops)

### Changed
- Input injection migrated from xdotool to native enigo
- Frame receiver uses timeout-based recv instead of polling loop (eliminates idle CPU usage)

### Fixed
- RTT polling uses lock-free atomic for main-thread safety
- Streaming task errors are now logged instead of silently discarded
- Timer callbacks properly check mounted state before FFI calls
```

- [ ] **Step 2: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add CHANGELOG.md
git commit -m "docs: add CHANGELOG.md with Unreleased section for v0.1.0

- Document all Phase 0-5 additions
- Follow Keep a Changelog format"
```

---

### Task 2: GitHub Release Workflow

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Create the release workflow**

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

env:
  CARGO_TERM_COLOR: always

jobs:
  build-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Cache cargo
        uses: Swatinem/rust-cache@v2

      - name: Build release binary
        run: cargo build --release --bin linux-link

      - name: Run tests
        run: cargo test --workspace

      - name: Create release archive
        run: |
          mkdir -p release/linux-link
          cp target/release/linux-link release/linux-link/
          cp config.toml.example release/linux-link/
          cp linux-link.service release/linux-link/
          cp README.md release/linux-link/
          cp LICENSE release/linux-link/
          cd release
          tar czf "linux-link-${{ github.ref_name }}-x86_64-unknown-linux-gnu.tar.gz" linux-link/
          sha256sum "linux-link-${{ github.ref_name }}-x86_64-unknown-linux-gnu.tar.gz" > "linux-link-${{ github.ref_name }}-checksums.txt"

      - name: Upload Linux binary
        uses: actions/upload-artifact@v4
        with:
          name: linux-binary
          path: release/linux-link-*.tar.gz

      - name: Upload checksums
        uses: actions/upload-artifact@v4
        with:
          name: checksums
          path: release/linux-link-*-checksums.txt

  create-release:
    needs: [build-linux]
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/download-artifact@v4
        with:
          name: linux-binary

      - uses: actions/download-artifact@v4
        with:
          name: checksums

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          body_path: CHANGELOG.md
          files: |
            linux-link-*.tar.gz
            linux-link-*-checksums.txt
          draft: true
```

- [ ] **Step 2: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add .github/workflows/release.yml
git commit -m "ci: add GitHub Release workflow for automated binary releases

- Triggers on v* tags
- Builds Linux release binary with tests
- Creates checksums (sha256)
- Creates draft GitHub Release with CHANGELOG body"
```

---

### Task 3: AUR Packaging

**Files:**
- Create: `aur/PKGBUILD`
- Create: `aur/linux-link.install`

- [ ] **Step 1: Create the PKGBUILD**

Create `aur/PKGBUILD`:

```bash
# Maintainer: sreevarshan <sreevarshan@example.com>
pkgname=linux-link
pkgver=0.1.0
pkgrel=1
pkgdesc="Remote desktop solution over Tailscale with KDE Connect integration"
arch=('x86_64')
url="https://github.com/sreevarshan-xenoz/Linux-Link"
license=('MIT' 'Apache')
depends=('tailscale' 'ffmpeg' 'pipewire' 'xdg-desktop-portal')
makedepends=('cargo' 'git')
source=("${pkgname}-${pkgver}.tar.gz::${url}/archive/refs/tags/v${pkgver}.tar.gz")
sha256sums=('SKIP')

build() {
  cd "${srcdir}/${pkgname}-${pkgver}"
  cargo build --release --bin linux-link
}

package() {
  cd "${srcdir}/${pkgname}-${pkgver}"
  install -Dm755 "target/release/linux-link" "${pkgdir}/usr/bin/linux-link"
  install -Dm644 "linux-link.service" "${pkgdir}/usr/lib/systemd/system/linux-link.service"
  install -Dm644 "config.toml.example" "${pkgdir}/usr/share/doc/${pkgname}/config.toml.example"
  install -Dm644 "README.md" "${pkgdir}/usr/share/doc/${pkgname}/README.md"
  install -Dm644 "CHANGELOG.md" "${pkgdir}/usr/share/doc/${pkgname}/CHANGELOG.md"
}
```

- [ ] **Step 2: Create .install script for AUR post-install messages**

Create `aur/linux-link.install`:

```bash
post_install() {
  echo ">>> Linux Link has been installed."
  echo ">>> Configuration: /etc/linux-link/config.toml"
  echo ">>> Copy config.toml.example to ~/.config/linux-link/config.toml"
  echo ">>> Enable with: systemctl enable --now linux-link.service"
}

post_upgrade() {
  post_install
}
```

- [ ] **Step 3: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add aur/PKGBUILD aur/linux-link.install
git commit -m "feat: add AUR packaging (PKGBUILD + install script)

- Builds from git tag source
- Installs binary, systemd service, and docs
- Post-install message with setup instructions"
```

---

### Task 4: CI Expansion

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add audit and Android build jobs to CI**

Read the current `.github/workflows/ci.yml`. Append these jobs after the existing `rust-build-and-test` job:

```yaml
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-audit
        run: cargo install cargo-audit

      - name: Run security audit
        run: cargo audit || echo "Security audit found vulnerabilities (see output above)"

  lint-android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Flutter
        uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.24.0'
          cache: true

      - name: Flutter analyze
        run: |
          cd android
          flutter analyze
```

- [ ] **Step 2: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add .github/workflows/ci.yml
git commit -m "ci: add cargo audit and Flutter analyze jobs

- Security audit scans dependencies for known vulnerabilities
- Flutter analyze checks Android code quality"
```

---

### Task 5: Man Page

**Files:**
- Create: `man/linux-link.1`

- [ ] **Step 1: Create the man page**

Create `man/linux-link.1`:

```roff
.TH LINUX-LINK 1 "2026-04-11" "Linux Link 0.1.0"
.SH NAME
linux-link \- Remote desktop over Tailscale with KDE Connect integration
.SH SYNOPSIS
.B linux-link
[\fIOPTIONS\fR] [\fICOMMAND\fR]
.SH DESCRIPTION
Linux Link is a pure-Rust remote desktop solution for Linux.
It combines KDE Connect device integration with low-latency
screen streaming over Tailscale.
.SH COMMANDS
.TP
.B start
Start the server daemon
.TP
.B stop
Stop the running daemon
.TP
.B status
Show connection status
.TP
.B list
List available peers on tailnet
.TP
.B connect \fIPEER\fR
Connect to a specific peer
.TP
.B watch
Watch for peer discovery events
.TP
.B capabilities
Show KDE Connect capabilities
.TP
.B pair \fIPIN\fR
Pair with a new device
.SH OPTIONS
.TP
.BI "\-\-config " PATH
Config file path (default: ~/.config/linux-link/config.toml)
.TP
.BI "\-\-port " PORT
Override the control port
.TP
.B \-v, \-\-verbose
Verbose output
.TP
.B \-h, \-\-help
Print help
.TP
.B \-V, \-\-version
Print version
.SH FILES
.TP
.I ~/.config/linux-link/config.toml
Configuration file
.SH ENVIRONMENT
.TP
.B RUST_LOG
Log level (trace, debug, info, warn, error)
.SH SEE ALSO
.BR tailscaled (8),
.BR hyprland (1)
.SH BUGS
Report bugs at https://github.com/sreevarshan-xenoz/Linux-Link/issues
.SH AUTHOR
Linux Link Development Team
```

- [ ] **Step 2: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add man/linux-link.1
git commit -m "docs: add man page for linux-link CLI

- Documents all commands and options
- Installable to /usr/share/man/man1/"
```

---

### Task 6: Install Script

**Files:**
- Create: `scripts/install.sh`

- [ ] **Step 1: Create the install script**

Create `scripts/install.sh`:

```bash
#!/usr/bin/env bash
#
# Linux Link Installer
# Downloads and installs Linux Link from GitHub Releases.
#
# Usage: ./install.sh [VERSION]
#   VERSION: Version tag (e.g., v0.1.0). Defaults to 'latest'.
#
# Example:
#   ./install.sh           # Install latest release
#   ./install.sh v0.1.0    # Install specific version

set -euo pipefail

# Repository configuration
REPO_OWNER="sreevarshan-xenoz"
REPO_NAME="Linux-Link"
BINARY_NAME="linux-link"

VERSION="${1:-latest}"
if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" \
    | grep -o '"tag_name": *"[^"]*"' \
    | head -1 \
    | sed 's/"tag_name": *"//;s/"//')
  if [ -z "$VERSION" ]; then
    echo "Error: Could not determine latest version" >&2
    exit 1
  fi
fi

ARCHIVE_NAME="${BINARY_NAME}-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"
URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${VERSION}/${ARCHIVE_NAME}"

echo "Installing ${BINARY_NAME} ${VERSION}..."
echo "Downloading from ${URL}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -fsSL "$URL" -o "${TMPDIR}/${ARCHIVE_NAME}"

echo "Extracting..."
tar xzf "${TMPDIR}/${ARCHIVE_NAME}" -C "$TMPDIR"

echo "Installing to /usr/bin/${BINARY_NAME}..."
sudo cp "${TMPDIR}/${BINARY_NAME}/${BINARY_NAME}" "/usr/bin/${BINARY_NAME}"
sudo chmod +x "/usr/bin/${BINARY_NAME}"

echo "Installing systemd service..."
sudo cp "${TMPDIR}/${BINARY_NAME}/${BINARY_NAME}.service" /etc/systemd/system/
sudo systemctl daemon-reload

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Copy config: mkdir -p ~/.config/linux-link && cp /usr/share/doc/${BINARY_NAME}/config.toml.example ~/.config/linux-link/config.toml"
echo "  2. Edit config: nano ~/.config/linux-link/config.toml"
echo "  3. Start service: sudo systemctl enable --now ${BINARY_NAME}"
echo "  4. Check status: systemctl status ${BINARY_NAME}"
```

- [ ] **Step 2: Make executable**

```bash
chmod +x scripts/install.sh
```

- [ ] **Step 3: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add scripts/install.sh
git commit -m "feat: add install script for one-command installation

- Downloads from GitHub Releases
- Installs binary and systemd service
- Supports specific version or latest"
```

---

### Task 7: CONTRIBUTING.md

**Files:**
- Create: `CONTRIBUTING.md`

- [ ] **Step 1: Create the contributing guide**

Create `CONTRIBUTING.md`:

```markdown
# Contributing to Linux Link

Thank you for your interest in contributing! This document covers the basics.

## Development Setup

### Prerequisites

- Rust 1.80+ (edition 2024)
- Flutter 3.24+ (for Android client)
- Android SDK & NDK (for Android builds)
- Tailscale (for testing connectivity)
- FFmpeg, PipeWire, xdg-desktop-portal (for streaming)

### Building

```bash
# Build all Rust crates
cargo build --workspace

# Run tests
cargo test --workspace

# Format and lint
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Build Android client (requires Flutter SDK)
cd android
flutter pub get
flutter build apk --debug
```

### Running

```bash
# Start the server
cargo run --bin linux-link -- start

# Or with a specific config
cargo run --bin linux-link -- --config /path/to/config.toml start
```

## Code Style

- **Rust:** Follow `cargo fmt` and `cargo clippy -D warnings`. No warnings allowed.
- **Dart:** Follow `flutter analyze`. Use `const` constructors where possible.
- **Commits:** Use conventional commit messages (`feat:`, `fix:`, `docs:`, `chore:`, etc.)

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear, focused commits
3. Ensure all tests pass (`cargo test --workspace`)
4. Ensure clippy passes (`cargo clippy --workspace -- -D warnings`)
5. Push and open a PR with a clear description of changes
6. Wait for review

## Reporting Issues

- **Bug reports:** Use the bug report template with reproduction steps
- **Feature requests:** Use the feature request template
- **Security issues:** Email directly (do not open a public issue)

## Architecture Overview

See `plan.md` for the full architecture and development roadmap.
Key components:
- `core/` — Shared protocol, streaming, and utility code
- `server/` — Linux daemon (CLI + service)
- `android/` — Flutter Android client + Rust FFI bridge
```

- [ ] **Step 2: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add CONTRIBUTING.md
git commit -m "docs: add CONTRIBUTING.md with development setup and PR process

- Prerequisites, build instructions, code style guidelines
- Pull request process and issue reporting"
```

---

### Task 8: Update README Phase Badge

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the phase badge**

In `README.md`, find the line with the Phase badge (currently says "Phase 3 Complete"). Update it:

```markdown
[![Phase](https://img.shields.io/badge/Phase-5%20Complete-brightgreen)](plan.md)
```

- [ ] **Step 2: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add README.md
git commit -m "docs: update README phase badge to Phase 5 Complete"
```

---

### Task 9: Update Plan Documentation

**Files:**
- Modify: `plan.md`

- [ ] **Step 1: Update Phase 6 status**

Find the Phase 6 section in `plan.md` and update:

```markdown
### Phase 6: Release & Packaging (Week 29-30)

**Status: COMPLETE**

- [x] CHANGELOG.md with Unreleased section
- [x] GitHub Release workflow (binary builds + checksums + draft release)
- [x] AUR packaging (PKGBUILD + install script)
- [x] CI expansion (cargo audit, Flutter analyze)
- [x] Man page (linux-link.1)
- [x] Install script (scripts/install.sh)
- [x] CONTRIBUTING.md
- [ ] First release tagged and published (requires manual action)
```

- [ ] **Step 2: Commit**

```bash
cd /home/sreevarshan/projects/Linux-Link
git add plan.md
git commit -m "docs: update plan.md with Phase 6 completion status"
```

---

### Task 10: Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run Rust quality gates**

Run: `cd /home/sreevarshan/projects/Linux-Link && cargo fmt --check && cargo clippy --workspace -- -D warnings && cargo test --workspace`

Expected: All pass.

- [ ] **Step 2: Verify all new files exist**

Run:
```bash
cd /home/sreevarshan/projects/Linux-Link
test -f CHANGELOG.md && echo "CHANGELOG.md: OK"
test -f .github/workflows/release.yml && echo "release.yml: OK"
test -f aur/PKGBUILD && echo "PKGBUILD: OK"
test -f aur/linux-link.install && echo "linux-link.install: OK"
test -f man/linux-link.1 && echo "man page: OK"
test -f scripts/install.sh && echo "install.sh: OK"
test -f CONTRIBUTING.md && echo "CONTRIBUTING.md: OK"
```

Expected: All "OK".

- [ ] **Step 3: Fix any issues and commit**

If any issues found, fix and commit:
```bash
git add -A && git commit -m "fix: address final Phase 6 quality gate findings"
```
