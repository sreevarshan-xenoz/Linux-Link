# Phase 6: Release & Packaging — Design Spec

> **Date:** 2026-04-11
> **Status:** Draft — awaiting review
> **Scope:** Release automation, AUR packaging, CI expansion, documentation polish

---

## 1. Objective

Make Linux Link release-ready: automated GitHub Releases with binaries and checksums, AUR package for Arch Linux, Android APK build in CI, and polished documentation.

---

## 2. Workstreams

### Stream 1: CHANGELOG.md and Version Management

**CHANGELOG.md** — Standard [Keep a Changelog](https://keepachangelog.com/) format:

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
- TOML configuration with video quality presets

### Changed
- Input injection migrated from xdotool to native enigo

### Fixed
- Frame receiver uses timeout-based recv instead of wasteful polling
- RTT polling uses lock-free atomic for main-thread safety
```

**Version management** — Use `cargo-release` for version bumping:
- Add `cargo-release` to dev dependencies (or document manual process)
- `Cargo.toml` version is the single source of truth
- Changelog is manually maintained (no auto-generation for now)

### Stream 2: GitHub Release Workflow

Create `.github/workflows/release.yml` that triggers on git tag push:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-action@stable
      - name: Build release binary
        run: cargo build --release --bin linux-link
      - name: Create release archive
        run: |
          mkdir -p release
          cp target/release/linux-link release/
          cp config.toml.example release/
          cp linux-link.service release/
          cp README.md release/
          tar czf linux-link-$(git describe --tags)-x86_64-unknown-linux-gnu.tar.gz -C release .
      - name: Generate checksums
        run: sha256sum linux-link-*.tar.gz > linux-link-$(git describe --tags)-checksums.txt
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: linux-release-binaries
          path: |
            linux-link-*.tar.gz
            linux-link-*-checksums.txt

  build-android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.24.0'
      - uses: dtolnay/rust-action@stable
      - name: Add Android target
        run: rustup target add aarch64-linux-android
      - name: Build APK
        run: |
          cd android
          flutter build apk --release
      - name: Upload APK
        uses: actions/upload-artifact@v4
        with:
          name: android-apk
          path: android/build/app/outputs/flutter-apk/app-release.apk

  create-release:
    needs: [build-linux, build-android]
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          body_path: CHANGELOG.md
          files: |
            linux-release-binaries/*
            android-apk/*
          draft: true
```

### Stream 3: AUR Packaging

Create `PKGBUILD` in an `aur/` directory:

```bash
# Maintainer: Your Name <your.email@example.com>
pkgname=linux-link
pkgver=0.1.0
pkgrel=1
pkgdesc="Remote desktop solution over Tailscale with KDE Connect integration"
arch=('x86_64')
url="https://github.com/yourusername/linux-link"
license=('MIT' 'Apache')
depends=('tailscale' 'ffmpeg' 'pipewire' 'xdg-desktop-portal')
makedepends=('cargo' 'git')
source=("linux-link-$pkgver.tar.gz::https://github.com/yourusername/linux-link/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
  cd "linux-link-$pkgver"
  cargo build --release --bin linux-link
}

package() {
  cd "linux-link-$pkgver"
  install -Dm755 "target/release/linux-link" "$pkgdir/usr/bin/linux-link"
  install -Dm644 "linux-link.service" "$pkgdir/usr/lib/systemd/system/linux-link.service"
  install -Dm644 "config.toml.example" "$pkgdir/usr/share/doc/linux-link/config.toml.example"
  install -Dm644 "README.md" "$pkgdir/usr/share/doc/linux-link/README.md"
}
```

Also create `.github/workflows/aur-publish.yml` to update AUR on release:

```yaml
name: Publish to AUR

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Update PKGBUILD version
        run: |
          VERSION=$(echo "${{ github.ref }}" | sed 's/refs\/tags\/v//')
          sed -i "s/pkgver=.*/pkgver=$VERSION/" aur/PKGBUILD
      - name: Publish to AUR
        uses: KSXGitHub/github-actions-deploy-aur@v3.0.1
        with:
          pkgname: linux-link
          pkgbuild: aur/PKGBUILD
          commit_username: ${{ secrets.AUR_USERNAME }}
          commit_email: ${{ secrets.AUR_EMAIL }}
          ssh_private_key: ${{ secrets.AUR_SSH_PRIVATE_KEY }}
          commit_message: "Update to v${{ github.ref_name }}"
```

### Stream 4: CI Expansion

Extend `.github/workflows/ci.yml` with:
- `cargo audit` job for security vulnerability scanning
- Android APK build job (debug build on PR, release on main)
- Binary size tracking (report binary size in PR comments)

Add to existing CI:

```yaml
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-action@stable
      - name: Install cargo-audit
        run: cargo install cargo-audit
      - name: Run security audit
        run: cargo audit

  build-android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.24.0'
      - uses: dtolnay/rust-action@stable
      - name: Add Android targets
        run: rustup target add aarch64-linux-android armv7-linux-androideabi
      - name: Build debug APK
        run: |
          cd android
          flutter build apk --debug
```

### Stream 5: Documentation Polish

**Man page** — Create `man/linux-link.1`:

```
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
.B connect <peer>
Connect to a specific peer
.TP
.B watch
Watch for peer discovery events
.TP
.B capabilities
Show KDE Connect capabilities
.SH OPTIONS
.TP
.B \-\-config <path>
Config file path (default: ~/.config/linux-link/config.toml)
.TP
.B \-v, \-\-verbose
Verbose output
.SH FILES
.TP
.I ~/.config/linux-link/config.toml
Configuration file
.SH SEE ALSO
.BR tailscaled (8)
```

**CONTRIBUTING.md** — Standard contributing guide with setup instructions, coding standards, PR template.

**Install script** — `scripts/install.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Configuration — update these for your repository
REPO_OWNER="yourusername"
REPO_NAME="linux-link"

VERSION="${1:-latest}"
if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -s "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" | jq -r .tag_name | sed 's/v//')
fi

URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/v${VERSION}/${REPO_NAME}-v${VERSION}-x86_64-unknown-linux-gnu.tar.gz"
echo "Downloading ${REPO_NAME} v${VERSION}..."
curl -fsSL "$URL" -o /tmp/${REPO_NAME}.tar.gz

echo "Installing..."
tar xzf /tmp/${REPO_NAME}.tar.gz -C /tmp/
sudo cp /tmp/${REPO_NAME}/${REPO_NAME} /usr/bin/${REPO_NAME}
sudo cp /tmp/${REPO_NAME}/${REPO_NAME}.service /etc/systemd/system/
sudo systemctl daemon-reload

echo "Installed successfully! Run '${REPO_NAME} --help' or 'sudo systemctl enable --now ${REPO_NAME}'"
```

---

## 3. Execution Order

```
Stream 1 (CHANGELOG + version) ───────────────── 0.5 days
    ↓
Stream 2 (GitHub Release workflow) ───────────── 1 day
    ↓
Stream 3 (AUR packaging) ─────────────────────── 1 day
    ↓
Stream 4 (CI expansion) ──────────────────────── 0.5 days
    ↓
Stream 5 (Documentation polish) ──────────────── 1 day
```

Total: ~4 days of implementation work.

---

## 4. Success Criteria

- [ ] `CHANGELOG.md` with Unreleased section documenting all Phase 0-5 work
- [ ] GitHub Release workflow triggers on tag, builds Linux binaries + Android APK, creates draft release
- [ ] PKGBUILD builds and installs correctly (tested locally with `makepkg`)
- [ ] CI includes `cargo audit` and Android APK build jobs
- [ ] Man page renders correctly (`man ./man/linux-link.1`)
- [ ] Install script downloads and installs from GitHub Release
- [ ] `linux-link --version` reports correct version
