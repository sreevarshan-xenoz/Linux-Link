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
