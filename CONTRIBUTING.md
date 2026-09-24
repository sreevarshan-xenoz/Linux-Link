# Contributing to Linux Link

Thank you for your interest in contributing! This document covers the basics.

## Development Setup

### Prerequisites

- Rust 1.80+ (edition 2024)
- JDK 17+ (for Android client)
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

# Build Android client (requires Android SDK/NDK)
cd android
./gradlew assembleDebug
```

### Running

```bash
# Start the server
cargo run --bin linux-link -- start

# There is no --config flag: the server reads $XDG_CONFIG_HOME/linux-link/config.toml,
# so point XDG_CONFIG_HOME at a scratch directory for a throwaway run.
XDG_CONFIG_HOME=$PWD/devconfig cargo run --bin linux-link -- start
```

## Code Style

- **Rust:** Follow `cargo fmt` and `cargo clippy -D warnings`. No warnings allowed.
- **Kotlin:** Follow Android Lint; format with `ktfmt`/`ktlint` defaults.
- **Commits:** Use conventional commit messages (`feat:`, `fix:`, `docs:`, `chore:`, etc.)

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear, focused commits
3. Ensure all tests pass (`cargo test --workspace`)
4. Ensure clippy passes (`cargo clippy --workspace -- -D warnings`)
5. Push and open a PR with a clear description of changes
6. Wait for review

## Reporting Issues

- **Bug reports:** Use the bug report template
- **Feature requests:** Use the feature request template
- **Security issues:** Email directly (do not open a public issue)

## Architecture Overview

See `plan.md` for the full architecture and development roadmap.
Key components:
- `core/` — Shared protocol, streaming, and utility code
- `server/` — Linux daemon (CLI + service)
- `android/` — Native Kotlin Android client + Rust JNI/UniFFI bridge
