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
