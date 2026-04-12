#!/usr/bin/env bash
#
# Linux Link Installer
# Downloads and installs Linux Link from GitHub Releases.
#
# Usage: ./install.sh [VERSION]
#   VERSION: Version tag (e.g., v0.1.0). Defaults to 'latest'.
#   --dry-run     Show what would be done without making changes.
#   --uninstall   Remove an existing installation.
#
# Example:
#   ./install.sh              # Install latest release
#   ./install.sh v0.1.0       # Install specific version
#   ./install.sh --dry-run    # Preview installation
#   ./install.sh --uninstall  # Remove installation

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

REPO_OWNER="sreevarshan-xenoz"
REPO_NAME="Linux-Link"
BINARY_NAME="linux-link"
INSTALL_PREFIX="/usr"
SERVICE_FILE="/etc/systemd/system/${BINARY_NAME}.service"
CONFIG_DIR="$HOME/.config/${BINARY_NAME}"
CONFIG_FILE="${CONFIG_DIR}/config.toml"

# ─── Color output ────────────────────────────────────────────────────────────

if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  BLUE='\033[0;34m'
  BOLD='\033[1m'
  RESET='\033[0m'
else
  RED='' GREEN='' YELLOW='' BLUE='' BOLD='' RESET=''
fi

info()  { echo -e "${BLUE}[info]${RESET} $*"; }
ok()    { echo -e "${GREEN}[ok]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[warn]${RESET} $*"; }
error() { echo -e "${RED}[error]${RESET} $*" >&2; }
fatal() { error "$@"; exit 1; }

# ─── Argument parsing ────────────────────────────────────────────────────────

DRY_RUN=false
UNINSTALL=false
VERSION="latest"

for arg in "$@"; do
  case "$arg" in
    --dry-run)  DRY_RUN=true ;;
    --uninstall) UNINSTALL=true ;;
    -h|--help)
      echo "Usage: $0 [VERSION] [OPTIONS]"
      echo ""
      echo "Install or uninstall Linux Link from GitHub Releases."
      echo ""
      echo "Arguments:"
      echo "  VERSION    Version tag (e.g., v0.1.0). Defaults to 'latest'."
      echo ""
      echo "Options:"
      echo "  --dry-run      Show what would be done without making changes."
      echo "  --uninstall    Remove an existing installation."
      echo "  -h, --help     Show this help message."
      exit 0
      ;;
    -v*)
      # Accept -v0.1.0 as well as plain v0.1.0
      VERSION="$arg"
      ;;
    *)
      VERSION="$arg"
      ;;
  esac
done

# ─── Cleanup on exit / interrupt ─────────────────────────────────────────────

TMPDIR=""
cleanup() {
  if [ -n "$TMPDIR" ] && [ -d "$TMPDIR" ]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT INT TERM

# ─── Uninstall mode ──────────────────────────────────────────────────────────

if [ "$UNINSTALL" = true ]; then
  info "Removing Linux Link..."

  # Stop and disable service
  if systemctl is-active --quiet "$BINARY_NAME" 2>/dev/null; then
    info "Stopping ${BINARY_NAME} service..."
    [ "$DRY_RUN" = true ] || sudo systemctl stop "$BINARY_NAME"
  fi
  if systemctl is-enabled --quiet "$BINARY_NAME" 2>/dev/null; then
    info "Disabling ${BINARY_NAME} service..."
    [ "$DRY_RUN" = true ] || sudo systemctl disable "$BINARY_NAME"
  fi

  # Remove binary
  if [ -f "${INSTALL_PREFIX}/bin/${BINARY_NAME}" ]; then
    info "Removing binary ${INSTALL_PREFIX}/bin/${BINARY_NAME}..."
    [ "$DRY_RUN" = true ] || sudo rm -f "${INSTALL_PREFIX}/bin/${BINARY_NAME}"
  fi

  # Remove service file
  if [ -f "$SERVICE_FILE" ]; then
    info "Removing service file ${SERVICE_FILE}..."
    [ "$DRY_RUN" = true ] || sudo rm -f "$SERVICE_FILE"
    [ "$DRY_RUN" = true ] || sudo systemctl daemon-reload
  fi

  # Remove docs
  for f in README.md CHANGELOG.md config.toml.example; do
    if [ -f "${INSTALL_PREFIX}/share/doc/${BINARY_NAME}/$f" ]; then
      [ "$DRY_RUN" = true ] || sudo rm -f "${INSTALL_PREFIX}/share/doc/${BINARY_NAME}/$f"
    fi
  done
  [ "$DRY_RUN" = true ] || sudo rmdir "${INSTALL_PREFIX}/share/doc/${BINARY_NAME}" 2>/dev/null || true

  # Remove man page
  if [ -f "${INSTALL_PREFIX}/share/man/man1/${BINARY_NAME}.1" ]; then
    info "Removing man page..."
    [ "$DRY_RUN" = true ] || sudo rm -f "${INSTALL_PREFIX}/share/man/man1/${BINARY_NAME}.1"
  fi

  # Keep user config, just warn
  if [ -d "$CONFIG_DIR" ]; then
    warn "User config kept at ${CONFIG_DIR} (not removed)."
    warn "Remove manually with: rm -rf ${CONFIG_DIR}"
  fi

  ok "Uninstallation complete."
  if [ "$DRY_RUN" = true ]; then
    echo ""
    warn "DRY RUN — no changes were made."
  fi
  exit 0
fi

# ─── Pre-flight checks ──────────────────────────────────────────────────────

# Check required commands
for cmd in curl tar sudo; do
  if ! command -v "$cmd" &>/dev/null; then
    fatal "Required command not found: ${cmd}. Please install it and try again."
  fi
done

# Check architecture
ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
  warn "Architecture detected: ${ARCH}"
  warn "Only x86_64 pre-built binaries are available."
  warn "You may need to build from source on this architecture."
  read -rp "Continue anyway? [y/N] " confirm
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
  fi
fi

# Check sudo access
if ! sudo -n true 2>/dev/null; then
  info "Verifying sudo access (will prompt for password if needed)..."
  if ! sudo -v; then
    fatal "Cannot obtain sudo access. This installer needs root privileges to install to ${INSTALL_PREFIX}/bin/."
  fi
fi

# Check disk space (need ~100 MB for download + install)
if command -v df &>/dev/null; then
  AVAILABLE_KB=$(df -k /usr 2>/dev/null | awk 'NR==2 {print $4}')
  if [ -n "$AVAILABLE_KB" ] && [ "$AVAILABLE_KB" -lt 102400 ]; then
    warn "Less than 100 MB free on /usr. Installation may fail."
  fi
fi

# Check for existing installation (upgrade path)
UPGRADE=false
if [ -f "${INSTALL_PREFIX}/bin/${BINARY_NAME}" ]; then
  CURRENT_VERSION=$("${INSTALL_PREFIX}/bin/${BINARY_NAME}" --version 2>/dev/null || echo "unknown")
  warn "Existing installation found: ${BINARY_NAME} ${CURRENT_VERSION}"
  UPGRADE=true
fi

if [ "$DRY_RUN" = true ]; then
  info "DRY RUN — no changes will be made."
fi

# ─── Determine version ───────────────────────────────────────────────────────

if [ "$VERSION" = "latest" ]; then
  info "Fetching latest release from GitHub..."

  # Try GitHub API first
  API_RESPONSE=$(curl -fsSL --max-time 15 \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null) || {
    # Fallback: scrape the releases page
    warn "GitHub API not reachable, trying HTML fallback..."
    HTML=$(curl -fsSL --max-time 15 "https://github.com/${REPO_OWNER}/${REPO_NAME}/releases" 2>/dev/null) || \
      fatal "Cannot reach GitHub. Check your internet connection and DNS."
    VERSION=$(echo "$HTML" | grep -o '/releases/tag/[^"]*' | head -1 | sed 's|/releases/tag/||') || \
      fatal "Cannot determine latest version from GitHub."
  }

  if [ -n "${API_RESPONSE:-}" ]; then
    VERSION=$(echo "$API_RESPONSE" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/"tag_name": *"//;s/"//')
  fi

  if [ -z "$VERSION" ]; then
    fatal "Could not determine the latest version. The repository may have no releases yet."
  fi

  info "Latest version: ${VERSION}"
else
  # Normalize version: ensure it starts with 'v'
  if [[ ! "$VERSION" =~ ^v[0-9] ]]; then
    VERSION="v${VERSION}"
  fi
  info "Using version: ${VERSION}"
fi

# ─── Download ────────────────────────────────────────────────────────────────

ARCHIVE_NAME="${BINARY_NAME}-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"
URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${VERSION}/${ARCHIVE_NAME}"

TMPDIR=$(mktemp -d)

info "Downloading ${BINARY_NAME} ${VERSION}..."
info "URL: ${URL}"

HTTP_CODE=$(curl -fsSL --max-time 120 --retry 3 --retry-delay 5 \
  -w '%{http_code}' \
  -o "${TMPDIR}/${ARCHIVE_NAME}" \
  "$URL" 2>/dev/null) || {
  # curl failed entirely (network error, DNS, etc.)
  if curl -fsS --max-time 5 -o /dev/null "https://github.com" 2>/dev/null; then
    fatal "Failed to download release. The URL may be wrong or the release may not exist yet."
  else
    fatal "Network unavailable. Please check your internet connection."
  fi
}

if [ "$HTTP_CODE" = "404" ]; then
  fatal "Release ${VERSION} not found (HTTP 404). Check available releases at https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
elif [ "$HTTP_CODE" != "200" ]; then
  fatal "Download failed with HTTP ${HTTP_CODE}."
fi

# Verify the archive is not empty
ARCHIVE_SIZE=$(stat -c%s "${TMPDIR}/${ARCHIVE_NAME}" 2>/dev/null || stat -f%z "${TMPDIR}/${ARCHIVE_NAME}" 2>/dev/null || echo "0")
if [ "$ARCHIVE_SIZE" -lt 100 ]; then
  fatal "Downloaded file is too small (${ARCHIVE_SIZE} bytes). The release asset may be corrupted."
fi

# If checksums are available, verify them
CHECKSUM_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${VERSION}/${BINARY_NAME}-${VERSION}-checksums.txt"
CHECKSUM_FILE="${TMPDIR}/checksums.txt"
if curl -fsSL --max-time 15 -o "$CHECKSUM_FILE" "$CHECKSUM_URL" 2>/dev/null; then
  EXPECTED=$(grep "$ARCHIVE_NAME" "$CHECKSUM_FILE" 2>/dev/null | awk '{print $1}' || true)
  if [ -n "$EXPECTED" ]; then
    if command -v sha256sum &>/dev/null; then
      ACTUAL=$(sha256sum "${TMPDIR}/${ARCHIVE_NAME}" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
      ACTUAL=$(shasum -a 256 "${TMPDIR}/${ARCHIVE_NAME}" | awk '{print $1}')
    else
      warn "No sha256sum or shasum available — skipping checksum verification."
      ACTUAL=""
    fi
    if [ -n "$ACTUAL" ] && [ "$ACTUAL" != "$EXPECTED" ]; then
      fatal "Checksum mismatch! The downloaded file may be corrupted or tampered with."
    else
      ok "Checksum verified."
    fi
  fi
else
  warn "No checksums file found — skipping verification."
fi

# ─── Extract ─────────────────────────────────────────────────────────────────

info "Extracting archive..."

if ! tar xzf "${TMPDIR}/${ARCHIVE_NAME}" -C "$TMPDIR" 2>/dev/null; then
  fatal "Failed to extract archive. The file may be corrupted."
fi

# Verify expected directory structure
EXTRACTED_DIR="${TMPDIR}/${BINARY_NAME}"
if [ ! -d "$EXTRACTED_DIR" ]; then
  # Try to find the extracted directory (may have different name)
  EXTRACTED_DIR=$(find "$TMPDIR" -maxdepth 1 -type d -not -name "$(basename "$TMPDIR")" | head -1)
  if [ -z "$EXTRACTED_DIR" ]; then
    fatal "Archive extracted but expected directory structure not found."
  fi
fi

# Verify the binary exists and is executable
if [ ! -f "${EXTRACTED_DIR}/${BINARY_NAME}" ]; then
  fatal "Binary '${BINARY_NAME}' not found in release archive."
fi

if ! file "${EXTRACTED_DIR}/${BINARY_NAME}" | grep -q "ELF"; then
  fatal "Binary is not a valid ELF executable. This release may be for the wrong architecture."
fi

# ─── Install ─────────────────────────────────────────────────────────────────

if [ "$UPGRADE" = true ]; then
  info "Upgrading from ${CURRENT_VERSION} to ${VERSION}..."

  # Stop the service before upgrading
  if systemctl is-active --quiet "$BINARY_NAME" 2>/dev/null; then
    info "Stopping ${BINARY_NAME} service for upgrade..."
    [ "$DRY_RUN" = true ] || sudo systemctl stop "$BINARY_NAME"
  fi
fi

# Backup existing config
if [ "$UPGRADE" = true ] && [ -f "$CONFIG_FILE" ]; then
  BACKUP="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
  info "Backing up config to ${BACKUP}..."
  [ "$DRY_RUN" = true ] || cp "$CONFIG_FILE" "$BACKUP"
fi

# Install binary
info "Installing binary to ${INSTALL_PREFIX}/bin/${BINARY_NAME}..."
[ "$DRY_RUN" = true ] || sudo install -Dm755 "${EXTRACTED_DIR}/${BINARY_NAME}" "${INSTALL_PREFIX}/bin/${BINARY_NAME}"

# Install service file
if [ -f "${EXTRACTED_DIR}/${BINARY_NAME}.service" ]; then
  info "Installing systemd service..."
  [ "$DRY_RUN" = true ] || sudo install -Dm644 "${EXTRACTED_DIR}/${BINARY_NAME}.service" "$SERVICE_FILE"
  [ "$DRY_RUN" = true ] || sudo systemctl daemon-reload
fi

# Install documentation
for doc in README.md CHANGELOG.md config.toml.example; do
  if [ -f "${EXTRACTED_DIR}/${doc}" ]; then
    [ "$DRY_RUN" = true ] || sudo install -Dm644 "${EXTRACTED_DIR}/${doc}" \
      "${INSTALL_PREFIX}/share/doc/${BINARY_NAME}/${doc}"
  fi
done

# Install man page
if [ -f "${EXTRACTED_DIR}/man/${BINARY_NAME}.1" ]; then
  info "Installing man page..."
  [ "$DRY_RUN" = true ] || sudo install -Dm644 "${EXTRACTED_DIR}/man/${BINARY_NAME}.1" \
    "${INSTALL_PREFIX}/share/man/man1/${BINARY_NAME}.1"
  [ "$DRY_RUN" = true ] || mandb -q 2>/dev/null || true
fi

# Set up user config directory
if [ ! -d "$CONFIG_DIR" ]; then
  info "Creating config directory ${CONFIG_DIR}..."
  [ "$DRY_RUN" = true ] || mkdir -p "$CONFIG_DIR"
fi

if [ ! -f "$CONFIG_FILE" ] && [ -f "${EXTRACTED_DIR}/config.toml.example" ]; then
  info "Installing default config to ${CONFIG_FILE}..."
  [ "$DRY_RUN" = true ] || cp "${EXTRACTED_DIR}/config.toml.example" "$CONFIG_FILE"
fi

# ─── Post-install ────────────────────────────────────────────────────────────

# Enable and start service (only if systemctl is available)
if command -v systemctl &>/dev/null; then
  if [ "$UPGRADE" = true ]; then
    info "Restarting ${BINARY_NAME} service..."
    [ "$DRY_RUN" = true ] || sudo systemctl restart "$BINARY_NAME"
  else
    info "Would you like to enable and start the ${BINARY_NAME} service? [Y/n] "
    read -r -t 10 ENABLE_SERVICE || true
    if [[ ! "$ENABLE_SERVICE" =~ ^[Nn]$ ]]; then
      info "Enabling and starting ${BINARY_NAME} service..."
      [ "$DRY_RUN" = true ] || sudo systemctl enable "$BINARY_NAME"
      [ "$DRY_RUN" = true ] || sudo systemctl start "$BINARY_NAME"
    fi
  fi
else
  warn "systemctl not found — service will not be managed automatically."
  warn "Start manually with: ${BINARY_NAME} start"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}Installation complete!${RESET}"
echo ""
INSTALLED_VER=$("${INSTALL_PREFIX}/bin/${BINARY_NAME}" --version 2>/dev/null || echo "${VERSION}")
echo "  Binary:   ${INSTALL_PREFIX}/bin/${BINARY_NAME} (${INSTALLED_VER})"
echo "  Config:   ${CONFIG_FILE}"
echo "  Service:  ${SERVICE_FILE}"
echo ""
echo "Next steps:"
echo "  1. Edit config:   nano ${CONFIG_FILE}"
echo "  2. Start daemon:  sudo systemctl enable --now ${BINARY_NAME}"
echo "  3. Check status:  systemctl status ${BINARY_NAME}"
echo "  4. View logs:     journalctl -u ${BINARY_NAME} -f"
echo "  5. Read docs:     man ${BINARY_NAME}"
echo ""

if [ "$DRY_RUN" = true ]; then
  echo -e "${YELLOW}${BOLD}DRY RUN — no changes were made.${RESET}"
  echo ""
fi
