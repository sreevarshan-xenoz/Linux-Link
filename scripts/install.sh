#!/usr/bin/env bash
#
# Linux Link Installer
# Downloads and installs Linux Link from GitHub Releases.
#
# Usage: ./install.sh [VERSION] [OPTIONS]
#
# Arguments:
#   VERSION    Version tag (e.g., v0.1.0). Defaults to 'latest'.
#
# Options:
#   --yes, -y                  Non-interactive mode; accept all defaults
#   --dry-run                  Show what would be done without making changes
#   --verbose                  Show detailed debug output
#   --force                    Force reinstall even if current version matches
#   --no-service               Skip systemd service installation
#   --no-config                Skip config file creation
#   --no-docs                  Skip documentation installation
#   --no-man                   Skip man page installation
#   --prefix PATH              Install prefix (default: /usr)
#   --check-updates            Check if installed version is up to date
#   --list-versions            List all available releases
#   --status                   Show current installation status
#   --rollback                 Roll back to the previous version
#   --uninstall                Remove an existing installation
#   -h, --help                 Show this help message
#
# Examples:
#   ./install.sh                    # Install latest release
#   ./install.sh v0.1.0             # Install specific version
#   ./install.sh --yes              # Non-interactive install
#   ./install.sh --dry-run          # Preview installation
#   ./install.sh --prefix /opt      # Install to /opt
#   ./install.sh --check-updates    # Check for updates
#   ./install.sh --list-versions    # List available versions
#   ./install.sh --status           # Show installation info
#   ./install.sh --rollback         # Roll back to previous version
#   ./install.sh --uninstall        # Remove installation

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

REPO_OWNER="sreevarshan-xenoz"
REPO_NAME="Linux-Link"
BINARY_NAME="linux-link"
INSTALL_PREFIX="/usr"
SERVICE_FILE=""
CONFIG_DIR="$HOME/.config/${BINARY_NAME}"
CONFIG_FILE=""
STATE_FILE=""
BACKUP_DIR=""

# ─── Flags (set by argument parsing) ────────────────────────────────────────

DRY_RUN=false
VERBOSE=false
FORCE=false
NO_SERVICE=false
NO_CONFIG=false
NO_DOCS=false
NO_MAN=false
NON_INTERACTIVE=false
UNINSTALL=false
CHECK_UPDATES=false
LIST_VERSIONS=false
SHOW_STATUS=false
ROLLBACK=false
VERSION="latest"

# ─── Color output ────────────────────────────────────────────────────────────

if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  BLUE='\033[0;34m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  DIM='\033[2m'
  RESET='\033[0m'
else
  RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' RESET=''
fi

info()    { echo -e "${BLUE}[info]${RESET} $*"; }
ok()      { echo -e "${GREEN}[ok]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[warn]${RESET} $*"; }
error()   { echo -e "${RED}[error]${RESET} $*" >&2; }
debug()   { if [ "$VERBOSE" = true ]; then echo -e "${DIM}[debug]${RESET} $*"; fi; }
fatal()   { error "$@"; exit 1; }
section() { echo -e "\n${BOLD}═══ $* ═══${RESET}"; }

# ─── Resolve paths after prefix is known ────────────────────────────────────

resolve_paths() {
  SERVICE_FILE="/etc/systemd/system/${BINARY_NAME}.service"
  CONFIG_FILE="${CONFIG_DIR}/config.toml"
  STATE_FILE="${CONFIG_DIR}/.install-state"
  BACKUP_DIR="${CONFIG_DIR}/.backups"
}

# ─── Argument parsing ────────────────────────────────────────────────────────

parse_args() {
  for arg in "$@"; do
    case "$arg" in
      --yes|-y)               NON_INTERACTIVE=true ;;
      --dry-run)              DRY_RUN=true ;;
      --verbose)              VERBOSE=true ;;
      --force)                FORCE=true ;;
      --no-service)           NO_SERVICE=true ;;
      --no-config)            NO_CONFIG=true ;;
      --no-docs)              NO_DOCS=true ;;
      --no-man)               NO_MAN=true ;;
      --uninstall)            UNINSTALL=true ;;
      --check-updates)        CHECK_UPDATES=true ;;
      --list-versions)        LIST_VERSIONS=true ;;
      --status)               SHOW_STATUS=true ;;
      --rollback)             ROLLBACK=true ;;
      -h|--help)              show_help; exit 0 ;;
      --prefix)
        shift
        INSTALL_PREFIX="${1:?--prefix requires a path argument}"
        ;;
      --prefix=*)
        INSTALL_PREFIX="${arg#--prefix=}"
        ;;
      -v*)
        # Accept -v0.1.0 as version (but not --verbose which is handled above)
        VERSION="${arg#-v}"
        ;;
      v[0-9]*)
        VERSION="$arg"
        ;;
      [0-9]*)
        VERSION="v${arg}"
        ;;
      -*)
        fatal "Unknown option: ${arg}. Run '$0 --help' for usage."
        ;;
      *)
        VERSION="$arg"
        ;;
    esac
  done
}

show_help() {
  cat <<'EOF'
Linux Link Installer — Installation and management tool

USAGE
    install.sh [VERSION] [OPTIONS]

ARGUMENTS
    VERSION       Version tag (e.g., v0.1.0). Defaults to 'latest'.

OPTIONS
    -y, --yes             Non-interactive; accept all defaults
    --dry-run             Preview actions without making changes
    --verbose             Show detailed debug output
    --force               Force reinstall even if same version installed
    --no-service          Skip systemd service installation
    --no-config           Skip config file creation
    --no-docs             Skip documentation installation
    --no-man              Skip man page installation
    --prefix PATH         Install prefix (default: /usr)
    --check-updates       Check if installed version is up to date
    --list-versions       List all available releases
    --status              Show current installation status
    --rollback            Roll back to the previous version
    --uninstall           Remove an existing installation
    -h, --help            Show this help message

EXAMPLES
    install.sh                        Install latest release
    install.sh v0.1.0                 Install specific version
    install.sh --yes                  Non-interactive install
    install.sh --dry-run              Preview all actions
    install.sh --prefix /opt          Install to /opt instead of /usr
    install.sh --no-service           Skip systemd service setup
    install.sh --check-updates        Check for available updates
    install.sh --list-versions        Show all available versions
    install.sh --status               Show installed version and info
    install.sh --rollback             Revert to previous version
    install.sh --uninstall            Remove installation

ENVIRONMENT
    HTTP_PROXY, HTTPS_PROXY   Proxy settings passed to curl automatically
    NO_COLOR                  Disable colored output when set

EXIT CODES
    0    Success
    1    Fatal error (network, permissions, missing dependencies)
    2    Invalid arguments
    3    Version not found
    4    Checksum verification failed
    5    Rollback failed

For more information, see: https://github.com/sreevarshan-xenoz/Linux-Link
EOF
}

# ─── Cleanup on exit / interrupt ─────────────────────────────────────────────

TMPDIR=""
cleanup() {
  if [ -n "$TMPDIR" ] && [ -d "$TMPDIR" ]; then
    debug "Cleaning up temporary directory: ${TMPDIR}"
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT INT TERM

# ─── State management ────────────────────────────────────────────────────────

save_state() {
  local version="$1"
  local prev_version="$2"
  [ "$DRY_RUN" = true ] && return
  mkdir -p "$(dirname "$STATE_FILE")"
  cat > "$STATE_FILE" <<EOF
version=${version}
previous_version=${prev_version}
install_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
prefix=${INSTALL_PREFIX}
EOF
  debug "State saved to ${STATE_FILE}"
}

load_state() {
  if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    source "$STATE_FILE"
    debug "Loaded state: version=${version:-unknown} from ${STATE_FILE}"
    return 0
  fi
  return 1
}

get_previous_version() {
  if [ -f "$STATE_FILE" ]; then
    grep '^previous_version=' "$STATE_FILE" 2>/dev/null | cut -d= -f2 || true
  fi
}

# ─── Status command ──────────────────────────────────────────────────────────

cmd_status() {
  resolve_paths
  section "Installation Status"

  if [ -f "${INSTALL_PREFIX}/bin/${BINARY_NAME}" ]; then
    local bin_path="${INSTALL_PREFIX}/bin/${BINARY_NAME}"
    local ver
    ver=$("$bin_path" --version 2>/dev/null || echo "unknown")
    ok "Binary installed: ${bin_path} (${ver})"
  else
    error "Binary not installed."
  fi

  if [ -f "$SERVICE_FILE" ]; then
    ok "Service file: ${SERVICE_FILE}"
    if command -v systemctl &>/dev/null; then
      if systemctl is-active --quiet "$BINARY_NAME" 2>/dev/null; then
        ok "Service status: active"
      elif systemctl is-enabled --quiet "$BINARY_NAME" 2>/dev/null; then
        warn "Service status: enabled (not running)"
      else
        warn "Service status: disabled"
      fi
    fi
  else
    warn "Service file: not installed"
  fi

  if [ -f "$CONFIG_FILE" ]; then
    ok "Config: ${CONFIG_FILE}"
  else
    warn "Config: not found at ${CONFIG_FILE}"
  fi

  if [ -f "$STATE_FILE" ]; then
    ok "Install state: ${STATE_FILE}"
    if load_state; then
      echo "  Installed version:  ${version:-unknown}"
      echo "  Previous version:   ${previous_version:-none}"
      echo "  Install date:       ${install_date:-unknown}"
      echo "  Install prefix:     ${prefix:-unknown}"
    fi
  else
    warn "Install state: not tracked"
  fi

  # Check latest release
  echo ""
  info "Checking for updates..."
  local latest
  latest=$(fetch_latest_version 2>/dev/null) || latest="unknown"
  if [ "$latest" != "unknown" ] && [ -f "${INSTALL_PREFIX}/bin/${BINARY_NAME}" ]; then
    local current
    current=$("${INSTALL_PREFIX}/bin/${BINARY_NAME}" --version 2>/dev/null || echo "unknown")
    if [ "$current" = "$latest" ]; then
      ok "Latest version: ${latest} — you are up to date."
    else
      warn "Latest version: ${latest} — you have ${current}."
      warn "Run '$0 --yes' to upgrade."
    fi
  fi
}

# ─── List versions command ──────────────────────────────────────────────────

cmd_list_versions() {
  resolve_paths
  section "Available Releases"

  local releases
  releases=$(curl -fsSL --max-time 15 \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases?per_page=20" 2>/dev/null) || \
    fatal "Cannot reach GitHub API. Check your internet connection."

  # Parse tag_name and published_at
  echo -e "${BOLD}  Version${RESET}        ${BOLD}Published${RESET}"
  echo "  ───────────────────────────────"

  echo "$releases" | grep -E '"tag_name"|"published_at"' | \
    paste - - | \
    sed 's/.*"tag_name": *"\([^"]*\)".*"published_at": *"\([^"]*\)".*/  \1   \2/' | \
    while IFS= read -r line; do
      echo "$line"
    done

  echo ""
  info "For older versions, visit: https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
}

# ─── Check updates command ──────────────────────────────────────────────────

cmd_check_updates() {
  resolve_paths

  if [ ! -f "${INSTALL_PREFIX}/bin/${BINARY_NAME}" ]; then
    fatal "Linux Link is not installed. Run '$0' to install."
  fi

  local current
  current=$("${INSTALL_PREFIX}/bin/${BINARY_NAME}" --version 2>/dev/null || echo "unknown")
  info "Installed version: ${current}"

  local latest
  latest=$(fetch_latest_version) || fatal "Cannot check for updates."

  if [ "$current" = "$latest" ]; then
    ok "You are running the latest version (${current})."
  else
    warn "Update available: ${current} → ${latest}"
    echo ""
    echo "  To upgrade, run:  $0 --yes"
    echo "  To rollback:      $0 --rollback"
  fi
}

# ─── Rollback command ───────────────────────────────────────────────────────

cmd_rollback() {
  resolve_paths

  local prev_version
  prev_version=$(get_previous_version)

  if [ -z "$prev_version" ]; then
    fatal "No previous version to rollback to. State file may be missing."
  fi

  section "Rollback to ${prev_version}"
  warn "This will reinstall Linux Link ${prev_version}."
  echo ""

  if [ "$NON_INTERACTIVE" != true ]; then
    read -rp "Continue? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
      echo "Aborted."
      exit 0
    fi
  fi

  # Run full install with the previous version
  VERSION="$prev_version"
  FORCE=true
  info "Rolling back to ${prev_version}..."
  cmd_install
}

# ─── Helper: fetch latest version ────────────────────────────────────────────

fetch_latest_version() {
  local response
  response=$(curl -fsSL --max-time 15 \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" 2>/dev/null) || \
    return 1

  echo "$response" | grep -o '"tag_name": *"[^"]*"' | head -1 | \
    sed 's/"tag_name": *"//;s/"//'
}

# ─── Uninstall mode ──────────────────────────────────────────────────────────

cmd_uninstall() {
  resolve_paths
  section "Removing Linux Link"

  if [ "$DRY_RUN" = true ]; then
    info "DRY RUN — showing what would be removed."
  fi

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
  local doc_dir="${INSTALL_PREFIX}/share/doc/${BINARY_NAME}"
  if [ -d "$doc_dir" ]; then
    info "Removing documentation ${doc_dir}..."
    [ "$DRY_RUN" = true ] || sudo rm -rf "$doc_dir"
  fi

  # Remove man page
  local man_page="${INSTALL_PREFIX}/share/man/man1/${BINARY_NAME}.1"
  if [ -f "$man_page" ]; then
    info "Removing man page ${man_page}..."
    [ "$DRY_RUN" = true ] || sudo rm -f "$man_page"
    [ "$DRY_RUN" = true ] || mandb -q 2>/dev/null || true
  fi

  # Remove state file
  if [ -f "$STATE_FILE" ]; then
    [ "$DRY_RUN" = true ] || rm -f "$STATE_FILE"
  fi

  # Remove backups
  if [ -d "$BACKUP_DIR" ]; then
    warn "Backup directory found: ${BACKUP_DIR}"
    if [ "$NON_INTERACTIVE" = true ]; then
      info "Non-interactive mode — removing backups."
      [ "$DRY_RUN" = true ] || rm -rf "$BACKUP_DIR"
    else
      read -rp "Remove backup configs (${BACKUP_DIR})? [y/N] " confirm
      if [[ "$confirm" =~ ^[Yy]$ ]]; then
        [ "$DRY_RUN" = true ] || rm -rf "$BACKUP_DIR"
      fi
    fi
  fi

  # Keep user config, just warn
  if [ -d "$CONFIG_DIR" ]; then
    warn "User config kept at ${CONFIG_DIR} (not removed)."
    warn "Remove manually with: rm -rf ${CONFIG_DIR}"
  fi

  echo ""
  ok "Uninstallation complete."
  if [ "$DRY_RUN" = true ]; then
    echo ""
    warn "DRY RUN — no changes were made."
  fi
}

# ─── Pre-flight checks ──────────────────────────────────────────────────────

preflight() {
  section "Pre-flight Checks"

  # Check required commands
  debug "Checking required commands..."
  for cmd in curl tar sudo; do
    if ! command -v "$cmd" &>/dev/null; then
      fatal "Required command not found: ${cmd}. Install it and try again."
    fi
    debug "  ${cmd}: found"
  done

  # Detect distribution for distro-specific tips
  local distro="unknown"
  if [ -f /etc/os-release ]; then
    distro=$(. /etc/os-release && echo "${ID:-unknown}")
  fi
  debug "  Distribution: ${distro}"

  # Check architecture
  local arch
  arch=$(uname -m)
  debug "  Architecture: ${arch}"
  if [ "$arch" != "x86_64" ]; then
    warn "Architecture detected: ${arch}"
    warn "Only x86_64 pre-built binaries are available."
    warn "You may need to build from source on this architecture."
    if [ "$NON_INTERACTIVE" = true ]; then
      fatal "Non-interactive mode: cannot prompt for architecture confirmation."
    fi
    read -rp "Continue anyway? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
      echo "Aborted."
      exit 0
    fi
  fi

  # Check sudo access
  debug "Checking sudo access..."
  if ! sudo -n true 2>/dev/null; then
    info "Verifying sudo access (will prompt for password if needed)..."
    if ! sudo -v; then
      fatal "Cannot obtain sudo access. This installer needs root privileges."
    fi
  fi
  debug "  sudo: OK"

  # Check disk space (need ~100 MB for download + install)
  if command -v df &>/dev/null; then
    local available_kb
    available_kb=$(df -k "$INSTALL_PREFIX" 2>/dev/null | awk 'NR==2 {print $4}')
    debug "  Free space on ${INSTALL_PREFIX}: ${available_kb} KB"
    if [ -n "$available_kb" ] && [ "$available_kb" -lt 102400 ]; then
      fatal "Less than 100 MB free on ${INSTALL_PREFIX} (${available_kb} KB). Free up space and try again."
    fi
  fi

  # Check for existing installation
  if [ -f "${INSTALL_PREFIX}/bin/${BINARY_NAME}" ]; then
    CURRENT_VERSION=$("${INSTALL_PREFIX}/bin/${BINARY_NAME}" --version 2>/dev/null || echo "unknown")
    warn "Existing installation: ${BINARY_NAME} ${CURRENT_VERSION}"
    UPGRADE=true
  fi

  ok "Pre-flight checks passed."
}

# ─── Determine version ───────────────────────────────────────────────────────

resolve_version() {
  if [ "$VERSION" = "latest" ]; then
    info "Fetching latest release from GitHub..."
    VERSION=$(fetch_latest_version) || {
      warn "GitHub API not reachable, trying HTML fallback..."
      local html
      html=$(curl -fsSL --max-time 15 "https://github.com/${REPO_OWNER}/${REPO_NAME}/releases" 2>/dev/null) || \
        fatal "Cannot reach GitHub. Check your internet connection and DNS."
      VERSION=$(echo "$html" | grep -o '/releases/tag/[^"]*' | head -1 | sed 's|/releases/tag/||') || \
        fatal "Cannot determine latest version from GitHub."
    }

    if [ -z "$VERSION" ]; then
      fatal "Could not determine the latest version. The repository may have no releases yet."
    fi

    ok "Latest version: ${VERSION}"
  else
    # Normalize version: ensure it starts with 'v'
    if [[ ! "$VERSION" =~ ^v[0-9] ]]; then
      VERSION="v${VERSION}"
    fi
    info "Using version: ${VERSION}"
  fi
}

# ─── Install command ────────────────────────────────────────────────────────

cmd_install() {
  resolve_paths
  local prev_version=""

  # Check if already at target version
  if [ "$UPGRADE" = true ] && [ "$FORCE" != true ] && [ "${CURRENT_VERSION:-unknown}" = "$VERSION" ]; then
    ok "${BINARY_NAME} ${VERSION} is already installed. Use --force to reinstall."
    return 0
  fi

  # Save previous version for rollback support
  if [ "$UPGRADE" = true ]; then
    prev_version="${CURRENT_VERSION}"
  elif load_state 2>/dev/null; then
    prev_version="${version:-}"
  fi

  section "Downloading"

  # Build download URL
  local archive_name="${BINARY_NAME}-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"
  local url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${VERSION}/${archive_name}"

  TMPDIR=$(mktemp -d)
  debug "Temp directory: ${TMPDIR}"

  info "Downloading ${BINARY_NAME} ${VERSION}..."
  debug "URL: ${url}"

  # Respect proxy settings
  local curl_opts=(-fsSL --max-time 120 --retry 3 --retry-delay 5 -w '%{http_code}')

  # Add proxy if set
  if [ -n "${HTTPS_PROXY:-}" ]; then
    curl_opts+=(--proxy "$HTTPS_PROXY")
  elif [ -n "${HTTP_PROXY:-}" ]; then
    curl_opts+=(--proxy "$HTTP_PROXY")
  fi

  local http_code
  http_code=$(curl "${curl_opts[@]}" -o "${TMPDIR}/${archive_name}" "$url" 2>/dev/null) || {
    if curl -fsS --max-time 5 -o /dev/null "https://github.com" 2>/dev/null; then
      fatal "Failed to download release. Check available releases at https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
    else
      fatal "Network unavailable. Check your internet connection."
    fi
  }

  if [ "$http_code" = "404" ]; then
    fatal "Release ${VERSION} not found (HTTP 404). Check https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
  elif [ "$http_code" != "200" ]; then
    fatal "Download failed with HTTP ${http_code}."
  fi

  # Verify archive size
  local archive_size
  archive_size=$(stat -c%s "${TMPDIR}/${archive_name}" 2>/dev/null || stat -f%z "${TMPDIR}/${archive_name}" 2>/dev/null || echo "0")
  if [ "$archive_size" -lt 100 ]; then
    fatal "Downloaded file is too small (${archive_size} bytes). Release may be corrupted."
  fi
  debug "Archive size: ${archive_size} bytes"

  # Checksum verification
  local checksum_url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${VERSION}/${BINARY_NAME}-${VERSION}-checksums.txt"
  local checksum_file="${TMPDIR}/checksums.txt"
  if curl -fsSL --max-time 15 -o "$checksum_file" "$checksum_url" 2>/dev/null; then
    local expected
    expected=$(grep "$archive_name" "$checksum_file" 2>/dev/null | awk '{print $1}' || true)
    if [ -n "$expected" ]; then
      local actual=""
      if command -v sha256sum &>/dev/null; then
        actual=$(sha256sum "${TMPDIR}/${archive_name}" | awk '{print $1}')
      elif command -v shasum &>/dev/null; then
        actual=$(shasum -a 256 "${TMPDIR}/${archive_name}" | awk '{print $1}')
      else
        warn "No sha256sum or shasum found — skipping checksum verification."
      fi
      if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then
        fatal "Checksum mismatch! Expected: ${expected}, Got: ${actual}. File may be corrupted or tampered."
      else
        ok "Checksum verified."
      fi
    fi
  else
    debug "No checksums file found — skipping verification."
  fi

  # Extract
  section "Extracting"
  info "Extracting archive..."
  if ! tar xzf "${TMPDIR}/${archive_name}" -C "$TMPDIR" 2>/dev/null; then
    fatal "Failed to extract archive. File may be corrupted."
  fi

  # Find extracted directory
  local extracted_dir="${TMPDIR}/${BINARY_NAME}"
  if [ ! -d "$extracted_dir" ]; then
    extracted_dir=$(find "$TMPDIR" -maxdepth 1 -type d -not -name "$(basename "$TMPDIR")" | head -1)
    if [ -z "$extracted_dir" ]; then
      fatal "Archive extracted but expected directory structure not found."
    fi
  fi
  debug "Extracted to: ${extracted_dir}"

  # Verify binary
  if [ ! -f "${extracted_dir}/${BINARY_NAME}" ]; then
    fatal "Binary '${BINARY_NAME}' not found in release archive."
  fi
  if ! file "${extracted_dir}/${BINARY_NAME}" | grep -q "ELF"; then
    fatal "Binary is not a valid ELF executable. Release may be for wrong architecture."
  fi
  ok "Archive verified."

  # Install
  section "Installing"

  # Stop service before upgrade
  if [ "$UPGRADE" = true ] && systemctl is-active --quiet "$BINARY_NAME" 2>/dev/null; then
    info "Stopping service for upgrade..."
    [ "$DRY_RUN" = true ] || sudo systemctl stop "$BINARY_NAME"
  fi

  # Backup config before upgrade
  if [ "$UPGRADE" = true ] && [ -f "$CONFIG_FILE" ]; then
    [ "$DRY_RUN" = true ] || mkdir -p "$BACKUP_DIR"
    local backup_file="${BACKUP_DIR}/config.toml.bak.$(date +%Y%m%d%H%M%S)"
    info "Backing up config to ${backup_file}..."
    [ "$DRY_RUN" = true ] || cp "$CONFIG_FILE" "$backup_file"

    # Keep only last 5 backups
    if [ -d "$BACKUP_DIR" ] && [ "$DRY_RUN" != true ]; then
      local backup_count
      backup_count=$(ls -1 "$BACKUP_DIR"/config.toml.bak.* 2>/dev/null | wc -l)
      if [ "$backup_count" -gt 5 ]; then
        ls -1t "$BACKUP_DIR"/config.toml.bak.* | tail -n +6 | xargs rm -f
        debug "Cleaned up old backups (kept 5 most recent)."
      fi
    fi
  fi

  # Install binary
  info "Installing binary to ${INSTALL_PREFIX}/bin/${BINARY_NAME}..."
  [ "$DRY_RUN" = true ] || sudo install -Dm755 "${extracted_dir}/${BINARY_NAME}" "${INSTALL_PREFIX}/bin/${BINARY_NAME}"

  # Install service
  if [ "$NO_SERVICE" = true ]; then
    info "Skipping service installation (--no-service)."
  elif [ -f "${extracted_dir}/${BINARY_NAME}.service" ]; then
    info "Installing systemd service..."
    [ "$DRY_RUN" = true ] || sudo install -Dm644 "${extracted_dir}/${BINARY_NAME}.service" "$SERVICE_FILE"
    [ "$DRY_RUN" = true ] || sudo systemctl daemon-reload
  else
    warn "Service file not found in release archive."
  fi

  # Install docs
  if [ "$NO_DOCS" = true ]; then
    info "Skipping documentation installation (--no-docs)."
  else
    local doc_dir="${INSTALL_PREFIX}/share/doc/${BINARY_NAME}"
    for doc in README.md CHANGELOG.md config.toml.example; do
      if [ -f "${extracted_dir}/${doc}" ]; then
        [ "$DRY_RUN" = true ] || sudo install -Dm644 "${extracted_dir}/${doc}" "${doc_dir}/${doc}"
      fi
    done
  fi

  # Install man page
  if [ "$NO_MAN" = true ]; then
    info "Skipping man page installation (--no-man)."
  elif [ -f "${extracted_dir}/man/${BINARY_NAME}.1" ]; then
    info "Installing man page..."
    [ "$DRY_RUN" = true ] || sudo install -Dm644 "${extracted_dir}/man/${BINARY_NAME}.1" \
      "${INSTALL_PREFIX}/share/man/man1/${BINARY_NAME}.1"
    [ "$DRY_RUN" = true ] || mandb -q 2>/dev/null || true
  fi

  # Setup config directory
  if [ "$NO_CONFIG" = true ]; then
    info "Skipping config setup (--no-config)."
  else
    if [ ! -d "$CONFIG_DIR" ]; then
      info "Creating config directory ${CONFIG_DIR}..."
      [ "$DRY_RUN" = true ] || mkdir -p "$CONFIG_DIR"
    fi

    if [ ! -f "$CONFIG_FILE" ] && [ -f "${extracted_dir}/config.toml.example" ]; then
      info "Installing default config to ${CONFIG_FILE}..."
      [ "$DRY_RUN" = true ] || cp "${extracted_dir}/config.toml.example" "$CONFIG_FILE"
    fi
  fi

  # Save install state
  if [ "$DRY_RUN" != true ]; then
    save_state "$VERSION" "$prev_version"
  fi

  # Post-install: enable and start service
  section "Post-install"
  if command -v systemctl &>/dev/null && [ "$NO_SERVICE" != true ]; then
    if [ "$UPGRADE" = true ]; then
      info "Restarting ${BINARY_NAME} service..."
      [ "$DRY_RUN" = true ] || sudo systemctl restart "$BINARY_NAME"
    elif [ "$NON_INTERACTIVE" = true ]; then
      info "Non-interactive mode — enabling service..."
      [ "$DRY_RUN" = true ] || sudo systemctl enable "$BINARY_NAME"
      [ "$DRY_RUN" = true ] || sudo systemctl start "$BINARY_NAME"
    else
      echo ""
      echo -n "Enable and start ${BINARY_NAME} service? [Y/n] "
      read -r -t 10 enable_service || true
      if [[ ! "$enable_service" =~ ^[Nn]$ ]]; then
        info "Enabling and starting ${BINARY_NAME} service..."
        [ "$DRY_RUN" = true ] || sudo systemctl enable "$BINARY_NAME"
        [ "$DRY_RUN" = true ] || sudo systemctl start "$BINARY_NAME"
      else
        info "Service not started. Run 'sudo systemctl enable --now ${BINARY_NAME}' manually."
      fi
    fi

    # Verify service health
    if [ "$DRY_RUN" != true ] && systemctl is-active --quiet "$BINARY_NAME" 2>/dev/null; then
      ok "Service is running."
    fi
  elif [ "$NO_SERVICE" != true ]; then
    warn "systemctl not found — service will not be managed automatically."
    warn "Start manually with: ${BINARY_NAME} start"
  fi

  # Post-install health check
  section "Health Check"
  local installed_ver
  installed_ver=$("${INSTALL_PREFIX}/bin/${BINARY_NAME}" --version 2>/dev/null || echo "failed")
  if [ "$installed_ver" != "failed" ]; then
    ok "Binary responds: ${installed_ver}"
  else
    warn "Binary did not respond to --version."
  fi

  # Summary
  section "Summary"
  echo ""
  echo -e "${GREEN}${BOLD}Installation complete!${RESET}"
  echo ""
  echo "  Binary:   ${INSTALL_PREFIX}/bin/${BINARY_NAME} (${installed_ver})"
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
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
  parse_args "$@"
  resolve_paths

  # Handle standalone commands (don't need install flow)
  if [ "$LIST_VERSIONS" = true ]; then
    cmd_list_versions
    exit 0
  fi

  if [ "$SHOW_STATUS" = true ]; then
    cmd_status
    exit 0
  fi

  if [ "$CHECK_UPDATES" = true ]; then
    cmd_check_updates
    exit 0
  fi

  if [ "$UNINSTALL" = true ]; then
    cmd_uninstall
    exit 0
  fi

  if [ "$ROLLBACK" = true ]; then
    cmd_rollback
    exit 0
  fi

  # Full install flow
  preflight
  resolve_version
  cmd_install
}

main "$@"
