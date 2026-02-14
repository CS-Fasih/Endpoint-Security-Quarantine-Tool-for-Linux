#!/usr/bin/env bash
# ============================================================================
# install_deps.sh — Dependency installer for Sentinel Endpoint Security Tool
# Targets: Ubuntu 20.04+ / Debian-based systems
# Must be run as root (sudo).
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

QUARANTINE_DIR="/opt/quarantine"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[  OK]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[FAIL]${NC}  $*"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "This script must be run as root.  Use: sudo bash $0"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------------
install_system_packages() {
    log_info "Updating package lists..."
    apt-get update -qq

    log_info "Installing build tools and libraries..."
    apt-get install -y -qq \
        build-essential \
        pkg-config \
        libwebsockets-dev \
        libjson-c-dev \
        clamav \
        clamav-daemon \
        curl \
        > /dev/null 2>&1
    log_ok "System packages installed."
}

# ---------------------------------------------------------------------------
# 2. Node.js (via NodeSource if not already present)
# ---------------------------------------------------------------------------
install_nodejs() {
    if command -v node &> /dev/null; then
        local ver
        ver=$(node --version)
        log_ok "Node.js already installed: ${ver}"
    else
        log_info "Installing Node.js 20.x LTS via NodeSource..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash - > /dev/null 2>&1
        apt-get install -y -qq nodejs > /dev/null 2>&1
        log_ok "Node.js $(node --version) installed."
    fi
}

# ---------------------------------------------------------------------------
# 3. ClamAV daemon setup
# ---------------------------------------------------------------------------
configure_clamav() {
    log_info "Stopping clamav-freshclam for initial DB update..."
    systemctl stop clamav-freshclam 2>/dev/null || true

    log_info "Downloading initial ClamAV virus definitions (this may take a minute)..."
    if freshclam --quiet 2>/dev/null; then
        log_ok "Virus definitions updated."
    else
        log_warn "freshclam returned non-zero — definitions may already be up to date."
    fi

    log_info "Enabling and starting ClamAV services..."
    systemctl enable clamav-freshclam --quiet
    systemctl start  clamav-freshclam

    systemctl enable clamav-daemon --quiet
    systemctl start  clamav-daemon

    # Wait for clamd socket to appear (up to 30 s)
    log_info "Waiting for clamd socket to become available..."
    local retries=30
    while [[ ! -S /var/run/clamav/clamd.ctl ]] && (( retries-- > 0 )); do
        sleep 1
    done

    if [[ -S /var/run/clamav/clamd.ctl ]]; then
        log_ok "clamd is running and socket is ready."
    else
        log_warn "clamd socket not found after 30 s — the daemon may still be loading."
    fi
}

# ---------------------------------------------------------------------------
# 4. Quarantine directory
# ---------------------------------------------------------------------------
create_quarantine_dir() {
    if [[ -d "$QUARANTINE_DIR" ]]; then
        log_ok "Quarantine directory already exists: ${QUARANTINE_DIR}"
    else
        mkdir -p "$QUARANTINE_DIR"
        log_ok "Created quarantine directory: ${QUARANTINE_DIR}"
    fi
    chown root:root "$QUARANTINE_DIR"
    chmod 700 "$QUARANTINE_DIR"
    log_ok "Quarantine permissions set to 700 (root only)."
}

# ---------------------------------------------------------------------------
# 5. GUI npm dependencies
# ---------------------------------------------------------------------------
install_gui_deps() {
    local gui_dir
    gui_dir="$(cd "$(dirname "$0")/../gui" && pwd)"

    if [[ -f "${gui_dir}/package.json" ]]; then
        log_info "Installing Electron GUI npm dependencies..."
        (cd "$gui_dir" && npm install --no-audit --no-fund --loglevel=error)
        log_ok "GUI dependencies installed."
    else
        log_warn "gui/package.json not found — skipping npm install."
    fi
}

# ---------------------------------------------------------------------------
# 6. Build the daemon
# ---------------------------------------------------------------------------
build_daemon() {
    local daemon_dir
    daemon_dir="$(cd "$(dirname "$0")/../daemon" && pwd)"

    if [[ -f "${daemon_dir}/Makefile" ]]; then
        log_info "Building sentinel daemon..."
        (cd "$daemon_dir" && make clean && make)
        log_ok "Daemon built successfully."
    else
        log_warn "daemon/Makefile not found — skipping build."
    fi
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   Sentinel — Endpoint Security Tool  ·  Installer      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    check_root
    install_system_packages
    install_nodejs
    configure_clamav
    create_quarantine_dir
    install_gui_deps
    build_daemon

    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Installation complete!${NC}"
    echo -e "${GREEN}  Next steps:${NC}"
    echo -e "${GREEN}    1. sudo make install     (in daemon/)${NC}"
    echo -e "${GREEN}    2. sudo systemctl start sentinel${NC}"
    echo -e "${GREEN}    3. cd gui && npm start${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
}

main "$@"
