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

    # ── Memory-optimisation for low-end hardware ──────────────────────
    # ConcurrentDatabaseReload: When set to "yes" (default), clamd loads
    #   the new signature database into RAM while the old one is still in
    #   memory, effectively doubling RAM usage during reloads.  On machines
    #   with ≤ 8 GB RAM this can trigger OOM-kills.  Setting it to "no"
    #   forces a serial reload that frees the old DB before loading the new.
    #
    # MaxThreads: Limit the number of concurrent scan threads to reduce
    #   peak memory usage on constrained hardware.
    # ──────────────────────────────────────────────────────────────────
    local clamd_conf="/etc/clamav/clamd.conf"
    if [[ -f "$clamd_conf" ]]; then
        log_info "Applying low-memory ClamAV optimisations to ${clamd_conf} ..."

        # ConcurrentDatabaseReload
        if grep -q "^ConcurrentDatabaseReload" "$clamd_conf"; then
            sed -i 's/^ConcurrentDatabaseReload.*/ConcurrentDatabaseReload no/' "$clamd_conf"
        else
            echo "ConcurrentDatabaseReload no" >> "$clamd_conf"
        fi

        # MaxThreads — keep it modest on low-end CPUs
        if grep -q "^MaxThreads" "$clamd_conf"; then
            sed -i 's/^MaxThreads.*/MaxThreads 2/' "$clamd_conf"
        else
            echo "MaxThreads 2" >> "$clamd_conf"
        fi

        log_ok "ClamAV memory optimisations applied (ConcurrentDatabaseReload=no, MaxThreads=2)."
    else
        log_warn "${clamd_conf} not found — skipping memory optimisations."
    fi

    log_info "Enabling and starting ClamAV services..."
    systemctl enable clamav-freshclam --quiet
    systemctl start  clamav-freshclam

    systemctl enable clamav-daemon --quiet
    systemctl start  clamav-daemon

    # Wait for clamd socket to appear (up to 150 s)
    # On older hardware (i5 4th gen, 8 GB RAM) signature loading can take
    # well over 30 seconds — we give it a generous 2.5-minute window.
    log_info "Waiting for clamd socket to become available (timeout: 150 s)..."
    local retries=150
    while [[ ! -S /var/run/clamav/clamd.ctl ]] && (( retries-- > 0 )); do
        sleep 1
    done

    if [[ -S /var/run/clamav/clamd.ctl ]]; then
        log_ok "clamd is running and socket is ready."
    else
        log_warn "clamd socket not found after 150 s — the daemon may still be loading."
        log_warn "The Sentinel daemon will retry scanner connections automatically."
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
