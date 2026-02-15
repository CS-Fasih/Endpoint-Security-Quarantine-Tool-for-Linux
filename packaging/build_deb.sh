#!/bin/bash
# ============================================================================
#  build_deb.sh — Debian Package Builder for Sentinel Endpoint Security
# ============================================================================
#
#  This script automates the creation of a .deb installer that bundles:
#    • The compiled C daemon binary          → /usr/local/bin/sentinel-daemon
#    • The systemd service unit              → /etc/systemd/system/sentinel.service
#    • The packaged Electron GUI             → /opt/sentinel-gui/
#    • A .desktop launcher entry             → /usr/share/applications/sentinel.desktop
#
#  PREREQUISITES (must be installed before running this script):
#    • build-essential, libjson-c-dev        — to compile the C daemon
#    • nodejs (v18+), npm                    — to install Electron dependencies
#    • electron-packager                     — to bundle the Electron app
#    • dpkg-deb                              — to assemble the .deb (pre-installed on Ubuntu)
#
#  USAGE:
#    chmod +x build_deb.sh
#    ./build_deb.sh
#
#  OUTPUT:
#    ./sentinel-endpoint-security_1.0.0_amd64.deb
#
#  INSTALLATION:
#    sudo dpkg -i sentinel-endpoint-security_1.0.0_amd64.deb
#    sudo apt-get install -f   # Resolve any missing dependencies
#
# ============================================================================

set -e   # Exit immediately on any error — no partial/broken packages.

# ── Package metadata ────────────────────────────────────────────────────────
PKG_NAME="sentinel-endpoint-security"
PKG_VERSION="1.1.0"
PKG_ARCH="amd64"

# ── Directory layout ────────────────────────────────────────────────────────
# PROJECT_ROOT is the top-level repo directory (parent of this script).
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DAEMON_DIR="${PROJECT_ROOT}/daemon"
GUI_DIR="${PROJECT_ROOT}/gui"
PACKAGING_DIR="${PROJECT_ROOT}/packaging"

# STAGING_DIR is the fake-root that mirrors the target filesystem hierarchy.
# dpkg-deb reads this directory to assemble the .deb archive.
STAGING_DIR="${PACKAGING_DIR}/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}"

# Output .deb file
DEB_OUTPUT="${PACKAGING_DIR}/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║       Sentinel Endpoint Security — Debian Package Builder       ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Project root:  ${PROJECT_ROOT}"
echo "  Staging dir:   ${STAGING_DIR}"
echo "  Output:        ${DEB_OUTPUT}"
echo ""

# ── Step 0: Clean previous build artifacts ──────────────────────────────────
echo "━━━ [0/5] Cleaning previous build artifacts ━━━"

if [ -d "${STAGING_DIR}" ]; then
    echo "  Removing old staging directory ..."
    rm -rf "${STAGING_DIR}"
fi

if [ -f "${DEB_OUTPUT}" ]; then
    echo "  Removing old .deb package ..."
    rm -f "${DEB_OUTPUT}"
fi

echo "  ✓ Clean."
echo ""

# ── Step 1: Compile the C daemon ────────────────────────────────────────────
echo "━━━ [1/5] Compiling the C daemon ━━━"

echo "  Running 'make clean && make' in ${DAEMON_DIR} ..."
(cd "${DAEMON_DIR}" && make clean && make)

# Verify the binary was produced.
if [ ! -f "${DAEMON_DIR}/sentinel-daemon" ]; then
    echo "  ✗ ERROR: Daemon binary not found at ${DAEMON_DIR}/sentinel-daemon"
    echo "    Make sure 'make' completes successfully."
    exit 1
fi

echo "  ✓ Daemon compiled: $(file "${DAEMON_DIR}/sentinel-daemon" | cut -d: -f2)"
echo ""

# ── Step 2: Package the Electron GUI with electron-packager ─────────────────
echo "━━━ [2/5] Packaging the Electron GUI ━━━"

# Install npm dependencies (including devDependencies for electron-packager).
echo "  Installing npm dependencies ..."
(cd "${GUI_DIR}" && npm install)

# Install electron-packager as a local dev dependency if not already present.
if ! (cd "${GUI_DIR}" && npx --no-install electron-packager --version) &> /dev/null; then
    echo "  Installing electron-packager as local devDependency ..."
    (cd "${GUI_DIR}" && npm install --save-dev electron-packager)
fi

# Output the packaged Electron app to a build/ directory OUTSIDE of gui/
# to avoid electron-packager scanning its own output.
BUILD_OUTPUT_DIR="${PACKAGING_DIR}/build"
ELECTRON_OUTPUT_DIR="${BUILD_OUTPUT_DIR}/sentinel-gui-linux-x64"

if [ -d "${BUILD_OUTPUT_DIR}" ]; then
    echo "  Removing previous build output ..."
    rm -rf "${BUILD_OUTPUT_DIR}"
fi
mkdir -p "${BUILD_OUTPUT_DIR}"

echo "  Running electron-packager ..."
echo "  (This may take a minute — it bundles the entire Electron runtime)"
(cd "${GUI_DIR}" && npx electron-packager . sentinel-gui \
    --platform=linux \
    --arch=x64 \
    --out="${BUILD_OUTPUT_DIR}" \
    --overwrite)

# Verify the packaged GUI output exists.
if [ ! -d "${ELECTRON_OUTPUT_DIR}" ]; then
    echo "  ✗ ERROR: Electron packager output not found at ${ELECTRON_OUTPUT_DIR}"
    echo "    Check the electron-packager logs above for errors."
    exit 1
fi

echo "  ✓ Electron GUI packaged: ${ELECTRON_OUTPUT_DIR}"
echo ""

# ── Step 3: Assemble the staging directory (fake-root) ──────────────────────
echo "━━━ [3/5] Assembling staging directory (fake-root) ━━━"

# Create the fake-root directory tree that mirrors the target filesystem.
# Each path here corresponds to where the file will be installed on the system.
echo "  Creating directory structure ..."
mkdir -p "${STAGING_DIR}/DEBIAN"
mkdir -p "${STAGING_DIR}/usr/local/bin"
mkdir -p "${STAGING_DIR}/etc/systemd/system"
mkdir -p "${STAGING_DIR}/opt/sentinel-gui"
mkdir -p "${STAGING_DIR}/usr/share/applications"

# ── 3a: DEBIAN control files ───────────────────────────────────────────────
# These are the package metadata files that dpkg reads during installation.
echo "  Copying DEBIAN control files ..."
cp "${PACKAGING_DIR}/DEBIAN/control"  "${STAGING_DIR}/DEBIAN/control"
cp "${PACKAGING_DIR}/DEBIAN/postinst" "${STAGING_DIR}/DEBIAN/postinst"
cp "${PACKAGING_DIR}/DEBIAN/prerm"    "${STAGING_DIR}/DEBIAN/prerm"

# Maintainer scripts MUST be executable, or dpkg will reject the package.
chmod 0755 "${STAGING_DIR}/DEBIAN/postinst"
chmod 0755 "${STAGING_DIR}/DEBIAN/prerm"

# ── 3b: Daemon binary → /usr/local/bin/sentinel-daemon ─────────────────────
# This is the compiled C binary that inotify-monitors the filesystem,
# scans with ClamAV, quarantines threats, and serves the IPC socket.
echo "  Installing daemon binary → /usr/local/bin/sentinel-daemon"
cp "${DAEMON_DIR}/sentinel-daemon" "${STAGING_DIR}/usr/local/bin/sentinel-daemon"
chmod 0755 "${STAGING_DIR}/usr/local/bin/sentinel-daemon"

# ── 3c: Systemd service → /etc/systemd/system/sentinel.service ─────────────
# The unit file that manages the daemon lifecycle (start/stop/restart).
echo "  Installing systemd service → /etc/systemd/system/sentinel.service"
cp "${DAEMON_DIR}/sentinel.service" "${STAGING_DIR}/etc/systemd/system/sentinel.service"
chmod 0644 "${STAGING_DIR}/etc/systemd/system/sentinel.service"

# ── 3d: Electron GUI → /opt/sentinel-gui/ ──────────────────────────────────
# The full Electron app directory (runtime + app code + resources).
# We copy the entire electron-packager output into /opt/sentinel-gui/.
echo "  Installing Electron GUI → /opt/sentinel-gui/"
cp -r "${ELECTRON_OUTPUT_DIR}/"* "${STAGING_DIR}/opt/sentinel-gui/"

# Ensure the main binary is executable.
if [ -f "${STAGING_DIR}/opt/sentinel-gui/sentinel-gui" ]; then
    chmod 0755 "${STAGING_DIR}/opt/sentinel-gui/sentinel-gui"
fi

# CRITICAL: Electron's Chromium sandbox helper requires SUID (mode 4755).
# Without this, the GUI silently crashes on launch because the setuid sandbox
# refuses to start. The postinst also sets this for safety, but we set it
# here so it's baked into the .deb archive itself.
if [ -f "${STAGING_DIR}/opt/sentinel-gui/chrome-sandbox" ]; then
    chmod 4755 "${STAGING_DIR}/opt/sentinel-gui/chrome-sandbox"
    echo "  Set SUID on chrome-sandbox (mode 4755)"
fi

# ── 3e: Desktop entry → /usr/share/applications/ ───────────────────────────
# Makes the GUI appear in the Ubuntu application menu (GNOME, KDE, etc.).
echo "  Installing desktop entry → /usr/share/applications/sentinel.desktop"
cp "${PACKAGING_DIR}/sentinel.desktop" \
   "${STAGING_DIR}/usr/share/applications/sentinel.desktop"
chmod 0644 "${STAGING_DIR}/usr/share/applications/sentinel.desktop"

echo "  ✓ Staging directory assembled."
echo ""

# ── Step 4: Compute installed size ──────────────────────────────────────────
echo "━━━ [4/5] Computing installed size ━━━"

# dpkg uses the Installed-Size field (in KiB) to show the disk space required.
# We calculate it from the staging directory, excluding the DEBIAN metadata.
INSTALLED_SIZE=$(du -sk "${STAGING_DIR}" --exclude=DEBIAN | cut -f1)
echo "  Installed size: ${INSTALLED_SIZE} KiB"

# Append the Installed-Size field to the control file.
# (We do this dynamically so it's always accurate, not hardcoded.)
echo "Installed-Size: ${INSTALLED_SIZE}" >> "${STAGING_DIR}/DEBIAN/control"

echo "  ✓ Control file updated."
echo ""

# ── Step 5: Build the .deb package ──────────────────────────────────────────
echo "━━━ [5/5] Building .deb package ━━━"

# dpkg-deb assembles the staging directory into a binary .deb archive.
# --root-owner-group ensures all files in the .deb are owned by root,
# regardless of who ran the build script.
dpkg-deb --root-owner-group --build "${STAGING_DIR}" "${DEB_OUTPUT}"

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  ✓ Package built successfully!                                  ║"
echo "║                                                                 ║"
echo "║  Output: ${DEB_OUTPUT}"
echo "║                                                                 ║"
echo "║  To install:                                                    ║"
echo "║    sudo dpkg -i ${DEB_OUTPUT}"
echo "║    sudo apt-get install -f                                      ║"
echo "║                                                                 ║"
echo "║  To remove:                                                     ║"
echo "║    sudo dpkg -r sentinel-endpoint-security                      ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
