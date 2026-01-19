#!/bin/bash
# ===========================================================================
# Jarwis Agent - Docker Linux Build Script
# ===========================================================================
# This script runs inside Docker to build Linux packages on any platform
# ===========================================================================

set -e

echo ""
echo "============================================================"
echo "  Jarwis Agent - Linux Build (Docker)"
echo "============================================================"
echo ""

APP_NAME="jarwis-agent"
VERSION="1.0.0"
ARCH="amd64"
BUILD_DIR="/app/dist/linux"
INSTALLER_DIR="/app/installer"

# Create build directory
mkdir -p "$BUILD_DIR"
mkdir -p /dist/linux/x64

echo "[1/5] Building executable with PyInstaller..."
cd /app

# Create a minimal spec file for the agent
cat > /tmp/jarwis-agent.spec << 'EOF'
# -*- mode: python ; coding: utf-8 -*-
import sys
import os

block_cipher = None

# Get the project root
PROJECT_ROOT = '/app'

a = Analysis(
    [os.path.join(PROJECT_ROOT, 'jarwis_agent.py')],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=[
        (os.path.join(PROJECT_ROOT, 'config', 'config.yaml'), 'config'),
    ],
    hiddenimports=[
        'websockets',
        'aiohttp',
        'yaml',
        'cryptography',
        'ssl',
        'certifi',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'PIL',
        'numpy',
        'pandas',
        'scipy',
        'PyQt5',
        'PyQt6',
        'PySide2',
        'PySide6',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='jarwis-agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
EOF

python3 -m PyInstaller /tmp/jarwis-agent.spec \
    --distpath "$BUILD_DIR" \
    --workpath "$BUILD_DIR/build" \
    --clean \
    --noconfirm

echo "[2/5] Creating package structure..."

# Create package root
PKG_ROOT="$BUILD_DIR/pkg-root"
rm -rf "$PKG_ROOT"
mkdir -p "$PKG_ROOT/usr/bin"
mkdir -p "$PKG_ROOT/etc/jarwis"
mkdir -p "$PKG_ROOT/var/log/jarwis"
mkdir -p "$PKG_ROOT/var/lib/jarwis"
mkdir -p "$PKG_ROOT/lib/systemd/system"
mkdir -p "$PKG_ROOT/usr/share/doc/jarwis-agent"

# Copy files
cp "$BUILD_DIR/$APP_NAME" "$PKG_ROOT/usr/bin/"
cp "$INSTALLER_DIR/linux/jarwis-agent.service" "$PKG_ROOT/lib/systemd/system/"

# Create default config
cat > "$PKG_ROOT/etc/jarwis/agent.conf" << CONF
# Jarwis Agent Configuration
# 
# Edit this file or use: jarwis-agent --configure

SERVER_URL=wss://jarwis.io/ws/agent
ACTIVATION_KEY=
LOG_LEVEL=INFO
MITM_PORT=8082
DATA_DIR=/var/lib/jarwis
CONF

# Copy config if exists
if [ -f "/app/config/config.yaml" ]; then
    cp "/app/config/config.yaml" "$PKG_ROOT/etc/jarwis/"
fi

# Create basic docs
echo "Jarwis Security Agent" > "$PKG_ROOT/usr/share/doc/jarwis-agent/README"
echo "Copyright (c) 2026 Jarwis Security" > "$PKG_ROOT/usr/share/doc/jarwis-agent/copyright"

# Set permissions
chmod 755 "$PKG_ROOT/usr/bin/$APP_NAME"
chmod 644 "$PKG_ROOT/lib/systemd/system/jarwis-agent.service"
chmod 644 "$PKG_ROOT/etc/jarwis/agent.conf"

echo "[3/5] Creating maintainer scripts..."

# Create postinstall script
cat > "$BUILD_DIR/postinstall.sh" << 'SCRIPT'
#!/bin/bash
set -e
# Reload systemd
systemctl daemon-reload || true
# Enable service
systemctl enable jarwis-agent.service || true
echo "Jarwis Agent installed. Start with: sudo systemctl start jarwis-agent"
SCRIPT
chmod +x "$BUILD_DIR/postinstall.sh"

# Create preremove script
cat > "$BUILD_DIR/preremove.sh" << 'SCRIPT'
#!/bin/bash
set -e
# Stop service
systemctl stop jarwis-agent.service || true
# Disable service
systemctl disable jarwis-agent.service || true
SCRIPT
chmod +x "$BUILD_DIR/preremove.sh"

# Create postremove script
cat > "$BUILD_DIR/postremove.sh" << 'SCRIPT'
#!/bin/bash
set -e
# Reload systemd
systemctl daemon-reload || true
SCRIPT
chmod +x "$BUILD_DIR/postremove.sh"

echo "[4/5] Building DEB package..."

fpm -s dir -t deb \
    --name "jarwis-agent" \
    --version "$VERSION" \
    --architecture "$ARCH" \
    --maintainer "Jarwis Security <support@jarwis.io>" \
    --vendor "Jarwis Security" \
    --description "Jarwis Security Testing Agent - Background agent for security testing" \
    --url "https://jarwis.io" \
    --license "Proprietary" \
    --category "utils" \
    --config-files "/etc/jarwis/agent.conf" \
    --directories "/var/lib/jarwis" \
    --directories "/var/log/jarwis" \
    --depends "libc6" \
    --after-install "$BUILD_DIR/postinstall.sh" \
    --before-remove "$BUILD_DIR/preremove.sh" \
    --after-remove "$BUILD_DIR/postremove.sh" \
    -C "$PKG_ROOT" \
    --package "/dist/linux/x64/jarwis-agent_${VERSION}_${ARCH}.deb" \
    .

echo "DEB package created!"

echo "[5/5] Building RPM package..."

fpm -s dir -t rpm \
    --name "jarwis-agent" \
    --version "$VERSION" \
    --architecture "x86_64" \
    --maintainer "Jarwis Security <support@jarwis.io>" \
    --vendor "Jarwis Security" \
    --description "Jarwis Security Testing Agent - Background agent for security testing" \
    --url "https://jarwis.io" \
    --license "Proprietary" \
    --category "Applications/System" \
    --config-files "/etc/jarwis/agent.conf" \
    --directories "/var/lib/jarwis" \
    --directories "/var/log/jarwis" \
    --depends "glibc" \
    --after-install "$BUILD_DIR/postinstall.sh" \
    --before-remove "$BUILD_DIR/preremove.sh" \
    --after-remove "$BUILD_DIR/postremove.sh" \
    -C "$PKG_ROOT" \
    --package "/dist/linux/x64/jarwis-agent-${VERSION}-1.x86_64.rpm" \
    .

echo "RPM package created!"

# Also copy the binary executable
cp "$BUILD_DIR/$APP_NAME" "/dist/linux/x64/"

echo ""
echo "============================================================"
echo "  Build Complete!"
echo "============================================================"
echo ""
echo "Output files:"
ls -lh /dist/linux/x64/
echo ""
