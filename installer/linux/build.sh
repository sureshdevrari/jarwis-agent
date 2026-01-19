#!/bin/bash
# ===========================================================================
# Jarwis Agent - Linux Build Script
# ===========================================================================
#
# Builds Linux packages (DEB and RPM) for Jarwis Security Agent.
#
# Prerequisites:
#   - Python 3.10+ with PyInstaller
#   - fpm (Effing Package Management): gem install fpm
#   - dpkg-deb (for DEB)
#   - rpm-build (for RPM)
#
# Usage:
#   ./build.sh                    - Build both DEB and RPM
#   ./build.sh --deb              - Build DEB only
#   ./build.sh --rpm              - Build RPM only
#
# ===========================================================================

set -e

echo ""
echo "============================================================"
echo "  Jarwis Agent - Linux Build"
echo "============================================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/dist/linux"
INSTALLER_DIR="$PROJECT_ROOT/installer"
APP_NAME="jarwis-agent"
VERSION="1.0.0"
ARCH="$(uname -m)"

# Map architecture
case "$ARCH" in
    x86_64)  ARCH_DEB="amd64"; ARCH_RPM="x86_64" ;;
    aarch64) ARCH_DEB="arm64"; ARCH_RPM="aarch64" ;;
    armv7l)  ARCH_DEB="armhf"; ARCH_RPM="armv7hl" ;;
    *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Parse arguments
BUILD_DEB=1
BUILD_RPM=1
if [ "$1" == "--deb" ]; then BUILD_RPM=0; fi
if [ "$1" == "--rpm" ]; then BUILD_DEB=0; fi

# Create build directory
mkdir -p "$BUILD_DIR"

echo "[1/5] Building executable with PyInstaller..."
cd "$PROJECT_ROOT"

python3 -m PyInstaller "$INSTALLER_DIR/jarwis-agent.spec" \
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
cp "$PROJECT_ROOT/config/config.yaml" "$PKG_ROOT/etc/jarwis/"
cp "$PROJECT_ROOT/LICENSE" "$PKG_ROOT/usr/share/doc/jarwis-agent/"
cp "$PROJECT_ROOT/README.md" "$PKG_ROOT/usr/share/doc/jarwis-agent/"

# Create default config
cat > "$PKG_ROOT/etc/jarwis/agent.conf" << EOF
# Jarwis Agent Configuration
# 
# Edit this file or use: jarwis-agent --configure

SERVER_URL=wss://jarwis.io/ws/agent
ACTIVATION_KEY=
LOG_LEVEL=INFO
MITM_PORT=8082
DATA_DIR=/var/lib/jarwis
EOF

# Set permissions
chmod 755 "$PKG_ROOT/usr/bin/$APP_NAME"
chmod 644 "$PKG_ROOT/lib/systemd/system/jarwis-agent.service"
chmod 644 "$PKG_ROOT/etc/jarwis/agent.conf"

echo "[3/5] Checking for fpm..."

if ! command -v fpm &> /dev/null; then
    echo "ERROR: fpm not found. Install with: gem install fpm"
    exit 1
fi

echo "[4/5] Building packages..."

# Common fpm options
FPM_OPTS=(
    --name "jarwis-agent"
    --version "$VERSION"
    --architecture "$ARCH_DEB"
    --maintainer "Jarwis Security <support@jarwis.io>"
    --vendor "Jarwis Security"
    --description "Jarwis Security Testing Agent - Background agent for security testing"
    --url "https://jarwis.io"
    --license "Proprietary"
    --category "utils"
    --config-files "/etc/jarwis/agent.conf"
    --directories "/var/lib/jarwis"
    --directories "/var/log/jarwis"
    --after-install "$INSTALLER_DIR/linux/postinstall.sh"
    --before-remove "$INSTALLER_DIR/linux/preremove.sh"
    --after-remove "$INSTALLER_DIR/linux/postremove.sh"
    -C "$PKG_ROOT"
)

if [ $BUILD_DEB -eq 1 ]; then
    echo "Building DEB package..."
    
    fpm -s dir -t deb \
        "${FPM_OPTS[@]}" \
        --architecture "$ARCH_DEB" \
        --depends "libc6" \
        --deb-systemd "$INSTALLER_DIR/linux/jarwis-agent.service" \
        --deb-systemd-enable \
        --deb-no-default-config-files \
        --package "$BUILD_DIR/jarwis-agent_${VERSION}_${ARCH_DEB}.deb" \
        .
    
    echo "DEB package created: jarwis-agent_${VERSION}_${ARCH_DEB}.deb"
fi

if [ $BUILD_RPM -eq 1 ]; then
    echo "Building RPM package..."
    
    fpm -s dir -t rpm \
        "${FPM_OPTS[@]}" \
        --architecture "$ARCH_RPM" \
        --depends "glibc" \
        --rpm-os "linux" \
        --rpm-auto-add-directories \
        --package "$BUILD_DIR/jarwis-agent-${VERSION}-1.${ARCH_RPM}.rpm" \
        .
    
    echo "RPM package created: jarwis-agent-${VERSION}-1.${ARCH_RPM}.rpm"
fi

# Also create a generic tarball
echo "[5/5] Creating tarball..."
TARBALL="$BUILD_DIR/jarwis-agent-${VERSION}-linux-${ARCH}.tar.gz"
tar -czf "$TARBALL" \
    -C "$PKG_ROOT" \
    usr/bin/jarwis-agent \
    etc/jarwis \
    lib/systemd/system/jarwis-agent.service

echo ""
echo "============================================================"
echo "  Build Complete!"
echo "============================================================"
echo ""
echo "Output files:"
if [ $BUILD_DEB -eq 1 ]; then
    echo "  DEB: $BUILD_DIR/jarwis-agent_${VERSION}_${ARCH_DEB}.deb"
fi
if [ $BUILD_RPM -eq 1 ]; then
    echo "  RPM: $BUILD_DIR/jarwis-agent-${VERSION}-1.${ARCH_RPM}.rpm"
fi
echo "  Tarball: $TARBALL"
echo ""
echo "Install commands:"
echo "  DEB (Ubuntu/Debian):"
echo "    sudo dpkg -i jarwis-agent_${VERSION}_${ARCH_DEB}.deb"
echo ""
echo "  RPM (RHEL/CentOS/Fedora):"
echo "    sudo rpm -i jarwis-agent-${VERSION}-1.${ARCH_RPM}.rpm"
echo ""
echo "  Tarball (any distro):"
echo "    sudo tar -xzf jarwis-agent-*.tar.gz -C /"
echo "    sudo systemctl daemon-reload"
echo "    sudo systemctl enable --now jarwis-agent"
echo ""
echo "One-liner install (curl | bash):"
echo "  curl -sL https://jarwis.io/install.sh | sudo bash -s -- YOUR_ACTIVATION_KEY"
echo ""

# Cleanup
rm -rf "$PKG_ROOT" "$BUILD_DIR/build"
