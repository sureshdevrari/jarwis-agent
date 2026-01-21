#!/bin/bash
# ===========================================================================
# Jarwis Agent - Linux Full Build Script (CLI + GUI Components)
# ===========================================================================
#
# Builds all Linux components:
#   1. jarwis-agent          - CLI agent (core)
#   2. JarwisAgentSetup-linux - GUI installer wizard (requires X11/Qt)
#   3. jarwis-tray           - System tray app (requires X11/Qt)
#   4. jarwis-config         - Configuration tool
#   5. DEB package           - Debian/Ubuntu
#   6. RPM package           - RHEL/CentOS/Fedora
#   7. Tarball               - Universal Linux
#
# Prerequisites:
#   - Python 3.10+ with PyInstaller
#   - PyQt6 (pip install PyQt6) - for GUI components
#   - fpm (gem install fpm) - for package creation
#   - X11 development headers - for GUI builds
#
# Usage:
#   ./build-all.sh              - Build all components
#   ./build-all.sh --cli-only   - Build only CLI agent
#   ./build-all.sh --gui-only   - Build only GUI components
#   ./build-all.sh --skip-pkg   - Skip DEB/RPM creation
#   ./build-all.sh --deb        - Build DEB only
#   ./build-all.sh --rpm        - Build RPM only
#
# ===========================================================================

set -e

echo ""
echo "============================================================"
echo "  Jarwis Agent - Linux Full Build"
echo "============================================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/dist/linux/amd64"
INSTALLER_DIR="$PROJECT_ROOT/installer"
GUI_DIR="$INSTALLER_DIR/gui"
ASSETS_DIR="$INSTALLER_DIR/assets"
VERSION="2.1.0"
ARCH="$(uname -m)"

# Map architecture
case "$ARCH" in
    x86_64)  ARCH_DEB="amd64"; ARCH_RPM="x86_64"; ARCH_LABEL="amd64" ;;
    aarch64) ARCH_DEB="arm64"; ARCH_RPM="aarch64"; ARCH_LABEL="arm64" ;;
    *)       ARCH_DEB="amd64"; ARCH_RPM="x86_64"; ARCH_LABEL="amd64" ;;
esac

# Parse arguments
BUILD_CLI=1
BUILD_GUI=1
BUILD_PACKAGES=1
BUILD_DEB=1
BUILD_RPM=1

while [[ $# -gt 0 ]]; do
    case $1 in
        --cli-only)
            BUILD_GUI=0
            shift
            ;;
        --gui-only)
            BUILD_CLI=0
            shift
            ;;
        --skip-pkg)
            BUILD_PACKAGES=0
            shift
            ;;
        --deb)
            BUILD_RPM=0
            shift
            ;;
        --rpm)
            BUILD_DEB=0
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create build directory
mkdir -p "$BUILD_DIR"

cd "$PROJECT_ROOT"

# Count steps
TOTAL_STEPS=0
[ $BUILD_CLI -eq 1 ] && TOTAL_STEPS=$((TOTAL_STEPS + 1))
[ $BUILD_GUI -eq 1 ] && TOTAL_STEPS=$((TOTAL_STEPS + 3))
[ $BUILD_PACKAGES -eq 1 ] && TOTAL_STEPS=$((TOTAL_STEPS + 1))
CURRENT_STEP=0

# ===========================================================================
# Step 1: Build CLI Agent
# ===========================================================================
if [ $BUILD_CLI -eq 1 ]; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo "[$CURRENT_STEP/$TOTAL_STEPS] Building CLI Agent (jarwis-agent)..."
    echo ""
    
    python3 -m PyInstaller "$INSTALLER_DIR/jarwis-agent.spec" \
        --distpath "$BUILD_DIR" \
        --workpath "$BUILD_DIR/build/cli" \
        --clean \
        --noconfirm
    
    # Handle folder vs file output
    if [ -d "$BUILD_DIR/jarwis-agent" ]; then
        mv "$BUILD_DIR/jarwis-agent/jarwis-agent" "$BUILD_DIR/jarwis-agent-bin"
        rm -rf "$BUILD_DIR/jarwis-agent"
        mv "$BUILD_DIR/jarwis-agent-bin" "$BUILD_DIR/jarwis-agent"
    fi
    
    chmod +x "$BUILD_DIR/jarwis-agent"
    echo "   ✓ jarwis-agent built successfully"
fi

# ===========================================================================
# Step 2: Build GUI Setup Wizard
# ===========================================================================
if [ $BUILD_GUI -eq 1 ]; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo "[$CURRENT_STEP/$TOTAL_STEPS] Building GUI Setup Wizard (JarwisAgentSetup-linux)..."
    echo ""
    
    # Check for PyQt6
    if ! python3 -c "import PyQt6" 2>/dev/null; then
        echo "   WARNING: PyQt6 not found, skipping GUI build"
        echo "   Install with: pip install PyQt6"
    else
        python3 -m PyInstaller "$INSTALLER_DIR/jarwis-setup-gui.spec" \
            --distpath "$BUILD_DIR" \
            --workpath "$BUILD_DIR/build/setup-gui" \
            --clean \
            --noconfirm
        
        chmod +x "$BUILD_DIR/JarwisAgentSetup-linux" 2>/dev/null || true
        echo "   ✓ JarwisAgentSetup-linux built successfully"
    fi
fi

# ===========================================================================
# Step 3: Build System Tray App
# ===========================================================================
if [ $BUILD_GUI -eq 1 ]; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo "[$CURRENT_STEP/$TOTAL_STEPS] Building System Tray App (jarwis-tray)..."
    echo ""
    
    if ! python3 -c "import PyQt6" 2>/dev/null; then
        echo "   WARNING: PyQt6 not found, skipping tray build"
    else
        python3 -m PyInstaller "$INSTALLER_DIR/jarwis-tray.spec" \
            --distpath "$BUILD_DIR" \
            --workpath "$BUILD_DIR/build/tray" \
            --clean \
            --noconfirm
        
        chmod +x "$BUILD_DIR/jarwis-tray" 2>/dev/null || true
        echo "   ✓ jarwis-tray built successfully"
    fi
fi

# ===========================================================================
# Step 4: Build Configuration Tool
# ===========================================================================
if [ $BUILD_GUI -eq 1 ]; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo "[$CURRENT_STEP/$TOTAL_STEPS] Building Configuration Tool (jarwis-config)..."
    echo ""
    
    if ! python3 -c "import PyQt6" 2>/dev/null; then
        echo "   WARNING: PyQt6 not found, skipping config tool build"
    else
        python3 -m PyInstaller "$INSTALLER_DIR/jarwis-config.spec" \
            --distpath "$BUILD_DIR" \
            --workpath "$BUILD_DIR/build/config" \
            --clean \
            --noconfirm
        
        chmod +x "$BUILD_DIR/jarwis-config" 2>/dev/null || true
        echo "   ✓ jarwis-config built successfully"
    fi
fi

# ===========================================================================
# Copy Additional Files
# ===========================================================================
echo ""
echo "Copying additional files..."

[ -f "$PROJECT_ROOT/config/config.yaml" ] && cp "$PROJECT_ROOT/config/config.yaml" "$BUILD_DIR/"
[ -f "$PROJECT_ROOT/LICENSE" ] && cp "$PROJECT_ROOT/LICENSE" "$BUILD_DIR/LICENSE.txt"
[ -f "$PROJECT_ROOT/README.md" ] && cp "$PROJECT_ROOT/README.md" "$BUILD_DIR/README.txt"

# Create .desktop file for GUI apps
if [ $BUILD_GUI -eq 1 ]; then
    cat > "$BUILD_DIR/jarwis-agent.desktop" << EOF
[Desktop Entry]
Name=Jarwis Agent Setup
Comment=Configure Jarwis Security Agent
Exec=/opt/jarwis/JarwisAgentSetup-linux
Icon=/opt/jarwis/jarwis-agent.png
Terminal=false
Type=Application
Categories=Utility;Security;
EOF

    cat > "$BUILD_DIR/jarwis-tray.desktop" << EOF
[Desktop Entry]
Name=Jarwis Agent Status
Comment=Jarwis Agent System Tray
Exec=/opt/jarwis/jarwis-tray
Icon=/opt/jarwis/jarwis-agent.png
Terminal=false
Type=Application
Categories=Utility;Security;
StartupNotify=false
X-GNOME-Autostart-enabled=true
EOF

    # Copy icon if available
    if [ -f "$ASSETS_DIR/icons/jarwis-agent.png" ]; then
        cp "$ASSETS_DIR/icons/jarwis-agent.png" "$BUILD_DIR/"
    fi
fi

# ===========================================================================
# Build Packages
# ===========================================================================
if [ $BUILD_PACKAGES -eq 1 ]; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo "[$CURRENT_STEP/$TOTAL_STEPS] Building distribution packages..."
    
    # Create package root structure
    PKG_ROOT="$BUILD_DIR/pkg-root"
    rm -rf "$PKG_ROOT"
    
    # CLI package structure
    mkdir -p "$PKG_ROOT/usr/bin"
    mkdir -p "$PKG_ROOT/etc/jarwis"
    mkdir -p "$PKG_ROOT/var/log/jarwis"
    mkdir -p "$PKG_ROOT/var/lib/jarwis"
    mkdir -p "$PKG_ROOT/lib/systemd/system"
    mkdir -p "$PKG_ROOT/usr/share/doc/jarwis-agent"
    mkdir -p "$PKG_ROOT/opt/jarwis"
    mkdir -p "$PKG_ROOT/usr/share/applications"
    
    # Copy CLI
    [ -f "$BUILD_DIR/jarwis-agent" ] && cp "$BUILD_DIR/jarwis-agent" "$PKG_ROOT/usr/bin/"
    
    # Copy GUI components to /opt/jarwis
    [ -f "$BUILD_DIR/JarwisAgentSetup-linux" ] && cp "$BUILD_DIR/JarwisAgentSetup-linux" "$PKG_ROOT/opt/jarwis/"
    [ -f "$BUILD_DIR/jarwis-tray" ] && cp "$BUILD_DIR/jarwis-tray" "$PKG_ROOT/opt/jarwis/"
    [ -f "$BUILD_DIR/jarwis-config" ] && cp "$BUILD_DIR/jarwis-config" "$PKG_ROOT/opt/jarwis/"
    [ -f "$BUILD_DIR/jarwis-agent.png" ] && cp "$BUILD_DIR/jarwis-agent.png" "$PKG_ROOT/opt/jarwis/"
    
    # Copy desktop entries
    [ -f "$BUILD_DIR/jarwis-agent.desktop" ] && cp "$BUILD_DIR/jarwis-agent.desktop" "$PKG_ROOT/usr/share/applications/"
    [ -f "$BUILD_DIR/jarwis-tray.desktop" ] && cp "$BUILD_DIR/jarwis-tray.desktop" "$PKG_ROOT/usr/share/applications/"
    
    # Copy config and docs
    [ -f "$PROJECT_ROOT/config/config.yaml" ] && cp "$PROJECT_ROOT/config/config.yaml" "$PKG_ROOT/etc/jarwis/"
    [ -f "$PROJECT_ROOT/LICENSE" ] && cp "$PROJECT_ROOT/LICENSE" "$PKG_ROOT/usr/share/doc/jarwis-agent/"
    [ -f "$PROJECT_ROOT/README.md" ] && cp "$PROJECT_ROOT/README.md" "$PKG_ROOT/usr/share/doc/jarwis-agent/"
    
    # Copy systemd service
    if [ -f "$INSTALLER_DIR/linux/jarwis-agent.service" ]; then
        cp "$INSTALLER_DIR/linux/jarwis-agent.service" "$PKG_ROOT/lib/systemd/system/"
    fi
    
    # Set permissions
    chmod 755 "$PKG_ROOT/usr/bin/"* 2>/dev/null || true
    chmod 755 "$PKG_ROOT/opt/jarwis/"* 2>/dev/null || true
    
    # Check for fpm
    if command -v fpm &> /dev/null; then
        # Build DEB
        if [ $BUILD_DEB -eq 1 ]; then
            echo "   Building DEB package..."
            fpm -s dir -t deb \
                --name "jarwis-agent" \
                --version "$VERSION" \
                --architecture "$ARCH_DEB" \
                --maintainer "Jarwis Security <support@jarwis.io>" \
                --description "Jarwis Security Testing Agent with GUI installer" \
                --url "https://jarwis.io" \
                --license "Proprietary" \
                --depends "libc6" \
                -C "$PKG_ROOT" \
                --package "$BUILD_DIR/jarwis-agent_${VERSION}_${ARCH_DEB}.deb" \
                . 2>/dev/null
            echo "   ✓ DEB package created"
        fi
        
        # Build RPM
        if [ $BUILD_RPM -eq 1 ]; then
            echo "   Building RPM package..."
            fpm -s dir -t rpm \
                --name "jarwis-agent" \
                --version "$VERSION" \
                --architecture "$ARCH_RPM" \
                --maintainer "Jarwis Security <support@jarwis.io>" \
                --description "Jarwis Security Testing Agent with GUI installer" \
                --url "https://jarwis.io" \
                --license "Proprietary" \
                --depends "glibc" \
                -C "$PKG_ROOT" \
                --package "$BUILD_DIR/jarwis-agent-${VERSION}-1.${ARCH_RPM}.rpm" \
                . 2>/dev/null
            echo "   ✓ RPM package created"
        fi
    else
        echo "   WARNING: fpm not found, skipping DEB/RPM creation"
        echo "   Install with: gem install fpm"
    fi
    
    # Create tarball (always)
    echo "   Creating installer tarball..."
    TARBALL_DIR="$BUILD_DIR/jarwis-agent-${VERSION}-linux-installer"
    rm -rf "$TARBALL_DIR"
    mkdir -p "$TARBALL_DIR"
    
    # Copy all components to tarball
    [ -f "$BUILD_DIR/jarwis-agent" ] && cp "$BUILD_DIR/jarwis-agent" "$TARBALL_DIR/"
    [ -f "$BUILD_DIR/JarwisAgentSetup-linux" ] && cp "$BUILD_DIR/JarwisAgentSetup-linux" "$TARBALL_DIR/"
    [ -f "$BUILD_DIR/jarwis-tray" ] && cp "$BUILD_DIR/jarwis-tray" "$TARBALL_DIR/"
    [ -f "$BUILD_DIR/jarwis-config" ] && cp "$BUILD_DIR/jarwis-config" "$TARBALL_DIR/"
    [ -f "$BUILD_DIR/config.yaml" ] && cp "$BUILD_DIR/config.yaml" "$TARBALL_DIR/"
    [ -f "$BUILD_DIR/README.txt" ] && cp "$BUILD_DIR/README.txt" "$TARBALL_DIR/"
    
    # Create install script
    cat > "$TARBALL_DIR/install.sh" << 'INSTALL_SCRIPT'
#!/bin/bash
# Jarwis Agent Installer
set -e

echo "Installing Jarwis Agent..."

# Install CLI
sudo install -m 755 jarwis-agent /usr/local/bin/

# Install GUI components (optional)
if [ -f "JarwisAgentSetup-linux" ]; then
    sudo mkdir -p /opt/jarwis
    sudo install -m 755 JarwisAgentSetup-linux /opt/jarwis/
    [ -f "jarwis-tray" ] && sudo install -m 755 jarwis-tray /opt/jarwis/
    [ -f "jarwis-config" ] && sudo install -m 755 jarwis-config /opt/jarwis/
fi

# Install config
sudo mkdir -p /etc/jarwis
[ -f "config.yaml" ] && sudo install -m 644 config.yaml /etc/jarwis/

echo ""
echo "Installation complete!"
echo "Run: jarwis-agent --help"
[ -f "/opt/jarwis/JarwisAgentSetup-linux" ] && echo "Or run the GUI: /opt/jarwis/JarwisAgentSetup-linux"
INSTALL_SCRIPT
    chmod +x "$TARBALL_DIR/install.sh"
    
    # Create tarball
    tar -czf "$BUILD_DIR/jarwis-agent-${VERSION}-linux-installer.tar.gz" \
        -C "$BUILD_DIR" \
        "jarwis-agent-${VERSION}-linux-installer"
    
    rm -rf "$TARBALL_DIR" "$PKG_ROOT"
    echo "   ✓ Installer tarball created"
fi

# ===========================================================================
# Summary
# ===========================================================================
echo ""
echo "============================================================"
echo "  Build Complete!"
echo "============================================================"
echo ""
echo "Output directory: $BUILD_DIR"
echo ""
echo "Built files:"
[ -f "$BUILD_DIR/jarwis-agent" ] && echo "   ✓ jarwis-agent              ($(stat -c%s "$BUILD_DIR/jarwis-agent" 2>/dev/null || echo "?") bytes)"
[ -f "$BUILD_DIR/JarwisAgentSetup-linux" ] && echo "   ✓ JarwisAgentSetup-linux    ($(stat -c%s "$BUILD_DIR/JarwisAgentSetup-linux" 2>/dev/null || echo "?") bytes)"
[ -f "$BUILD_DIR/jarwis-tray" ] && echo "   ✓ jarwis-tray               ($(stat -c%s "$BUILD_DIR/jarwis-tray" 2>/dev/null || echo "?") bytes)"
[ -f "$BUILD_DIR/jarwis-config" ] && echo "   ✓ jarwis-config             ($(stat -c%s "$BUILD_DIR/jarwis-config" 2>/dev/null || echo "?") bytes)"
[ -f "$BUILD_DIR/jarwis-agent_${VERSION}_${ARCH_DEB}.deb" ] && echo "   ✓ DEB package"
[ -f "$BUILD_DIR/jarwis-agent-${VERSION}-1.${ARCH_RPM}.rpm" ] && echo "   ✓ RPM package"
[ -f "$BUILD_DIR/jarwis-agent-${VERSION}-linux-installer.tar.gz" ] && echo "   ✓ Installer tarball"
echo ""
