#!/bin/bash
# ===========================================================================
# Jarwis Agent - macOS Full Build Script (CLI + GUI Components)
# ===========================================================================
#
# Builds all macOS components:
#   1. jarwis-agent          - CLI agent (core)
#   2. JarwisAgentSetup-macos - GUI installer wizard
#   3. jarwis-tray           - System tray/menu bar app
#   4. jarwis-config         - Configuration tool
#   5. PKG installer         - macOS package
#   6. DMG image             - Distribution format
#
# Prerequisites:
#   - Python 3.10+ with PyInstaller
#   - PyQt6 (pip install PyQt6)
#   - Xcode Command Line Tools
#   - Apple Developer ID (for signing)
#
# Usage:
#   ./build-all.sh              - Build all components
#   ./build-all.sh --cli-only   - Build only CLI agent
#   ./build-all.sh --gui-only   - Build only GUI components
#   ./build-all.sh --sign       - Build and sign with Apple certs
#   ./build-all.sh --arch arm64 - Build for Apple Silicon
#   ./build-all.sh --arch x86_64 - Build for Intel
#   ./build-all.sh --universal  - Build Universal binary
#
# ===========================================================================

set -e

echo ""
echo "============================================================"
echo "  Jarwis Agent - macOS Full Build"
echo "============================================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/dist/macos"
INSTALLER_DIR="$PROJECT_ROOT/installer"
GUI_DIR="$INSTALLER_DIR/gui"
ASSETS_DIR="$INSTALLER_DIR/assets"
VERSION="2.1.0"

# Detect architecture
CURRENT_ARCH="$(uname -m)"

# Parse arguments
BUILD_CLI=1
BUILD_GUI=1
BUILD_PKG=1
SIGN_BUILD=0
TARGET_ARCH="$CURRENT_ARCH"
BUILD_UNIVERSAL=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --cli-only)
            BUILD_GUI=0
            BUILD_PKG=0
            shift
            ;;
        --gui-only)
            BUILD_CLI=0
            shift
            ;;
        --skip-pkg)
            BUILD_PKG=0
            shift
            ;;
        --sign)
            SIGN_BUILD=1
            shift
            ;;
        --arch)
            TARGET_ARCH="$2"
            shift 2
            ;;
        --universal)
            BUILD_UNIVERSAL=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Set architecture label
if [ "$BUILD_UNIVERSAL" = "1" ]; then
    ARCH_LABEL="universal"
    ARCH_DIR="universal"
    echo "Building: Universal Binary (arm64 + x86_64)"
elif [ "$TARGET_ARCH" = "arm64" ]; then
    ARCH_LABEL="apple-silicon"
    ARCH_DIR="arm64"
    PYINSTALLER_ARCH="--target-architecture arm64"
    echo "Building for: Apple Silicon (arm64)"
else
    ARCH_LABEL="intel"
    ARCH_DIR="x86_64"
    PYINSTALLER_ARCH="--target-architecture x86_64"
    echo "Building for: Intel (x86_64)"
fi

# Create build directory
BUILD_DIR="$PROJECT_ROOT/dist/macos/$ARCH_DIR"
mkdir -p "$BUILD_DIR"

cd "$PROJECT_ROOT"

# Count total steps
TOTAL_STEPS=0
[ $BUILD_CLI -eq 1 ] && TOTAL_STEPS=$((TOTAL_STEPS + 1))
[ $BUILD_GUI -eq 1 ] && TOTAL_STEPS=$((TOTAL_STEPS + 3))
[ $BUILD_PKG -eq 1 ] && TOTAL_STEPS=$((TOTAL_STEPS + 1))
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
        $PYINSTALLER_ARCH \
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
    echo "[$CURRENT_STEP/$TOTAL_STEPS] Building GUI Setup Wizard (JarwisAgentSetup-macos)..."
    echo ""
    
    python3 -m PyInstaller "$INSTALLER_DIR/jarwis-setup-gui.spec" \
        --distpath "$BUILD_DIR" \
        --workpath "$BUILD_DIR/build/setup-gui" \
        $PYINSTALLER_ARCH \
        --clean \
        --noconfirm
    
    chmod +x "$BUILD_DIR/JarwisAgentSetup-macos" 2>/dev/null || true
    
    # If it created an app bundle, note the path
    if [ -d "$BUILD_DIR/Jarwis Agent Setup.app" ]; then
        echo "   ✓ Jarwis Agent Setup.app built successfully"
    else
        echo "   ✓ JarwisAgentSetup-macos built successfully"
    fi
fi

# ===========================================================================
# Step 3: Build System Tray/Menu Bar App
# ===========================================================================
if [ $BUILD_GUI -eq 1 ]; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo "[$CURRENT_STEP/$TOTAL_STEPS] Building Menu Bar App (jarwis-tray)..."
    echo ""
    
    python3 -m PyInstaller "$INSTALLER_DIR/jarwis-tray.spec" \
        --distpath "$BUILD_DIR" \
        --workpath "$BUILD_DIR/build/tray" \
        $PYINSTALLER_ARCH \
        --clean \
        --noconfirm
    
    chmod +x "$BUILD_DIR/jarwis-tray" 2>/dev/null || true
    echo "   ✓ jarwis-tray built successfully"
fi

# ===========================================================================
# Step 4: Build Configuration Tool
# ===========================================================================
if [ $BUILD_GUI -eq 1 ]; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo "[$CURRENT_STEP/$TOTAL_STEPS] Building Configuration Tool (jarwis-config)..."
    echo ""
    
    python3 -m PyInstaller "$INSTALLER_DIR/jarwis-config.spec" \
        --distpath "$BUILD_DIR" \
        --workpath "$BUILD_DIR/build/config" \
        $PYINSTALLER_ARCH \
        --clean \
        --noconfirm
    
    chmod +x "$BUILD_DIR/jarwis-config" 2>/dev/null || true
    echo "   ✓ jarwis-config built successfully"
fi

# ===========================================================================
# Copy Additional Files
# ===========================================================================
echo ""
echo "Copying additional files..."

[ -f "$PROJECT_ROOT/config/config.yaml" ] && cp "$PROJECT_ROOT/config/config.yaml" "$BUILD_DIR/"
[ -f "$PROJECT_ROOT/LICENSE" ] && cp "$PROJECT_ROOT/LICENSE" "$BUILD_DIR/LICENSE.txt"
[ -f "$PROJECT_ROOT/README.md" ] && cp "$PROJECT_ROOT/README.md" "$BUILD_DIR/README.txt"

# ===========================================================================
# Code Signing (if enabled)
# ===========================================================================
if [ $SIGN_BUILD -eq 1 ]; then
    echo ""
    echo "Signing executables..."
    
    if [ -z "$APPLE_DEVELOPER_ID" ]; then
        echo "WARNING: APPLE_DEVELOPER_ID not set, skipping signing"
    else
        for exe in jarwis-agent JarwisAgentSetup-macos jarwis-tray jarwis-config; do
            if [ -f "$BUILD_DIR/$exe" ]; then
                echo "   Signing $exe..."
                codesign --force --options runtime \
                    --sign "$APPLE_DEVELOPER_ID" \
                    --timestamp \
                    "$BUILD_DIR/$exe" 2>/dev/null && echo "   ✓ $exe signed" || echo "   ⚠ Failed to sign $exe"
            fi
        done
        
        # Sign app bundles
        for app in "Jarwis Agent Setup.app" "Jarwis Tray.app" "Jarwis Config.app"; do
            if [ -d "$BUILD_DIR/$app" ]; then
                echo "   Signing $app..."
                codesign --force --deep --options runtime \
                    --sign "$APPLE_DEVELOPER_ID" \
                    --timestamp \
                    "$BUILD_DIR/$app" 2>/dev/null && echo "   ✓ $app signed" || echo "   ⚠ Failed to sign $app"
            fi
        done
    fi
fi

# ===========================================================================
# Build DMG (if GUI was built)
# ===========================================================================
if [ $BUILD_GUI -eq 1 ] && [ $BUILD_PKG -eq 1 ]; then
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo "[$CURRENT_STEP/$TOTAL_STEPS] Creating DMG installer..."
    
    DMG_NAME="JarwisAgentSetup-${VERSION}-${ARCH_LABEL}.dmg"
    DMG_TEMP="$BUILD_DIR/dmg-temp"
    
    rm -rf "$DMG_TEMP"
    mkdir -p "$DMG_TEMP"
    
    # Copy files to DMG staging
    [ -f "$BUILD_DIR/JarwisAgentSetup-macos" ] && cp "$BUILD_DIR/JarwisAgentSetup-macos" "$DMG_TEMP/"
    [ -d "$BUILD_DIR/Jarwis Agent Setup.app" ] && cp -R "$BUILD_DIR/Jarwis Agent Setup.app" "$DMG_TEMP/"
    [ -f "$BUILD_DIR/jarwis-agent" ] && cp "$BUILD_DIR/jarwis-agent" "$DMG_TEMP/"
    [ -f "$BUILD_DIR/README.txt" ] && cp "$BUILD_DIR/README.txt" "$DMG_TEMP/"
    
    # Create DMG
    hdiutil create \
        -volname "Jarwis Agent $VERSION" \
        -srcfolder "$DMG_TEMP" \
        -ov \
        -format UDZO \
        "$BUILD_DIR/$DMG_NAME"
    
    rm -rf "$DMG_TEMP"
    
    if [ $SIGN_BUILD -eq 1 ] && [ -n "$APPLE_DEVELOPER_ID" ]; then
        codesign --sign "$APPLE_DEVELOPER_ID" "$BUILD_DIR/$DMG_NAME" 2>/dev/null || true
    fi
    
    echo "   ✓ DMG created: $DMG_NAME"
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
[ -f "$BUILD_DIR/jarwis-agent" ] && echo "   ✓ jarwis-agent              ($(stat -f%z "$BUILD_DIR/jarwis-agent" 2>/dev/null || stat -c%s "$BUILD_DIR/jarwis-agent" 2>/dev/null) bytes)"
[ -f "$BUILD_DIR/JarwisAgentSetup-macos" ] && echo "   ✓ JarwisAgentSetup-macos    ($(stat -f%z "$BUILD_DIR/JarwisAgentSetup-macos" 2>/dev/null || stat -c%s "$BUILD_DIR/JarwisAgentSetup-macos" 2>/dev/null) bytes)"
[ -d "$BUILD_DIR/Jarwis Agent Setup.app" ] && echo "   ✓ Jarwis Agent Setup.app"
[ -f "$BUILD_DIR/jarwis-tray" ] && echo "   ✓ jarwis-tray               ($(stat -f%z "$BUILD_DIR/jarwis-tray" 2>/dev/null || stat -c%s "$BUILD_DIR/jarwis-tray" 2>/dev/null) bytes)"
[ -f "$BUILD_DIR/jarwis-config" ] && echo "   ✓ jarwis-config             ($(stat -f%z "$BUILD_DIR/jarwis-config" 2>/dev/null || stat -c%s "$BUILD_DIR/jarwis-config" 2>/dev/null) bytes)"
ls "$BUILD_DIR"/*.dmg 2>/dev/null && echo "   ✓ DMG installer"
echo ""
