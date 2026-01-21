#!/bin/bash
# ===========================================================================
# Jarwis Agent - macOS Build Script
# ===========================================================================
#
# Builds the macOS installer (PKG inside DMG) for Jarwis Security Agent.
#
# Prerequisites:
#   - Python 3.10+ with PyInstaller
#   - Xcode Command Line Tools
#   - Apple Developer ID (for signing and notarization)
#
# Environment Variables:
#   APPLE_DEVELOPER_ID     - Developer ID Application cert name
#   APPLE_INSTALLER_ID     - Developer ID Installer cert name  
#   APPLE_TEAM_ID          - Apple Team ID
#   APPLE_ID               - Apple ID email for notarization
#   APPLE_APP_PASSWORD     - App-specific password for notarization
#
# Usage:
#   ./build.sh                    - Build unsigned
#   ./build.sh --sign             - Build, sign, and notarize
#
# ===========================================================================

set -e

echo ""
echo "============================================================"
echo "  Jarwis Agent - macOS Build"
echo "============================================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/dist/macos"
INSTALLER_DIR="$PROJECT_ROOT/installer"
APP_NAME="jarwis-agent"
PKG_NAME="jarwis-agent.pkg"
DMG_NAME="jarwis-agent.dmg"
VERSION="2.1.0"
BUNDLE_ID="com.jarwis.agent"

# Detect architecture
CURRENT_ARCH="$(uname -m)"
if [ "$CURRENT_ARCH" = "arm64" ]; then
    ARCH_LABEL="apple-silicon"
    PYINSTALLER_ARCH="--target-architecture arm64"
    echo "Detected: Apple Silicon (arm64)"
else
    ARCH_LABEL="intel"
    PYINSTALLER_ARCH="--target-architecture x86_64"
    echo "Detected: Intel (x86_64)"
fi

# Parse arguments
SIGN_BUILD=0
TARGET_ARCH="$CURRENT_ARCH"
BUILD_UNIVERSAL=0

while [[ $# -gt 0 ]]; do
    case $1 in
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
            echo "Usage: $0 [--sign] [--arch arm64|x86_64] [--universal]"
            exit 1
            ;;
    esac
done

# Update arch label and PyInstaller flags based on target
if [ "$BUILD_UNIVERSAL" = "1" ]; then
    ARCH_LABEL="universal"
    PYINSTALLER_ARCH=""  # Let PyInstaller build for current arch, we'll combine later
    echo "Building: Universal Binary (arm64 + x86_64)"
elif [ "$TARGET_ARCH" = "arm64" ]; then
    ARCH_LABEL="apple-silicon"
    PYINSTALLER_ARCH="--target-architecture arm64"
    echo "Building for: Apple Silicon (arm64)"
elif [ "$TARGET_ARCH" = "x86_64" ]; then
    ARCH_LABEL="intel"
    PYINSTALLER_ARCH="--target-architecture x86_64"
    echo "Building for: Intel (x86_64)"
fi

# Update output names with architecture
PKG_NAME="jarwis-agent-${VERSION}-${ARCH_LABEL}.pkg"
DMG_NAME="jarwis-agent-${VERSION}-${ARCH_LABEL}.dmg"

# Create build directory
mkdir -p "$BUILD_DIR"

echo "[1/6] Building executable with PyInstaller..."
cd "$PROJECT_ROOT"

python3 -m PyInstaller "$INSTALLER_DIR/jarwis-agent.spec" \
    --distpath "$BUILD_DIR" \
    --workpath "$BUILD_DIR/build" \
    $PYINSTALLER_ARCH \
    --clean \
    --noconfirm

# For universal builds, we need to build both architectures and combine
if [ "$BUILD_UNIVERSAL" = "1" ]; then
    echo "Building Universal Binary..."
    
    # Build for arm64
    echo "  Building arm64..."
    python3 -m PyInstaller "$INSTALLER_DIR/jarwis-agent.spec" \
        --distpath "$BUILD_DIR/arm64" \
        --workpath "$BUILD_DIR/build-arm64" \
        --target-architecture arm64 \
        --clean \
        --noconfirm
    
    # Build for x86_64
    echo "  Building x86_64..."
    python3 -m PyInstaller "$INSTALLER_DIR/jarwis-agent.spec" \
        --distpath "$BUILD_DIR/x86_64" \
        --workpath "$BUILD_DIR/build-x86_64" \
        --target-architecture x86_64 \
        --clean \
        --noconfirm
    
    # Combine into universal binary using lipo
    echo "  Creating universal binary with lipo..."
    lipo -create \
        "$BUILD_DIR/arm64/$APP_NAME" \
        "$BUILD_DIR/x86_64/$APP_NAME" \
        -output "$BUILD_DIR/$APP_NAME"
    
    # Cleanup architecture-specific builds
    rm -rf "$BUILD_DIR/arm64" "$BUILD_DIR/x86_64" "$BUILD_DIR/build-arm64" "$BUILD_DIR/build-x86_64"
fi

echo "[2/6] Creating package structure..."

# Create package root
PKG_ROOT="$BUILD_DIR/pkg-root"
rm -rf "$PKG_ROOT"
mkdir -p "$PKG_ROOT/usr/local/bin"
mkdir -p "$PKG_ROOT/Library/LaunchDaemons"
mkdir -p "$PKG_ROOT/usr/local/etc/jarwis"

# Copy files
cp "$BUILD_DIR/$APP_NAME" "$PKG_ROOT/usr/local/bin/"
cp "$INSTALLER_DIR/macos/com.jarwis.agent.plist" "$PKG_ROOT/Library/LaunchDaemons/"
cp "$PROJECT_ROOT/config/config.yaml" "$PKG_ROOT/usr/local/etc/jarwis/"

# Set permissions
chmod 755 "$PKG_ROOT/usr/local/bin/$APP_NAME"
chmod 644 "$PKG_ROOT/Library/LaunchDaemons/com.jarwis.agent.plist"

if [ $SIGN_BUILD -eq 1 ]; then
    echo "[3/6] Signing executable..."
    
    if [ -z "$APPLE_DEVELOPER_ID" ]; then
        echo "ERROR: APPLE_DEVELOPER_ID not set"
        exit 1
    fi
    
    codesign --force --options runtime \
        --sign "$APPLE_DEVELOPER_ID" \
        --entitlements "$INSTALLER_DIR/macos/entitlements.plist" \
        --timestamp \
        "$PKG_ROOT/usr/local/bin/$APP_NAME"
    
    echo "Verifying signature..."
    codesign --verify --verbose "$PKG_ROOT/usr/local/bin/$APP_NAME"
else
    echo "[3/6] Skipping code signing (use --sign to enable)"
fi

echo "[4/6] Building PKG installer..."

# Create component package
pkgbuild \
    --root "$PKG_ROOT" \
    --identifier "$BUNDLE_ID" \
    --version "$VERSION" \
    --scripts "$INSTALLER_DIR/macos/scripts" \
    --install-location "/" \
    "$BUILD_DIR/jarwis-agent-component.pkg"

# Create distribution XML
cat > "$BUILD_DIR/distribution.xml" << EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>Jarwis Security Agent</title>
    <organization>com.jarwis</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="true" hostArchitectures="x86_64,arm64"/>
    
    <welcome file="welcome.html"/>
    <license file="license.html"/>
    <conclusion file="conclusion.html"/>
    
    <choices-outline>
        <line choice="default">
            <line choice="com.jarwis.agent"/>
        </line>
    </choices-outline>
    
    <choice id="default"/>
    <choice id="com.jarwis.agent" visible="false">
        <pkg-ref id="com.jarwis.agent"/>
    </choice>
    
    <pkg-ref id="com.jarwis.agent" version="$VERSION" onConclusion="none">jarwis-agent-component.pkg</pkg-ref>
</installer-gui-script>
EOF

# Create installer resources
mkdir -p "$BUILD_DIR/resources"
cat > "$BUILD_DIR/resources/welcome.html" << EOF
<!DOCTYPE html>
<html>
<head><style>body { font-family: -apple-system, sans-serif; padding: 20px; }</style></head>
<body>
<h1>Jarwis Security Agent</h1>
<p>This installer will install the Jarwis Security Agent on your Mac.</p>
<p>The agent runs in the background and connects to your Jarwis cloud console to enable security testing.</p>
</body>
</html>
EOF

cat > "$BUILD_DIR/resources/license.html" << EOF
<!DOCTYPE html>
<html>
<head><style>body { font-family: -apple-system, sans-serif; padding: 20px; font-size: 12px; }</style></head>
<body>
<h2>End User License Agreement</h2>
<p>By installing this software, you agree to the Jarwis Terms of Service.</p>
<p>Visit https://jarwis.io/terms for the full agreement.</p>
</body>
</html>
EOF

cat > "$BUILD_DIR/resources/conclusion.html" << EOF
<!DOCTYPE html>
<html>
<head><style>body { font-family: -apple-system, sans-serif; padding: 20px; }</style></head>
<body>
<h1>Installation Complete</h1>
<p>The Jarwis Agent has been installed successfully.</p>
<p>To activate the agent, run:</p>
<pre>sudo jarwis-agent --activate YOUR_ACTIVATION_KEY</pre>
<p>Or visit <a href="https://jarwis.io/agent/setup">jarwis.io/agent/setup</a> for setup instructions.</p>
</body>
</html>
EOF

# Build product archive
productbuild \
    --distribution "$BUILD_DIR/distribution.xml" \
    --package-path "$BUILD_DIR" \
    --resources "$BUILD_DIR/resources" \
    "$BUILD_DIR/$PKG_NAME.unsigned"

if [ $SIGN_BUILD -eq 1 ]; then
    echo "[5/6] Signing PKG installer..."
    
    productsign \
        --sign "$APPLE_INSTALLER_ID" \
        --timestamp \
        "$BUILD_DIR/$PKG_NAME.unsigned" \
        "$BUILD_DIR/$PKG_NAME"
    
    rm "$BUILD_DIR/$PKG_NAME.unsigned"
    
    echo "Notarizing PKG..."
    xcrun notarytool submit "$BUILD_DIR/$PKG_NAME" \
        --apple-id "$APPLE_ID" \
        --team-id "$APPLE_TEAM_ID" \
        --password "$APPLE_APP_PASSWORD" \
        --wait
    
    xcrun stapler staple "$BUILD_DIR/$PKG_NAME"
else
    echo "[5/6] Skipping PKG signing"
    mv "$BUILD_DIR/$PKG_NAME.unsigned" "$BUILD_DIR/$PKG_NAME"
fi

echo "[6/6] Creating DMG..."

# Create DMG
DMG_TEMP="$BUILD_DIR/dmg-temp"
rm -rf "$DMG_TEMP"
mkdir -p "$DMG_TEMP"
cp "$BUILD_DIR/$PKG_NAME" "$DMG_TEMP/"
cp "$PROJECT_ROOT/README.md" "$DMG_TEMP/README.txt"

hdiutil create \
    -volname "Jarwis Agent $VERSION" \
    -srcfolder "$DMG_TEMP" \
    -ov \
    -format UDZO \
    "$BUILD_DIR/$DMG_NAME"

if [ $SIGN_BUILD -eq 1 ]; then
    codesign --sign "$APPLE_DEVELOPER_ID" "$BUILD_DIR/$DMG_NAME"
    xcrun notarytool submit "$BUILD_DIR/$DMG_NAME" \
        --apple-id "$APPLE_ID" \
        --team-id "$APPLE_TEAM_ID" \
        --password "$APPLE_APP_PASSWORD" \
        --wait
    xcrun stapler staple "$BUILD_DIR/$DMG_NAME"
fi

# Cleanup
rm -rf "$PKG_ROOT" "$DMG_TEMP" "$BUILD_DIR/build" "$BUILD_DIR/resources"
rm -f "$BUILD_DIR/jarwis-agent-component.pkg" "$BUILD_DIR/distribution.xml"

echo ""
echo "============================================================"
echo "  Build Complete!"
echo "============================================================"
echo ""
echo "Output files:"
echo "  PKG Installer: $BUILD_DIR/$PKG_NAME"
echo "  DMG Image:     $BUILD_DIR/$DMG_NAME"
echo ""
echo "Install command:"
echo "  sudo installer -pkg jarwis-agent.pkg -target /"
echo ""
echo "Silent install with activation:"
echo "  sudo installer -pkg jarwis-agent.pkg -target / && sudo jarwis-agent --activate YOUR_KEY"
echo ""
