# Jarwis Agent - Professional Installer System

A comprehensive, enterprise-grade installer system for the Jarwis Security Agent that provides a polished, corporate user experience across Windows, macOS, and Linux.

## 🎯 Overview

This installer system addresses the need for a professional, corporate-style installation experience similar to enterprise security tools like Palo Alto Cortex XDR, CrowdStrike Falcon, or SentinelOne.

### Key Features

- **GUI Setup Wizard** - Full PyQt6-based wizard with welcome, license, path selection, feature selection, and configuration screens
- **System Tray Application** - Background agent with status indicator, quick access menu, and notifications
- **Professional Branding** - Custom icons, installer banners, and branded UI throughout
- **Windows Service** - Proper service installation with auto-start and recovery options
- **Silent Installation** - Enterprise deployment support via command-line parameters
- **Post-Install Configuration** - Interactive configuration window with connection testing

## 📁 Directory Structure

```
installer/
├── README.md                    # This file
├── LICENSE.rtf                  # EULA in RTF format for installers
├── jarwis-agent.spec            # PyInstaller specification
│
├── assets/                      # Branding assets
│   ├── create_icons.py          # Icon/bitmap generator script
│   ├── icons/                   # Generated icons
│   │   ├── jarwis-agent.ico     # Windows icon
│   │   └── jarwis-agent.icns    # macOS icon
│   └── bitmaps/                 # Installer images
│       ├── banner.bmp           # WiX/Inno top banner (493x58)
│       ├── dialog.bmp           # WiX welcome dialog (493x312)
│       ├── wizard_large.bmp     # Inno Setup large (164x314)
│       └── wizard_small.bmp     # Inno Setup small (55x55)
│
├── gui/                         # GUI applications
│   ├── setup_wizard.py          # PyQt6 setup wizard
│   ├── system_tray.py           # System tray application
│   └── post_install_config.py   # Post-install configuration
│
├── windows/                     # Windows-specific
│   ├── build.bat                # MSI build script (WiX)
│   ├── build_inno.bat           # EXE build script (Inno Setup)
│   ├── jarwis-agent.wxs         # WiX MSI configuration
│   └── version_info.txt         # Windows version resource
│
├── inno/                        # Inno Setup files
│   └── jarwis-agent.iss         # Inno Setup script
│
├── macos/                       # macOS-specific
│   ├── build.sh                 # PKG build script (supports --universal for Apple Silicon)
│   ├── com.jarwis.agent.plist   # LaunchDaemon configuration
│   ├── entitlements.plist       # App entitlements
│   └── scripts/                 # PKG scripts (preinstall, postinstall)
│
├── linux/                       # Linux-specific
│   ├── build.sh                 # DEB/RPM build script
│   ├── jarwis-agent.service     # systemd unit file
│   ├── postinstall.sh           # Post-install script
│   └── install.sh               # One-liner installer
│
├── BUILD_INSTALLER.bat          # Master build script (Windows)
├── CHECK_DEPS.bat               # Runtime dependency checker
├── preflight_check.py           # Pre-build validation
├── runtime_deps.py              # Runtime dependency module
└── INSTALLATION_TROUBLESHOOTING.md  # User troubleshooting guide
```

## 🚀 Quick Start

### One-Command Build (Windows)

From the project root, run:

```batch
BUILD_WINDOWS_INSTALLER.bat
```

This automatically:
1. Validates all prerequisites
2. Builds the executable with PyInstaller
3. Creates the EXE installer (if Inno Setup is available)
4. Creates the MSI installer (if WiX is available)

### Prerequisites

**Windows:**
- Python 3.10+
- PyInstaller: `pip install pyinstaller`
- PyQt6: `pip install PyQt6`
- Pillow: `pip install Pillow`
- WiX Toolset 3.11+ (for MSI): https://wixtoolset.org
- Inno Setup 6.2+ (for EXE): https://jrsoftware.org/isinfo.php

### Building the Installer

#### Option 1: Inno Setup (Recommended for User-Friendly Installer)

```batch
cd installer\windows
build_inno.bat
```

This creates: `dist\inno\jarwis-agent-2.0.0-setup.exe`

#### Option 2: WiX MSI (Recommended for Enterprise/Silent Deployment)

```batch
cd installer\windows
build.bat
```

This creates: `dist\windows\x64\jarwis-agent_x64.msi`

### Generating Branding Assets

Before building, generate the icons and installer images:

```batch
cd installer\assets
pip install Pillow
python create_icons.py
```

This creates all required `.ico`, `.bmp` files from the source logo.

## ✅ Pre-flight Validation

Before building, run the pre-flight checker to ensure all requirements are met:

```batch
# Check all platforms
python installer/preflight_check.py

# Check specific platform
python installer/preflight_check.py --platform windows

# Auto-fix simple issues
python installer/preflight_check.py --fix
```

This validates:
- Core files exist (config.yaml, spec file, license)
- Build tools installed (WiX, Inno Setup, pkgbuild, fpm)
- Branding assets generated
- Python dependencies available

## 🔧 Runtime Dependencies

The agent requires external tools for certain scanning capabilities. Check and document these for users:

```bash
# Check all runtime dependencies
python installer/runtime_deps.py

# Check specific category
python installer/runtime_deps.py --category network
python installer/runtime_deps.py --category mobile

# Output as JSON (for automation)
python installer/runtime_deps.py --json

# Attempt auto-installation (macOS/Linux only)
python installer/runtime_deps.py --install
```

See [INSTALLATION_TROUBLESHOOTING.md](INSTALLATION_TROUBLESHOOTING.md) for user-facing documentation.

## 🎨 Customization

### Branding

1. **Logo Source**: Replace `assets/logos/png/PNG-01.png` with your logo
2. **Regenerate Assets**: Run `python installer/assets/create_icons.py`
3. **License Text**: Edit `installer/LICENSE.rtf`
4. **Colors**: Modify the color constants in `setup_wizard.py` and `system_tray.py`

### Features

Edit the component lists in:
- `installer/inno/jarwis-agent.iss` - Inno Setup components
- `installer/gui/setup_wizard.py` - PyQt6 wizard features
- `installer/windows/jarwis-agent.wxs` - WiX features

## 📦 Build Outputs

| File | Type | Use Case |
|------|------|----------|
| `jarwis-agent-2.0.0-setup.exe` | Inno Setup EXE | End-user installation with GUI wizard |
| `jarwis-agent_x64.msi` | WiX MSI | Enterprise deployment (SCCM, Intune, GPO) |
| `jarwis-agent.exe` | Standalone | Manual installation or updates |
| `jarwis-tray.exe` | System Tray | Background status application |

## 🔧 Silent Installation

### MSI (Enterprise)

```batch
msiexec /i jarwis-agent_x64.msi /quiet ^
    ACTIVATION_KEY=your-key-here ^
    SERVER_URL=wss://your-server.com/ws/agent ^
    AUTO_START=1
```

### Inno Setup EXE

```batch
jarwis-agent-2.0.0-setup.exe /VERYSILENT /SUPPRESSMSGBOXES ^
    /NORESTART /SP- ^
    /LOG="install.log"
```

## 🛡️ Code Signing

### Windows (Azure Trusted Signing)

```batch
build.bat --sign
```

Requires:
- Azure CLI installed and logged in
- Azure Trusted Signing account configured
- Environment variables: `AZURE_SIGNING_ACCOUNT`, `AZURE_SIGNING_PROFILE`

### macOS (Apple Developer ID)

```bash
./build.sh --sign
```

Requires:
- Apple Developer ID Application certificate
- Apple Developer ID Installer certificate
- `APPLE_CODESIGN_IDENTITY` environment variable

## 🔍 Troubleshooting

### Common Installation Issues

See **[INSTALLATION_TROUBLESHOOTING.md](INSTALLATION_TROUBLESHOOTING.md)** for comprehensive troubleshooting including:
- Windows SmartScreen bypass instructions
- macOS Gatekeeper handling
- Linux package issues
- Runtime dependency installation

### "Terminal opens and closes immediately"

The old CLI-only agent had no GUI. The new installer includes:
1. **Setup Wizard** - Full GUI installation experience
2. **System Tray** - Background agent with visible status
3. **Post-Install Config** - Interactive configuration window

### "No branding/icons visible"

Run the icon generator:
```batch
cd installer\assets
python create_icons.py
```

### "WiX build fails"

Ensure WiX Toolset is installed and in PATH:
```batch
where candle
where light
```

Download from: https://wixtoolset.org/releases/

### "Inno Setup not found"

Ensure Inno Setup is installed and ISCC is in PATH:
```batch
where iscc
```

Download from: https://jrsoftware.org/isdl.php

## 📞 Support

- Documentation: https://jarwis.io/docs/agent
- Support: support@jarwis.io
- Issues: https://github.com/jarwis/jarwis-agent/issues

## 📄 License

Copyright © 2026 Jarwis Security. All rights reserved.
