# Jarwis Universal Agent - Enterprise Installer System

This directory contains the build system for creating native installers for the Jarwis Universal Security Testing Agent.

## 🎯 What is the Universal Agent?

The Jarwis Universal Agent is a **required component** for ALL security testing types:

| Scan Type | Description | Agent Required |
|-----------|-------------|----------------|
| **Web** | OWASP Top 10, API Security, Auth Testing | ✅ Yes |
| **Mobile Static** | APK/IPA Static Analysis | ✅ Yes |
| **Mobile Dynamic** | Runtime Analysis with Frida | ✅ Yes |
| **Network** | Port Scanning, Vuln Assessment | ✅ Yes |
| **Cloud AWS** | AWS Security Posture | ✅ Yes |
| **Cloud Azure** | Azure Security Posture | ✅ Yes |
| **Cloud GCP** | GCP Security Posture | ✅ Yes |
| **Cloud Kubernetes** | K8s Security | ✅ Yes |
| **SAST** | Static Code Analysis | ✅ Yes |

### Why is the Agent Required?

1. **Security** - All tests run through authenticated, encrypted channel
2. **Internal Access** - Can reach internal/private networks and services
3. **Credential Safety** - Cloud credentials never leave the client machine
4. **Compliance** - Full audit trail of all security testing activities
5. **Performance** - Local execution reduces latency for time-based attacks

## 📦 Supported Platforms

| Platform | Formats | Signing |
|----------|---------|---------|
| Windows 10/11 | MSI, EXE | Azure Trusted Signing |
| macOS 11+ | PKG, DMG | Apple Developer ID + Notarization |
| Linux (Ubuntu/Debian) | DEB | GPG signing (optional) |
| Linux (RHEL/CentOS) | RPM | GPG signing (optional) |

## 🏗️ Directory Structure

```
installer/
├── jarwis-agent.spec     # PyInstaller specification
├── hooks/                 # PyInstaller hooks for dependencies
│   ├── hook-frida.py
│   └── hook-mitmproxy.py
├── windows/
│   ├── build.bat         # Windows build script
│   ├── jarwis-agent.wxs  # WiX MSI configuration
│   └── version_info.txt  # Windows version resource
├── macos/
│   ├── build.sh          # macOS build script
│   ├── com.jarwis.agent.plist  # LaunchDaemon config
│   ├── entitlements.plist      # macOS entitlements
│   └── scripts/
│       ├── preinstall    # PKG pre-install script
│       └── postinstall   # PKG post-install script
└── linux/
    ├── build.sh          # Linux build script
    ├── jarwis-agent.service  # systemd unit file
    ├── install.sh        # One-liner install script
    ├── postinstall.sh    # Post-install script
    ├── preremove.sh      # Pre-removal script
    └── postremove.sh     # Post-removal script
```

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- PyInstaller: `pip install pyinstaller`

**Windows:**
- WiX Toolset v3.11+ (https://wixtoolset.org)
- Azure CLI (for code signing)

**macOS:**
- Xcode Command Line Tools
- Apple Developer account (for signing)

**Linux:**
- fpm: `gem install fpm`
- dpkg-deb (for DEB)
- rpm-build (for RPM)

### Building

**Windows:**
```batch
cd installer\windows
build.bat              # Unsigned build
build.bat --sign       # With Azure Trusted Signing
```

**macOS:**
```bash
cd installer/macos
./build.sh             # Unsigned build
./build.sh --sign      # With Apple signing + notarization
```

**Linux:**
```bash
cd installer/linux
./build.sh             # Build DEB and RPM
./build.sh --deb       # DEB only
./build.sh --rpm       # RPM only
```

## 🔐 Code Signing Setup

### Azure Trusted Signing (Windows)

1. Create Azure subscription and Trusted Signing account
2. Set up identity validation (1-7 days)
3. Create certificate profile
4. Configure environment variables:
   ```
   AZURE_CLIENT_ID=xxx
   AZURE_CLIENT_SECRET=xxx
   AZURE_TENANT_ID=xxx
   AZURE_SIGNING_ACCOUNT=jarwis-signing
   AZURE_SIGNING_PROFILE=JarwisCodeSign
   ```

### Apple Developer ID (macOS)

1. Join Apple Developer Program ($99/year)
2. Create "Developer ID Application" certificate
3. Create "Developer ID Installer" certificate
4. Configure environment variables:
   ```
   APPLE_DEVELOPER_ID="Developer ID Application: Your Name (TEAM_ID)"
   APPLE_INSTALLER_ID="Developer ID Installer: Your Name (TEAM_ID)"
   APPLE_TEAM_ID=XXXXXXXXXX
   APPLE_ID=your@email.com
   APPLE_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx
   ```

## 📋 CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/build-agent.yml`) automates:

1. **build-windows** - Builds EXE/MSI with Azure signing
2. **build-macos** - Builds PKG/DMG with Apple signing + notarization
3. **build-linux** - Builds DEB/RPM packages
4. **release** - Creates GitHub release with all artifacts

### Trigger Conditions

- Push to `release/*` branches
- Tags matching `v*`
- Manual workflow dispatch

### Required Secrets

| Secret | Description |
|--------|-------------|
| `AZURE_CLIENT_ID` | Azure service principal |
| `AZURE_CLIENT_SECRET` | Azure service principal secret |
| `AZURE_TENANT_ID` | Azure tenant ID |
| `AZURE_SIGNING_ACCOUNT` | Trusted Signing account name |
| `AZURE_SIGNING_PROFILE` | Certificate profile name |
| `APPLE_CERTIFICATE_P12` | Base64-encoded P12 certificate |
| `APPLE_CERTIFICATE_PASSWORD` | P12 password |
| `APPLE_INSTALLER_CERTIFICATE_P12` | Installer certificate |
| `APPLE_INSTALLER_CERTIFICATE_PASSWORD` | Installer cert password |
| `APPLE_TEAM_ID` | Apple Team ID |
| `APPLE_ID` | Apple ID email |
| `APPLE_APP_PASSWORD` | App-specific password |

## 📥 Installation

### Windows (Silent)

```batch
msiexec /i jarwis-agent.msi /quiet ACTIVATION_KEY=YOUR_KEY
```

### macOS (Silent)

```bash
sudo installer -pkg jarwis-agent.pkg -target /
sudo jarwis-agent --activate YOUR_KEY
```

### Linux (One-liner)

```bash
curl -sL https://jarwis.io/install.sh | sudo bash -s -- YOUR_KEY
```

### Linux (Manual)

**Ubuntu/Debian:**
```bash
sudo dpkg -i jarwis-agent_1.0.0_amd64.deb
sudo jarwis-agent --activate YOUR_KEY
sudo systemctl start jarwis-agent
```

**RHEL/CentOS:**
```bash
sudo rpm -i jarwis-agent-1.0.0-1.x86_64.rpm
sudo jarwis-agent --activate YOUR_KEY
sudo systemctl start jarwis-agent
```

## 🔧 Service Management

### Windows

```batch
sc query JarwisAgent           # Check status
sc start JarwisAgent           # Start
sc stop JarwisAgent            # Stop
```

### macOS

```bash
sudo launchctl list | grep jarwis    # Check status
sudo launchctl start com.jarwis.agent
sudo launchctl stop com.jarwis.agent
```

### Linux

```bash
sudo systemctl status jarwis-agent
sudo systemctl start jarwis-agent
sudo systemctl stop jarwis-agent
sudo journalctl -u jarwis-agent -f   # View logs
```

## 📊 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-19 | Initial release |

## 🔗 Related Documentation

- [Agent Architecture](../docs/agent-architecture.md)
- [API Reference](../docs/api-reference.md)
- [Troubleshooting Guide](../docs/troubleshooting.md)
