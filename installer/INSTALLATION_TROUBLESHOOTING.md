# Jarwis Agent - Installation Troubleshooting Guide

This guide helps resolve common installation issues across Windows, macOS, and Linux platforms.

## Table of Contents
- [Windows Installation Issues](#windows-installation-issues)
- [macOS Installation Issues](#macos-installation-issues)
- [Linux Installation Issues](#linux-installation-issues)
- [Runtime Dependencies](#runtime-dependencies)
- [Getting Help](#getting-help)

---

## Windows Installation Issues

### Windows SmartScreen Warning

When installing an unsigned version of Jarwis Agent, Windows SmartScreen may display a warning:

![SmartScreen Warning](https://jarwis.io/docs/images/smartscreen-warning.png)

**"Windows protected your PC"** or **"Windows Defender SmartScreen prevented an unrecognized app from starting"**

#### How to Bypass (Trusted Source Only)

> ⚠️ **Only bypass this warning if you downloaded the installer from the official Jarwis website or your organization's approved source.**

1. Click **"More info"** (on the warning dialog)
2. Click **"Run anyway"**
3. If prompted by UAC, click **"Yes"** to allow the installation

#### For IT Administrators (Group Policy)

To pre-approve Jarwis Agent for your organization:

**Option 1: Add to Windows Defender Exclusions**
```powershell
# Run as Administrator
Add-MpPreference -ExclusionPath "C:\Program Files\Jarwis Agent"
```

**Option 2: Deploy via SCCM/Intune**
- Use the MSI installer (`jarwis-agent_x64.msi`) for silent deployment
- Silent install: `msiexec /i jarwis-agent_x64.msi /quiet ACTIVATION_KEY=your-key`

**Option 3: Mark as trusted via Group Policy**
1. Open Group Policy Editor
2. Navigate to: Computer Configuration → Administrative Templates → Windows Components → Windows Defender SmartScreen
3. Configure "Configure App Install Control" to allow apps from anywhere

### Windows Defender Blocking Installation

If Windows Defender flags the installer as a potential threat:

1. **Check the detection name** - If it mentions "HackTool", "Frida", or "MITM", this is a false positive due to legitimate security testing tools
2. **Submit false positive report** to Microsoft
3. **Add exclusion temporarily**:
   ```powershell
   # Add exclusion for installer
   Add-MpPreference -ExclusionPath "C:\Users\$env:USERNAME\Downloads\jarwis-agent-setup.exe"
   
   # After installation, add exclusion for install directory
   Add-MpPreference -ExclusionPath "C:\Program Files\Jarwis Agent"
   ```

### Service Failed to Start

If the Jarwis Agent service fails to start after installation:

1. **Check Windows Event Viewer**:
   - Open Event Viewer → Windows Logs → Application
   - Look for errors from "JarwisAgent"

2. **Verify port availability**:
   ```powershell
   netstat -an | findstr "8082"
   ```
   The MITM proxy uses port 8082 by default.

3. **Run manual start for debugging**:
   ```powershell
   cd "C:\Program Files\Jarwis Agent"
   .\jarwis-agent.exe --debug
   ```

---

## macOS Installation Issues

### Gatekeeper Warning

When opening an unsigned or non-notarized PKG installer, macOS Gatekeeper shows:

**"jarwis-agent.pkg cannot be opened because it is from an unidentified developer"**

#### How to Bypass (Trusted Source Only)

> ⚠️ **Only bypass if you downloaded from the official Jarwis website or your organization's approved source.**

**Method 1: Right-click Open**
1. Locate the `.pkg` file in Finder
2. **Right-click** (or Control-click) the file
3. Select **"Open"** from the context menu
4. Click **"Open"** in the dialog that appears

**Method 2: System Preferences**
1. Try to open the installer normally (it will be blocked)
2. Open **System Preferences** → **Security & Privacy** → **General**
3. Look for the message about the blocked app
4. Click **"Open Anyway"**
5. Enter your administrator password

**Method 3: Terminal (Advanced)**
```bash
# Remove quarantine attribute
sudo xattr -rd com.apple.quarantine /path/to/jarwis-agent.pkg

# Or disable Gatekeeper temporarily (not recommended for general use)
sudo spctl --master-disable
# Install the package
# Then re-enable:
sudo spctl --master-enable
```

### Apple Silicon (M1/M2/M3) Compatibility

Jarwis Agent supports both Intel and Apple Silicon Macs. If you encounter issues:

1. **Check architecture**:
   ```bash
   file /usr/local/bin/jarwis-agent
   ```
   Should show `arm64` for Apple Silicon or `x86_64` for Intel.

2. **For Rosetta 2 issues**:
   ```bash
   # Install Rosetta 2 if needed
   softwareupdate --install-rosetta --agree-to-license
   ```

3. **Download correct version**:
   - `jarwis-agent-*-apple-silicon.dmg` for M1/M2/M3 Macs
   - `jarwis-agent-*-intel.dmg` for Intel Macs
   - `jarwis-agent-*-universal.dmg` works on both

### Full Disk Access Required

For complete security scanning, Jarwis Agent may need Full Disk Access:

1. Open **System Preferences** → **Security & Privacy** → **Privacy**
2. Select **"Full Disk Access"** in the left panel
3. Click the **lock icon** and enter your password
4. Click **"+"** and add `/usr/local/bin/jarwis-agent`

### Notarization Issues

If macOS reports "This app is damaged and can't be opened":

```bash
# Check signature
codesign -dv --verbose=4 /usr/local/bin/jarwis-agent

# Check notarization status
spctl -a -v /usr/local/bin/jarwis-agent

# Clear extended attributes
xattr -cr /usr/local/bin/jarwis-agent
```

---

## Linux Installation Issues

### Package Installation Errors

#### Debian/Ubuntu (DEB)

```bash
# If dpkg reports missing dependencies
sudo apt-get install -f

# Force install (use with caution)
sudo dpkg -i --force-depends jarwis-agent_*.deb
```

#### RHEL/CentOS/Fedora (RPM)

```bash
# If rpm reports missing dependencies
sudo yum install jarwis-agent-*.rpm --skip-broken

# Or with DNF
sudo dnf install jarwis-agent-*.rpm --allowerasing
```

### Service Won't Start

```bash
# Check service status
sudo systemctl status jarwis-agent

# View logs
sudo journalctl -u jarwis-agent -f

# Check for port conflicts
sudo ss -tlnp | grep 8082

# Manually run for debugging
sudo /usr/bin/jarwis-agent --debug
```

### SELinux Blocking Agent

On RHEL/CentOS with SELinux enabled:

```bash
# Check for AVC denials
sudo ausearch -m AVC -ts recent | grep jarwis

# Create and install policy module
sudo audit2allow -a -M jarwis-agent
sudo semodule -i jarwis-agent.pp
```

---

## Runtime Dependencies

Jarwis Agent requires several tools for full functionality. Install based on your needs:

### Network Scanning (Nmap)

| Platform | Installation |
|----------|-------------|
| Windows | Download from https://nmap.org/download.html |
| macOS | `brew install nmap` |
| Linux | `sudo apt install nmap` or `sudo yum install nmap` |

### Mobile Testing (Android SDK)

| Platform | Installation |
|----------|-------------|
| Windows | Download Android Studio or SDK Platform Tools |
| macOS | `brew install android-platform-tools` |
| Linux | `sudo apt install android-tools-adb` |

Ensure `adb` is in your PATH:
```bash
adb version
```

### Cloud Security Scanning

**AWS CLI:**
```bash
# All platforms
pip install awscli
aws configure
```

**Google Cloud SDK:**
```bash
# All platforms - see https://cloud.google.com/sdk/docs/install
gcloud init
```

**Azure CLI:**
```bash
# All platforms - see https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
az login
```

### Checking All Dependencies

Run the built-in dependency checker:
```bash
jarwis-agent --check-deps
```

Or use the first-run wizard which automatically detects missing dependencies.

---

## Getting Help

### Logs Location

| Platform | Log Path |
|----------|----------|
| Windows | `C:\Program Files\Jarwis Agent\logs\agent.log` |
| macOS | `/var/log/jarwis/agent.log` |
| Linux | `/var/log/jarwis/agent.log` |

### Diagnostic Command

```bash
jarwis-agent --diagnostic > diagnostic-report.txt
```

### Support Channels

- **Documentation**: https://jarwis.io/docs
- **Support Portal**: https://jarwis.io/support
- **Email**: support@jarwis.io
- **GitHub Issues**: https://github.com/jarwis-security/agent/issues

When reporting issues, please include:
1. Operating system and version
2. Jarwis Agent version (`jarwis-agent --version`)
3. Error messages from logs
4. Output of `jarwis-agent --diagnostic`
