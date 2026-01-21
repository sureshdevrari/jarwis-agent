# Jarwis Agent Installation Guide

## ⚠️ Important: Security Warnings

Jarwis Agent installers are **not code-signed** (we do not have an Apple Developer account or Microsoft EV certificate). This is common for open-source and smaller software projects.

**Your download is safe** - all releases are built automatically via GitHub Actions and you can verify the source code.

---

## 📦 Windows Installation

### Option 1: GUI Installer (Recommended)

1. Download `jarwis-agent-X.X.X-setup.exe` from the [Releases page](https://github.com/sureshdevrari/jarwis-agent/releases)

2. **Run the installer** - You'll see SmartScreen warning:
   
   ![SmartScreen Warning](https://docs.microsoft.com/en-us/windows/security/threat-protection/images/smartscreen-app-reputation.png)
   
3. **Bypass SmartScreen:**
   - Click **"More info"** (small blue text)
   - Click **"Run anyway"**

4. Follow the installation wizard

### Option 2: MSI (Enterprise/Silent)

For enterprise deployment or silent installation:

```powershell
# Download the MSI
$url = "https://github.com/sureshdevrari/jarwis-agent/releases/latest/download/jarwis-agent-2.1.0.msi"
Invoke-WebRequest -Uri $url -OutFile jarwis-agent.msi

# Install silently
msiexec /i jarwis-agent.msi /quiet ACTIVATION_KEY=your-activation-key

# Or with GUI
msiexec /i jarwis-agent.msi ACTIVATION_KEY=your-activation-key
```

**MSI Properties:**
- `INSTALLDIR` - Installation directory (default: `C:\Program Files\Jarwis Security\Jarwis Agent`)
- `ACTIVATION_KEY` - License activation key
- `INSTALL_SERVICE` - Set to `1` to install as Windows service

### SmartScreen Details

**Why does this happen?**
Windows SmartScreen checks for a valid Authenticode digital signature from a trusted Certificate Authority. Since our app is unsigned, Windows shows a warning.

**Building reputation:**
SmartScreen uses a reputation system. After enough users download and run the app without issues, the warning may disappear. This typically requires:
- EV (Extended Validation) code signing certificate ($300-500/year)
- Or thousands of verified downloads

---

## 🍎 macOS Installation

### Option 1: PKG Installer

1. Download `jarwis-agent-X.X.X-intel.pkg` (Intel) or `jarwis-agent-X.X.X-apple-silicon.pkg` (M1/M2/M3)

2. **Double-click to install** - You'll see Gatekeeper warning:
   
   > "jarwis-agent-X.X.X.pkg" cannot be opened because it is from an unidentified developer.

3. **Bypass Gatekeeper:**
   
   **Method 1 - System Settings (Recommended):**
   - Go to **System Settings** → **Privacy & Security**
   - Scroll down to find "jarwis-agent was blocked..."
   - Click **"Open Anyway"**
   - Enter your password if prompted
   
   **Method 2 - Right-click:**
   - Right-click (or Ctrl+click) the `.pkg` file
   - Select **"Open"** from the context menu
   - Click **"Open"** in the dialog
   
   **Method 3 - Terminal (Advanced):**
   ```bash
   # Remove quarantine attribute
   xattr -dr com.apple.quarantine ~/Downloads/jarwis-agent-*.pkg
   
   # Then double-click to install normally
   ```

### Option 2: DMG (Manual Installation)

1. Download `JarwisAgentSetup-X.X.X-*.dmg`
2. Double-click to mount
3. Drag the app to Applications (or run the PKG inside)
4. Follow the same Gatekeeper bypass above

### After Installation

```bash
# Verify installation
/usr/local/bin/jarwis-agent --version

# Start the agent
sudo launchctl load /Library/LaunchDaemons/com.jarwis.agent.plist

# Check status
sudo launchctl list | grep jarwis

# View logs
tail -f /var/log/jarwis/agent.log
```

### Gatekeeper Details

**Why does this happen?**
macOS Gatekeeper requires apps to be:
1. Signed with an Apple Developer ID certificate (~$99/year)
2. Notarized by Apple (uploaded for automated malware scanning)

**Our app uses "ad-hoc" signing** which allows it to run after manual approval, but doesn't have Apple's trust chain.

---

## 🐧 Linux Installation

Linux does not require code signing - no warnings will appear.

### Debian/Ubuntu (.deb)

```bash
# Download the .deb package
wget https://github.com/sureshdevrari/jarwis-agent/releases/latest/download/jarwis-agent_2.1.0_amd64.deb

# Install
sudo dpkg -i jarwis-agent_*.deb

# Fix any dependency issues
sudo apt-get install -f

# Start service
sudo systemctl enable jarwis-agent
sudo systemctl start jarwis-agent

# Check status
sudo systemctl status jarwis-agent
```

### RHEL/CentOS/Fedora (.rpm)

```bash
# Download the .rpm package
wget https://github.com/sureshdevrari/jarwis-agent/releases/latest/download/jarwis-agent-2.1.0-1.x86_64.rpm

# Install
sudo rpm -i jarwis-agent-*.rpm
# Or with yum/dnf
sudo dnf install jarwis-agent-*.rpm

# Start service
sudo systemctl enable jarwis-agent
sudo systemctl start jarwis-agent
```

### Tarball (Generic Linux)

```bash
# Download and extract
wget https://github.com/sureshdevrari/jarwis-agent/releases/latest/download/jarwis-agent-2.1.0-linux-x86_64.tar.gz
sudo tar -xzf jarwis-agent-*.tar.gz -C /

# The files are installed to:
# /usr/bin/jarwis-agent
# /etc/jarwis/config.yaml
# /lib/systemd/system/jarwis-agent.service

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable jarwis-agent
sudo systemctl start jarwis-agent
```

---

## 🔧 Configuration

The configuration file is located at:
- **Windows:** `C:\Program Files\Jarwis Security\Jarwis Agent\config.yaml`
- **macOS:** `/usr/local/etc/jarwis/config.yaml`
- **Linux:** `/etc/jarwis/config.yaml`

### Basic Configuration

```yaml
# Jarwis Agent Configuration
agent:
  # Unique identifier (auto-generated)
  id: null
  
  # Activation key from your Jarwis account
  activation_key: "your-key-here"
  
  # Server connection
  server_url: "https://api.jarwis.io"
  
  # Logging level (DEBUG, INFO, WARNING, ERROR)
  log_level: INFO

# Proxy settings (optional)
proxy:
  enabled: false
  http: "http://proxy:8080"
  https: "http://proxy:8080"
  no_proxy: "localhost,127.0.0.1"
```

### Using the Config Tool

```bash
# Windows
"C:\Program Files\Jarwis Security\Jarwis Agent\jarwis-config.exe" --set activation_key=YOUR_KEY

# macOS/Linux
jarwis-config --set activation_key=YOUR_KEY
jarwis-config --get activation_key
jarwis-config --test-connection
```

---

## 🔍 Troubleshooting

### Windows

**Issue:** Installation fails with "Access Denied"
```powershell
# Run installer as Administrator
Start-Process .\jarwis-agent-setup.exe -Verb RunAs
```

**Issue:** Service won't start
```powershell
# Check Windows Event Log
Get-EventLog -LogName Application -Source "Jarwis Agent" -Newest 20

# Reinstall service
sc delete "Jarwis Agent"
"C:\Program Files\Jarwis Security\Jarwis Agent\jarwis-agent.exe" --install-service
```

### macOS

**Issue:** "jarwis-agent" is damaged and can't be opened
```bash
# This means Gatekeeper blocked it - use the bypass methods above
xattr -cr /Applications/JarwisAgent.app
# or
xattr -dr com.apple.quarantine /usr/local/bin/jarwis-agent
```

**Issue:** Permission denied on /var/log/jarwis
```bash
sudo mkdir -p /var/log/jarwis
sudo chown $USER:staff /var/log/jarwis
```

### Linux

**Issue:** systemd service fails to start
```bash
# Check logs
sudo journalctl -u jarwis-agent -f

# Check permissions
ls -la /usr/bin/jarwis-agent
ls -la /etc/jarwis/config.yaml

# Fix permissions if needed
sudo chmod 755 /usr/bin/jarwis-agent
sudo chmod 644 /etc/jarwis/config.yaml
```

**Issue:** Missing dependencies (glibc)
```bash
# Check what's missing
ldd /usr/bin/jarwis-agent | grep "not found"

# Install glibc
sudo apt-get install libc6  # Debian/Ubuntu
sudo yum install glibc      # RHEL/CentOS
```

---

## 📊 Verifying the Download

You can verify your download hasn't been tampered with:

```bash
# Download the checksums file
wget https://github.com/sureshdevrari/jarwis-agent/releases/latest/download/SHA256SUMS

# Verify (Linux/macOS)
sha256sum -c SHA256SUMS

# Verify (Windows PowerShell)
Get-FileHash jarwis-agent-*-setup.exe | Format-List
```

Or check the build logs directly:
1. Go to the [Actions tab](https://github.com/sureshdevrari/jarwis-agent/actions)
2. Find the release workflow run
3. Download and inspect the artifacts

---

## 🆘 Getting Help

- **Documentation:** https://docs.jarwis.io
- **GitHub Issues:** https://github.com/sureshdevrari/jarwis-agent/issues
- **Email Support:** support@jarwis.io

---

## 📝 Uninstallation

### Windows
```powershell
# Via Control Panel
# Settings → Apps → Jarwis Agent → Uninstall

# Or via MSI
msiexec /x jarwis-agent-*.msi /quiet

# Or via command line
"C:\Program Files\Jarwis Security\Jarwis Agent\uninstall.exe" /S
```

### macOS
```bash
# Stop and unload service
sudo launchctl unload /Library/LaunchDaemons/com.jarwis.agent.plist

# Remove files
sudo rm /usr/local/bin/jarwis-agent
sudo rm /Library/LaunchDaemons/com.jarwis.agent.plist
sudo rm -rf /usr/local/etc/jarwis
sudo rm -rf /var/log/jarwis
```

### Linux
```bash
# Debian/Ubuntu
sudo apt remove jarwis-agent

# RHEL/CentOS/Fedora
sudo rpm -e jarwis-agent

# Manual cleanup
sudo systemctl stop jarwis-agent
sudo systemctl disable jarwis-agent
sudo rm /usr/bin/jarwis-agent
sudo rm /lib/systemd/system/jarwis-agent.service
sudo rm -rf /etc/jarwis
sudo rm -rf /var/log/jarwis
```
