# Jarwis Security Agent

Cross-platform agent for the Jarwis Security Testing Platform.

## Features

- **Professional Installer** - Modern GUI setup wizard with branding and EULA
- **System Tray Application** - Real-time connection status indicator
- **Windows Service** - Automatic startup and background operation
- **Cross-Platform** - Windows, macOS, and Linux support
- **Secure Communication** - Encrypted connection to Jarwis server

## Supported Platforms

| Platform | Format | Recommended |
|----------|--------|-------------|
| Windows 10/11 | .exe (Setup Wizard) |  JarwisAgentSetup-GUI.exe |
| macOS 11+ | .dmg |  JarwisAgent-2.0.0.dmg |
| Linux (Debian/Ubuntu) | .deb |  jarwis-agent_2.0.0_amd64.deb |
| Linux (RHEL/Fedora) | .rpm |  jarwis-agent-2.0.0-1.x86_64.rpm |

## Installation

### Windows (Recommended)

1. Download `JarwisAgentSetup-GUI.exe` from the [Releases](https://github.com/sureshdevrari/jarwis-agent/releases)
2. Run the installer (requires Administrator privileges)
3. Follow the setup wizard:
   - Accept the license agreement
   - Choose installation location
   - Select features (Windows Service, System Tray, Desktop Shortcut)
   - Configure server URL
   - Enter activation key (optional)
4. Click Finish to complete installation

The agent will automatically start as a Windows service.

### Windows (Silent Install)

```batch
JarwisAgentSetup-GUI.exe /S /D=C:\Program Files\Jarwis\Agent
```

### macOS

```bash
# Mount the DMG
hdiutil attach JarwisAgent-2.0.0.dmg

# Copy to Applications
cp -R "/Volumes/Jarwis Agent/Jarwis Agent.app" /Applications/

# Unmount
hdiutil detach "/Volumes/Jarwis Agent"

# Activate
/Applications/Jarwis\ Agent.app/Contents/MacOS/jarwis-agent --activate YOUR_KEY
```

### Linux (Debian/Ubuntu)

```bash
sudo dpkg -i jarwis-agent_2.0.0_amd64.deb
sudo jarwis-agent --activate YOUR_KEY
sudo systemctl enable jarwis-agent
sudo systemctl start jarwis-agent
```

### Linux (RHEL/Fedora)

```bash
sudo rpm -i jarwis-agent-2.0.0-1.x86_64.rpm
sudo jarwis-agent --activate YOUR_KEY
sudo systemctl enable jarwis-agent
sudo systemctl start jarwis-agent
```

## Configuration

The configuration file is located at:
- **Windows:** `C:\Program Files\Jarwis\Agent\config\config.yaml`
- **macOS:** `/Applications/Jarwis Agent.app/Contents/Resources/config.yaml`
- **Linux:** `/etc/jarwis/config.yaml`

## System Tray

The system tray application provides:
- **Status Indicator** - Green (connected), Yellow (connecting), Red (error)
- **Quick Actions** - Open dashboard, restart service, view status details
- **Notifications** - Connection status changes

## Building from Source

### Prerequisites

- Python 3.11+
- PyInstaller
- PyQt6 (for GUI)
- Pillow (for icon generation)

### Build

```bash
# Clone the repository
git clone https://github.com/sureshdevrari/jarwis-agent.git
cd jarwis-agent

# Install dependencies
pip install -r requirements.txt
pip install pyinstaller pywin32

# Generate branding assets
cd installer/assets
python create_icons.py
cd ../..

# Build agent executable
pyinstaller installer/jarwis-agent.spec --clean --noconfirm

# Build system tray app
pyinstaller --name jarwis-tray --onefile --windowed \
    --icon=installer/assets/icons/jarwis-agent.ico \
    --add-data "assets/logos/PNG-01.png;assets/logos" \
    installer/gui/system_tray.py

# Build GUI setup wizard
pyinstaller --name JarwisAgentSetup-GUI --onefile --windowed \
    --icon=installer/assets/icons/jarwis-agent.ico \
    --add-data "assets/logos/PNG-01.png;assets/logos" \
    --add-data "installer/LICENSE.rtf;." \
    --add-data "config/config.yaml;config" \
    --uac-admin \
    installer/gui/setup_wizard.py
```

### Build Inno Setup Installer (Windows)

1. Install [Inno Setup 6](https://jrsoftware.org/isinfo.php)
2. Run: `"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer/inno/jarwis-agent.iss`

## Uninstallation

### Windows
- Use "Add or Remove Programs" in Windows Settings
- Or run: `"C:\Program Files\Jarwis\Agent\uninstall.exe"`

### Linux
```bash
# Debian/Ubuntu
sudo dpkg -r jarwis-agent

# RHEL/Fedora
sudo rpm -e jarwis-agent
```

## License

Proprietary - Jarwis Security

## Support

- Website: https://jarwis.ai
- Email: support@jarwis.ai
- Documentation: https://docs.jarwis.ai
