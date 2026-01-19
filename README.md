# Jarwis Security Agent

Cross-platform agent for Jarwis Security Testing Platform.

## Supported Platforms

| Platform | Format | Status |
|----------|--------|--------|
| Windows 10/11 | `.exe` | ✅ |
| macOS 11+ | `.dmg` | ✅ |
| Linux (Debian/Ubuntu) | `.deb` | ✅ |
| Linux (RHEL/Fedora) | `.rpm` | ✅ |

## Installation

### Windows
```
jarwis-agent.exe --activate YOUR_KEY
```

### macOS
```bash
# Mount DMG and copy to Applications, then:
sudo /Applications/jarwis-agent --install
jarwis-agent --activate YOUR_KEY
```

### Linux (Debian/Ubuntu)
```bash
sudo dpkg -i jarwis-agent_*_amd64.deb
sudo jarwis-agent --activate YOUR_KEY
sudo systemctl start jarwis-agent
```

### Linux (RHEL/Fedora)
```bash
sudo rpm -i jarwis-agent-*.x86_64.rpm
sudo jarwis-agent --activate YOUR_KEY
sudo systemctl start jarwis-agent
```

## Building from Source

### Prerequisites
- Python 3.11+
- PyInstaller

### Build
```bash
pip install -r requirements.txt
pip install pyinstaller
pyinstaller installer/jarwis-agent.spec
```

## License

Proprietary - Jarwis Security
