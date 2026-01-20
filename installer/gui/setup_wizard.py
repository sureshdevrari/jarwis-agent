#!/usr/bin/env python3
"""
Jarwis Agent Setup Wizard

A professional GUI installer wizard for Jarwis Security Agent.
Provides a corporate-grade installation experience with:
- Welcome screen with branding
- License agreement acceptance
- Installation path selection
- Feature selection
- Configuration options
- Progress tracking
- Post-install actions

Requirements:
    pip install PyQt6

Usage:
    python setup_wizard.py [--server-url URL] [--activation-key KEY]
"""

import sys
import os
import subprocess
import shutil
import json
import platform
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

# Platform-specific imports
IS_WINDOWS = platform.system() == 'Windows'
if IS_WINDOWS:
    import winreg
    import ctypes
else:
    winreg = None
    ctypes = None

try:
    from PyQt6.QtWidgets import (
        QApplication, QWizard, QWizardPage, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QCheckBox, QRadioButton, QButtonGroup,
        QProgressBar, QPushButton, QTextEdit, QFileDialog, QMessageBox,
        QGroupBox, QFrame, QSizePolicy, QSpacerItem, QWidget
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
    from PyQt6.QtGui import QPixmap, QFont, QIcon, QPalette, QColor
except ImportError:
    print("ERROR: PyQt6 is required. Install with: pip install PyQt6")
    sys.exit(1)


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class InstallConfig:
    """Installation configuration."""
    install_path: str = r"C:\Program Files\Jarwis Agent"
    server_url: str = "wss://jarwis.io/ws/agent"
    activation_key: str = ""
    install_service: bool = True
    auto_start: bool = True
    start_on_boot: bool = True
    create_shortcuts: bool = True
    send_telemetry: bool = True
    features: dict = field(default_factory=lambda: {
        'web_scanning': True,
        'mobile_scanning': True,
        'network_scanning': True,
        'cloud_scanning': True,
        'sast_scanning': True,
    })


# ============================================================================
# Styles
# ============================================================================

STYLESHEET = """
QWizard {
    background-color: #ffffff;
}

QWizardPage {
    background-color: #ffffff;
}

QLabel {
    color: #333333;
}

QLabel#titleLabel {
    font-size: 18px;
    font-weight: bold;
    color: #182038;
    margin-bottom: 10px;
}

QLabel#subtitleLabel {
    font-size: 12px;
    color: #666666;
    margin-bottom: 20px;
}

QLabel#brandLabel {
    font-size: 24px;
    font-weight: bold;
    color: #182038;
}

QGroupBox {
    font-weight: bold;
    border: 1px solid #cccccc;
    border-radius: 5px;
    margin-top: 10px;
    padding-top: 10px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px;
}

QLineEdit {
    padding: 8px;
    border: 1px solid #cccccc;
    border-radius: 4px;
    background-color: #ffffff;
}

QLineEdit:focus {
    border-color: #4a90d9;
}

QCheckBox {
    spacing: 8px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
}

QPushButton {
    padding: 8px 16px;
    border: 1px solid #cccccc;
    border-radius: 4px;
    background-color: #f5f5f5;
}

QPushButton:hover {
    background-color: #e5e5e5;
}

QPushButton#primaryButton {
    background-color: #4a90d9;
    color: white;
    border-color: #3a80c9;
}

QPushButton#primaryButton:hover {
    background-color: #3a80c9;
}

QProgressBar {
    border: 1px solid #cccccc;
    border-radius: 4px;
    text-align: center;
    height: 24px;
}

QProgressBar::chunk {
    background-color: #4a90d9;
    border-radius: 3px;
}

QTextEdit {
    border: 1px solid #cccccc;
    border-radius: 4px;
    background-color: #f9f9f9;
}

QFrame#sidePanel {
    background-color: #182038;
}
"""


# ============================================================================
# Worker Thread for Installation
# ============================================================================

class InstallWorker(QThread):
    """Background worker for installation tasks."""
    
    progress = pyqtSignal(int, str)  # progress %, message
    finished = pyqtSignal(bool, str)  # success, message
    
    def __init__(self, config: InstallConfig, source_dir: Path):
        super().__init__()
        self.config = config
        self.source_dir = source_dir
    
    def run(self):
        try:
            install_path = Path(self.config.install_path)
            
            # Step 1: Create directories
            self.progress.emit(10, "Creating installation directories...")
            install_path.mkdir(parents=True, exist_ok=True)
            (install_path / 'logs').mkdir(exist_ok=True)
            (install_path / 'data').mkdir(exist_ok=True)
            
            # Step 2: Copy files
            self.progress.emit(30, "Copying agent files...")
            self._copy_files(install_path)
            
            # Step 3: Create configuration
            self.progress.emit(50, "Creating configuration...")
            self._create_config(install_path)
            
            # Step 4: Install Windows service
            if self.config.install_service:
                self.progress.emit(70, "Installing Windows service...")
                self._install_service(install_path)
            
            # Step 5: Create shortcuts
            if self.config.create_shortcuts:
                self.progress.emit(85, "Creating shortcuts...")
                self._create_shortcuts(install_path)
            
            # Step 6: Add to registry
            self.progress.emit(95, "Registering application...")
            self._register_app(install_path)
            
            self.progress.emit(100, "Installation complete!")
            self.finished.emit(True, "Jarwis Agent has been installed successfully.")
            
        except Exception as e:
            self.finished.emit(False, f"Installation failed: {str(e)}")
    
    def _copy_files(self, install_path: Path):
        """Copy installation files."""
        # Copy main executable
        exe_src = self.source_dir / 'jarwis-agent.exe'
        if exe_src.exists():
            shutil.copy2(exe_src, install_path / 'jarwis-agent.exe')
        
        # Copy config template
        config_src = self.source_dir / 'config.yaml'
        if config_src.exists():
            shutil.copy2(config_src, install_path / 'config.yaml')
        
        # Copy license
        license_src = self.source_dir / 'LICENSE.txt'
        if license_src.exists():
            shutil.copy2(license_src, install_path / 'LICENSE.txt')
    
    def _create_config(self, install_path: Path):
        """Create agent configuration file."""
        config_content = f"""# Jarwis Agent Configuration
# Generated by Setup Wizard

server:
  url: "{self.config.server_url}"
  reconnect_interval: 30
  heartbeat_interval: 15

agent:
  activation_key: "{self.config.activation_key}"
  auto_start: {str(self.config.auto_start).lower()}
  telemetry_enabled: {str(self.config.send_telemetry).lower()}

features:
  web_scanning: {str(self.config.features.get('web_scanning', True)).lower()}
  mobile_scanning: {str(self.config.features.get('mobile_scanning', True)).lower()}
  network_scanning: {str(self.config.features.get('network_scanning', True)).lower()}
  cloud_scanning: {str(self.config.features.get('cloud_scanning', True)).lower()}
  sast_scanning: {str(self.config.features.get('sast_scanning', True)).lower()}

logging:
  level: INFO
  file: logs/agent.log
  max_size_mb: 50
  backup_count: 5
"""
        (install_path / 'agent-config.yaml').write_text(config_content)
    
    def _install_service(self, install_path: Path):
        """Install Windows service."""
        exe_path = install_path / 'jarwis-agent.exe'
        
        # Stop existing service if running
        subprocess.run(
            ['sc', 'stop', 'JarwisAgent'],
            capture_output=True
        )
        
        # Delete existing service
        subprocess.run(
            ['sc', 'delete', 'JarwisAgent'],
            capture_output=True
        )
        
        # Create new service
        result = subprocess.run([
            'sc', 'create', 'JarwisAgent',
            f'binPath= "{exe_path}" --service',
            'DisplayName= Jarwis Security Agent',
            'start= auto',
            'obj= LocalSystem'
        ], capture_output=True)
        
        # Set service description
        subprocess.run([
            'sc', 'description', 'JarwisAgent',
            'Background agent for Jarwis security testing platform. Connects to cloud for vulnerability scanning.'
        ], capture_output=True)
        
        # Configure service recovery
        subprocess.run([
            'sc', 'failure', 'JarwisAgent',
            'reset= 86400', 'actions= restart/60000/restart/60000/restart/60000'
        ], capture_output=True)
        
        # Start service if auto_start
        if self.config.auto_start:
            subprocess.run(['sc', 'start', 'JarwisAgent'], capture_output=True)
    
    def _create_shortcuts(self, install_path: Path):
        """Create Start Menu shortcuts."""
        try:
            import winshell
            from win32com.client import Dispatch
        except ImportError:
            # Fallback: use PowerShell to create shortcuts
            self._create_shortcuts_powershell(install_path)
            return
        
        # Start Menu folder
        programs = winshell.programs()
        jarwis_folder = Path(programs) / 'Jarwis Security'
        jarwis_folder.mkdir(exist_ok=True)
        
        # Create shortcut
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(str(jarwis_folder / 'Jarwis Agent.lnk'))
        shortcut.Targetpath = str(install_path / 'jarwis-agent.exe')
        shortcut.WorkingDirectory = str(install_path)
        shortcut.Description = 'Jarwis Security Agent'
        shortcut.save()
    
    def _create_shortcuts_powershell(self, install_path: Path):
        """Create shortcuts using PowerShell (fallback)."""
        ps_script = f'''
$WshShell = New-Object -ComObject WScript.Shell
$StartMenu = [Environment]::GetFolderPath('StartMenu')
$JarwisFolder = Join-Path $StartMenu 'Programs\\Jarwis Security'
New-Item -ItemType Directory -Force -Path $JarwisFolder | Out-Null

$Shortcut = $WshShell.CreateShortcut("$JarwisFolder\\Jarwis Agent.lnk")
$Shortcut.TargetPath = "{install_path}\\jarwis-agent.exe"
$Shortcut.WorkingDirectory = "{install_path}"
$Shortcut.Description = "Jarwis Security Agent"
$Shortcut.Save()
'''
        subprocess.run(['powershell', '-Command', ps_script], capture_output=True)
    
    def _register_app(self, install_path: Path):
        """Register application in Windows registry (Windows only)."""
        if not IS_WINDOWS or winreg is None:
            return  # Skip on non-Windows platforms
            
        try:
            # Add to installed programs
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\JarwisAgent"
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "Jarwis Security Agent")
            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, "2.1.0")
            winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "Jarwis Security")
            winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(install_path))
            winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, 
                             f'"{install_path}\\jarwis-agent.exe" --uninstall')
            winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, 
                             f'{install_path}\\jarwis-agent.exe,0')
            winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "URLInfoAbout", 0, winreg.REG_SZ, "https://jarwis.io")
            winreg.SetValueEx(key, "HelpLink", 0, winreg.REG_SZ, "https://jarwis.io/docs")
            
            winreg.CloseKey(key)
            
            # Add agent settings
            key_path = r"SOFTWARE\Jarwis\Agent"
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            
            winreg.SetValueEx(key, "InstallPath", 0, winreg.REG_SZ, str(install_path))
            winreg.SetValueEx(key, "Version", 0, winreg.REG_SZ, "2.1.0")
            winreg.SetValueEx(key, "ServerUrl", 0, winreg.REG_SZ, self.config.server_url)
            
            winreg.CloseKey(key)
            
        except Exception as e:
            print(f"Warning: Could not write registry: {e}")


# ============================================================================
# Wizard Pages
# ============================================================================

class WelcomePage(QWizardPage):
    """Welcome page with branding."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("")
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Left side panel with branding
        side_panel = QFrame()
        side_panel.setObjectName("sidePanel")
        side_panel.setFixedWidth(200)
        side_layout = QVBoxLayout(side_panel)
        side_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Logo placeholder
        logo_label = QLabel("🛡️")
        logo_label.setStyleSheet("font-size: 64px; color: white;")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side_layout.addWidget(logo_label)
        
        brand_label = QLabel("JARWIS")
        brand_label.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        brand_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side_layout.addWidget(brand_label)
        
        sub_label = QLabel("Security Agent")
        sub_label.setStyleSheet("font-size: 14px; color: #aaaaaa;")
        sub_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side_layout.addWidget(sub_label)
        
        layout.addWidget(side_panel)
        
        # Right side content
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(40, 40, 40, 40)
        
        title = QLabel("Welcome to Jarwis Security Agent Setup")
        title.setObjectName("titleLabel")
        content_layout.addWidget(title)
        
        subtitle = QLabel("Version 2.0.0")
        subtitle.setObjectName("subtitleLabel")
        content_layout.addWidget(subtitle)
        
        description = QLabel(
            "This wizard will guide you through the installation of the "
            "Jarwis Security Agent on your computer.\n\n"
            "The agent enables comprehensive security testing including:\n"
            "• Web Application Security Testing\n"
            "• Mobile Application Analysis (Android/iOS)\n"
            "• Network Vulnerability Scanning\n"
            "• Cloud Security Assessment\n"
            "• Static Code Analysis (SAST)\n\n"
            "Click Next to continue, or Cancel to exit Setup."
        )
        description.setWordWrap(True)
        description.setStyleSheet("line-height: 1.5;")
        content_layout.addWidget(description)
        
        content_layout.addStretch()
        
        # System requirements
        req_group = QGroupBox("System Requirements")
        req_layout = QVBoxLayout(req_group)
        req_layout.addWidget(QLabel("• Windows 10/11 (64-bit)"))
        req_layout.addWidget(QLabel("• 4 GB RAM minimum (8 GB recommended)"))
        req_layout.addWidget(QLabel("• 500 MB available disk space"))
        req_layout.addWidget(QLabel("• Internet connection"))
        content_layout.addWidget(req_group)
        
        layout.addWidget(content)


class LicensePage(QWizardPage):
    """License agreement page."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("License Agreement")
        self.setSubTitle("Please read the following license agreement carefully.")
        
        layout = QVBoxLayout(self)
        
        # License text
        self.license_text = QTextEdit()
        self.license_text.setReadOnly(True)
        self.license_text.setPlainText(self._get_license_text())
        layout.addWidget(self.license_text)
        
        # Accept checkbox
        self.accept_check = QCheckBox("I accept the terms of the License Agreement")
        self.accept_check.stateChanged.connect(self.completeChanged)
        layout.addWidget(self.accept_check)
        
        self.registerField("acceptLicense*", self.accept_check)
    
    def _get_license_text(self) -> str:
        """Get license text from file or return default."""
        # Try to load from file
        license_file = Path(__file__).parent.parent / 'LICENSE.rtf'
        if license_file.exists():
            # RTF needs to be converted to plain text
            pass
        
        return """JARWIS SECURITY AGENT
END USER LICENSE AGREEMENT
Version 2.0 | Effective Date: January 2026

IMPORTANT: PLEASE READ THIS LICENSE AGREEMENT CAREFULLY BEFORE INSTALLING OR USING THE JARWIS SECURITY AGENT SOFTWARE.

1. ACCEPTANCE OF TERMS
By downloading, installing, copying, or otherwise using the Jarwis Security Agent ("Software"), you agree to be bound by the terms of this End User License Agreement ("Agreement"). If you do not agree to these terms, do not install or use the Software.

2. LICENSE GRANT
Subject to the terms of this Agreement, Jarwis Security grants you a limited, non-exclusive, non-transferable license to:
a. Install and use the Software on computers within your organization
b. Connect the Software to Jarwis cloud services for security testing purposes
c. Use the Software solely for authorized security testing of systems you own or have explicit permission to test

3. RESTRICTIONS
You shall NOT:
a. Reverse engineer, decompile, or disassemble the Software
b. Modify, adapt, or create derivative works based on the Software
c. Distribute, sell, lease, or sublicense the Software to third parties
d. Use the Software for unauthorized security testing or malicious purposes
e. Remove or alter any proprietary notices or labels on the Software
f. Use the Software in violation of any applicable laws or regulations

4. DATA COLLECTION AND PRIVACY
The Software collects and transmits the following data to Jarwis servers:
• System identification information (hostname, OS version)
• Network configuration data for security scanning
• Security scan results and vulnerability findings
• Agent connection status and performance metrics

This data is used solely for providing security testing services and is protected according to our Privacy Policy at https://jarwis.io/privacy

5. WARRANTY DISCLAIMER
THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.

6. LIMITATION OF LIABILITY
IN NO EVENT SHALL JARWIS SECURITY BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES.

Copyright © 2026 Jarwis Security. All rights reserved.
https://jarwis.io | support@jarwis.io
"""
    
    def isComplete(self) -> bool:
        return self.accept_check.isChecked()


class InstallLocationPage(QWizardPage):
    """Installation location selection page."""
    
    def __init__(self, config: InstallConfig, parent=None):
        super().__init__(parent)
        self.config = config
        self.setTitle("Installation Location")
        self.setSubTitle("Choose where to install Jarwis Security Agent.")
        
        layout = QVBoxLayout(self)
        
        # Path selection
        path_group = QGroupBox("Destination Folder")
        path_layout = QHBoxLayout(path_group)
        
        self.path_edit = QLineEdit(self.config.install_path)
        self.path_edit.textChanged.connect(self._update_space_info)
        path_layout.addWidget(self.path_edit)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse)
        path_layout.addWidget(browse_btn)
        
        layout.addWidget(path_group)
        
        # Space info
        self.space_label = QLabel()
        self._update_space_info()
        layout.addWidget(self.space_label)
        
        layout.addStretch()
        
        self.registerField("installPath", self.path_edit)
    
    def _browse(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select Installation Folder", self.path_edit.text()
        )
        if path:
            self.path_edit.setText(path)
    
    def _update_space_info(self):
        path = self.path_edit.text()
        try:
            if path:
                drive = Path(path).anchor
                total, used, free = shutil.disk_usage(drive)
                free_gb = free / (1024**3)
                self.space_label.setText(
                    f"Space required: ~200 MB | Available on {drive}: {free_gb:.1f} GB"
                )
        except Exception:
            self.space_label.setText("Space required: ~200 MB")
    
    def validatePage(self) -> bool:
        self.config.install_path = self.path_edit.text()
        return True


class FeatureSelectionPage(QWizardPage):
    """Feature selection page."""
    
    def __init__(self, config: InstallConfig, parent=None):
        super().__init__(parent)
        self.config = config
        self.setTitle("Feature Selection")
        self.setSubTitle("Select the security testing features you want to enable.")
        
        layout = QVBoxLayout(self)
        
        # Features group
        features_group = QGroupBox("Security Testing Features")
        features_layout = QVBoxLayout(features_group)
        
        self.feature_checks = {}
        
        features = [
            ('web_scanning', 'Web Application Security', 
             'OWASP Top 10, API testing, authentication analysis'),
            ('mobile_scanning', 'Mobile Application Security', 
             'Android/iOS static and dynamic analysis'),
            ('network_scanning', 'Network Security', 
             'Port scanning, service enumeration, vulnerability detection'),
            ('cloud_scanning', 'Cloud Security', 
             'AWS, Azure, GCP, Kubernetes security assessment'),
            ('sast_scanning', 'Static Code Analysis (SAST)', 
             'Source code vulnerability detection'),
        ]
        
        for key, name, description in features:
            check = QCheckBox(f"{name}")
            check.setChecked(self.config.features.get(key, True))
            check.setToolTip(description)
            self.feature_checks[key] = check
            
            feature_widget = QWidget()
            feature_layout = QVBoxLayout(feature_widget)
            feature_layout.setContentsMargins(0, 0, 0, 10)
            feature_layout.addWidget(check)
            
            desc_label = QLabel(f"    {description}")
            desc_label.setStyleSheet("color: #666666; font-size: 11px;")
            feature_layout.addWidget(desc_label)
            
            features_layout.addWidget(feature_widget)
        
        layout.addWidget(features_group)
        
        # Service options
        service_group = QGroupBox("Service Options")
        service_layout = QVBoxLayout(service_group)
        
        self.service_check = QCheckBox("Install as Windows Service")
        self.service_check.setChecked(self.config.install_service)
        self.service_check.setToolTip("Run agent as a background service")
        service_layout.addWidget(self.service_check)
        
        self.autostart_check = QCheckBox("Start agent after installation")
        self.autostart_check.setChecked(self.config.auto_start)
        service_layout.addWidget(self.autostart_check)
        
        self.boot_check = QCheckBox("Start agent when Windows starts")
        self.boot_check.setChecked(self.config.start_on_boot)
        service_layout.addWidget(self.boot_check)
        
        layout.addWidget(service_group)
        
        layout.addStretch()
    
    def validatePage(self) -> bool:
        for key, check in self.feature_checks.items():
            self.config.features[key] = check.isChecked()
        
        self.config.install_service = self.service_check.isChecked()
        self.config.auto_start = self.autostart_check.isChecked()
        self.config.start_on_boot = self.boot_check.isChecked()
        
        return True


class ConfigurationPage(QWizardPage):
    """Server configuration page."""
    
    def __init__(self, config: InstallConfig, parent=None):
        super().__init__(parent)
        self.config = config
        self.setTitle("Server Configuration")
        self.setSubTitle("Configure the connection to your Jarwis server.")
        
        layout = QVBoxLayout(self)
        
        # Server settings
        server_group = QGroupBox("Server Connection")
        server_layout = QVBoxLayout(server_group)
        
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Server URL:"))
        self.url_edit = QLineEdit(self.config.server_url)
        self.url_edit.setPlaceholderText("wss://jarwis.io/ws/agent")
        url_layout.addWidget(self.url_edit)
        server_layout.addLayout(url_layout)
        
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("Activation Key:"))
        self.key_edit = QLineEdit(self.config.activation_key)
        self.key_edit.setPlaceholderText("Enter your activation key (optional)")
        self.key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        key_layout.addWidget(self.key_edit)
        server_layout.addLayout(key_layout)
        
        note = QLabel(
            "💡 You can get your activation key from the Jarwis dashboard: "
            "Dashboard → Settings → Agent → Generate Key"
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: #666666; font-size: 11px; margin-top: 10px;")
        server_layout.addWidget(note)
        
        layout.addWidget(server_group)
        
        # Privacy settings
        privacy_group = QGroupBox("Privacy & Telemetry")
        privacy_layout = QVBoxLayout(privacy_group)
        
        self.telemetry_check = QCheckBox(
            "Send anonymous usage statistics to help improve Jarwis"
        )
        self.telemetry_check.setChecked(self.config.send_telemetry)
        privacy_layout.addWidget(self.telemetry_check)
        
        privacy_note = QLabel(
            "We collect anonymous data about feature usage and error reports. "
            "No sensitive information or scan results are included."
        )
        privacy_note.setWordWrap(True)
        privacy_note.setStyleSheet("color: #666666; font-size: 11px;")
        privacy_layout.addWidget(privacy_note)
        
        layout.addWidget(privacy_group)
        
        layout.addStretch()
        
        self.registerField("serverUrl", self.url_edit)
        self.registerField("activationKey", self.key_edit)
    
    def validatePage(self) -> bool:
        self.config.server_url = self.url_edit.text()
        self.config.activation_key = self.key_edit.text()
        self.config.send_telemetry = self.telemetry_check.isChecked()
        return True


class InstallProgressPage(QWizardPage):
    """Installation progress page."""
    
    def __init__(self, config: InstallConfig, parent=None):
        super().__init__(parent)
        self.config = config
        self.setTitle("Installing")
        self.setSubTitle("Please wait while Jarwis Security Agent is being installed.")
        
        self.install_complete = False
        self.install_success = False
        
        layout = QVBoxLayout(self)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Preparing installation...")
        self.status_label.setStyleSheet("margin-top: 10px;")
        layout.addWidget(self.status_label)
        
        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(200)
        layout.addWidget(self.log_output)
        
        layout.addStretch()
    
    def initializePage(self):
        """Start installation when page is shown."""
        # Get source directory (where installer files are)
        source_dir = Path(__file__).parent.parent
        
        self.worker = InstallWorker(self.config, source_dir)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()
    
    def _on_progress(self, percent: int, message: str):
        self.progress_bar.setValue(percent)
        self.status_label.setText(message)
        self.log_output.append(f"[{percent}%] {message}")
    
    def _on_finished(self, success: bool, message: str):
        self.install_complete = True
        self.install_success = success
        
        if success:
            self.log_output.append(f"\n✓ {message}")
            self.status_label.setText("✓ Installation completed successfully!")
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
        else:
            self.log_output.append(f"\n✗ {message}")
            self.status_label.setText(f"✗ {message}")
            self.status_label.setStyleSheet("color: red; font-weight: bold;")
        
        self.completeChanged.emit()
    
    def isComplete(self) -> bool:
        return self.install_complete


class CompletionPage(QWizardPage):
    """Installation completion page."""
    
    def __init__(self, config: InstallConfig, parent=None):
        super().__init__(parent)
        self.config = config
        self.setTitle("Installation Complete")
        self.setSubTitle("")
        
        layout = QVBoxLayout(self)
        
        # Success message
        success_label = QLabel(
            "🎉 Jarwis Security Agent has been installed successfully!\n\n"
            "The agent is now running as a Windows service and will "
            "automatically connect to the Jarwis server."
        )
        success_label.setWordWrap(True)
        success_label.setStyleSheet("font-size: 14px;")
        layout.addWidget(success_label)
        
        # Post-install actions
        actions_group = QGroupBox("What would you like to do?")
        actions_layout = QVBoxLayout(actions_group)
        
        self.open_dashboard = QCheckBox("Open Jarwis Dashboard in browser")
        self.open_dashboard.setChecked(True)
        actions_layout.addWidget(self.open_dashboard)
        
        self.view_status = QCheckBox("View agent connection status")
        self.view_status.setChecked(False)
        actions_layout.addWidget(self.view_status)
        
        self.read_docs = QCheckBox("Read the documentation")
        self.read_docs.setChecked(False)
        actions_layout.addWidget(self.read_docs)
        
        layout.addWidget(actions_group)
        
        layout.addStretch()
        
        # Support info
        support_label = QLabel(
            "Need help? Visit https://jarwis.io/docs or contact support@jarwis.io"
        )
        support_label.setStyleSheet("color: #666666;")
        layout.addWidget(support_label)
    
    def validatePage(self) -> bool:
        """Handle post-install actions."""
        import webbrowser
        
        if self.open_dashboard.isChecked():
            webbrowser.open("https://jarwis.io/dashboard")
        
        if self.view_status.isChecked():
            # Open status window or command
            subprocess.Popen([
                str(Path(self.config.install_path) / 'jarwis-agent.exe'),
                '--status'
            ])
        
        if self.read_docs.isChecked():
            webbrowser.open("https://jarwis.io/docs/agent")
        
        return True


# ============================================================================
# Main Wizard
# ============================================================================

class JarwisSetupWizard(QWizard):
    """Main setup wizard."""
    
    def __init__(self, config: InstallConfig = None):
        super().__init__()
        
        self.config = config or InstallConfig()
        
        # Window setup
        self.setWindowTitle("Jarwis Security Agent Setup")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setMinimumSize(700, 500)
        
        # Set icon
        # self.setWindowIcon(QIcon("path/to/icon.ico"))
        
        # Add pages
        self.addPage(WelcomePage())
        self.addPage(LicensePage())
        self.addPage(InstallLocationPage(self.config))
        self.addPage(FeatureSelectionPage(self.config))
        self.addPage(ConfigurationPage(self.config))
        self.addPage(InstallProgressPage(self.config))
        self.addPage(CompletionPage(self.config))
        
        # Apply styles
        self.setStyleSheet(STYLESHEET)
        
        # Button text
        self.setButtonText(QWizard.WizardButton.NextButton, "Next >")
        self.setButtonText(QWizard.WizardButton.BackButton, "< Back")
        self.setButtonText(QWizard.WizardButton.FinishButton, "Finish")
        self.setButtonText(QWizard.WizardButton.CancelButton, "Cancel")


# ============================================================================
# Entry Point
# ============================================================================

def is_admin() -> bool:
    """Check if running with administrator/root privileges."""
    if IS_WINDOWS and ctypes is not None:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        # On Unix-like systems, check if running as root
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else True


def run_as_admin():
    """Restart the script with admin/root privileges."""
    if IS_WINDOWS and ctypes is not None:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
    else:
        # On Unix, suggest running with sudo
        print("Please run with sudo: sudo python setup_wizard.py")
        sys.exit(1)


def main():
    # Check for admin rights (required for service installation)
    if not is_admin():
        result = QMessageBox.question(
            None,
            "Administrator Rights Required",
            "Jarwis Agent Setup requires administrator privileges to install "
            "the Windows service.\n\nWould you like to restart as Administrator?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if result == QMessageBox.StandardButton.Yes:
            run_as_admin()
        sys.exit(0)
    
    # Parse command line arguments
    config = InstallConfig()
    
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == '--server-url' and i + 1 < len(args):
            config.server_url = args[i + 1]
            i += 2
        elif args[i] == '--activation-key' and i + 1 < len(args):
            config.activation_key = args[i + 1]
            i += 2
        elif args[i] == '--silent':
            # Silent installation mode
            # TODO: Implement silent install
            i += 1
        else:
            i += 1
    
    # Create and run application
    app = QApplication(sys.argv)
    app.setApplicationName("Jarwis Agent Setup")
    app.setOrganizationName("Jarwis Security")
    
    # Set application-wide font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    wizard = JarwisSetupWizard(config)
    wizard.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
