"""
Jarwis Security Agent - Linux Setup Wizard
Professional GUI installer with PyQt6 for Linux
"""

import sys
import os
import subprocess
import shutil
import grp
import pwd
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QWizard, QWizardPage, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QProgressBar,
    QTextEdit, QFileDialog, QMessageBox, QGroupBox, QRadioButton
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QPixmap, QFont, QIcon


APP_NAME = "Jarwis Security Agent"
APP_VERSION = "2.0.0"
COMPANY_NAME = "Jarwis Security"
DEFAULT_INSTALL_PATH = "/opt/jarwis"
SERVICE_NAME = "jarwis-agent"


def is_root():
    """Check if running as root"""
    return os.geteuid() == 0


def run_as_root():
    """Restart with pkexec or sudo"""
    script = os.path.abspath(sys.argv[0])
    if shutil.which("pkexec"):
        subprocess.run(["pkexec", sys.executable, script])
    else:
        subprocess.run(["sudo", sys.executable, script])
    sys.exit(0)


class InstallThread(QThread):
    """Background installation thread"""
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(bool, str)
    
    def __init__(self, install_path, options):
        super().__init__()
        self.install_path = install_path
        self.options = options
    
    def run(self):
        try:
            # Step 1: Create directories
            self.progress.emit(5, "Creating installation directories...")
            os.makedirs(self.install_path, exist_ok=True)
            os.makedirs(os.path.join(self.install_path, "bin"), exist_ok=True)
            os.makedirs(os.path.join(self.install_path, "config"), exist_ok=True)
            os.makedirs(os.path.join(self.install_path, "logs"), exist_ok=True)
            os.makedirs(os.path.join(self.install_path, "data"), exist_ok=True)
            
            # Step 2: Copy executables
            self.progress.emit(15, "Installing executables...")
            source_dir = os.path.dirname(os.path.dirname(sys.executable))
            if getattr(sys, 'frozen', False):
                source_dir = os.path.dirname(sys.executable)
            
            # Copy agent
            agent_src = os.path.join(source_dir, "jarwis-agent")
            if os.path.exists(agent_src):
                dest = os.path.join(self.install_path, "bin", "jarwis-agent")
                shutil.copy2(agent_src, dest)
                os.chmod(dest, 0o755)
            
            # Copy tray app
            tray_src = os.path.join(source_dir, "jarwis-tray")
            if os.path.exists(tray_src):
                dest = os.path.join(self.install_path, "bin", "jarwis-tray")
                shutil.copy2(tray_src, dest)
                os.chmod(dest, 0o755)
            
            # Step 3: Copy config
            self.progress.emit(30, "Installing configuration...")
            config_src = os.path.join(source_dir, "config", "config.yaml")
            if os.path.exists(config_src):
                shutil.copy2(config_src, os.path.join(self.install_path, "config", "config.yaml"))
            
            # Step 4: Copy icon
            self.progress.emit(40, "Installing resources...")
            icon_src = os.path.join(source_dir, "assets", "logos", "PNG-01.png")
            icon_dest = "/usr/share/icons/hicolor/256x256/apps/jarwis-agent.png"
            if os.path.exists(icon_src):
                os.makedirs(os.path.dirname(icon_dest), exist_ok=True)
                shutil.copy2(icon_src, icon_dest)
            
            # Step 5: Create symlinks
            self.progress.emit(50, "Creating command-line access...")
            self._create_symlinks()
            
            # Step 6: Install systemd service
            if self.options.get('install_service', True):
                self.progress.emit(60, "Installing systemd service...")
                self._install_systemd_service()
            
            # Step 7: Create desktop entry
            self.progress.emit(75, "Creating desktop integration...")
            self._create_desktop_entry()
            
            # Step 8: Update server config
            self.progress.emit(85, "Configuring server connection...")
            self._update_config()
            
            # Step 9: Start service
            if self.options.get('start_service', True) and self.options.get('install_service', True):
                self.progress.emit(95, "Starting Jarwis Agent...")
                self._start_service()
            
            self.progress.emit(100, "Installation completed successfully!")
            self.finished.emit(True, "Installation completed successfully!")
            
        except Exception as e:
            self.finished.emit(False, str(e))
    
    def _create_symlinks(self):
        try:
            bin_dir = "/usr/local/bin"
            os.makedirs(bin_dir, exist_ok=True)
            
            # Agent symlink
            link = os.path.join(bin_dir, "jarwis-agent")
            if os.path.exists(link):
                os.remove(link)
            os.symlink(os.path.join(self.install_path, "bin", "jarwis-agent"), link)
            
            # Tray symlink
            link = os.path.join(bin_dir, "jarwis-tray")
            if os.path.exists(link):
                os.remove(link)
            os.symlink(os.path.join(self.install_path, "bin", "jarwis-tray"), link)
        except Exception as e:
            print(f"Symlink error: {e}")
    
    def _install_systemd_service(self):
        service_content = f'''[Unit]
Description=Jarwis Security Agent
Documentation=https://docs.jarwis.ai
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={self.install_path}/bin/jarwis-agent --daemon
Restart=always
RestartSec=10
User=root
Group=root
StandardOutput=append:{self.install_path}/logs/agent.log
StandardError=append:{self.install_path}/logs/agent.err

[Install]
WantedBy=multi-user.target
'''
        service_path = f"/etc/systemd/system/{SERVICE_NAME}.service"
        with open(service_path, "w") as f:
            f.write(service_content)
        
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)
    
    def _create_desktop_entry(self):
        desktop_content = f'''[Desktop Entry]
Name=Jarwis Agent
Comment=Jarwis Security Agent
Exec={self.install_path}/bin/jarwis-tray
Icon=jarwis-agent
Type=Application
Categories=System;Security;
Keywords=security;agent;jarwis;
StartupNotify=false
'''
        # System-wide
        desktop_path = "/usr/share/applications/jarwis-agent.desktop"
        with open(desktop_path, "w") as f:
            f.write(desktop_content)
        
        # Autostart for current user
        if self.options.get('autostart', True):
            autostart_dir = os.path.expanduser("~/.config/autostart")
            os.makedirs(autostart_dir, exist_ok=True)
            autostart_path = os.path.join(autostart_dir, "jarwis-agent.desktop")
            with open(autostart_path, "w") as f:
                f.write(desktop_content)
    
    def _update_config(self):
        config_path = os.path.join(self.install_path, "config", "config.yaml")
        if os.path.exists(config_path):
            with open(config_path, "a") as f:
                server_url = self.options.get('server_url', 'https://app.jarwis.ai')
                f.write(f"\n# Server configuration (set by installer)\n")
                f.write(f"server_url: {server_url}\n")
    
    def _start_service(self):
        try:
            subprocess.run(["systemctl", "start", SERVICE_NAME], capture_output=True)
        except Exception as e:
            print(f"Service start error: {e}")


class WelcomePage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("")
        
        layout = QVBoxLayout()
        layout.setSpacing(20)
        
        # Logo
        logo_label = QLabel()
        logo_path = self._find_logo()
        if logo_path:
            pixmap = QPixmap(logo_path).scaled(120, 120, Qt.AspectRatioMode.KeepAspectRatio,
                                               Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(pixmap)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo_label)
        
        # Title
        title = QLabel(f"Welcome to {APP_NAME}")
        title.setFont(QFont("Sans", 20, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #2980b9;")
        layout.addWidget(title)
        
        # Version
        version = QLabel(f"Version {APP_VERSION}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version.setStyleSheet("color: #666;")
        layout.addWidget(version)
        
        # Description
        desc = QLabel(
            "This installer will guide you through installing\n"
            "Jarwis Security Agent on your system.\n\n"
            " Real-time security monitoring\n"
            " Vulnerability scanning\n"
            " Network traffic analysis\n"
            " Jarwis Platform integration"
        )
        desc.setFont(QFont("Sans", 11))
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)
        
        layout.addStretch()
        
        # Root warning
        if not is_root():
            warning = QLabel(" Root privileges required for installation")
            warning.setStyleSheet("color: #e74c3c; padding: 10px; background: #fdf2f2; border-radius: 5px;")
            warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(warning)
        
        self.setLayout(layout)
    
    def _find_logo(self):
        paths = [
            os.path.join(os.path.dirname(__file__), "..", "..", "assets", "logos", "PNG-01.png"),
            os.path.join(os.path.dirname(sys.executable), "assets", "logos", "PNG-01.png"),
            "/usr/share/icons/hicolor/256x256/apps/jarwis-agent.png",
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None


class LicensePage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("License Agreement")
        self.setSubTitle("Please review and accept the license agreement")
        
        layout = QVBoxLayout()
        
        self.license_text = QTextEdit()
        self.license_text.setReadOnly(True)
        self.license_text.setPlainText(self._get_license())
        layout.addWidget(self.license_text)
        
        self.accept_check = QCheckBox("I accept the terms of the License Agreement")
        self.accept_check.setFont(QFont("Sans", 10, QFont.Weight.Bold))
        self.accept_check.stateChanged.connect(self.completeChanged)
        layout.addWidget(self.accept_check)
        
        self.setLayout(layout)
        self.registerField("license_accepted*", self.accept_check)
    
    def _get_license(self):
        return """JARWIS SECURITY AGENT - END USER LICENSE AGREEMENT

Copyright  2024-2026 Jarwis Security. All Rights Reserved.

1. LICENSE GRANT
Jarwis Security grants you a limited, non-exclusive license to use this software.

2. RESTRICTIONS
You may not reverse engineer, decompile, or redistribute this software.

3. DATA COLLECTION
The software collects security-related data as part of its operation.

4. DISCLAIMER
THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.

5. LIMITATION OF LIABILITY
JARWIS SECURITY SHALL NOT BE LIABLE FOR ANY DAMAGES ARISING FROM USE.

Contact: legal@jarwis.ai | https://jarwis.ai"""
    
    def isComplete(self):
        return self.accept_check.isChecked()


class InstallLocationPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Installation Location")
        self.setSubTitle("Choose where to install Jarwis Agent")
        
        layout = QVBoxLayout()
        
        path_group = QGroupBox("Destination Directory")
        path_layout = QHBoxLayout()
        
        self.path_edit = QLineEdit(DEFAULT_INSTALL_PATH)
        path_layout.addWidget(self.path_edit)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse)
        path_layout.addWidget(browse_btn)
        
        path_group.setLayout(path_layout)
        layout.addWidget(path_group)
        
        # Space info
        self.space_label = QLabel()
        self._update_space()
        layout.addWidget(self.space_label)
        
        layout.addStretch()
        self.setLayout(layout)
        self.registerField("install_path", self.path_edit)
    
    def _browse(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Location", "/opt")
        if folder:
            self.path_edit.setText(os.path.join(folder, "jarwis"))
            self._update_space()
    
    def _update_space(self):
        try:
            stat = os.statvfs("/")
            free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
            self.space_label.setText(f"Required: ~100 MB | Available: {free_gb:.1f} GB")
        except:
            self.space_label.setText("Required: ~100 MB")


class FeatureSelectionPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Installation Options")
        self.setSubTitle("Select the components to install")
        
        layout = QVBoxLayout()
        
        # Core
        core_group = QGroupBox("Core Components (Required)")
        core_layout = QVBoxLayout()
        core_agent = QCheckBox("Jarwis Agent")
        core_agent.setChecked(True)
        core_agent.setEnabled(False)
        core_layout.addWidget(core_agent)
        core_group.setLayout(core_layout)
        layout.addWidget(core_group)
        
        # Optional
        opt_group = QGroupBox("Optional Components")
        opt_layout = QVBoxLayout()
        
        self.service_check = QCheckBox("Systemd Service (auto-start at boot)")
        self.service_check.setChecked(True)
        opt_layout.addWidget(self.service_check)
        
        self.tray_check = QCheckBox("System Tray Application")
        self.tray_check.setChecked(True)
        opt_layout.addWidget(self.tray_check)
        
        self.autostart_check = QCheckBox("Start tray app at login")
        self.autostart_check.setChecked(True)
        opt_layout.addWidget(self.autostart_check)
        
        self.desktop_check = QCheckBox("Desktop menu entry")
        self.desktop_check.setChecked(True)
        opt_layout.addWidget(self.desktop_check)
        
        opt_group.setLayout(opt_layout)
        layout.addWidget(opt_group)
        
        layout.addStretch()
        self.setLayout(layout)
        
        self.registerField("install_service", self.service_check)
        self.registerField("install_tray", self.tray_check)
        self.registerField("autostart", self.autostart_check)
        self.registerField("desktop_entry", self.desktop_check)


class ConfigurationPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Server Configuration")
        self.setSubTitle("Configure your Jarwis server connection")
        
        layout = QVBoxLayout()
        
        server_group = QGroupBox("Jarwis Server")
        server_layout = QVBoxLayout()
        
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Server URL:"))
        self.server_url = QLineEdit("https://app.jarwis.ai")
        url_layout.addWidget(self.server_url)
        server_layout.addLayout(url_layout)
        
        server_group.setLayout(server_layout)
        layout.addWidget(server_group)
        
        activation_group = QGroupBox("Activation")
        activation_layout = QVBoxLayout()
        
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("Activation Key:"))
        self.activation_key = QLineEdit()
        self.activation_key.setPlaceholderText("Optional - activate later from dashboard")
        self.activation_key.setEchoMode(QLineEdit.EchoMode.Password)
        key_layout.addWidget(self.activation_key)
        activation_layout.addLayout(key_layout)
        
        activation_group.setLayout(activation_layout)
        layout.addWidget(activation_group)
        
        layout.addStretch()
        self.setLayout(layout)
        
        self.registerField("server_url", self.server_url)
        self.registerField("activation_key", self.activation_key)


class InstallProgressPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Installing")
        self.setSubTitle("Please wait while Jarwis Agent is installed")
        self.setCommitPage(True)
        
        layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Preparing...")
        layout.addWidget(self.status_label)
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(150)
        self.log_output.setFont(QFont("Monospace", 9))
        layout.addWidget(self.log_output)
        
        layout.addStretch()
        self.setLayout(layout)
        
        self.install_thread = None
        self.installation_complete = False
    
    def initializePage(self):
        self.wizard().button(QWizard.WizardButton.BackButton).setEnabled(False)
        self.wizard().button(QWizard.WizardButton.NextButton).setEnabled(False)
        
        options = {
            'install_service': self.field("install_service"),
            'install_tray': self.field("install_tray"),
            'autostart': self.field("autostart"),
            'desktop_entry': self.field("desktop_entry"),
            'server_url': self.field("server_url"),
            'activation_key': self.field("activation_key"),
            'start_service': True,
        }
        
        install_path = self.field("install_path") or DEFAULT_INSTALL_PATH
        
        self.install_thread = InstallThread(install_path, options)
        self.install_thread.progress.connect(self._on_progress)
        self.install_thread.finished.connect(self._on_finished)
        
        QTimer.singleShot(500, self.install_thread.start)
    
    def _on_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        self.log_output.append(f"[{value}%] {message}")
    
    def _on_finished(self, success, message):
        self.installation_complete = success
        if success:
            self.status_label.setText(" " + message)
        else:
            self.status_label.setText(" Error: " + message)
        
        self.wizard().button(QWizard.WizardButton.NextButton).setEnabled(True)
        self.completeChanged.emit()
    
    def isComplete(self):
        return self.installation_complete


class CompletionPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Installation Complete")
        
        layout = QVBoxLayout()
        
        success_label = QLabel(" Jarwis Security Agent installed successfully!")
        success_label.setFont(QFont("Sans", 14, QFont.Weight.Bold))
        success_label.setStyleSheet("color: #27ae60;")
        success_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(success_label)
        
        options_group = QGroupBox("Next Steps")
        options_layout = QVBoxLayout()
        
        self.launch_check = QCheckBox("Start Jarwis Agent tray application")
        self.launch_check.setChecked(True)
        options_layout.addWidget(self.launch_check)
        
        self.dashboard_check = QCheckBox("Open Dashboard in browser")
        self.dashboard_check.setChecked(False)
        options_layout.addWidget(self.dashboard_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        info = QLabel(
            "The agent service is running in the background.\n"
            "Use 'systemctl status jarwis-agent' to check status."
        )
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info.setStyleSheet("color: #666;")
        layout.addWidget(info)
        
        layout.addStretch()
        self.setLayout(layout)
        
        self.registerField("launch_agent", self.launch_check)
        self.registerField("open_dashboard", self.dashboard_check)


class LinuxSetupWizard(QWizard):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle(f"{APP_NAME} Installer")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setMinimumSize(650, 520)
        
        self.addPage(WelcomePage())
        self.addPage(LicensePage())
        self.addPage(InstallLocationPage())
        self.addPage(FeatureSelectionPage())
        self.addPage(ConfigurationPage())
        self.addPage(InstallProgressPage())
        self.addPage(CompletionPage())
        
        self.setStyleSheet("""
            QWizard { background-color: #fafafa; }
            QGroupBox { font-weight: bold; border: 1px solid #ddd; border-radius: 5px; margin-top: 10px; padding-top: 10px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
            QProgressBar { border: 1px solid #ddd; border-radius: 5px; text-align: center; height: 22px; }
            QProgressBar::chunk { background-color: #2980b9; border-radius: 4px; }
        """)
    
    def done(self, result):
        if result == QWizard.DialogCode.Accepted:
            install_path = self.field("install_path") or DEFAULT_INSTALL_PATH
            
            if self.field("launch_agent"):
                tray_path = os.path.join(install_path, "bin", "jarwis-tray")
                if os.path.exists(tray_path):
                    subprocess.Popen([tray_path], start_new_session=True)
            
            if self.field("open_dashboard"):
                import webbrowser
                webbrowser.open(self.field("server_url") or "https://app.jarwis.ai")
        
        super().done(result)


def main():
    # Check for root
    if not is_root():
        response = QMessageBox.question(
            None,
            "Root Required",
            "This installer requires root privileges.\n\nRestart with elevated permissions?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if response == QMessageBox.StandardButton.Yes:
            run_as_root()
        return
    
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setStyle("Fusion")
    
    wizard = LinuxSetupWizard()
    wizard.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
