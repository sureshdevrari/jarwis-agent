"""
Jarwis Security Agent - macOS Setup Wizard
Professional installer with PyQt6 for macOS
"""

import sys
import os
import subprocess
import shutil
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
DEFAULT_INSTALL_PATH = "/Applications/Jarwis Agent.app"
SERVICE_NAME = "com.jarwis.agent"


def is_root():
    """Check if running as root"""
    return os.geteuid() == 0


def run_as_root():
    """Restart with sudo"""
    script = os.path.abspath(sys.argv[0])
    subprocess.run(["osascript", "-e", 
        f'do shell script "python3 {script}" with administrator privileges'])
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
            # Step 1: Create app bundle structure
            self.progress.emit(10, "Creating application bundle...")
            contents_dir = os.path.join(self.install_path, "Contents")
            macos_dir = os.path.join(contents_dir, "MacOS")
            resources_dir = os.path.join(contents_dir, "Resources")
            
            os.makedirs(macos_dir, exist_ok=True)
            os.makedirs(resources_dir, exist_ok=True)
            os.makedirs(os.path.join(resources_dir, "config"), exist_ok=True)
            
            # Step 2: Copy executables
            self.progress.emit(25, "Installing executables...")
            source_dir = os.path.dirname(os.path.dirname(sys.executable))
            if getattr(sys, 'frozen', False):
                source_dir = os.path.dirname(sys.executable)
            
            # Copy main agent
            agent_src = os.path.join(source_dir, "jarwis-agent")
            if os.path.exists(agent_src):
                shutil.copy2(agent_src, os.path.join(macos_dir, "jarwis-agent"))
                os.chmod(os.path.join(macos_dir, "jarwis-agent"), 0o755)
            
            # Copy tray app
            tray_src = os.path.join(source_dir, "jarwis-tray")
            if os.path.exists(tray_src):
                shutil.copy2(tray_src, os.path.join(macos_dir, "jarwis-tray"))
                os.chmod(os.path.join(macos_dir, "jarwis-tray"), 0o755)
            
            # Step 3: Copy resources
            self.progress.emit(40, "Installing resources...")
            config_src = os.path.join(source_dir, "config", "config.yaml")
            if os.path.exists(config_src):
                shutil.copy2(config_src, os.path.join(resources_dir, "config", "config.yaml"))
            
            # Copy icon
            icon_src = os.path.join(source_dir, "assets", "logos", "PNG-01.png")
            if os.path.exists(icon_src):
                shutil.copy2(icon_src, os.path.join(resources_dir, "icon.png"))
            
            # Step 4: Create Info.plist
            self.progress.emit(55, "Creating application metadata...")
            self._create_info_plist(contents_dir)
            
            # Step 5: Install LaunchAgent if selected
            if self.options.get('install_service', True):
                self.progress.emit(70, "Installing launch agent...")
                self._install_launch_agent()
            
            # Step 6: Create symlink in /usr/local/bin
            if self.options.get('add_to_path', False):
                self.progress.emit(85, "Creating command-line access...")
                self._create_symlink()
            
            # Step 7: Start service if selected
            if self.options.get('start_service', True) and self.options.get('install_service', True):
                self.progress.emit(95, "Starting Jarwis Agent...")
                self._start_service()
            
            self.progress.emit(100, "Installation completed successfully!")
            self.finished.emit(True, "Installation completed successfully!")
            
        except Exception as e:
            self.finished.emit(False, str(e))
    
    def _create_info_plist(self, contents_dir):
        plist = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>jarwis-agent</string>
    <key>CFBundleIdentifier</key>
    <string>{SERVICE_NAME}</string>
    <key>CFBundleName</key>
    <string>{APP_NAME}</string>
    <key>CFBundleDisplayName</key>
    <string>{APP_NAME}</string>
    <key>CFBundleVersion</key>
    <string>{APP_VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>{APP_VERSION}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleSignature</key>
    <string>JRWS</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>'''
        with open(os.path.join(contents_dir, "Info.plist"), "w") as f:
            f.write(plist)
    
    def _install_launch_agent(self):
        launch_agents_dir = os.path.expanduser("~/Library/LaunchAgents")
        os.makedirs(launch_agents_dir, exist_ok=True)
        
        plist = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{SERVICE_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{self.install_path}/Contents/MacOS/jarwis-agent</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/jarwis-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/jarwis-agent.err</string>
</dict>
</plist>'''
        plist_path = os.path.join(launch_agents_dir, f"{SERVICE_NAME}.plist")
        with open(plist_path, "w") as f:
            f.write(plist)
    
    def _create_symlink(self):
        try:
            bin_dir = "/usr/local/bin"
            os.makedirs(bin_dir, exist_ok=True)
            link_path = os.path.join(bin_dir, "jarwis-agent")
            if os.path.exists(link_path):
                os.remove(link_path)
            os.symlink(
                os.path.join(self.install_path, "Contents", "MacOS", "jarwis-agent"),
                link_path
            )
        except Exception as e:
            print(f"Symlink error: {e}")
    
    def _start_service(self):
        try:
            plist_path = os.path.expanduser(f"~/Library/LaunchAgents/{SERVICE_NAME}.plist")
            subprocess.run(["launchctl", "unload", plist_path], capture_output=True)
            subprocess.run(["launchctl", "load", plist_path], capture_output=True)
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
        title.setFont(QFont(".AppleSystemUIFont", 24, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Version
        version = QLabel(f"Version {APP_VERSION}")
        version.setFont(QFont(".AppleSystemUIFont", 12))
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version.setStyleSheet("color: #666;")
        layout.addWidget(version)
        
        # Description
        desc = QLabel(
            "This installer will guide you through installing\n"
            "Jarwis Security Agent on your Mac.\n\n"
            " Real-time security monitoring\n"
            " Vulnerability scanning\n"
            " Network traffic analysis\n"
            " Jarwis Platform integration"
        )
        desc.setFont(QFont(".AppleSystemUIFont", 13))
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def _find_logo(self):
        paths = [
            os.path.join(os.path.dirname(__file__), "..", "..", "assets", "logos", "PNG-01.png"),
            os.path.join(os.path.dirname(sys.executable), "assets", "logos", "PNG-01.png"),
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
        self.accept_check.setFont(QFont(".AppleSystemUIFont", 12, QFont.Weight.Bold))
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
        
        path_group = QGroupBox("Destination")
        path_layout = QHBoxLayout()
        
        self.path_edit = QLineEdit(DEFAULT_INSTALL_PATH)
        path_layout.addWidget(self.path_edit)
        
        browse_btn = QPushButton("Choose...")
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
        folder = QFileDialog.getExistingDirectory(self, "Select Location", "/Applications")
        if folder:
            self.path_edit.setText(os.path.join(folder, "Jarwis Agent.app"))
            self._update_space()
    
    def _update_space(self):
        try:
            stat = os.statvfs("/Applications")
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
        
        self.service_check = QCheckBox("Launch Agent (auto-start at login)")
        self.service_check.setChecked(True)
        opt_layout.addWidget(self.service_check)
        
        self.tray_check = QCheckBox("Menu Bar Application")
        self.tray_check.setChecked(True)
        opt_layout.addWidget(self.tray_check)
        
        self.path_check = QCheckBox("Add to PATH (/usr/local/bin)")
        self.path_check.setChecked(False)
        opt_layout.addWidget(self.path_check)
        
        opt_group.setLayout(opt_layout)
        layout.addWidget(opt_group)
        
        layout.addStretch()
        self.setLayout(layout)
        
        self.registerField("install_service", self.service_check)
        self.registerField("install_tray", self.tray_check)
        self.registerField("add_to_path", self.path_check)


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
        self.log_output.setFont(QFont("Menlo", 10))
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
            'add_to_path': self.field("add_to_path"),
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
        success_label.setFont(QFont(".AppleSystemUIFont", 16, QFont.Weight.Bold))
        success_label.setStyleSheet("color: #27ae60;")
        success_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(success_label)
        
        options_group = QGroupBox("Next Steps")
        options_layout = QVBoxLayout()
        
        self.launch_check = QCheckBox("Open Jarwis Agent")
        self.launch_check.setChecked(True)
        options_layout.addWidget(self.launch_check)
        
        self.dashboard_check = QCheckBox("Open Dashboard in browser")
        self.dashboard_check.setChecked(False)
        options_layout.addWidget(self.dashboard_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        info = QLabel("The agent runs in the menu bar.\nClick the icon to access settings.")
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info.setStyleSheet("color: #666;")
        layout.addWidget(info)
        
        layout.addStretch()
        self.setLayout(layout)
        
        self.registerField("launch_agent", self.launch_check)
        self.registerField("open_dashboard", self.dashboard_check)


class MacOSSetupWizard(QWizard):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle(f"{APP_NAME} Installer")
        self.setWizardStyle(QWizard.WizardStyle.MacStyle)
        self.setMinimumSize(600, 500)
        
        self.addPage(WelcomePage())
        self.addPage(LicensePage())
        self.addPage(InstallLocationPage())
        self.addPage(FeatureSelectionPage())
        self.addPage(ConfigurationPage())
        self.addPage(InstallProgressPage())
        self.addPage(CompletionPage())
    
    def done(self, result):
        if result == QWizard.DialogCode.Accepted:
            if self.field("launch_agent"):
                install_path = self.field("install_path") or DEFAULT_INSTALL_PATH
                subprocess.Popen(["open", install_path])
            
            if self.field("open_dashboard"):
                import webbrowser
                webbrowser.open(self.field("server_url") or "https://app.jarwis.ai")
        
        super().done(result)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    
    wizard = MacOSSetupWizard()
    wizard.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
