"""
Jarwis Security Agent - Professional Setup Wizard
A modern, corporate-style installer with PyQt6
"""

import sys
import os
import subprocess
import ctypes
import winreg
import shutil
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QWizard, QWizardPage, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QProgressBar,
    QTextEdit, QFileDialog, QMessageBox, QRadioButton, QButtonGroup,
    QGroupBox, QFrame, QSpacerItem, QSizePolicy, QComboBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QPixmap, QFont, QIcon, QPalette, QColor


# Constants
APP_NAME = "Jarwis Security Agent"
APP_VERSION = "2.0.0"
COMPANY_NAME = "Jarwis Security"
DEFAULT_INSTALL_PATH = r"C:\Program Files\Jarwis\Agent"
SERVICE_NAME = "JarwisAgent"


def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    """Restart the application with admin privileges"""
    if sys.platform == 'win32':
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)


class InstallThread(QThread):
    """Background thread for installation"""
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
            os.makedirs(os.path.join(self.install_path, "logs"), exist_ok=True)
            os.makedirs(os.path.join(self.install_path, "config"), exist_ok=True)
            os.makedirs(os.path.join(self.install_path, "data"), exist_ok=True)
            
            # Step 2: Copy files
            self.progress.emit(15, "Copying program files...")
            source_dir = os.path.dirname(os.path.dirname(sys.executable))
            if getattr(sys, 'frozen', False):
                source_dir = os.path.dirname(sys.executable)
            
            # Copy main executable
            exe_path = sys.executable if getattr(sys, 'frozen', False) else None
            if exe_path and os.path.exists(exe_path):
                dest_exe = os.path.join(self.install_path, "jarwis-agent.exe")
                shutil.copy2(exe_path, dest_exe)
            
            # Step 3: Copy config
            self.progress.emit(30, "Installing configuration files...")
            config_src = os.path.join(source_dir, "config", "config.yaml")
            if os.path.exists(config_src):
                shutil.copy2(config_src, os.path.join(self.install_path, "config", "config.yaml"))
            
            # Step 4: Create registry entries
            self.progress.emit(45, "Creating registry entries...")
            self._create_registry_entries()
            
            # Step 5: Install service if selected
            if self.options.get('install_service', True):
                self.progress.emit(60, "Installing Windows service...")
                self._install_service()
            
            # Step 6: Create shortcuts
            if self.options.get('create_shortcuts', True):
                self.progress.emit(75, "Creating shortcuts...")
                self._create_shortcuts()
            
            # Step 7: Add to PATH if selected
            if self.options.get('add_to_path', False):
                self.progress.emit(85, "Adding to system PATH...")
                self._add_to_path()
            
            # Step 8: Start service if selected
            if self.options.get('start_service', True) and self.options.get('install_service', True):
                self.progress.emit(95, "Starting Jarwis Agent service...")
                self._start_service()
            
            self.progress.emit(100, "Installation completed successfully!")
            self.finished.emit(True, "Installation completed successfully!")
            
        except Exception as e:
            self.finished.emit(False, str(e))
    
    def _create_registry_entries(self):
        """Create Windows registry entries"""
        try:
            # Uninstall information
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\JarwisAgent"
            key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
            
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, APP_NAME)
            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, APP_VERSION)
            winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, COMPANY_NAME)
            winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, self.install_path)
            winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, 
                            f'"{os.path.join(self.install_path, "uninstall.exe")}"')
            winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ,
                            os.path.join(self.install_path, "jarwis-agent.exe"))
            
            winreg.CloseKey(key)
        except Exception as e:
            print(f"Registry error: {e}")
    
    def _install_service(self):
        """Install Windows service"""
        exe_path = os.path.join(self.install_path, "jarwis-agent.exe")
        try:
            # Stop existing service if running
            subprocess.run(["sc", "stop", SERVICE_NAME], capture_output=True)
            subprocess.run(["sc", "delete", SERVICE_NAME], capture_output=True)
            
            # Create new service
            subprocess.run([
                "sc", "create", SERVICE_NAME,
                f"binPath={exe_path} --service",
                "start=auto",
                f"DisplayName={APP_NAME}"
            ], check=True, capture_output=True)
            
            # Set description
            subprocess.run([
                "sc", "description", SERVICE_NAME,
                "Jarwis Security Agent - Endpoint protection and security scanning service"
            ], capture_output=True)
            
        except Exception as e:
            print(f"Service installation error: {e}")
    
    def _create_shortcuts(self):
        """Create Start Menu and Desktop shortcuts"""
        try:
            import win32com.client
            shell = win32com.client.Dispatch("WScript.Shell")
            
            # Start Menu
            start_menu = shell.SpecialFolders("StartMenu")
            jarwis_folder = os.path.join(start_menu, "Programs", "Jarwis Security")
            os.makedirs(jarwis_folder, exist_ok=True)
            
            shortcut = shell.CreateShortcut(os.path.join(jarwis_folder, "Jarwis Agent.lnk"))
            shortcut.TargetPath = os.path.join(self.install_path, "jarwis-agent.exe")
            shortcut.WorkingDirectory = self.install_path
            shortcut.Description = "Jarwis Security Agent"
            shortcut.save()
            
            # Desktop shortcut
            if self.options.get('desktop_shortcut', True):
                desktop = shell.SpecialFolders("Desktop")
                shortcut = shell.CreateShortcut(os.path.join(desktop, "Jarwis Agent.lnk"))
                shortcut.TargetPath = os.path.join(self.install_path, "jarwis-agent.exe")
                shortcut.WorkingDirectory = self.install_path
                shortcut.Description = "Jarwis Security Agent"
                shortcut.save()
                
        except ImportError:
            print("win32com not available, skipping shortcuts")
        except Exception as e:
            print(f"Shortcut creation error: {e}")
    
    def _add_to_path(self):
        """Add installation directory to system PATH"""
        try:
            key = winreg.OpenKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                0, winreg.KEY_READ | winreg.KEY_WRITE
            )
            path, _ = winreg.QueryValueEx(key, "Path")
            if self.install_path not in path:
                new_path = f"{path};{self.install_path}"
                winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
            winreg.CloseKey(key)
        except Exception as e:
            print(f"PATH update error: {e}")
    
    def _start_service(self):
        """Start the Windows service"""
        try:
            subprocess.run(["sc", "start", SERVICE_NAME], capture_output=True)
        except Exception as e:
            print(f"Service start error: {e}")


class WelcomePage(QWizardPage):
    """Welcome page with branding"""
    
    def __init__(self):
        super().__init__()
        self.setTitle("")
        self.setSubTitle("")
        
        layout = QVBoxLayout()
        layout.setSpacing(20)
        
        # Logo
        logo_label = QLabel()
        logo_path = self._find_logo()
        if logo_path and os.path.exists(logo_path):
            pixmap = QPixmap(logo_path).scaled(150, 150, Qt.AspectRatioMode.KeepAspectRatio,
                                               Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(pixmap)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo_label)
        
        # Title
        title = QLabel(f"Welcome to {APP_NAME} Setup")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #2980b9;")
        layout.addWidget(title)
        
        # Version
        version = QLabel(f"Version {APP_VERSION}")
        version.setFont(QFont("Segoe UI", 12))
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version.setStyleSheet("color: #7f8c8d;")
        layout.addWidget(version)
        
        # Description
        desc = QLabel(
            "This wizard will guide you through the installation of the\n"
            "Jarwis Security Agent on your computer.\n\n"
            "The agent provides:\n"
            " Real-time security monitoring\n"
            " Vulnerability scanning\n"
            " Network traffic analysis\n"
            " Integration with Jarwis Security Platform"
        )
        desc.setFont(QFont("Segoe UI", 11))
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)
        
        layout.addStretch()
        
        # Admin warning
        if not is_admin():
            warning = QLabel(" Administrator privileges required for installation")
            warning.setFont(QFont("Segoe UI", 10))
            warning.setStyleSheet("color: #e74c3c; padding: 10px; background: #fdf2f2; border-radius: 5px;")
            warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(warning)
        
        self.setLayout(layout)
    
    def _find_logo(self):
        """Find the logo file"""
        paths = [
            os.path.join(os.path.dirname(__file__), "..", "assets", "logos", "PNG-01.png"),
            os.path.join(os.path.dirname(__file__), "..", "..", "assets", "logos", "PNG-01.png"),
            os.path.join(os.path.dirname(sys.executable), "assets", "logos", "PNG-01.png"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None


class LicensePage(QWizardPage):
    """License agreement page"""
    
    def __init__(self):
        super().__init__()
        self.setTitle("License Agreement")
        self.setSubTitle("Please read the following license agreement carefully")
        
        layout = QVBoxLayout()
        
        # License text
        self.license_text = QTextEdit()
        self.license_text.setReadOnly(True)
        self.license_text.setFont(QFont("Segoe UI", 10))
        self.license_text.setPlainText(self._get_license_text())
        layout.addWidget(self.license_text)
        
        # Accept checkbox
        self.accept_check = QCheckBox("I accept the terms of the License Agreement")
        self.accept_check.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.accept_check.stateChanged.connect(self.completeChanged)
        layout.addWidget(self.accept_check)
        
        self.setLayout(layout)
        self.registerField("license_accepted*", self.accept_check)
    
    def _get_license_text(self):
        return """JARWIS SECURITY AGENT - END USER LICENSE AGREEMENT

IMPORTANT - READ CAREFULLY: This End User License Agreement ("Agreement") is a legal agreement between you (either an individual or a single entity) and Jarwis Security ("Company") for the Jarwis Security Agent software product ("Software").

By installing, copying, or otherwise using the Software, you agree to be bound by the terms of this Agreement.

1. GRANT OF LICENSE
Subject to the terms of this Agreement, the Company grants you a limited, non-exclusive, non-transferable license to install and use the Software on devices owned or controlled by you.

2. RESTRICTIONS
You may NOT:
 Copy, modify, or distribute the Software except as permitted
 Reverse engineer, decompile, or disassemble the Software
 Use the Software for any unlawful purpose
 Sublicense, rent, or lend the Software

3. DATA COLLECTION
The Software may collect system and security data as part of its operation. All data is handled according to our Privacy Policy.

4. DISCLAIMER OF WARRANTIES
THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.

5. LIMITATION OF LIABILITY
IN NO EVENT SHALL THE COMPANY BE LIABLE FOR ANY DAMAGES ARISING FROM USE OF THE SOFTWARE.

Copyright  2024-2026 Jarwis Security. All Rights Reserved.
Contact: legal@jarwis.ai | https://jarwis.ai"""
    
    def isComplete(self):
        return self.accept_check.isChecked()


class InstallLocationPage(QWizardPage):
    """Installation location selection"""
    
    def __init__(self):
        super().__init__()
        self.setTitle("Installation Location")
        self.setSubTitle("Choose the folder where you want to install Jarwis Agent")
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Path selection
        path_group = QGroupBox("Destination Folder")
        path_layout = QHBoxLayout()
        
        self.path_edit = QLineEdit(DEFAULT_INSTALL_PATH)
        self.path_edit.setFont(QFont("Segoe UI", 10))
        path_layout.addWidget(self.path_edit)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse)
        path_layout.addWidget(browse_btn)
        
        path_group.setLayout(path_layout)
        layout.addWidget(path_group)
        
        # Space info
        self.space_label = QLabel()
        self.space_label.setFont(QFont("Segoe UI", 9))
        self._update_space_info()
        layout.addWidget(self.space_label)
        
        layout.addStretch()
        
        self.setLayout(layout)
        self.registerField("install_path", self.path_edit)
    
    def _browse(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Installation Folder")
        if folder:
            self.path_edit.setText(folder)
            self._update_space_info()
    
    def _update_space_info(self):
        try:
            path = self.path_edit.text()
            drive = os.path.splitdrive(path)[0] or "C:"
            total, used, free = shutil.disk_usage(drive)
            free_gb = free / (1024**3)
            self.space_label.setText(f"Space required: ~50 MB | Available: {free_gb:.1f} GB")
        except:
            self.space_label.setText("Space required: ~50 MB")


class FeatureSelectionPage(QWizardPage):
    """Feature selection page"""
    
    def __init__(self):
        super().__init__()
        self.setTitle("Select Features")
        self.setSubTitle("Choose the features you want to install")
        
        layout = QVBoxLayout()
        layout.setSpacing(10)
        
        # Core features (always installed)
        core_group = QGroupBox("Core Components (Required)")
        core_layout = QVBoxLayout()
        
        core_agent = QCheckBox("Jarwis Agent Core")
        core_agent.setChecked(True)
        core_agent.setEnabled(False)
        core_layout.addWidget(core_agent)
        
        core_group.setLayout(core_layout)
        layout.addWidget(core_group)
        
        # Optional features
        optional_group = QGroupBox("Optional Components")
        optional_layout = QVBoxLayout()
        
        self.service_check = QCheckBox("Install as Windows Service (Recommended)")
        self.service_check.setChecked(True)
        self.service_check.setToolTip("Run the agent automatically at system startup")
        optional_layout.addWidget(self.service_check)
        
        self.tray_check = QCheckBox("System Tray Application")
        self.tray_check.setChecked(True)
        self.tray_check.setToolTip("Show status icon in the system tray")
        optional_layout.addWidget(self.tray_check)
        
        self.shortcut_check = QCheckBox("Create Desktop Shortcut")
        self.shortcut_check.setChecked(True)
        optional_layout.addWidget(self.shortcut_check)
        
        self.path_check = QCheckBox("Add to System PATH")
        self.path_check.setChecked(False)
        self.path_check.setToolTip("Allow running jarwis-agent from command line")
        optional_layout.addWidget(self.path_check)
        
        optional_group.setLayout(optional_layout)
        layout.addWidget(optional_group)
        
        layout.addStretch()
        
        self.setLayout(layout)
        
        self.registerField("install_service", self.service_check)
        self.registerField("install_tray", self.tray_check)
        self.registerField("desktop_shortcut", self.shortcut_check)
        self.registerField("add_to_path", self.path_check)


class ConfigurationPage(QWizardPage):
    """Server configuration page"""
    
    def __init__(self):
        super().__init__()
        self.setTitle("Server Configuration")
        self.setSubTitle("Configure the connection to your Jarwis server")
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Server URL
        server_group = QGroupBox("Jarwis Server")
        server_layout = QVBoxLayout()
        
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Server URL:"))
        self.server_url = QLineEdit("https://app.jarwis.ai")
        self.server_url.setPlaceholderText("https://your-jarwis-server.com")
        url_layout.addWidget(self.server_url)
        server_layout.addLayout(url_layout)
        
        server_group.setLayout(server_layout)
        layout.addWidget(server_group)
        
        # Activation
        activation_group = QGroupBox("Activation")
        activation_layout = QVBoxLayout()
        
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("Activation Key:"))
        self.activation_key = QLineEdit()
        self.activation_key.setPlaceholderText("Enter your activation key (optional)")
        self.activation_key.setEchoMode(QLineEdit.EchoMode.Password)
        key_layout.addWidget(self.activation_key)
        activation_layout.addLayout(key_layout)
        
        note = QLabel("You can activate the agent later from the dashboard")
        note.setFont(QFont("Segoe UI", 9))
        note.setStyleSheet("color: #7f8c8d;")
        activation_layout.addWidget(note)
        
        activation_group.setLayout(activation_layout)
        layout.addWidget(activation_group)
        
        layout.addStretch()
        
        self.setLayout(layout)
        
        self.registerField("server_url", self.server_url)
        self.registerField("activation_key", self.activation_key)


class InstallProgressPage(QWizardPage):
    """Installation progress page"""
    
    def __init__(self):
        super().__init__()
        self.setTitle("Installing")
        self.setSubTitle("Please wait while Jarwis Agent is being installed")
        self.setCommitPage(True)
        
        layout = QVBoxLayout()
        layout.setSpacing(20)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Preparing installation...")
        self.status_label.setFont(QFont("Segoe UI", 10))
        layout.addWidget(self.status_label)
        
        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(150)
        self.log_output.setFont(QFont("Consolas", 9))
        layout.addWidget(self.log_output)
        
        layout.addStretch()
        
        self.setLayout(layout)
        
        self.install_thread = None
        self.installation_complete = False
    
    def initializePage(self):
        """Start installation when page is shown"""
        self.wizard().button(QWizard.WizardButton.BackButton).setEnabled(False)
        self.wizard().button(QWizard.WizardButton.NextButton).setEnabled(False)
        
        # Get installation options
        options = {
            'install_service': self.field("install_service"),
            'install_tray': self.field("install_tray"),
            'desktop_shortcut': self.field("desktop_shortcut"),
            'add_to_path': self.field("add_to_path"),
            'server_url': self.field("server_url"),
            'activation_key': self.field("activation_key"),
            'start_service': True,
            'create_shortcuts': True,
        }
        
        install_path = self.field("install_path") or DEFAULT_INSTALL_PATH
        
        # Start installation thread
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
            self.log_output.append(f"\n {message}")
        else:
            self.status_label.setText(" Installation failed: " + message)
            self.log_output.append(f"\n Error: {message}")
        
        self.wizard().button(QWizard.WizardButton.NextButton).setEnabled(True)
        self.completeChanged.emit()
    
    def isComplete(self):
        return self.installation_complete


class CompletionPage(QWizardPage):
    """Installation complete page"""
    
    def __init__(self):
        super().__init__()
        self.setTitle("Installation Complete")
        self.setSubTitle("")
        
        layout = QVBoxLayout()
        layout.setSpacing(20)
        
        # Success message
        success_label = QLabel(" Jarwis Security Agent has been successfully installed!")
        success_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        success_label.setStyleSheet("color: #27ae60;")
        success_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(success_label)
        
        # Post-install options
        options_group = QGroupBox("Post-Installation Options")
        options_layout = QVBoxLayout()
        
        self.launch_check = QCheckBox("Launch Jarwis Agent")
        self.launch_check.setChecked(True)
        options_layout.addWidget(self.launch_check)
        
        self.open_dashboard_check = QCheckBox("Open Jarwis Dashboard in browser")
        self.open_dashboard_check.setChecked(False)
        options_layout.addWidget(self.open_dashboard_check)
        
        self.view_readme_check = QCheckBox("View documentation")
        self.view_readme_check.setChecked(False)
        options_layout.addWidget(self.view_readme_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Info
        info = QLabel(
            "The agent is now running as a Windows service.\n"
            "You can manage it from the system tray or Services console."
        )
        info.setFont(QFont("Segoe UI", 10))
        info.setStyleSheet("color: #7f8c8d;")
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(info)
        
        layout.addStretch()
        
        self.setLayout(layout)
        
        self.registerField("launch_agent", self.launch_check)
        self.registerField("open_dashboard", self.open_dashboard_check)


class JarwisSetupWizard(QWizard):
    """Main setup wizard"""
    
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle(f"{APP_NAME} Setup")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setMinimumSize(700, 550)
        
        # Set icon
        icon_path = self._find_icon()
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))
        
        # Add pages
        self.addPage(WelcomePage())
        self.addPage(LicensePage())
        self.addPage(InstallLocationPage())
        self.addPage(FeatureSelectionPage())
        self.addPage(ConfigurationPage())
        self.addPage(InstallProgressPage())
        self.addPage(CompletionPage())
        
        # Style
        self.setStyleSheet("""
            QWizard {
                background-color: #ffffff;
            }
            QWizardPage {
                background-color: #ffffff;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QPushButton {
                padding: 8px 20px;
                border-radius: 4px;
            }
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 5px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #2980b9;
                border-radius: 4px;
            }
        """)
    
    def _find_icon(self):
        paths = [
            os.path.join(os.path.dirname(__file__), "..", "assets", "icons", "jarwis-agent.ico"),
            os.path.join(os.path.dirname(sys.executable), "jarwis-agent.ico"),
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None
    
    def done(self, result):
        if result == QWizard.DialogCode.Accepted:
            # Post-install actions
            if self.field("launch_agent"):
                install_path = self.field("install_path") or DEFAULT_INSTALL_PATH
                exe = os.path.join(install_path, "jarwis-agent.exe")
                if os.path.exists(exe):
                    subprocess.Popen([exe, "--tray"])
            
            if self.field("open_dashboard"):
                import webbrowser
                server_url = self.field("server_url") or "https://app.jarwis.ai"
                webbrowser.open(server_url)
        
        super().done(result)


def main():
    # Check for admin on Windows
    if sys.platform == 'win32' and not is_admin():
        response = QMessageBox.question(
            None,
            "Administrator Required",
            "This installer requires administrator privileges.\n\nWould you like to restart as administrator?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if response == QMessageBox.StandardButton.Yes:
            run_as_admin()
        return
    
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set application info
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(COMPANY_NAME)
    
    wizard = JarwisSetupWizard()
    wizard.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
