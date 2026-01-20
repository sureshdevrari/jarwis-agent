#!/usr/bin/env python3
"""
Jarwis Agent - Post-Install Configuration Tool

A GUI utility for configuring the Jarwis Security Agent after installation.
Allows users to enter server URL, activation key, and connection settings.

Copyright (c) 2025 Jarwis Security
"""

import sys
import os
import yaml
from pathlib import Path

# PyQt6 imports
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QGroupBox, QFormLayout,
    QMessageBox, QCheckBox, QSpinBox, QComboBox, QTextEdit,
    QTabWidget, QProgressBar, QStatusBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QFont, QPalette, QColor

# Version
VERSION = "2.1.0"


def get_config_path():
    """Get the configuration file path based on platform."""
    if sys.platform == 'win32':
        return Path(os.environ.get('PROGRAMDATA', 'C:\\ProgramData')) / 'Jarwis' / 'config.yaml'
    elif sys.platform == 'darwin':
        return Path('/usr/local/etc/jarwis/config.yaml')
    else:  # Linux
        return Path('/etc/jarwis/config.yaml')


def get_log_path():
    """Get the log directory path based on platform."""
    if sys.platform == 'win32':
        return Path(os.environ.get('PROGRAMDATA', 'C:\\ProgramData')) / 'Jarwis' / 'logs'
    elif sys.platform == 'darwin':
        return Path('/var/log/jarwis')
    else:  # Linux
        return Path('/var/log/jarwis')


class ConnectionTestThread(QThread):
    """Thread for testing server connection."""
    finished = pyqtSignal(bool, str)
    
    def __init__(self, server_url, activation_key):
        super().__init__()
        self.server_url = server_url
        self.activation_key = activation_key
    
    def run(self):
        """Test connection to server."""
        try:
            import urllib.request
            import json
            
            # Test basic connectivity
            url = f"{self.server_url.rstrip('/')}/api/health"
            req = urllib.request.Request(url, method='GET')
            req.add_header('User-Agent', f'JarwisAgent/{VERSION}')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    self.finished.emit(True, "Connection successful!")
                else:
                    self.finished.emit(False, f"Server returned status {response.status}")
        except urllib.error.URLError as e:
            self.finished.emit(False, f"Connection failed: {e.reason}")
        except Exception as e:
            self.finished.emit(False, f"Error: {str(e)}")


class JarwisConfigTool(QMainWindow):
    """Main configuration window."""
    
    def __init__(self):
        super().__init__()
        self.config = {}
        self.config_path = get_config_path()
        self.load_config()
        self.init_ui()
    
    def load_config(self):
        """Load existing configuration."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    self.config = yaml.safe_load(f) or {}
            except Exception as e:
                self.config = {}
                print(f"Could not load config: {e}")
        else:
            self.config = {
                'server': {
                    'url': 'https://app.jarwis.ai',
                    'port': 443,
                },
                'agent': {
                    'activation_key': '',
                    'auto_connect': True,
                    'reconnect_interval': 30,
                    'log_level': 'INFO',
                },
                'security': {
                    'verify_ssl': True,
                    'allowed_scan_types': ['web', 'api', 'mobile'],
                }
            }
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle(f'Jarwis Agent Configuration v{VERSION}')
        self.setMinimumSize(500, 450)
        self.setMaximumSize(600, 550)
        
        # Load icon if available
        icon_path = Path(__file__).parent / 'assets' / 'icons' / 'jarwis-agent.ico'
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Title
        title = QLabel('Jarwis Security Agent Configuration')
        title.setFont(QFont('Arial', 14, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Tab widget
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Connection tab
        conn_tab = QWidget()
        conn_layout = QVBoxLayout(conn_tab)
        tabs.addTab(conn_tab, "Connection")
        
        # Server settings
        server_group = QGroupBox("Server Settings")
        server_layout = QFormLayout(server_group)
        
        self.server_url = QLineEdit()
        self.server_url.setText(self.config.get('server', {}).get('url', 'https://app.jarwis.ai'))
        self.server_url.setPlaceholderText('https://app.jarwis.ai')
        server_layout.addRow("Server URL:", self.server_url)
        
        self.activation_key = QLineEdit()
        self.activation_key.setText(self.config.get('agent', {}).get('activation_key', ''))
        self.activation_key.setPlaceholderText('Enter your activation key')
        self.activation_key.setEchoMode(QLineEdit.EchoMode.Password)
        server_layout.addRow("Activation Key:", self.activation_key)
        
        self.show_key = QCheckBox("Show key")
        self.show_key.stateChanged.connect(self.toggle_key_visibility)
        server_layout.addRow("", self.show_key)
        
        conn_layout.addWidget(server_group)
        
        # Connection options
        options_group = QGroupBox("Connection Options")
        options_layout = QFormLayout(options_group)
        
        self.auto_connect = QCheckBox()
        self.auto_connect.setChecked(self.config.get('agent', {}).get('auto_connect', True))
        options_layout.addRow("Auto-connect on startup:", self.auto_connect)
        
        self.verify_ssl = QCheckBox()
        self.verify_ssl.setChecked(self.config.get('security', {}).get('verify_ssl', True))
        options_layout.addRow("Verify SSL certificates:", self.verify_ssl)
        
        self.reconnect_interval = QSpinBox()
        self.reconnect_interval.setRange(5, 300)
        self.reconnect_interval.setValue(self.config.get('agent', {}).get('reconnect_interval', 30))
        self.reconnect_interval.setSuffix(" seconds")
        options_layout.addRow("Reconnect interval:", self.reconnect_interval)
        
        conn_layout.addWidget(options_group)
        
        # Test connection button
        test_layout = QHBoxLayout()
        self.test_btn = QPushButton("Test Connection")
        self.test_btn.clicked.connect(self.test_connection)
        test_layout.addStretch()
        test_layout.addWidget(self.test_btn)
        test_layout.addStretch()
        conn_layout.addLayout(test_layout)
        
        self.test_progress = QProgressBar()
        self.test_progress.setVisible(False)
        conn_layout.addWidget(self.test_progress)
        
        conn_layout.addStretch()
        
        # Advanced tab
        adv_tab = QWidget()
        adv_layout = QVBoxLayout(adv_tab)
        tabs.addTab(adv_tab, "Advanced")
        
        # Logging settings
        log_group = QGroupBox("Logging")
        log_layout = QFormLayout(log_group)
        
        self.log_level = QComboBox()
        self.log_level.addItems(['DEBUG', 'INFO', 'WARNING', 'ERROR'])
        current_level = self.config.get('agent', {}).get('log_level', 'INFO')
        index = self.log_level.findText(current_level)
        if index >= 0:
            self.log_level.setCurrentIndex(index)
        log_layout.addRow("Log level:", self.log_level)
        
        log_path_label = QLabel(str(get_log_path()))
        log_path_label.setStyleSheet("color: gray; font-size: 10px;")
        log_layout.addRow("Log directory:", log_path_label)
        
        adv_layout.addWidget(log_group)
        
        # Scan types
        scan_group = QGroupBox("Allowed Scan Types")
        scan_layout = QVBoxLayout(scan_group)
        
        allowed = self.config.get('security', {}).get('allowed_scan_types', ['web', 'api', 'mobile'])
        
        self.scan_web = QCheckBox("Web application scanning")
        self.scan_web.setChecked('web' in allowed)
        scan_layout.addWidget(self.scan_web)
        
        self.scan_api = QCheckBox("API security testing")
        self.scan_api.setChecked('api' in allowed)
        scan_layout.addWidget(self.scan_api)
        
        self.scan_mobile = QCheckBox("Mobile application testing")
        self.scan_mobile.setChecked('mobile' in allowed)
        scan_layout.addWidget(self.scan_mobile)
        
        self.scan_network = QCheckBox("Network scanning")
        self.scan_network.setChecked('network' in allowed)
        scan_layout.addWidget(self.scan_network)
        
        adv_layout.addWidget(scan_group)
        adv_layout.addStretch()
        
        # About tab
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        tabs.addTab(about_tab, "About")
        
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setHtml(f"""
            <h2>Jarwis Security Agent</h2>
            <p><b>Version:</b> {VERSION}</p>
            <p><b>Configuration file:</b><br>{self.config_path}</p>
            <p><b>Log directory:</b><br>{get_log_path()}</p>
            <hr>
            <p>Jarwis Security Agent provides automated security testing
            capabilities for web applications, APIs, and mobile apps.</p>
            <p>For support, visit: <a href="https://jarwis.io">https://jarwis.io</a></p>
            <p>© 2025 Jarwis Security. All rights reserved.</p>
        """)
        about_layout.addWidget(about_text)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        save_btn = QPushButton("Save Configuration")
        save_btn.clicked.connect(self.save_config)
        save_btn.setDefault(True)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.close)
        
        btn_layout.addStretch()
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        
        layout.addLayout(btn_layout)
        
        # Status bar
        self.statusBar().showMessage('Ready')
    
    def toggle_key_visibility(self, state):
        """Toggle activation key visibility."""
        if state:
            self.activation_key.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.activation_key.setEchoMode(QLineEdit.EchoMode.Password)
    
    def test_connection(self):
        """Test connection to server."""
        self.test_btn.setEnabled(False)
        self.test_progress.setVisible(True)
        self.test_progress.setRange(0, 0)  # Indeterminate
        self.statusBar().showMessage('Testing connection...')
        
        self.test_thread = ConnectionTestThread(
            self.server_url.text(),
            self.activation_key.text()
        )
        self.test_thread.finished.connect(self.on_test_complete)
        self.test_thread.start()
    
    def on_test_complete(self, success, message):
        """Handle connection test result."""
        self.test_btn.setEnabled(True)
        self.test_progress.setVisible(False)
        
        if success:
            self.statusBar().showMessage(message)
            QMessageBox.information(self, "Connection Test", message)
        else:
            self.statusBar().showMessage(f"Connection failed: {message}")
            QMessageBox.warning(self, "Connection Test", message)
    
    def save_config(self):
        """Save configuration to file."""
        # Build config
        allowed_scans = []
        if self.scan_web.isChecked():
            allowed_scans.append('web')
        if self.scan_api.isChecked():
            allowed_scans.append('api')
        if self.scan_mobile.isChecked():
            allowed_scans.append('mobile')
        if self.scan_network.isChecked():
            allowed_scans.append('network')
        
        self.config = {
            'server': {
                'url': self.server_url.text().strip(),
                'port': 443,
            },
            'agent': {
                'activation_key': self.activation_key.text().strip(),
                'auto_connect': self.auto_connect.isChecked(),
                'reconnect_interval': self.reconnect_interval.value(),
                'log_level': self.log_level.currentText(),
            },
            'security': {
                'verify_ssl': self.verify_ssl.isChecked(),
                'allowed_scan_types': allowed_scans,
            }
        }
        
        # Ensure directory exists
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_path, 'w') as f:
                yaml.safe_dump(self.config, f, default_flow_style=False)
            
            self.statusBar().showMessage('Configuration saved successfully!')
            QMessageBox.information(
                self, 
                "Configuration Saved",
                f"Configuration has been saved to:\n{self.config_path}\n\n"
                "Restart the Jarwis Agent service for changes to take effect."
            )
        except PermissionError:
            QMessageBox.critical(
                self,
                "Permission Denied",
                f"Cannot write to {self.config_path}\n\n"
                "Please run this tool as Administrator (Windows) or with sudo (Linux/macOS)."
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to save configuration:\n{str(e)}"
            )


def main():
    """Main entry point."""
    app = QApplication(sys.argv)
    app.setApplicationName("Jarwis Configuration")
    app.setApplicationVersion(VERSION)
    app.setOrganizationName("Jarwis Security")
    app.setOrganizationDomain("jarwis.io")
    
    # Set style
    app.setStyle('Fusion')
    
    window = JarwisConfigTool()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
