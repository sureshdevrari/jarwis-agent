#!/usr/bin/env python3
"""
Jarwis Agent Post-Install Configuration UI

A simple configuration window that runs after installation to:
- Verify installation success
- Configure server connection
- Test connectivity
- Show connection status
- Provide quick links to dashboard and docs

Requirements:
    pip install PyQt6

Usage:
    python post_install_config.py [--install-path PATH]
"""

import sys
import os
import asyncio
import json
import webbrowser
from pathlib import Path
from typing import Optional

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QProgressBar, QGroupBox,
        QFrame, QMessageBox, QCheckBox, QTextEdit
    )
    from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
    from PyQt6.QtGui import QFont, QPixmap, QPainter, QColor
except ImportError:
    print("ERROR: PyQt6 is required. Install with: pip install PyQt6")
    sys.exit(1)


# ============================================================================
# Styles
# ============================================================================

STYLESHEET = """
QMainWindow {
    background-color: #ffffff;
}

QWidget {
    font-family: 'Segoe UI', Arial, sans-serif;
}

QLabel {
    color: #333333;
}

QLabel#headerLabel {
    font-size: 20px;
    font-weight: bold;
    color: #182038;
}

QLabel#subheaderLabel {
    font-size: 12px;
    color: #666666;
}

QLabel#successLabel {
    font-size: 14px;
    color: #22c55e;
    font-weight: bold;
}

QLabel#errorLabel {
    font-size: 14px;
    color: #ef4444;
    font-weight: bold;
}

QGroupBox {
    font-weight: bold;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 12px;
    background-color: #f9fafb;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 8px;
    color: #374151;
}

QLineEdit {
    padding: 10px 12px;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    background-color: #ffffff;
    font-size: 13px;
}

QLineEdit:focus {
    border-color: #4a90d9;
    outline: none;
}

QPushButton {
    padding: 10px 20px;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    background-color: #ffffff;
    font-size: 13px;
    font-weight: 500;
}

QPushButton:hover {
    background-color: #f3f4f6;
}

QPushButton#primaryButton {
    background-color: #182038;
    color: white;
    border-color: #182038;
}

QPushButton#primaryButton:hover {
    background-color: #2a3550;
}

QPushButton#successButton {
    background-color: #22c55e;
    color: white;
    border-color: #22c55e;
}

QPushButton#linkButton {
    border: none;
    background: none;
    color: #4a90d9;
    text-decoration: underline;
    padding: 4px;
}

QPushButton#linkButton:hover {
    color: #2563eb;
}

QProgressBar {
    border: 1px solid #d1d5db;
    border-radius: 6px;
    text-align: center;
    height: 28px;
    background-color: #f3f4f6;
}

QProgressBar::chunk {
    background-color: #4a90d9;
    border-radius: 5px;
}

QTextEdit {
    border: 1px solid #d1d5db;
    border-radius: 6px;
    background-color: #f9fafb;
    font-family: 'Consolas', monospace;
    font-size: 11px;
}

QFrame#statusFrame {
    border: 2px solid #d1d5db;
    border-radius: 8px;
    padding: 16px;
    background-color: #f9fafb;
}

QFrame#statusFrame[status="connected"] {
    border-color: #22c55e;
    background-color: #f0fdf4;
}

QFrame#statusFrame[status="error"] {
    border-color: #ef4444;
    background-color: #fef2f2;
}

QFrame#statusFrame[status="connecting"] {
    border-color: #f59e0b;
    background-color: #fffbeb;
}
"""


# ============================================================================
# Connection Test Worker
# ============================================================================

class ConnectionTestWorker(QThread):
    """Worker thread for testing server connection."""
    
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(bool, str)
    
    def __init__(self, server_url: str, activation_key: str = ""):
        super().__init__()
        self.server_url = server_url
        self.activation_key = activation_key
    
    def run(self):
        try:
            import socket
            import ssl
            from urllib.parse import urlparse
            
            self.progress.emit(20, "Parsing server URL...")
            
            # Parse URL
            parsed = urlparse(self.server_url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme in ('wss', 'https') else 80)
            use_ssl = parsed.scheme in ('wss', 'https')
            
            self.progress.emit(40, f"Connecting to {host}:{port}...")
            
            # Test TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            if use_ssl:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            
            self.progress.emit(60, "Connection established, testing WebSocket...")
            
            # Send WebSocket handshake
            handshake = (
                f"GET {parsed.path or '/ws/agent'} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            )
            
            sock.send(handshake.encode())
            
            self.progress.emit(80, "Waiting for server response...")
            
            response = sock.recv(1024).decode()
            
            sock.close()
            
            self.progress.emit(100, "Connection test complete!")
            
            if "101" in response or "Switching Protocols" in response:
                self.finished.emit(True, "Successfully connected to Jarwis server!")
            elif "401" in response or "403" in response:
                self.finished.emit(False, "Authentication failed. Please check your activation key.")
            else:
                self.finished.emit(True, "Server is reachable. Connection will be established when agent starts.")
            
        except socket.timeout:
            self.finished.emit(False, "Connection timed out. Please check the server URL.")
        except socket.gaierror:
            self.finished.emit(False, "Could not resolve server hostname. Please check the URL.")
        except ConnectionRefusedError:
            self.finished.emit(False, "Connection refused. The server may be down.")
        except ssl.SSLError as e:
            self.finished.emit(False, f"SSL error: {str(e)}")
        except Exception as e:
            self.finished.emit(False, f"Connection failed: {str(e)}")


# ============================================================================
# Main Configuration Window
# ============================================================================

class PostInstallConfigWindow(QMainWindow):
    """Post-installation configuration window."""
    
    def __init__(self, install_path: str = None):
        super().__init__()
        
        self.install_path = install_path or r"C:\Program Files\Jarwis Agent"
        self.test_worker = None
        
        self._setup_ui()
        self._load_existing_config()
    
    def _setup_ui(self):
        """Setup the user interface."""
        self.setWindowTitle("Jarwis Agent - Setup Complete")
        self.setFixedSize(600, 700)
        self.setStyleSheet(STYLESHEET)
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        
        layout = QVBoxLayout(central)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Header with logo
        header_layout = QHBoxLayout()
        
        # Logo placeholder
        logo_label = QLabel("🛡️")
        logo_label.setStyleSheet("font-size: 48px;")
        header_layout.addWidget(logo_label)
        
        # Title
        title_layout = QVBoxLayout()
        title = QLabel("Installation Complete!")
        title.setObjectName("headerLabel")
        title_layout.addWidget(title)
        
        subtitle = QLabel("Jarwis Security Agent v2.0.0 has been installed successfully.")
        subtitle.setObjectName("subheaderLabel")
        title_layout.addWidget(subtitle)
        
        header_layout.addLayout(title_layout)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Status frame
        self.status_frame = QFrame()
        self.status_frame.setObjectName("statusFrame")
        status_layout = QVBoxLayout(self.status_frame)
        
        self.status_icon = QLabel("✓")
        self.status_icon.setStyleSheet("font-size: 32px; color: #22c55e;")
        self.status_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_layout.addWidget(self.status_icon)
        
        self.status_label = QLabel("Agent installed and ready to configure")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        status_layout.addWidget(self.status_label)
        
        layout.addWidget(self.status_frame)
        
        # Server configuration
        server_group = QGroupBox("Server Configuration")
        server_layout = QVBoxLayout(server_group)
        
        url_label = QLabel("Server URL:")
        server_layout.addWidget(url_label)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("wss://jarwis.io/ws/agent")
        self.url_input.setText("wss://jarwis.io/ws/agent")
        server_layout.addWidget(self.url_input)
        
        key_label = QLabel("Activation Key (optional):")
        server_layout.addWidget(key_label)
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter your activation key")
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        server_layout.addWidget(self.key_input)
        
        # Show/hide key toggle
        self.show_key_check = QCheckBox("Show activation key")
        self.show_key_check.stateChanged.connect(self._toggle_key_visibility)
        server_layout.addWidget(self.show_key_check)
        
        layout.addWidget(server_group)
        
        # Connection test
        test_group = QGroupBox("Connection Test")
        test_layout = QVBoxLayout(test_group)
        
        self.test_progress = QProgressBar()
        self.test_progress.setRange(0, 100)
        self.test_progress.setValue(0)
        self.test_progress.setVisible(False)
        test_layout.addWidget(self.test_progress)
        
        self.test_status = QLabel("")
        self.test_status.setWordWrap(True)
        test_layout.addWidget(self.test_status)
        
        test_btn_layout = QHBoxLayout()
        self.test_button = QPushButton("Test Connection")
        self.test_button.clicked.connect(self._test_connection)
        test_btn_layout.addWidget(self.test_button)
        test_btn_layout.addStretch()
        test_layout.addLayout(test_btn_layout)
        
        layout.addWidget(test_group)
        
        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout(actions_group)
        
        dashboard_btn = QPushButton("Open Dashboard")
        dashboard_btn.setObjectName("primaryButton")
        dashboard_btn.clicked.connect(lambda: webbrowser.open("https://jarwis.io/dashboard"))
        actions_layout.addWidget(dashboard_btn)
        
        docs_btn = QPushButton("Documentation")
        docs_btn.clicked.connect(lambda: webbrowser.open("https://jarwis.io/docs/agent"))
        actions_layout.addWidget(docs_btn)
        
        support_btn = QPushButton("Get Support")
        support_btn.clicked.connect(lambda: webbrowser.open("https://jarwis.io/support"))
        actions_layout.addWidget(support_btn)
        
        layout.addWidget(actions_group)
        
        layout.addStretch()
        
        # Bottom buttons
        bottom_layout = QHBoxLayout()
        
        save_btn = QPushButton("Save Configuration")
        save_btn.setObjectName("primaryButton")
        save_btn.clicked.connect(self._save_config)
        bottom_layout.addWidget(save_btn)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        bottom_layout.addWidget(close_btn)
        
        layout.addLayout(bottom_layout)
    
    def _toggle_key_visibility(self):
        """Toggle activation key visibility."""
        if self.show_key_check.isChecked():
            self.key_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
    
    def _load_existing_config(self):
        """Load existing configuration if available."""
        config_path = Path(self.install_path) / 'agent-config.yaml'
        
        if config_path.exists():
            try:
                import yaml
                with open(config_path) as f:
                    config = yaml.safe_load(f)
                
                if 'server' in config:
                    self.url_input.setText(config['server'].get('url', ''))
                
                if 'agent' in config:
                    self.key_input.setText(config['agent'].get('activation_key', ''))
                    
            except Exception:
                pass  # Use defaults
    
    def _test_connection(self):
        """Test server connection."""
        self.test_button.setEnabled(False)
        self.test_progress.setVisible(True)
        self.test_progress.setValue(0)
        self.test_status.setText("Starting connection test...")
        
        self.test_worker = ConnectionTestWorker(
            self.url_input.text(),
            self.key_input.text()
        )
        self.test_worker.progress.connect(self._on_test_progress)
        self.test_worker.finished.connect(self._on_test_finished)
        self.test_worker.start()
    
    def _on_test_progress(self, percent: int, message: str):
        """Handle test progress updates."""
        self.test_progress.setValue(percent)
        self.test_status.setText(message)
    
    def _on_test_finished(self, success: bool, message: str):
        """Handle test completion."""
        self.test_button.setEnabled(True)
        self.test_progress.setVisible(False)
        
        if success:
            self.test_status.setText(f"✓ {message}")
            self.test_status.setStyleSheet("color: #22c55e; font-weight: bold;")
            
            # Update status frame
            self.status_frame.setProperty("status", "connected")
            self.status_frame.style().unpolish(self.status_frame)
            self.status_frame.style().polish(self.status_frame)
            self.status_icon.setText("✓")
            self.status_icon.setStyleSheet("font-size: 32px; color: #22c55e;")
            self.status_label.setText("Connected to Jarwis Server")
        else:
            self.test_status.setText(f"✗ {message}")
            self.test_status.setStyleSheet("color: #ef4444; font-weight: bold;")
            
            # Update status frame
            self.status_frame.setProperty("status", "error")
            self.status_frame.style().unpolish(self.status_frame)
            self.status_frame.style().polish(self.status_frame)
            self.status_icon.setText("!")
            self.status_icon.setStyleSheet("font-size: 32px; color: #ef4444;")
            self.status_label.setText("Connection Issue")
    
    def _save_config(self):
        """Save configuration to file."""
        config_content = f"""# Jarwis Agent Configuration
# Generated by Post-Install Configuration

server:
  url: "{self.url_input.text()}"
  reconnect_interval: 30
  heartbeat_interval: 15

agent:
  activation_key: "{self.key_input.text()}"
  auto_start: true
  telemetry_enabled: true

features:
  web_scanning: true
  mobile_scanning: true
  network_scanning: true
  cloud_scanning: true
  sast_scanning: true

logging:
  level: INFO
  file: logs/agent.log
  max_size_mb: 50
  backup_count: 5
"""
        
        try:
            config_path = Path(self.install_path) / 'agent-config.yaml'
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(config_content)
            
            QMessageBox.information(
                self,
                "Configuration Saved",
                f"Configuration has been saved to:\n{config_path}\n\n"
                "The agent will use these settings on next restart."
            )
            
            # Offer to restart service
            result = QMessageBox.question(
                self,
                "Restart Agent?",
                "Would you like to restart the agent service to apply the new configuration?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if result == QMessageBox.StandardButton.Yes:
                self._restart_service()
                
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to save configuration:\n{str(e)}"
            )
    
    def _restart_service(self):
        """Restart the Windows service."""
        import subprocess
        
        try:
            # Stop service
            subprocess.run(['sc', 'stop', 'JarwisAgent'], 
                         capture_output=True, check=False)
            
            # Wait a moment
            import time
            time.sleep(2)
            
            # Start service
            result = subprocess.run(['sc', 'start', 'JarwisAgent'], 
                                  capture_output=True, check=False)
            
            if result.returncode == 0:
                QMessageBox.information(
                    self,
                    "Service Restarted",
                    "The Jarwis Agent service has been restarted with the new configuration."
                )
            else:
                raise Exception("Service failed to start")
                
        except Exception as e:
            QMessageBox.warning(
                self,
                "Service Restart",
                f"Could not restart the service automatically.\n\n"
                f"Please restart it manually from Windows Services (services.msc)\n"
                f"or run: sc start JarwisAgent"
            )


# ============================================================================
# Entry Point
# ============================================================================

def main():
    # Parse command line arguments
    install_path = None
    args = sys.argv[1:]
    
    i = 0
    while i < len(args):
        if args[i] == '--install-path' and i + 1 < len(args):
            install_path = args[i + 1]
            i += 2
        else:
            i += 1
    
    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("Jarwis Agent Configuration")
    app.setOrganizationName("Jarwis Security")
    
    # Create and show window
    window = PostInstallConfigWindow(install_path)
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
