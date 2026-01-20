"""
Jarwis Security Agent - System Tray Application
Shows connection status and provides quick access to agent features
"""

import sys
import os
from enum import Enum
from PyQt6.QtWidgets import (
    QApplication, QSystemTrayIcon, QMenu, QDialog, QVBoxLayout,
    QHBoxLayout, QLabel, QPushButton, QGroupBox, QFrame
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QIcon, QPixmap, QColor, QPainter, QAction
import requests


class ConnectionStatus(Enum):
    CONNECTED = "connected"
    CONNECTING = "connecting"
    DISCONNECTED = "disconnected"
    ERROR = "error"


def create_status_icon(status: ConnectionStatus, size=64):
    """Create a status indicator icon"""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    
    # Status colors
    colors = {
        ConnectionStatus.CONNECTED: QColor(39, 174, 96),      # Green
        ConnectionStatus.CONNECTING: QColor(241, 196, 15),    # Yellow
        ConnectionStatus.DISCONNECTED: QColor(149, 165, 166), # Gray
        ConnectionStatus.ERROR: QColor(231, 76, 60),          # Red
    }
    
    color = colors.get(status, colors[ConnectionStatus.DISCONNECTED])
    
    # Draw shield shape
    painter.setBrush(QColor(41, 128, 185))  # Jarwis blue base
    painter.setPen(Qt.PenStyle.NoPen)
    
    # Main shield
    from PyQt6.QtGui import QPainterPath
    path = QPainterPath()
    path.moveTo(size/2, 4)
    path.lineTo(size-8, 12)
    path.lineTo(size-8, size/2)
    path.quadTo(size/2, size-4, size/2, size-4)
    path.quadTo(size/2, size-4, 8, size/2)
    path.lineTo(8, 12)
    path.closeSubpath()
    painter.drawPath(path)
    
    # Status indicator circle
    painter.setBrush(color)
    indicator_size = size // 4
    painter.drawEllipse(
        size - indicator_size - 4,
        size - indicator_size - 4,
        indicator_size,
        indicator_size
    )
    
    painter.end()
    return QIcon(pixmap)


class StatusCheckThread(QThread):
    """Background thread for checking connection status"""
    status_changed = pyqtSignal(ConnectionStatus, str)
    
    def __init__(self, server_url):
        super().__init__()
        self.server_url = server_url
        self.running = True
    
    def run(self):
        while self.running:
            try:
                response = requests.get(
                    f"{self.server_url}/api/health",
                    timeout=5
                )
                if response.status_code == 200:
                    self.status_changed.emit(
                        ConnectionStatus.CONNECTED,
                        "Connected to Jarwis server"
                    )
                else:
                    self.status_changed.emit(
                        ConnectionStatus.ERROR,
                        f"Server error: {response.status_code}"
                    )
            except requests.exceptions.ConnectionError:
                self.status_changed.emit(
                    ConnectionStatus.DISCONNECTED,
                    "Cannot reach Jarwis server"
                )
            except requests.exceptions.Timeout:
                self.status_changed.emit(
                    ConnectionStatus.ERROR,
                    "Connection timeout"
                )
            except Exception as e:
                self.status_changed.emit(
                    ConnectionStatus.ERROR,
                    str(e)
                )
            
            # Check every 30 seconds
            for _ in range(30):
                if not self.running:
                    break
                self.msleep(1000)
    
    def stop(self):
        self.running = False


class StatusDialog(QDialog):
    """Detailed status dialog"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Jarwis Agent Status")
        self.setMinimumSize(400, 300)
        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        )
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        # Status section
        status_group = QGroupBox("Connection Status")
        status_layout = QVBoxLayout()
        
        self.status_indicator = QLabel(" Checking...")
        self.status_indicator.setStyleSheet("font-size: 14px; font-weight: bold;")
        status_layout.addWidget(self.status_indicator)
        
        self.status_message = QLabel("")
        status_layout.addWidget(self.status_message)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Info section
        info_group = QGroupBox("Agent Information")
        info_layout = QVBoxLayout()
        
        self.version_label = QLabel("Version: 2.0.0")
        info_layout.addWidget(self.version_label)
        
        self.service_label = QLabel("Service: Running")
        info_layout.addWidget(self.service_label)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        button_layout.addWidget(refresh_btn)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def set_status(self, status: ConnectionStatus, message: str):
        colors = {
            ConnectionStatus.CONNECTED: "#27ae60",
            ConnectionStatus.CONNECTING: "#f1c40f",
            ConnectionStatus.DISCONNECTED: "#95a5a6",
            ConnectionStatus.ERROR: "#e74c3c",
        }
        labels = {
            ConnectionStatus.CONNECTED: "Connected",
            ConnectionStatus.CONNECTING: "Connecting...",
            ConnectionStatus.DISCONNECTED: "Disconnected",
            ConnectionStatus.ERROR: "Error",
        }
        
        color = colors.get(status, "#95a5a6")
        label = labels.get(status, "Unknown")
        
        self.status_indicator.setText(f" {label}")
        self.status_indicator.setStyleSheet(
            f"font-size: 14px; font-weight: bold; color: {color};"
        )
        self.status_message.setText(message)
    
    def refresh(self):
        self.status_indicator.setText(" Checking...")
        self.status_indicator.setStyleSheet(
            "font-size: 14px; font-weight: bold; color: #f1c40f;"
        )


class JarwisTrayApp:
    """Main system tray application"""
    
    def __init__(self, server_url="https://app.jarwis.ai"):
        self.app = QApplication(sys.argv)
        self.app.setQuitOnLastWindowClosed(False)
        
        self.server_url = server_url
        self.current_status = ConnectionStatus.CONNECTING
        
        # Create tray icon
        self.tray_icon = QSystemTrayIcon()
        self.tray_icon.setIcon(create_status_icon(self.current_status))
        self.tray_icon.setToolTip("Jarwis Security Agent - Connecting...")
        
        # Create menu
        self.menu = QMenu()
        
        # Status action (non-clickable header)
        self.status_action = QAction("Status: Connecting...")
        self.status_action.setEnabled(False)
        self.menu.addAction(self.status_action)
        
        self.menu.addSeparator()
        
        # Actions
        show_status = QAction("Show Details...")
        show_status.triggered.connect(self.show_status_dialog)
        self.menu.addAction(show_status)
        
        open_dashboard = QAction("Open Dashboard")
        open_dashboard.triggered.connect(self.open_dashboard)
        self.menu.addAction(open_dashboard)
        
        self.menu.addSeparator()
        
        # Service controls
        restart_service = QAction("Restart Service")
        restart_service.triggered.connect(self.restart_service)
        self.menu.addAction(restart_service)
        
        self.menu.addSeparator()
        
        # Quit
        quit_action = QAction("Quit")
        quit_action.triggered.connect(self.quit)
        self.menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(self.menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        
        # Status dialog
        self.status_dialog = StatusDialog()
        
        # Start status checker
        self.status_thread = StatusCheckThread(self.server_url)
        self.status_thread.status_changed.connect(self.on_status_changed)
        self.status_thread.start()
        
        # Show tray icon
        self.tray_icon.show()
    
    def on_status_changed(self, status: ConnectionStatus, message: str):
        self.current_status = status
        self.tray_icon.setIcon(create_status_icon(status))
        
        tooltips = {
            ConnectionStatus.CONNECTED: "Jarwis Security Agent - Connected",
            ConnectionStatus.CONNECTING: "Jarwis Security Agent - Connecting...",
            ConnectionStatus.DISCONNECTED: "Jarwis Security Agent - Disconnected",
            ConnectionStatus.ERROR: f"Jarwis Security Agent - Error: {message}",
        }
        self.tray_icon.setToolTip(tooltips.get(status, "Jarwis Security Agent"))
        
        status_texts = {
            ConnectionStatus.CONNECTED: "Status: Connected ",
            ConnectionStatus.CONNECTING: "Status: Connecting...",
            ConnectionStatus.DISCONNECTED: "Status: Disconnected",
            ConnectionStatus.ERROR: "Status: Error",
        }
        self.status_action.setText(status_texts.get(status, "Status: Unknown"))
        
        # Update dialog if open
        if self.status_dialog.isVisible():
            self.status_dialog.set_status(status, message)
    
    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_status_dialog()
    
    def show_status_dialog(self):
        self.status_dialog.set_status(self.current_status, "")
        self.status_dialog.show()
        self.status_dialog.raise_()
        self.status_dialog.activateWindow()
    
    def open_dashboard(self):
        import webbrowser
        webbrowser.open(self.server_url)
    
    def restart_service(self):
        import subprocess
        try:
            subprocess.run(["sc", "stop", "JarwisAgent"], capture_output=True)
            subprocess.run(["sc", "start", "JarwisAgent"], capture_output=True)
            self.tray_icon.showMessage(
                "Jarwis Agent",
                "Service restarted successfully",
                QSystemTrayIcon.MessageIcon.Information,
                3000
            )
        except Exception as e:
            self.tray_icon.showMessage(
                "Jarwis Agent",
                f"Failed to restart service: {e}",
                QSystemTrayIcon.MessageIcon.Warning,
                3000
            )
    
    def quit(self):
        self.status_thread.stop()
        self.status_thread.wait()
        self.tray_icon.hide()
        self.app.quit()
    
    def run(self):
        return self.app.exec()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Jarwis Agent System Tray")
    parser.add_argument("--server", default="https://app.jarwis.ai",
                       help="Jarwis server URL")
    args = parser.parse_args()
    
    app = JarwisTrayApp(server_url=args.server)
    sys.exit(app.run())


if __name__ == "__main__":
    main()
