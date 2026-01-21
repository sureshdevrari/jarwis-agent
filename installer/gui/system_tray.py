#!/usr/bin/env python3
"""
Jarwis Agent System Tray Application

Provides a system tray icon for the Jarwis Security Agent with:
- Connection status indicator (green/yellow/red)
- Quick access menu
- Configuration options
- Notifications

Requirements:
    pip install PyQt6 pystray Pillow

Usage:
    python system_tray.py
"""

import sys
import os
import json
import asyncio
import threading
from pathlib import Path
from typing import Optional, Callable
from dataclasses import dataclass
from enum import Enum

try:
    from PyQt6.QtWidgets import (
        QApplication, QSystemTrayIcon, QMenu, QWidget, QVBoxLayout,
        QHBoxLayout, QLabel, QPushButton, QFrame, QDialog, QLineEdit,
        QCheckBox, QMessageBox, QGroupBox
    )
    from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
    from PyQt6.QtGui import QIcon, QAction, QPixmap, QPainter, QColor, QFont
except ImportError:
    print("ERROR: PyQt6 is required. Install with: pip install PyQt6")
    sys.exit(1)


# ============================================================================
# Constants
# ============================================================================

class ConnectionStatus(Enum):
    """Agent connection status."""
    CONNECTED = "connected"
    CONNECTING = "connecting"
    DISCONNECTED = "disconnected"
    ERROR = "error"


STATUS_COLORS = {
    ConnectionStatus.CONNECTED: "#22c55e",      # Green
    ConnectionStatus.CONNECTING: "#f59e0b",     # Yellow/Orange
    ConnectionStatus.DISCONNECTED: "#6b7280",   # Gray
    ConnectionStatus.ERROR: "#ef4444",          # Red
}

STATUS_MESSAGES = {
    ConnectionStatus.CONNECTED: "Connected to Jarwis Server",
    ConnectionStatus.CONNECTING: "Connecting...",
    ConnectionStatus.DISCONNECTED: "Disconnected",
    ConnectionStatus.ERROR: "Connection Error",
}


# ============================================================================
# Icon Generator
# ============================================================================

def create_status_icon(status: ConnectionStatus, size: int = 64) -> QPixmap:
    """Create a status-colored icon."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    
    # Draw shield background
    color = QColor(24, 32, 56)  # Dark blue
    painter.setBrush(color)
    painter.setPen(Qt.PenStyle.NoPen)
    
    # Shield shape
    shield_points = [
        (size * 0.5, size * 0.05),   # Top center
        (size * 0.9, size * 0.2),    # Top right
        (size * 0.9, size * 0.5),    # Middle right
        (size * 0.5, size * 0.95),   # Bottom center
        (size * 0.1, size * 0.5),    # Middle left
        (size * 0.1, size * 0.2),    # Top left
    ]
    
    from PyQt6.QtGui import QPolygon
    from PyQt6.QtCore import QPoint
    polygon = QPolygon([QPoint(int(x), int(y)) for x, y in shield_points])
    painter.drawPolygon(polygon)
    
    # Draw status indicator dot
    status_color = QColor(STATUS_COLORS[status])
    painter.setBrush(status_color)
    indicator_size = size * 0.25
    painter.drawEllipse(
        int(size * 0.65),
        int(size * 0.65),
        int(indicator_size),
        int(indicator_size)
    )
    
    # Draw "J" letter
    painter.setPen(QColor(255, 255, 255))
    font = QFont("Arial", int(size * 0.4), QFont.Weight.Bold)
    painter.setFont(font)
    painter.drawText(
        int(size * 0.28),
        int(size * 0.65),
        "J"
    )
    
    painter.end()
    return pixmap


# ============================================================================
# Status Dialog
# ============================================================================

class StatusDialog(QDialog):
    """Agent status and configuration dialog."""
    
    def __init__(self, agent_controller, parent=None):
        super().__init__(parent)
        self.agent = agent_controller
        
        self.setWindowTitle("Jarwis Security Agent")
        self.setFixedSize(400, 500)
        self.setWindowFlags(
            Qt.WindowType.Dialog | 
            Qt.WindowType.WindowCloseButtonHint
        )
        
        self._setup_ui()
        self._update_status()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header = QLabel("🛡️ Jarwis Security Agent")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #182038;")
        layout.addWidget(header)
        
        version = QLabel("Version 2.0.0")
        version.setStyleSheet("color: #666666; margin-bottom: 10px;")
        layout.addWidget(version)
        
        # Status section
        status_group = QGroupBox("Connection Status")
        status_layout = QVBoxLayout(status_group)
        
        self.status_indicator = QLabel()
        self.status_indicator.setStyleSheet("""
            padding: 10px;
            border-radius: 5px;
            font-weight: bold;
        """)
        status_layout.addWidget(self.status_indicator)
        
        self.server_label = QLabel()
        self.server_label.setStyleSheet("color: #666666;")
        status_layout.addWidget(self.server_label)
        
        self.uptime_label = QLabel()
        self.uptime_label.setStyleSheet("color: #666666;")
        status_layout.addWidget(self.uptime_label)
        
        layout.addWidget(status_group)
        
        # Statistics section
        stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.scans_label = QLabel("Scans completed: 0")
        stats_layout.addWidget(self.scans_label)
        
        self.findings_label = QLabel("Vulnerabilities found: 0")
        stats_layout.addWidget(self.findings_label)
        
        self.last_scan_label = QLabel("Last scan: Never")
        stats_layout.addWidget(self.last_scan_label)
        
        layout.addWidget(stats_group)
        
        # Actions section
        actions_group = QGroupBox("Actions")
        actions_layout = QVBoxLayout(actions_group)
        
        reconnect_btn = QPushButton("Reconnect to Server")
        reconnect_btn.clicked.connect(self._on_reconnect)
        actions_layout.addWidget(reconnect_btn)
        
        logs_btn = QPushButton("View Logs")
        logs_btn.clicked.connect(self._on_view_logs)
        actions_layout.addWidget(logs_btn)
        
        dashboard_btn = QPushButton("Open Dashboard")
        dashboard_btn.clicked.connect(self._on_open_dashboard)
        actions_layout.addWidget(dashboard_btn)
        
        layout.addWidget(actions_group)
        
        layout.addStretch()
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn)
    
    def _update_status(self):
        status = self.agent.get_status()
        
        # Update status indicator
        color = STATUS_COLORS[status]
        message = STATUS_MESSAGES[status]
        
        if status == ConnectionStatus.CONNECTED:
            bg_color = "#dcfce7"  # Light green
            text_color = "#166534"
        elif status == ConnectionStatus.CONNECTING:
            bg_color = "#fef3c7"  # Light yellow
            text_color = "#92400e"
        elif status == ConnectionStatus.ERROR:
            bg_color = "#fee2e2"  # Light red
            text_color = "#991b1b"
        else:
            bg_color = "#f3f4f6"  # Light gray
            text_color = "#374151"
        
        self.status_indicator.setText(f"● {message}")
        self.status_indicator.setStyleSheet(f"""
            padding: 10px;
            border-radius: 5px;
            font-weight: bold;
            background-color: {bg_color};
            color: {text_color};
        """)
        
        self.server_label.setText(f"Server: {self.agent.server_url}")
        self.uptime_label.setText(f"Uptime: {self.agent.get_uptime()}")
        
        # Update stats
        stats = self.agent.get_stats()
        self.scans_label.setText(f"Scans completed: {stats.get('scans', 0)}")
        self.findings_label.setText(f"Vulnerabilities found: {stats.get('findings', 0)}")
        self.last_scan_label.setText(f"Last scan: {stats.get('last_scan', 'Never')}")
    
    def _on_reconnect(self):
        self.agent.reconnect()
        QTimer.singleShot(1000, self._update_status)
    
    def _on_view_logs(self):
        import subprocess
        log_path = Path(self.agent.install_path) / 'logs' / 'agent.log'
        if log_path.exists():
            subprocess.Popen(['notepad.exe', str(log_path)])
        else:
            QMessageBox.information(self, "Logs", "No log file found.")
    
    def _on_open_dashboard(self):
        import webbrowser
        webbrowser.open("https://jarwis.io/dashboard")


# ============================================================================
# Agent Controller (Mock for tray app)
# ============================================================================

class AgentController:
    """Controller for agent operations."""
    
    def __init__(self):
        self.server_url = "wss://jarwis.io/ws/agent"
        self.install_path = r"C:\Program Files\Jarwis Agent"
        self._status = ConnectionStatus.DISCONNECTED
        self._start_time = None
        self._stats = {'scans': 0, 'findings': 0, 'last_scan': 'Never'}
    
    def get_status(self) -> ConnectionStatus:
        return self._status
    
    def set_status(self, status: ConnectionStatus):
        self._status = status
    
    def get_uptime(self) -> str:
        if self._start_time is None:
            return "Not started"
        
        import datetime
        delta = datetime.datetime.now() - self._start_time
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def get_stats(self) -> dict:
        return self._stats
    
    def connect(self):
        self._status = ConnectionStatus.CONNECTING
        # Simulate connection
        import datetime
        self._start_time = datetime.datetime.now()
        QTimer.singleShot(2000, lambda: self.set_status(ConnectionStatus.CONNECTED))
    
    def disconnect(self):
        self._status = ConnectionStatus.DISCONNECTED
        self._start_time = None
    
    def reconnect(self):
        self.disconnect()
        self.connect()


# ============================================================================
# System Tray Application
# ============================================================================

class JarwisTrayApp(QObject):
    """System tray application for Jarwis Agent."""
    
    status_changed = pyqtSignal(ConnectionStatus)
    
    def __init__(self):
        super().__init__()
        
        self.agent = AgentController()
        self.status_dialog = None
        
        # Create system tray icon
        self.tray_icon = QSystemTrayIcon()
        self._update_icon(ConnectionStatus.DISCONNECTED)
        
        # Create context menu
        self.menu = QMenu()
        self._setup_menu()
        self.tray_icon.setContextMenu(self.menu)
        
        # Connect signals
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.status_changed.connect(self._update_icon)
        
        # Start status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._check_status)
        self.status_timer.start(5000)  # Check every 5 seconds
        
        # Auto-connect on startup
        QTimer.singleShot(1000, self.agent.connect)
    
    def _setup_menu(self):
        """Setup context menu."""
        # Status header (non-clickable)
        self.status_action = QAction("● Disconnected")
        self.status_action.setEnabled(False)
        self.menu.addAction(self.status_action)
        
        self.menu.addSeparator()
        
        # Show status window
        status_action = QAction("Status && Configuration...")
        status_action.triggered.connect(self._show_status_dialog)
        self.menu.addAction(status_action)
        
        # Open dashboard
        dashboard_action = QAction("Open Dashboard")
        dashboard_action.triggered.connect(self._open_dashboard)
        self.menu.addAction(dashboard_action)
        
        self.menu.addSeparator()
        
        # Reconnect
        reconnect_action = QAction("Reconnect")
        reconnect_action.triggered.connect(self._reconnect)
        self.menu.addAction(reconnect_action)
        
        # View logs
        logs_action = QAction("View Logs")
        logs_action.triggered.connect(self._view_logs)
        self.menu.addAction(logs_action)
        
        self.menu.addSeparator()
        
        # Exit
        exit_action = QAction("Exit")
        exit_action.triggered.connect(self._exit)
        self.menu.addAction(exit_action)
    
    def _update_icon(self, status: ConnectionStatus):
        """Update tray icon based on status."""
        pixmap = create_status_icon(status)
        self.tray_icon.setIcon(QIcon(pixmap))
        self.tray_icon.setToolTip(f"Jarwis Agent - {STATUS_MESSAGES[status]}")
        
        # Update menu status
        self.status_action.setText(f"● {STATUS_MESSAGES[status]}")
    
    def _check_status(self):
        """Periodic status check."""
        status = self.agent.get_status()
        self.status_changed.emit(status)
    
    def _on_tray_activated(self, reason):
        """Handle tray icon activation."""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._show_status_dialog()
    
    def _show_status_dialog(self):
        """Show status dialog."""
        if self.status_dialog is None or not self.status_dialog.isVisible():
            self.status_dialog = StatusDialog(self.agent)
            self.status_dialog.show()
        else:
            self.status_dialog.raise_()
            self.status_dialog.activateWindow()
    
    def _open_dashboard(self):
        """Open Jarwis dashboard in browser."""
        import webbrowser
        webbrowser.open("https://jarwis.io/dashboard")
    
    def _reconnect(self):
        """Reconnect to server."""
        self.agent.reconnect()
        self.tray_icon.showMessage(
            "Jarwis Agent",
            "Reconnecting to server...",
            QSystemTrayIcon.MessageIcon.Information,
            2000
        )
    
    def _view_logs(self):
        """Open log file."""
        import subprocess
        log_path = Path(self.agent.install_path) / 'logs' / 'agent.log'
        if log_path.exists():
            subprocess.Popen(['notepad.exe', str(log_path)])
        else:
            self.tray_icon.showMessage(
                "Jarwis Agent",
                "No log file found.",
                QSystemTrayIcon.MessageIcon.Warning,
                2000
            )
    
    def _exit(self):
        """Exit application."""
        result = QMessageBox.question(
            None,
            "Exit Jarwis Agent",
            "Are you sure you want to exit?\n\n"
            "The agent will stop monitoring and disconnect from the server.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if result == QMessageBox.StandardButton.Yes:
            self.agent.disconnect()
            QApplication.quit()
    
    def show(self):
        """Show tray icon."""
        self.tray_icon.show()
        
        # Show startup notification
        self.tray_icon.showMessage(
            "Jarwis Security Agent",
            "Agent is running in the background.\nRight-click the icon for options.",
            QSystemTrayIcon.MessageIcon.Information,
            3000
        )


# ============================================================================
# Entry Point
# ============================================================================

def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)  # Keep running in tray
    app.setApplicationName("Jarwis Agent")
    app.setOrganizationName("Jarwis Security")
    
    # Check if system tray is available
    if not QSystemTrayIcon.isSystemTrayAvailable():
        QMessageBox.critical(
            None,
            "System Tray",
            "System tray is not available on this system."
        )
        sys.exit(1)
    
    # Create and show tray app
    tray_app = JarwisTrayApp()
    tray_app.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
