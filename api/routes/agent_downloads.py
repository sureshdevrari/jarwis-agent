# api/routes/agent_downloads.py
"""
Agent Download Routes

Provides endpoints for:
- Agent installer downloads (signed binaries)
- Release information (version, changelog)
- Download statistics
"""

import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import FileResponse, StreamingResponse, RedirectResponse
from pydantic import BaseModel

from database.dependencies import get_current_user
from database.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agent-downloads", tags=["Agent Downloads"])

# Agent release configuration
AGENT_VERSION = "2.1.0"
RELEASE_DATE = "2026-01-20"
RELEASE_NOTES = """
## Jarwis Agent v2.0.0

### 🚀 What's New
- **Professional GUI Installer** - User-friendly setup wizard with branding
- **System Tray Application** - Background status indicator and quick actions
- **Post-Install Configuration** - Interactive server configuration with connection testing
- **Feature Selection** - Choose which security testing modules to enable

### 🛡️ Features
- Web application security testing (OWASP Top 10)
- Mobile dynamic analysis with Frida integration
- Internal network scanning support
- Cloud security assessment (AWS, Azure, GCP)
- Static code analysis (SAST)
- WebSocket-based secure connection to cloud
- Auto-reconnection and heartbeat
- Windows service / macOS LaunchDaemon / Linux systemd support

### 📦 Installers
- **Windows (GUI)**: `jarwis-agent-setup.exe` - Recommended for end users
- **Windows (MSI)**: `jarwis-agent.msi` - Enterprise deployment (SCCM, Intune)
- **macOS**: `jarwis-agent.pkg` - Signed and notarized
- **Linux**: `.deb` (Debian/Ubuntu) and `.rpm` (RHEL/CentOS)

### Supported Platforms
- Windows 10/11 (x64)
- macOS 11+ (Intel & Apple Silicon)
- Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+, CentOS Stream 8+)
"""

# Base directory for local agent builds - using absolute path from project root
PROJECT_ROOT = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
LOCAL_BUILDS_DIR = PROJECT_ROOT / "dist"

# GitHub Release URLs
GITHUB_REPO = "sureshdevrari/jarwis-agent"
GITHUB_RELEASE_BASE = f"https://github.com/{GITHUB_REPO}/releases/download/v{AGENT_VERSION}"

# Check if we're in development mode
IS_DEV_MODE = os.environ.get("JARWIS_ENV", "development") == "development"

DOWNLOADS = {
    "windows": {
        "setup": {
            "filename": "JarwisAgentSetup-GUI.exe",
            "github_filename": "JarwisAgentSetup-GUI.exe",
            "size_bytes": 45000000,  # ~45 MB (includes PyQt6)
            "sha256": "",
            "content_type": "application/x-executable",
            "download_url": f"{GITHUB_RELEASE_BASE}/JarwisAgentSetup-GUI.exe",
            "description": "⭐ Recommended - Professional GUI installer wizard",
        },
        "inno": {
            "filename": f"JarwisAgentSetup-{AGENT_VERSION}.exe",
            "github_filename": f"JarwisAgentSetup-{AGENT_VERSION}.exe",
            "size_bytes": 35000000,  # ~35 MB
            "sha256": "",
            "content_type": "application/x-executable",
            "download_url": f"{GITHUB_RELEASE_BASE}/JarwisAgentSetup-{AGENT_VERSION}.exe",
            "description": "Inno Setup installer (alternative)",
        },
        "exe": {
            "filename": "jarwis-agent.exe",
            "github_filename": "jarwis-agent.exe",
            "size_bytes": 15049524,  # ~15 MB
            "sha256": "",
            "content_type": "application/x-executable",
            "download_url": f"{GITHUB_RELEASE_BASE}/jarwis-agent.exe",
            "description": "Standalone CLI executable",
        },
        "tray": {
            "filename": "jarwis-tray.exe",
            "github_filename": "jarwis-tray.exe",
            "size_bytes": 25000000,  # ~25 MB
            "sha256": "",
            "content_type": "application/x-executable",
            "download_url": f"{GITHUB_RELEASE_BASE}/jarwis-tray.exe",
            "description": "System tray application",
        },
    },
    "macos": {
        "dmg_installer": {
            "filename": f"JarwisAgentSetup-{AGENT_VERSION}.dmg",
            "github_filename": f"JarwisAgentSetup-{AGENT_VERSION}.dmg",
            "size_bytes": 45000000,  # ~45 MB
            "sha256": "",
            "content_type": "application/x-apple-diskimage",
            "download_url": f"{GITHUB_RELEASE_BASE}/JarwisAgentSetup-{AGENT_VERSION}.dmg",
            "description": "⭐ Recommended - DMG with GUI installer wizard",
        },
        "setup": {
            "filename": "JarwisAgentSetup-macos",
            "github_filename": "JarwisAgentSetup-macos",
            "size_bytes": 40000000,  # ~40 MB
            "sha256": "",
            "content_type": "application/x-executable",
            "download_url": f"{GITHUB_RELEASE_BASE}/JarwisAgentSetup-macos",
            "description": "GUI installer executable",
        },
        "binary": {
            "filename": "jarwis-agent-macos",
            "github_filename": "jarwis-agent-macos",
            "size_bytes": 14700470,  # ~14 MB
            "sha256": "",
            "content_type": "application/x-executable",
            "download_url": f"{GITHUB_RELEASE_BASE}/jarwis-agent-macos",
            "description": "Standalone CLI binary",
        },
    },
    "linux": {
        "installer": {
            "filename": f"jarwis-agent-{AGENT_VERSION}-linux-installer.tar.gz",
            "github_filename": f"jarwis-agent-{AGENT_VERSION}-linux-installer.tar.gz",
            "size_bytes": 50000000,  # ~50 MB
            "sha256": "",
            "content_type": "application/gzip",
            "download_url": f"{GITHUB_RELEASE_BASE}/jarwis-agent-{AGENT_VERSION}-linux-installer.tar.gz",
            "description": "⭐ Installer with GUI wizard (extract & run install.sh)",
        },
        "deb": {
            "filename": f"jarwis-agent_{AGENT_VERSION}_amd64.deb",
            "github_filename": f"jarwis-agent_{AGENT_VERSION}_amd64.deb",
            "size_bytes": 29111956,  # ~28 MB
            "sha256": "",
            "content_type": "application/vnd.debian.binary-package",
            "download_url": f"{GITHUB_RELEASE_BASE}/jarwis-agent_{AGENT_VERSION}_amd64.deb",
            "description": "Debian/Ubuntu package",
        },
        "rpm": {
            "filename": f"jarwis-agent-{AGENT_VERSION}-1.x86_64.rpm",
            "github_filename": f"jarwis-agent-{AGENT_VERSION}-1.x86_64.rpm",
            "size_bytes": 29126659,  # ~28 MB
            "sha256": "",
            "content_type": "application/x-rpm",
            "download_url": f"{GITHUB_RELEASE_BASE}/jarwis-agent-{AGENT_VERSION}-1.x86_64.rpm",
            "description": "RHEL/CentOS/Fedora package",
        },
        "setup": {
            "filename": "JarwisAgentSetup-linux",
            "github_filename": "JarwisAgentSetup-linux",
            "size_bytes": 45000000,  # ~45 MB
            "sha256": "",
            "content_type": "application/x-executable",
            "download_url": f"{GITHUB_RELEASE_BASE}/JarwisAgentSetup-linux",
            "description": "GUI installer executable (requires X11)",
        },
        "binary": {
            "filename": "jarwis-agent-linux",
            "github_filename": "jarwis-agent-linux",
            "size_bytes": 29380312,  # ~28 MB
            "sha256": "",
            "content_type": "application/x-executable",
            "download_url": f"{GITHUB_RELEASE_BASE}/jarwis-agent-linux",
            "description": "Standalone CLI binary",
        },
    },
}


# Response models
class ReleaseInfo(BaseModel):
    version: str
    release_date: str
    release_notes: str
    downloads: dict


class DownloadInfo(BaseModel):
    platform: str
    format: str
    filename: str
    download_url: str
    size_bytes: int
    sha256: str


@router.get("/release", response_model=ReleaseInfo)
async def get_release_info():
    """
    Get current agent release information.
    
    Returns version, release date, changelog, and available downloads.
    """
    downloads = {}
    for platform, formats in DOWNLOADS.items():
        downloads[platform] = {}
        for fmt, info in formats.items():
            downloads[platform][fmt] = {
                "filename": info["filename"],
                "size_bytes": info["size_bytes"],
                "size_human": _format_size(info["size_bytes"]),
                "sha256": info.get("sha256", ""),
                "download_url": info["download_url"],
                "description": info.get("description", ""),
            }
    
    return ReleaseInfo(
        version=AGENT_VERSION,
        release_date=RELEASE_DATE,
        release_notes=RELEASE_NOTES,
        downloads=downloads,
    )


@router.get("/recommended/{platform}")
async def get_recommended_download(platform: str):
    """
    Get recommended download for a platform.
    
    Returns the best installer option for the given platform.
    """
    platform = platform.lower()
    
    recommendations = {
        "windows": "setup",  # GUI installer
        "macos": "pkg",      # Signed PKG
        "linux": "deb",      # Most common
    }
    
    if platform not in DOWNLOADS:
        raise HTTPException(status_code=404, detail=f"Unknown platform: {platform}")
    
    recommended_format = recommendations.get(platform, list(DOWNLOADS[platform].keys())[0])
    info = DOWNLOADS[platform][recommended_format]
    
    return {
        "platform": platform,
        "format": recommended_format,
        "filename": info["filename"],
        "download_url": info["download_url"],
        "size_human": _format_size(info["size_bytes"]),
        "description": info.get("description", ""),
    }


@router.get("/download/{platform}/{format}")
async def download_agent(
    platform: str,
    format: str,
    request: Request,
    token: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """
    Get download URL for agent installer.
    
    Redirects to GitHub releases for actual download.
    Tracks download statistics.
    """
    # Validate platform
    if platform not in DOWNLOADS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid platform. Must be one of: {list(DOWNLOADS.keys())}"
        )
    
    # Validate format
    if format not in DOWNLOADS[platform]:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format for {platform}. Must be one of: {list(DOWNLOADS[platform].keys())}"
        )
    
    download_info = DOWNLOADS[platform][format]
    
    # Log download for analytics
    logger.info(
        f"Agent download: user={current_user.id}, platform={platform}, "
        f"format={format}, file={download_info['filename']}"
    )
    
    # Track download in database (optional)
    try:
        await _track_download(
            user_id=current_user.id,
            platform=platform,
            format=format,
            filename=download_info['filename'],
            ip_address=request.client.host if request.client else None,
        )
    except Exception as e:
        logger.warning(f"Failed to track download: {e}")
    
    # Redirect to GitHub releases
    return RedirectResponse(url=download_info["download_url"], status_code=302)


@router.get("/install-script")
async def get_install_script():
    """
    Get the Linux one-liner install script.
    
    Usage: curl -sL https://jarwis.io/api/agent-downloads/install-script | sudo bash
    """
    script = f"""#!/bin/bash
# Jarwis Agent Quick Install Script
# Usage: curl -sL https://jarwis.io/api/agent-downloads/install-script | sudo bash

set -e

AGENT_VERSION="{AGENT_VERSION}"
GITHUB_RELEASE="{GITHUB_RELEASE_BASE}"

echo "============================================"
echo "   Jarwis Agent Installer v$AGENT_VERSION"
echo "============================================"
echo ""

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)
        if command -v apt-get &> /dev/null; then
            echo "Detected Debian/Ubuntu - Installing via .deb package..."
            DOWNLOAD_URL="$GITHUB_RELEASE/jarwis-agent_${{AGENT_VERSION}}_amd64.deb"
            TMP_FILE="/tmp/jarwis-agent.deb"
            curl -sL "$DOWNLOAD_URL" -o "$TMP_FILE"
            sudo dpkg -i "$TMP_FILE"
            rm "$TMP_FILE"
        elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
            echo "Detected RHEL/CentOS/Fedora - Installing via .rpm package..."
            DOWNLOAD_URL="$GITHUB_RELEASE/jarwis-agent-${{AGENT_VERSION}}-1.x86_64.rpm"
            TMP_FILE="/tmp/jarwis-agent.rpm"
            curl -sL "$DOWNLOAD_URL" -o "$TMP_FILE"
            sudo rpm -i "$TMP_FILE"
            rm "$TMP_FILE"
        else
            echo "Installing standalone binary..."
            DOWNLOAD_URL="$GITHUB_RELEASE/jarwis-agent-linux"
            sudo curl -sL "$DOWNLOAD_URL" -o /usr/local/bin/jarwis-agent
            sudo chmod +x /usr/local/bin/jarwis-agent
        fi
        ;;
    darwin)
        echo "Detected macOS - Downloading DMG..."
        DOWNLOAD_URL="$GITHUB_RELEASE/jarwis-agent-macos.dmg"
        curl -sL "$DOWNLOAD_URL" -o ~/Downloads/jarwis-agent-macos.dmg
        echo "Downloaded to ~/Downloads/jarwis-agent-macos.dmg"
        echo "Please open the DMG and drag the app to Applications."
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

echo ""
echo "Installation complete!"
echo "Run 'jarwis-agent --check' to verify installation."
"""
    
    return Response(
        content=script,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": "attachment; filename=install.sh"},
    )


@router.get("/checksums/{platform}")
async def get_checksums(platform: str):
    """
    Get SHA256 checksums for all downloads of a platform.
    
    Used for verifying download integrity.
    """
    if platform not in DOWNLOADS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid platform. Must be one of: {list(DOWNLOADS.keys())}"
        )
    
    checksums = {}
    for fmt, info in DOWNLOADS[platform].items():
        checksums[info["filename"]] = info["sha256"]
    
    return checksums


# Helper functions
def _format_size(size_bytes: int) -> str:
    """Format byte size to human readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def _find_local_build(platform: str, format: str, download_info: dict) -> Optional[Path]:
    """Find local build file for given platform/format."""
    # Get the local filename (PyInstaller output) vs release filename
    local_filename = download_info.get("local_filename", download_info["filename"])
    release_filename = download_info["filename"]
    
    # Platform-specific subdirectories
    platform_subdirs = {
        "windows": ["windows/x64", "windows/x86", "windows"],
        "macos": ["macos/universal", "macos"],
        "linux": ["linux/amd64", "linux"],
    }
    
    subdirs = platform_subdirs.get(platform, [platform])
    
    # Check in order of preference for both local and release filenames
    search_paths = []
    for subdir in subdirs:
        search_paths.extend([
            LOCAL_BUILDS_DIR / subdir / local_filename,
            LOCAL_BUILDS_DIR / subdir / release_filename,
        ])
    
    # Also check root dist folder
    search_paths.extend([
        LOCAL_BUILDS_DIR / local_filename,
        LOCAL_BUILDS_DIR / release_filename,
    ])
    
    logger.debug(f"Searching for {platform}/{format} in: {[str(p) for p in search_paths]}")
    
    for path in search_paths:
        if path.exists():
            logger.info(f"Found local build: {path}")
            return path
    
    logger.debug(f"No local build found for {platform}/{format}")
    return None


def _get_build_command(platform: str) -> str:
    """Get the build command for a platform."""
    commands = {
        "windows": "cd installer\\windows && build.bat",
        "macos": "cd installer/macos && ./build.sh",
        "linux": "cd installer/linux && ./build.sh",
    }
    return commands.get(platform, "See installer/README.md")


async def _track_download(
    user_id: str,
    platform: str,
    format: str,
    filename: str,
    ip_address: Optional[str] = None,
):
    """
    Track download in database for analytics.
    
    In a real implementation, this would insert into a downloads table.
    """
    # TODO: Implement database tracking
    pass


@router.get("/build-status")
async def get_build_status():
    """
    Check which agent builds are available.
    All builds are now hosted on GitHub releases.
    """
    status = {
        "is_dev_mode": IS_DEV_MODE,
        "version": AGENT_VERSION,
        "github_repo": GITHUB_REPO,
        "release_url": f"https://github.com/{GITHUB_REPO}/releases/tag/v{AGENT_VERSION}",
        "platforms": {}
    }
    
    for platform, formats in DOWNLOADS.items():
        status["platforms"][platform] = {}
        for fmt, info in formats.items():
            status["platforms"][platform][fmt] = {
                "filename": info['filename'],
                "available": True,  # Always available via GitHub
                "download_url": info['download_url'],
                "size_bytes": info['size_bytes'],
                "size_human": _format_size(info['size_bytes']),
                "sha256": info.get('sha256', ''),
            }
    
    return status
