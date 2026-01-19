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
AGENT_VERSION = "1.0.0"
RELEASE_DATE = "2026-01-19"
RELEASE_NOTES = """
## Jarwis Agent v1.0.0

### Features
- Mobile dynamic analysis with Frida integration
- Internal network scanning support
- WebSocket-based secure connection to cloud
- Auto-reconnection and heartbeat
- Windows service / macOS LaunchDaemon / Linux systemd support

### Supported Platforms
- Windows 10/11 (x64)
- macOS 11+ (Intel & Apple Silicon)
- Linux (Ubuntu 18.04+, Debian 10+, RHEL 7+, CentOS 7+)
"""

# Base directory for local agent builds - using absolute path from project root
PROJECT_ROOT = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
LOCAL_BUILDS_DIR = PROJECT_ROOT / "dist"

# Download URLs - In production, these would point to your release CDN
RELEASE_BASE_URL = os.environ.get(
    "AGENT_RELEASE_URL", 
    "https://releases.jarwis.io/agent"
)

# Check if we're in development mode (no CDN URL set)
IS_DEV_MODE = "AGENT_RELEASE_URL" not in os.environ

DOWNLOADS = {
    "windows": {
        "msi": {
            "filename": f"jarwis-agent_{AGENT_VERSION}_x64.msi",
            "local_filename": "jarwis-agent_x64.msi",  # PyInstaller output name
            "size_bytes": 47185920,  # ~45 MB
            "sha256": "pending",  # Will be populated during build
            "content_type": "application/x-msi",
        },
        "exe": {
            "filename": f"jarwis-agent_{AGENT_VERSION}_x64.exe",
            "local_filename": "jarwis-agent.exe",  # PyInstaller output name
            "size_bytes": 191102976,  # ~182 MB (actual built size)
            "sha256": "pending",
            "content_type": "application/x-executable",
        },
    },
    "macos": {
        "pkg": {
            "filename": f"jarwis-agent_{AGENT_VERSION}_universal.pkg",
            "local_filename": "jarwis-agent.pkg",
            "size_bytes": 50331648,  # ~48 MB
            "sha256": "pending",
            "content_type": "application/x-apple-diskimage",
        },
        "dmg": {
            "filename": f"jarwis-agent_{AGENT_VERSION}_universal.dmg",
            "local_filename": "jarwis-agent.dmg",
            "size_bytes": 54525952,  # ~52 MB
            "sha256": "pending",
            "content_type": "application/x-apple-diskimage",
        },
        "binary": {
            "filename": f"jarwis-agent_{AGENT_VERSION}_macos",
            "local_filename": "jarwis-agent",  # PyInstaller output name
            "size_bytes": 50331648,
            "sha256": "pending",
            "content_type": "application/octet-stream",
        },
    },
    "linux": {
        "deb": {
            "filename": f"jarwis-agent_{AGENT_VERSION}_amd64.deb",
            "local_filename": "jarwis-agent.deb",
            "size_bytes": 41943040,  # ~40 MB
            "sha256": "pending",
            "content_type": "application/vnd.debian.binary-package",
        },
        "rpm": {
            "filename": f"jarwis-agent-{AGENT_VERSION}-1.x86_64.rpm",
            "local_filename": "jarwis-agent.rpm",
            "size_bytes": 41943040,  # ~40 MB
            "sha256": "pending",
            "content_type": "application/x-rpm",
        },
        "binary": {
            "filename": f"jarwis-agent_{AGENT_VERSION}_linux",
            "local_filename": "jarwis-agent",  # PyInstaller output name
            "size_bytes": 41943040,
            "sha256": "pending",
            "content_type": "application/octet-stream",
        },
        "script": {
            "filename": "install.sh",
            "local_filename": "install.sh",
            "size_bytes": 5120,  # ~5 KB
            "sha256": "pending",
            "content_type": "text/x-shellscript",
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
                "download_url": f"{RELEASE_BASE_URL}/v{AGENT_VERSION}/{info['filename']}",
            }
    
    return ReleaseInfo(
        version=AGENT_VERSION,
        release_date=RELEASE_DATE,
        release_notes=RELEASE_NOTES,
        downloads=downloads,
    )


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
    
    Redirects to the actual download URL (CDN or direct file).
    Tracks download statistics.
    
    In dev mode, serves local builds if available.
    Token can be passed as query param for browser-initiated downloads.
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
    
    # In dev mode, check for local builds first
    if IS_DEV_MODE:
        local_file = _find_local_build(platform, format, download_info)
        if local_file and local_file.exists():
            logger.info(f"Serving local build: {local_file}")
            # Get actual file size
            actual_size = local_file.stat().st_size
            return FileResponse(
                path=str(local_file),
                filename=download_info['filename'],
                media_type=download_info['content_type'],
                headers={
                    "Content-Length": str(actual_size),
                    "X-Jarwis-Agent-Version": AGENT_VERSION,
                }
            )
        else:
            # No local build - return helpful error
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "build_not_found",
                    "message": f"Agent installer not found. Please build it first using the installer scripts.",
                    "platform": platform,
                    "format": format,
                    "expected_path": str(LOCAL_BUILDS_DIR / platform / download_info.get('local_filename', download_info['filename'])),
                    "build_command": _get_build_command(platform),
                }
            )
    
    # Production mode: redirect to CDN
    download_url = f"{RELEASE_BASE_URL}/v{AGENT_VERSION}/{download_info['filename']}"
    return RedirectResponse(url=download_url, status_code=302)


@router.get("/install-script")
async def get_install_script():
    """
    Get the Linux one-liner install script.
    
    Usage: curl -sL https://jarwis.io/api/agent-downloads/install-script | sudo bash
    """
    # Read the install script from disk
    script_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "installer", "linux", "install.sh"
    )
    
    if os.path.exists(script_path):
        return FileResponse(
            path=script_path,
            media_type="text/x-shellscript",
            filename="install.sh",
        )
    
    # Fallback: Return a simple redirect script
    script = f"""#!/bin/bash
# Jarwis Agent Quick Install
# This script downloads and installs the latest Jarwis Agent

set -e

echo "Downloading Jarwis Agent installer..."
curl -sL {RELEASE_BASE_URL}/v{AGENT_VERSION}/install.sh | sudo bash -s -- "$@"
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
    Check which agent builds are available locally.
    Useful for development to know what needs to be built.
    """
    status = {
        "is_dev_mode": IS_DEV_MODE,
        "builds_dir": str(LOCAL_BUILDS_DIR),
        "project_root": str(PROJECT_ROOT),
        "platforms": {}
    }
    
    for platform, formats in DOWNLOADS.items():
        status["platforms"][platform] = {}
        for fmt, info in formats.items():
            local_file = _find_local_build(platform, fmt, info)
            is_available = local_file is not None and local_file.exists()
            file_size = local_file.stat().st_size if is_available else None
            status["platforms"][platform][fmt] = {
                "filename": info['filename'],
                "local_filename": info.get('local_filename', info['filename']),
                "available": is_available,
                "local_path": str(local_file) if local_file else None,
                "size_bytes": file_size,
                "size_human": _format_size(file_size) if file_size else None,
                "build_command": _get_build_command(platform),
            }
    
    return status
