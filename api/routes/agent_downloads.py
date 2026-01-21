# api/routes/agent_downloads.py
"""
Agent Download Routes - GitHub Release Based

All downloads are served from GitHub releases.
The API dynamically fetches the latest release information.

Provides endpoints for:
- Agent installer downloads (always from GitHub)
- Latest release information (version, changelog)
- Download statistics
"""

import os
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import StreamingResponse, RedirectResponse
import httpx
from pydantic import BaseModel

from database.dependencies import get_current_user, get_current_user_optional
from database.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agent-downloads", tags=["Agent Downloads"])

# ============================================================================
# GitHub Configuration
# ============================================================================

GITHUB_REPO = "sureshdevrari/jarwis-agent"
GITHUB_API_BASE = "https://api.github.com"
GITHUB_RELEASES_URL = f"{GITHUB_API_BASE}/repos/{GITHUB_REPO}/releases"

# Cache for GitHub release data (to avoid hitting rate limits)
_release_cache: Dict[str, Any] = {
    "data": None,
    "fetched_at": None,
    "ttl_seconds": 300,  # Cache for 5 minutes
}

# ============================================================================
# Asset filename mappings (what we expect in each release)
# ============================================================================

PLATFORM_ASSETS = {
    "windows": {
        "setup": {
            "patterns": ["JarwisAgentSetup-GUI.exe", "jarwis-agent-setup.exe"],
            "description": "⭐ Recommended - Professional GUI installer wizard",
            "content_type": "application/x-executable",
        },
        "exe": {
            "patterns": ["jarwis-agent.exe"],
            "description": "Standalone CLI agent executable",
            "content_type": "application/x-executable",
        },
        "tray": {
            "patterns": ["jarwis-tray.exe"],
            "description": "System tray status application",
            "content_type": "application/x-executable",
        },
        "config": {
            "patterns": ["jarwis-config.exe"],
            "description": "Configuration tool for server setup",
            "content_type": "application/x-executable",
        },
        "msi": {
            "patterns": ["jarwis-agent.msi", "JarwisAgent.msi"],
            "description": "Enterprise MSI installer (SCCM, Intune)",
            "content_type": "application/x-msi",
        },
    },
    "macos": {
        "pkg_intel": {
            "patterns": ["jarwis-agent-*-intel.pkg", "jarwis-agent-intel.pkg"],
            "description": "⭐ macOS Intel installer (signed & notarized)",
            "content_type": "application/x-newton-compatible-pkg",
        },
        "pkg_arm": {
            "patterns": ["jarwis-agent-*-apple-silicon.pkg", "jarwis-agent-arm64.pkg"],
            "description": "⭐ macOS Apple Silicon installer (signed & notarized)",
            "content_type": "application/x-newton-compatible-pkg",
        },
        "dmg_intel": {
            "patterns": ["JarwisAgentSetup-*-intel.dmg", "jarwis-agent-intel.dmg"],
            "description": "macOS Intel DMG image",
            "content_type": "application/x-apple-diskimage",
        },
        "dmg_arm": {
            "patterns": ["JarwisAgentSetup-*-apple-silicon.dmg", "jarwis-agent-arm64.dmg"],
            "description": "macOS Apple Silicon DMG image",
            "content_type": "application/x-apple-diskimage",
        },
        "binary": {
            "patterns": ["jarwis-agent-macos", "jarwis-agent-darwin"],
            "description": "Standalone CLI binary",
            "content_type": "application/x-executable",
        },
    },
    "linux": {
        "deb": {
            "patterns": ["jarwis-agent_*_amd64.deb", "jarwis-agent*.deb"],
            "description": "⭐ Debian/Ubuntu package",
            "content_type": "application/vnd.debian.binary-package",
        },
        "rpm": {
            "patterns": ["jarwis-agent-*.x86_64.rpm", "jarwis-agent*.rpm"],
            "description": "⭐ RHEL/CentOS/Fedora package",
            "content_type": "application/x-rpm",
        },
        "binary": {
            "patterns": ["jarwis-agent-linux", "jarwis-agent-linux-amd64"],
            "description": "Standalone CLI binary",
            "content_type": "application/x-executable",
        },
        "tarball": {
            "patterns": ["jarwis-agent-*-linux.tar.gz", "jarwis-agent-linux.tar.gz"],
            "description": "Portable tarball archive",
            "content_type": "application/gzip",
        },
    },
}

# ============================================================================
# Response Models
# ============================================================================

class ReleaseInfo(BaseModel):
    version: str
    tag_name: str
    release_date: str
    release_notes: str
    html_url: str
    downloads: dict


class DownloadInfo(BaseModel):
    platform: str
    format: str
    filename: str
    download_url: str
    size_bytes: int
    size_human: str


# ============================================================================
# GitHub API Functions
# ============================================================================

async def _fetch_latest_release() -> Optional[Dict[str, Any]]:
    """
    Fetch the latest release from GitHub API.
    Uses caching to avoid rate limits.
    """
    global _release_cache
    
    # Check cache
    if _release_cache["data"] and _release_cache["fetched_at"]:
        age = datetime.now() - _release_cache["fetched_at"]
        if age.total_seconds() < _release_cache["ttl_seconds"]:
            logger.debug("Returning cached release data")
            return _release_cache["data"]
    
    # Fetch from GitHub
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{GITHUB_RELEASES_URL}/latest",
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "Jarwis-Agent-API",
                }
            )
            
            if response.status_code == 404:
                logger.warning("No releases found on GitHub")
                return None
            
            response.raise_for_status()
            data = response.json()
            
            # Update cache
            _release_cache["data"] = data
            _release_cache["fetched_at"] = datetime.now()
            
            logger.info(f"Fetched latest release: {data.get('tag_name')}")
            return data
            
    except httpx.HTTPError as e:
        logger.error(f"Failed to fetch release from GitHub: {e}")
        # Return cached data if available (even if stale)
        if _release_cache["data"]:
            logger.warning("Using stale cache due to GitHub API error")
            return _release_cache["data"]
        return None


async def _fetch_all_releases() -> list:
    """Fetch all releases from GitHub API."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                GITHUB_RELEASES_URL,
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "Jarwis-Agent-API",
                }
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as e:
        logger.error(f"Failed to fetch releases: {e}")
        return []


def _match_asset_pattern(asset_name: str, patterns: list) -> bool:
    """Check if asset name matches any of the patterns (supports wildcards)."""
    import fnmatch
    for pattern in patterns:
        if fnmatch.fnmatch(asset_name, pattern) or fnmatch.fnmatch(asset_name.lower(), pattern.lower()):
            return True
    return False


def _map_assets_to_downloads(assets: list) -> Dict[str, Dict[str, Any]]:
    """
    Map GitHub release assets to our platform/format structure.
    """
    downloads = {}
    
    for platform, formats in PLATFORM_ASSETS.items():
        downloads[platform] = {}
        
        for fmt, config in formats.items():
            # Find matching asset
            matched_asset = None
            for asset in assets:
                if _match_asset_pattern(asset["name"], config["patterns"]):
                    matched_asset = asset
                    break
            
            if matched_asset:
                downloads[platform][fmt] = {
                    "filename": matched_asset["name"],
                    "download_url": matched_asset["browser_download_url"],
                    "size_bytes": matched_asset["size"],
                    "size_human": _format_size(matched_asset["size"]),
                    "description": config["description"],
                    "content_type": config["content_type"],
                    "available": True,
                    "download_count": matched_asset.get("download_count", 0),
                }
            else:
                # Asset not found in this release
                downloads[platform][fmt] = {
                    "filename": config["patterns"][0].replace("*", "VERSION"),
                    "download_url": None,
                    "size_bytes": 0,
                    "size_human": "N/A",
                    "description": config["description"],
                    "content_type": config["content_type"],
                    "available": False,
                    "download_count": 0,
                }
    
    return downloads


# ============================================================================
# API Endpoints
# ============================================================================

@router.get("/release", response_model=ReleaseInfo)
async def get_release_info():
    """
    Get the latest agent release information from GitHub.
    
    Returns version, release date, changelog, and available downloads.
    """
    release = await _fetch_latest_release()
    
    if not release:
        raise HTTPException(
            status_code=503,
            detail="Unable to fetch release information from GitHub. Please try again later."
        )
    
    # Map assets to downloads
    downloads = _map_assets_to_downloads(release.get("assets", []))
    
    return ReleaseInfo(
        version=release["tag_name"].lstrip("v"),
        tag_name=release["tag_name"],
        release_date=release["published_at"][:10],
        release_notes=release.get("body", "No release notes available."),
        html_url=release["html_url"],
        downloads=downloads,
    )


@router.get("/releases")
async def list_releases():
    """
    List all available releases.
    """
    releases = await _fetch_all_releases()
    
    return {
        "count": len(releases),
        "releases": [
            {
                "version": r["tag_name"].lstrip("v"),
                "tag_name": r["tag_name"],
                "release_date": r["published_at"][:10],
                "prerelease": r["prerelease"],
                "draft": r["draft"],
                "html_url": r["html_url"],
                "asset_count": len(r.get("assets", [])),
            }
            for r in releases
        ]
    }


@router.get("/recommended/{platform}")
async def get_recommended_download(platform: str):
    """
    Get recommended download for a platform from the latest GitHub release.
    """
    platform = platform.lower()
    
    if platform not in PLATFORM_ASSETS:
        raise HTTPException(status_code=404, detail=f"Unknown platform: {platform}")
    
    release = await _fetch_latest_release()
    if not release:
        raise HTTPException(status_code=503, detail="Unable to fetch release from GitHub")
    
    downloads = _map_assets_to_downloads(release.get("assets", []))
    
    # Recommended formats per platform
    recommendations = {
        "windows": ["setup", "exe", "msi"],
        "macos": ["pkg_arm", "pkg_intel", "dmg_arm", "dmg_intel", "binary"],
        "linux": ["deb", "rpm", "binary", "tarball"],
    }
    
    # Find first available recommended format
    for fmt in recommendations.get(platform, []):
        if fmt in downloads[platform] and downloads[platform][fmt]["available"]:
            info = downloads[platform][fmt]
            return {
                "platform": platform,
                "format": fmt,
                "version": release["tag_name"].lstrip("v"),
                "filename": info["filename"],
                "download_url": info["download_url"],
                "size_human": info["size_human"],
                "description": info["description"],
            }
    
    raise HTTPException(
        status_code=404,
        detail=f"No downloads available for {platform} in the latest release"
    )


@router.get("/download/{platform}/{format}")
async def download_agent(
    platform: str,
    format: str,
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Download agent installer from GitHub releases.
    
    Redirects to the GitHub download URL for the requested platform/format.
    """
    platform = platform.lower()
    
    # Validate platform
    if platform not in PLATFORM_ASSETS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid platform. Must be one of: {list(PLATFORM_ASSETS.keys())}"
        )
    
    # Validate format
    if format not in PLATFORM_ASSETS[platform]:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format for {platform}. Must be one of: {list(PLATFORM_ASSETS[platform].keys())}"
        )
    
    # Get latest release
    release = await _fetch_latest_release()
    if not release:
        raise HTTPException(status_code=503, detail="Unable to fetch release from GitHub")
    
    downloads = _map_assets_to_downloads(release.get("assets", []))
    
    download_info = downloads[platform].get(format)
    if not download_info or not download_info["available"]:
        raise HTTPException(
            status_code=404,
            detail=f"Download not available for {platform}/{format} in release {release['tag_name']}"
        )
    
    # Log download for analytics
    user_id = current_user.id if current_user else "anonymous"
    logger.info(
        f"Agent download: user={user_id}, platform={platform}, "
        f"format={format}, file={download_info['filename']}, version={release['tag_name']}"
    )
    
    # Track download in database (optional)
    if current_user:
        try:
            await _track_download(
                user_id=current_user.id,
                platform=platform,
                format=format,
                filename=download_info['filename'],
                version=release['tag_name'],
                ip_address=request.client.host if request.client else None,
            )
        except Exception as e:
            logger.warning(f"Failed to track download: {e}")
    
    # Redirect to GitHub download URL
    return RedirectResponse(
        url=download_info["download_url"],
        status_code=302,
        headers={"X-Download-Version": release["tag_name"]}
    )


@router.get("/download/{platform}/{format}/stream")
async def stream_download(platform: str, format: str, request: Request):
    """
    Stream the download through our server (instead of redirecting).
    
    Useful when direct GitHub access is blocked.
    """
    platform = platform.lower()
    
    if platform not in PLATFORM_ASSETS or format not in PLATFORM_ASSETS[platform]:
        raise HTTPException(status_code=400, detail="Invalid platform or format")
    
    release = await _fetch_latest_release()
    if not release:
        raise HTTPException(status_code=503, detail="Unable to fetch release from GitHub")
    
    downloads = _map_assets_to_downloads(release.get("assets", []))
    download_info = downloads[platform].get(format)
    
    if not download_info or not download_info["available"]:
        raise HTTPException(status_code=404, detail="Download not available")
    
    return await _stream_from_url(
        download_info["download_url"],
        download_info["filename"],
        download_info["content_type"]
    )


@router.get("/install-script")
async def get_install_script():
    """
    Get the Linux one-liner install script.
    
    Usage: curl -sL https://your-server/api/agent-downloads/install-script | sudo bash
    """
    release = await _fetch_latest_release()
    version = release["tag_name"] if release else "latest"
    
    script = f"""#!/bin/bash
# Jarwis Agent Quick Install Script
# Usage: curl -sL https://jarwis.io/api/agent-downloads/install-script | sudo bash

set -e

GITHUB_REPO="{GITHUB_REPO}"
API_BASE="https://api.github.com/repos/$GITHUB_REPO/releases/latest"

echo "============================================"
echo "   Jarwis Agent Installer"
echo "============================================"
echo ""

# Fetch latest release info
echo "Fetching latest release..."
RELEASE_INFO=$(curl -sL "$API_BASE")
VERSION=$(echo "$RELEASE_INFO" | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
echo "Latest version: $VERSION"
echo ""

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

DOWNLOAD_BASE="https://github.com/$GITHUB_REPO/releases/download/$VERSION"

case "$OS" in
    linux)
        if command -v apt-get &> /dev/null; then
            echo "Detected Debian/Ubuntu - Installing via .deb package..."
            # Find the .deb file in release
            DEB_FILE=$(echo "$RELEASE_INFO" | grep -o '"name": *"[^"]*\\.deb"' | head -1 | cut -d'"' -f4)
            if [ -n "$DEB_FILE" ]; then
                curl -sL "$DOWNLOAD_BASE/$DEB_FILE" -o "/tmp/$DEB_FILE"
                sudo dpkg -i "/tmp/$DEB_FILE"
                rm "/tmp/$DEB_FILE"
            else
                echo "No .deb package found, installing binary..."
                sudo curl -sL "$DOWNLOAD_BASE/jarwis-agent-linux" -o /usr/local/bin/jarwis-agent
                sudo chmod +x /usr/local/bin/jarwis-agent
            fi
        elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
            echo "Detected RHEL/CentOS/Fedora - Installing via .rpm package..."
            RPM_FILE=$(echo "$RELEASE_INFO" | grep -o '"name": *"[^"]*\\.rpm"' | head -1 | cut -d'"' -f4)
            if [ -n "$RPM_FILE" ]; then
                curl -sL "$DOWNLOAD_BASE/$RPM_FILE" -o "/tmp/$RPM_FILE"
                sudo rpm -i "/tmp/$RPM_FILE"
                rm "/tmp/$RPM_FILE"
            else
                echo "No .rpm package found, installing binary..."
                sudo curl -sL "$DOWNLOAD_BASE/jarwis-agent-linux" -o /usr/local/bin/jarwis-agent
                sudo chmod +x /usr/local/bin/jarwis-agent
            fi
        else
            echo "Installing standalone binary..."
            sudo curl -sL "$DOWNLOAD_BASE/jarwis-agent-linux" -o /usr/local/bin/jarwis-agent
            sudo chmod +x /usr/local/bin/jarwis-agent
        fi
        ;;
    darwin)
        echo "Detected macOS..."
        if [ "$ARCH" = "arm64" ]; then
            echo "Apple Silicon detected"
            PKG_PATTERN="apple-silicon.pkg"
        else
            echo "Intel Mac detected"
            PKG_PATTERN="intel.pkg"
        fi
        PKG_FILE=$(echo "$RELEASE_INFO" | grep -o '"name": *"[^"]*'$PKG_PATTERN'"' | head -1 | cut -d'"' -f4)
        if [ -n "$PKG_FILE" ]; then
            curl -sL "$DOWNLOAD_BASE/$PKG_FILE" -o "/tmp/$PKG_FILE"
            sudo installer -pkg "/tmp/$PKG_FILE" -target /
            rm "/tmp/$PKG_FILE"
        else
            echo "No .pkg found. Please download manually from:"
            echo "https://github.com/$GITHUB_REPO/releases/latest"
        fi
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
    
    Note: Checksums should be included in the release notes or a separate checksums.txt file.
    """
    if platform not in PLATFORM_ASSETS:
        raise HTTPException(status_code=400, detail=f"Invalid platform: {platform}")
    
    release = await _fetch_latest_release()
    if not release:
        raise HTTPException(status_code=503, detail="Unable to fetch release")
    
    # Look for checksums file in assets
    checksums = {}
    for asset in release.get("assets", []):
        if "checksum" in asset["name"].lower() or "sha256" in asset["name"].lower():
            # Found checksums file - would need to download and parse
            checksums["_checksums_file"] = asset["browser_download_url"]
            break
    
    downloads = _map_assets_to_downloads(release.get("assets", []))
    for fmt, info in downloads[platform].items():
        if info["available"]:
            checksums[info["filename"]] = "See checksums file in release"
    
    return {
        "version": release["tag_name"],
        "platform": platform,
        "checksums": checksums,
    }


@router.get("/build-status")
async def get_build_status():
    """
    Check which agent builds are available in the latest GitHub release.
    """
    release = await _fetch_latest_release()
    
    if not release:
        return {
            "status": "no_release",
            "message": "No releases found on GitHub",
            "github_repo": GITHUB_REPO,
            "create_release_url": f"https://github.com/{GITHUB_REPO}/releases/new",
        }
    
    downloads = _map_assets_to_downloads(release.get("assets", []))
    
    # Count available downloads
    total_formats = 0
    available_formats = 0
    
    platforms_status = {}
    for platform, formats in downloads.items():
        platforms_status[platform] = {}
        for fmt, info in formats.items():
            total_formats += 1
            if info["available"]:
                available_formats += 1
            platforms_status[platform][fmt] = {
                "filename": info["filename"],
                "available": info["available"],
                "download_url": info["download_url"],
                "size_human": info["size_human"],
                "download_count": info.get("download_count", 0),
            }
    
    return {
        "status": "ok",
        "version": release["tag_name"],
        "release_date": release["published_at"][:10],
        "html_url": release["html_url"],
        "github_repo": GITHUB_REPO,
        "total_assets": len(release.get("assets", [])),
        "available_formats": f"{available_formats}/{total_formats}",
        "platforms": platforms_status,
    }


@router.post("/clear-cache")
async def clear_release_cache():
    """
    Clear the cached release data (admin only).
    
    Forces the next request to fetch fresh data from GitHub.
    """
    global _release_cache
    _release_cache = {
        "data": None,
        "fetched_at": None,
        "ttl_seconds": 300,
    }
    return {"message": "Cache cleared", "next_fetch": "on next request"}


# ============================================================================
# Helper Functions
# ============================================================================

def _format_size(size_bytes: int) -> str:
    """Format byte size to human readable string."""
    if size_bytes == 0:
        return "N/A"
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


async def _stream_from_url(url: str, filename: str, content_type: str) -> StreamingResponse:
    """
    Stream a file from a URL to the client.
    """
    async def stream_content():
        async with httpx.AsyncClient(follow_redirects=True, timeout=300.0) as client:
            async with client.stream("GET", url) as response:
                if response.status_code != 200:
                    logger.error(f"Download failed: {response.status_code} for {url}")
                    raise HTTPException(
                        status_code=502,
                        detail=f"Failed to download: HTTP {response.status_code}"
                    )
                async for chunk in response.aiter_bytes(chunk_size=65536):
                    yield chunk
    
    return StreamingResponse(
        stream_content(),
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Download-Source": "github-stream",
        }
    )


async def _track_download(
    user_id: str,
    platform: str,
    format: str,
    filename: str,
    version: str,
    ip_address: Optional[str] = None,
):
    """
    Track download in database for analytics.
    """
    # TODO: Implement database tracking
    logger.info(f"Download tracked: user={user_id}, platform={platform}, format={format}, version={version}")
    pass
