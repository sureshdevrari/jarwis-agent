"""
Server Configuration API

Provides dynamic server configuration based on environment.
This allows the frontend to get the correct URLs for dev/staging/production.
"""

import os
import logging
from fastapi import APIRouter, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/config", tags=["Server Configuration"])

# Environment detection
def get_environment():
    """Detect current environment"""
    env = os.environ.get("JARWIS_ENV", "development")
    if env in ["production", "prod"]:
        return "production"
    elif env in ["staging", "stage"]:
        return "staging"
    return "development"

# Version info
AGENT_VERSION = "2.1.0"
PLATFORM_VERSION = "1.0.0"


class ServerConfig(BaseModel):
    """Server configuration response"""
    environment: str
    server_url: str
    api_url: str
    ws_url: str
    agent_version: str
    platform_version: str
    github_repo: str
    github_release_url: str
    features: dict


class AgentSetupConfig(BaseModel):
    """Agent setup specific configuration"""
    server_url: str
    ws_url: str
    agent_version: str
    activation_key_required: bool
    downloads: dict


@router.get("/server", response_model=ServerConfig)
async def get_server_config(request: Request):
    """
    Get server configuration based on current environment.
    
    This endpoint returns dynamic URLs based on:
    1. Environment variables (JARWIS_SERVER_URL, JARWIS_API_URL)
    2. Request origin (for auto-detection)
    3. Environment mode (dev/staging/prod)
    
    Frontend should call this on app init to get correct URLs.
    """
    environment = get_environment()
    
    # Determine server URL from environment or request
    # Priority: ENV var > Request origin
    server_url = os.environ.get("JARWIS_SERVER_URL")
    api_url = os.environ.get("JARWIS_API_URL")
    
    if not server_url:
        # Auto-detect from request
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
        server_url = f"{scheme}://{host}"
    
    if not api_url:
        api_url = server_url
    
    # Derive WebSocket URL
    ws_url = server_url.replace("https://", "wss://").replace("http://", "ws://")
    
    # GitHub repo info
    github_repo = os.environ.get("JARWIS_GITHUB_REPO", "sureshdevrari/jarwis-agent")
    github_release_url = f"https://github.com/{github_repo}/releases/download/v{AGENT_VERSION}"
    
    # Feature flags based on environment
    features = {
        "agent_installer": True,
        "gui_installer": True,
        "auto_update": environment == "production",
        "telemetry": environment == "production",
        "debug_mode": environment == "development",
    }
    
    return ServerConfig(
        environment=environment,
        server_url=server_url,
        api_url=api_url,
        ws_url=ws_url,
        agent_version=AGENT_VERSION,
        platform_version=PLATFORM_VERSION,
        github_repo=github_repo,
        github_release_url=github_release_url,
        features=features,
    )


@router.get("/agent-setup", response_model=AgentSetupConfig)
async def get_agent_setup_config(request: Request):
    """
    Get configuration specifically for agent setup page.
    
    Returns all info needed for the Agent Download/Setup page
    including dynamic URLs based on environment.
    """
    environment = get_environment()
    
    # Determine server URL
    server_url = os.environ.get("JARWIS_SERVER_URL")
    if not server_url:
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
        server_url = f"{scheme}://{host}"
    
    ws_url = server_url.replace("https://", "wss://").replace("http://", "ws://")
    
    # GitHub release URL
    github_repo = os.environ.get("JARWIS_GITHUB_REPO", "sureshdevrari/jarwis-agent")
    release_base = f"https://github.com/{github_repo}/releases/download/v{AGENT_VERSION}"
    
    # Download info
    downloads = {
        "windows": {
            "gui": {
                "name": "GUI Installer",
                "filename": "JarwisAgentSetup-GUI.exe",
                "url": f"{release_base}/JarwisAgentSetup-GUI.exe",
                "size": "45 MB",
                "recommended": True,
                "description": "Professional installer wizard with branding and EULA",
            },
            "cli": {
                "name": "CLI Executable",
                "filename": "jarwis-agent.exe",
                "url": f"{release_base}/jarwis-agent.exe",
                "size": "15 MB",
                "recommended": False,
                "description": "Standalone CLI for advanced users",
            },
        },
        "macos": {
            "dmg": {
                "name": "DMG Installer",
                "filename": f"JarwisAgentSetup-{AGENT_VERSION}.dmg",
                "url": f"{release_base}/JarwisAgentSetup-{AGENT_VERSION}.dmg",
                "size": "45 MB",
                "recommended": True,
                "description": "DMG with GUI installer wizard",
            },
            "binary": {
                "name": "CLI Binary",
                "filename": "jarwis-agent-macos",
                "url": f"{release_base}/jarwis-agent-macos",
                "size": "14 MB",
                "recommended": False,
                "description": "Standalone CLI binary",
            },
        },
        "linux": {
            "installer": {
                "name": "GUI Installer",
                "filename": f"jarwis-agent-{AGENT_VERSION}-linux-installer.tar.gz",
                "url": f"{release_base}/jarwis-agent-{AGENT_VERSION}-linux-installer.tar.gz",
                "size": "50 MB",
                "recommended": True,
                "description": "Installer with GUI wizard",
            },
            "deb": {
                "name": "DEB Package",
                "filename": f"jarwis-agent_{AGENT_VERSION}_amd64.deb",
                "url": f"{release_base}/jarwis-agent_{AGENT_VERSION}_amd64.deb",
                "size": "28 MB",
                "recommended": False,
                "description": "For Debian/Ubuntu",
            },
            "rpm": {
                "name": "RPM Package",
                "filename": f"jarwis-agent-{AGENT_VERSION}-1.x86_64.rpm",
                "url": f"{release_base}/jarwis-agent-{AGENT_VERSION}-1.x86_64.rpm",
                "size": "28 MB",
                "recommended": False,
                "description": "For RHEL/Fedora",
            },
        },
    }
    
    return AgentSetupConfig(
        server_url=server_url,
        ws_url=ws_url,
        agent_version=AGENT_VERSION,
        activation_key_required=False,  # Optional
        downloads=downloads,
    )
