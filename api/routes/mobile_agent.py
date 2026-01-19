"""
Jarwis API - Mobile Agent Routes

WebSocket and REST endpoints for mobile agent management.
"""

import io
import logging
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.mobile_agent_server import mobile_agent_manager, AgentState
from api.routes.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/mobile-agent", tags=["Mobile Agent"])


# === Models ===

class AgentInfo(BaseModel):
    """Agent information response"""
    agent_id: str
    state: str
    connected_at: str
    capabilities: list
    os: str
    hostname: str
    current_scan_id: Optional[str]


class StartScanRequest(BaseModel):
    """Request to start scan on agent"""
    agent_id: str
    scan_id: str
    app_path: Optional[str] = None
    app_package: str
    platform: str = "android"
    ssl_bypass: bool = True
    crawl_enabled: bool = True
    crawl_duration: int = 120
    target_hosts: list = []


class AttackRequest(BaseModel):
    """Request to execute attack on agent"""
    scan_id: str
    attack_id: str
    request_id: str
    scanner_name: str
    url: str
    method: str
    headers: dict
    body: str = ""
    payload: str = ""
    injection_point: str = ""
    parameter_name: str = ""
    timeout: int = 30


# === WebSocket Endpoint ===

@router.websocket("/ws/{auth_token}")
async def agent_websocket(websocket: WebSocket, auth_token: str):
    """
    WebSocket endpoint for mobile agents to connect.
    
    Agents connect here and maintain persistent connection for:
    - Receiving scan commands
    - Sending captured traffic
    - Receiving and responding to attack requests
    """
    # Validate token and get user
    try:
        from services.auth_service import auth_service
        user = await auth_service.get_user_from_token(auth_token)
        if not user:
            await websocket.close(code=4001, reason="Invalid token")
            return
    except Exception as e:
        logger.error(f"Auth error: {e}")
        await websocket.close(code=4001, reason="Authentication failed")
        return
    
    # Handle agent connection
    agent_id = await mobile_agent_manager.handle_agent_connection(
        websocket=websocket,
        user_id=user.id,
        auth_token=auth_token
    )
    
    if not agent_id:
        return
    
    try:
        # Main message loop
        while True:
            message = await websocket.receive_text()
            await mobile_agent_manager.handle_agent_message(agent_id, message)
            
    except WebSocketDisconnect:
        logger.info(f"Agent disconnected: {agent_id}")
    except Exception as e:
        logger.error(f"Agent WebSocket error: {e}")
    finally:
        await mobile_agent_manager.disconnect_agent(agent_id)


# === REST Endpoints ===

@router.get("/agents")
async def list_agents(current_user = Depends(get_current_user)):
    """List all connected agents for current user"""
    agents = mobile_agent_manager.get_user_agents(current_user.id)
    return {
        "agents": [a.to_dict() for a in agents],
        "count": len(agents)
    }


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str, current_user = Depends(get_current_user)):
    """Get specific agent details"""
    agent = mobile_agent_manager.get_agent(agent_id)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    if agent.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your agent")
    
    return agent.to_dict()


@router.post("/agents/{agent_id}/disconnect")
async def disconnect_agent(agent_id: str, current_user = Depends(get_current_user)):
    """Disconnect an agent"""
    agent = mobile_agent_manager.get_agent(agent_id)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    if agent.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your agent")
    
    await mobile_agent_manager.disconnect_agent(agent_id)
    return {"status": "disconnected"}


@router.post("/scan/start")
async def start_scan(request: StartScanRequest, current_user = Depends(get_current_user)):
    """Start a mobile scan on specified agent"""
    agent = mobile_agent_manager.get_agent(request.agent_id)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    if agent.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your agent")
    
    if agent.state != AgentState.IDLE:
        raise HTTPException(status_code=400, detail=f"Agent is {agent.state.value}")
    
    # Build scan config
    scan_config = {
        "scan_id": request.scan_id,
        "command": "start",
        "app_path": request.app_path,
        "app_package": request.app_package,
        "platform": request.platform,
        "ssl_bypass": request.ssl_bypass,
        "crawl_enabled": request.crawl_enabled,
        "crawl_duration": request.crawl_duration,
        "target_hosts": request.target_hosts
    }
    
    success = await mobile_agent_manager.start_scan_on_agent(
        agent_id=request.agent_id,
        scan_id=request.scan_id,
        scan_config=scan_config
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to start scan")
    
    return {"status": "started", "scan_id": request.scan_id}


@router.post("/scan/{scan_id}/stop")
async def stop_scan(scan_id: str, current_user = Depends(get_current_user)):
    """Stop a running mobile scan"""
    agent = mobile_agent_manager.get_scan_agent(scan_id)
    
    if not agent:
        raise HTTPException(status_code=404, detail="No agent found for scan")
    
    if agent.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your scan")
    
    success = await mobile_agent_manager.stop_scan_on_agent(scan_id)
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to stop scan")
    
    return {"status": "stopping"}


@router.post("/attack")
async def send_attack(request: AttackRequest, current_user = Depends(get_current_user)):
    """Send attack request to agent"""
    agent = mobile_agent_manager.get_scan_agent(request.scan_id)
    
    if not agent:
        raise HTTPException(status_code=404, detail="No agent found for scan")
    
    if agent.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your scan")
    
    attack_data = {
        "attack_id": request.attack_id,
        "request_id": request.request_id,
        "scanner_name": request.scanner_name,
        "url": request.url,
        "method": request.method,
        "headers": request.headers,
        "body": request.body,
        "payload": request.payload,
        "injection_point": request.injection_point,
        "parameter_name": request.parameter_name,
        "timeout": request.timeout
    }
    
    success = await mobile_agent_manager.send_attack_to_agent(
        scan_id=request.scan_id,
        attack_request=attack_data
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to send attack")
    
    return {"status": "sent", "attack_id": request.attack_id}


@router.get("/stats")
async def get_stats(current_user = Depends(get_current_user)):
    """Get agent manager statistics (admin only)"""
    # Check if admin
    if not getattr(current_user, 'is_admin', False):
        # Return only user's stats
        agents = mobile_agent_manager.get_user_agents(current_user.id)
        return {
            "your_agents": len(agents),
            "idle": sum(1 for a in agents if a.state == AgentState.IDLE),
            "scanning": sum(1 for a in agents if a.state == AgentState.SCANNING)
        }
    
    return mobile_agent_manager.get_stats()


@router.post("/token")
async def generate_agent_token(current_user = Depends(get_current_user)):
    """
    Generate a one-time token for agent connection.
    Token is valid for 30 minutes.
    """
    from services.auth_service import auth_service
    try:
        token = await auth_service.create_agent_token(current_user.id)
        return {
            "token": token,
            "expires_in": 1800,  # 30 minutes
            "server_url": f"/api/mobile-agent/ws/{token}"
        }
    except Exception as e:
        logger.error(f"Failed to generate agent token: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate token")


@router.get("/prerequisites")
async def check_prerequisites(current_user = Depends(get_current_user)):
    """Check if server-side prerequisites are met for mobile agent"""
    return {
        "websocket_enabled": True,
        "agent_support": True,
        "max_agents_per_user": 5,
        "features": [
            "traffic_capture",
            "frida_instrumentation",
            "ssl_bypass",
            "mitm_proxy",
            "app_analysis"
        ]
    }


# === Agent Download ===

@router.get("/download")
async def download_agent(
    platform: str = Query("windows", enum=["windows", "macos", "linux"]),
    current_user = Depends(get_current_user)
):
    """
    Download the mobile agent package as a ZIP file.
    Includes the agent script, required modules, setup scripts, and instructions.
    """
    # Get project root
    project_root = Path(__file__).parent.parent.parent
    
    # Files to include in the package
    agent_files = {
        "jarwis_agent.py": project_root / "jarwis_agent.py",
        "core/mobile_agent/__init__.py": project_root / "core" / "mobile_agent" / "__init__.py",
        "core/mobile_agent/agent_core.py": project_root / "core" / "mobile_agent" / "agent_core.py",
        "core/mobile_agent/agent_protocol.py": project_root / "core" / "mobile_agent" / "agent_protocol.py",
        "core/mobile_agent/emulator_controller.py": project_root / "core" / "mobile_agent" / "emulator_controller.py",
        "core/mobile_agent/frida_manager.py": project_root / "core" / "mobile_agent" / "frida_manager.py",
        "core/mobile_agent/local_mitm.py": project_root / "core" / "mobile_agent" / "local_mitm.py",
        "core/mobile_agent/traffic_relay.py": project_root / "core" / "mobile_agent" / "traffic_relay.py",
    }
    
    # Create ZIP in memory
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add agent files
        for archive_name, file_path in agent_files.items():
            if file_path.exists():
                zf.write(file_path, archive_name)
            else:
                logger.warning(f"Agent file not found: {file_path}")
        
        # Add requirements.txt
        requirements_content = """# Jarwis Mobile Agent Requirements
# Install with: pip install -r requirements.txt

# Core dependencies
websockets>=11.0
aiohttp>=3.8.0
psutil>=5.9.0

# Mobile testing tools
frida-tools>=12.0.0
mitmproxy>=10.0.0

# Optional: For UI features
rich>=13.0.0
"""
        zf.writestr("requirements.txt", requirements_content)
        
        # NOTE: We no longer include .bat/.sh scripts in the package
        # because Windows SmartScreen and macOS Gatekeeper block downloaded scripts.
        # Instead, the Jarwis UI shows copy-paste commands for manual setup.
        
        # Add README with copy-paste setup instructions
        readme_content = _generate_readme(platform)
        zf.writestr("README.md", readme_content)
    
    # Reset buffer position
    zip_buffer.seek(0)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d")
    filename = f"jarwis-mobile-agent-{platform}-{timestamp}.zip"
    
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "application/zip"
        }
    )


# NOTE: Script generation functions (_generate_windows_setup_script, _generate_unix_setup_script, etc.)
# have been removed. We no longer include .bat/.sh files in the download package because:
# - Windows SmartScreen blocks downloaded .bat files from untrusted sources
# - macOS Gatekeeper blocks downloaded .sh scripts from untrusted sources
# - Users would need to manually bypass security warnings
# 
# Instead, the Jarwis UI now shows copy-paste terminal commands that users run directly.
# This is a more trusted approach as the user sees exactly what commands will execute.


def _generate_readme(platform: str) -> str:
    """Generate README file for the agent package with copy-paste setup commands"""
    python_cmd = "python" if platform == "windows" else "python3"
    pip_cmd = "pip" if platform == "windows" else "pip3"
    activate_cmd = "venv\\Scripts\\activate" if platform == "windows" else "source venv/bin/activate"
    
    # Platform-specific Python install instructions
    if platform == "windows":
        python_install = """1. Download Python from https://www.python.org/downloads/
2. Run the installer
3. **IMPORTANT:** Check ✓ "Add Python to PATH" at the bottom of the installer
4. Click "Install Now"
5. Restart your terminal after installation"""
    elif platform == "macos":
        python_install = """Option 1: Download from https://www.python.org/downloads/

Option 2: Install via Homebrew:
```bash
brew install python
```"""
    else:  # linux
        python_install = """Install via package manager:
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```"""
    
    return f'''# Jarwis Mobile Agent

A local agent for mobile security testing that connects to your Jarwis server.

## Prerequisites

### Install Python 3.9+ (Required)

Most Windows and macOS systems don't have Python pre-installed. Check if you have it:

{"```batch" if platform == "windows" else "```bash"}
{python_cmd} --version
```

If you see "command not found" or version < 3.9, install Python:

{python_install}

## Quick Start

### 1. Create Virtual Environment & Install Dependencies

Open a terminal in this folder and run:

{"```batch" if platform == "windows" else "```bash"}
# Create virtual environment
{python_cmd} -m venv venv

# Activate it
{activate_cmd}

# Install dependencies
{pip_cmd} install -r requirements.txt
```

### 2. Get Your Connection Token

1. Go to your Jarwis dashboard
2. Navigate to **Mobile Scan > Agent Setup**
3. Copy the connection token (valid for 30 minutes)

### 3. Connect to Server

Make sure the virtual environment is activated, then run:

{"```batch" if platform == "windows" else "```bash"}
{python_cmd} jarwis_agent.py --server wss://YOUR_SERVER/api/mobile-agent/ws/YOUR_TOKEN
```

Or specify server and token separately:

{"```batch" if platform == "windows" else "```bash"}
{python_cmd} jarwis_agent.py --server wss://YOUR_SERVER/api/mobile-agent/ws --token YOUR_TOKEN
```

## Requirements

- **Python 3.9 or higher** - [Download](https://www.python.org/downloads/)
- **Android Debug Bridge (ADB)** - [Download](https://developer.android.com/studio/releases/platform-tools)
- **Android emulator or physical device** with USB debugging enabled
- **Network access** to your Jarwis server

## Install ADB

{"**Windows:**" if platform == "windows" else "**" + platform.title() + ":**"}
{"1. Download Android SDK Platform Tools from https://developer.android.com/studio/releases/platform-tools" if platform == "windows" else ""}
{"2. Extract to a folder (e.g., C:\\\\Android\\\\platform-tools)" if platform == "windows" else ""}
{"3. Add the folder to your system PATH" if platform == "windows" else ""}
{"" if platform == "windows" else "```bash"}
{"" if platform == "windows" else "# Linux (Ubuntu/Debian)"}
{"" if platform == "windows" else "sudo apt-get install -y android-tools-adb"}
{"" if platform == "windows" else ""}
{"" if platform == "windows" else "# macOS"}
{"" if platform == "windows" else "brew install android-platform-tools"}
{"" if platform == "windows" else "```"}

## Features

- **Traffic Capture**: Intercepts mobile app HTTP/HTTPS traffic via MITM proxy
- **Frida Integration**: Runtime instrumentation for SSL pinning bypass
- **Emulator Control**: Manages Android emulator lifecycle
- **Secure Connection**: WebSocket connection to Jarwis server
- **Real-time Relay**: Sends captured traffic for security analysis

## Troubleshooting

### Emulator not starting
- Ensure hardware virtualization is enabled in BIOS
- Windows: Enable Hyper-V or install Intel HAXM
- Linux: Ensure KVM is available (`ls /dev/kvm`)

### ADB not found
- Download Android SDK Platform Tools
- Add the folder to your system PATH
- Restart your terminal

### Frida connection issues
- Ensure frida-server is running on the device/emulator
- Check with: `frida-ps -U`
- Device must have root access or use frida-gadget

### Agent can't connect to server
- Check firewall settings
- Ensure outbound WebSocket (port 443) is allowed
- Verify the token hasn't expired (30 minute validity)

## Support

For issues and questions, contact support through your Jarwis dashboard.
'''


# === Agent Setup Helper ===

@router.get("/setup-instructions")
async def get_setup_instructions(
    platform: str = Query("windows", enum=["windows", "macos", "linux"]),
    current_user = Depends(get_current_user)
):
    """
    Get setup instructions for mobile agent on client machine.
    Returns step-by-step guide for installing and running the agent.
    """
    # Generate connection token for this user
    from services.auth_service import auth_service
    agent_token = await auth_service.create_agent_token(current_user.id)
    
    base_instructions = {
        "overview": """
The Jarwis Mobile Agent runs on your local machine and connects to the Jarwis server.
It manages the Android emulator, Frida, and MITM proxy locally, relaying traffic
to the server for analysis.

Benefits:
- Emulator runs on YOUR machine (no cloud costs)
- Full control over test environment
- No VPN required - uses secure WebSocket
- Real device support
        """.strip(),
        
        "requirements": {
            "windows": [
                "Windows 10/11 64-bit",
                "8GB RAM minimum (16GB recommended)",
                "20GB free disk space",
                "Hardware virtualization enabled (Hyper-V or HAXM)",
                "Python 3.10+"
            ],
            "macos": [
                "macOS 11+ (Big Sur or later)",
                "8GB RAM minimum",
                "20GB free disk space",
                "Python 3.10+"
            ],
            "linux": [
                "Ubuntu 20.04+ or similar",
                "8GB RAM minimum",
                "20GB free disk space",
                "KVM virtualization support",
                "Python 3.10+"
            ]
        }[platform],
        
        "steps": {
            "windows": [
                {
                    "step": 1,
                    "title": "Install Python Dependencies",
                    "command": "pip install frida frida-tools websockets aiohttp psutil"
                },
                {
                    "step": 2,
                    "title": "Download Jarwis Agent",
                    "command": "git clone https://github.com/jarwis/mobile-agent.git\ncd mobile-agent"
                },
                {
                    "step": 3,
                    "title": "Run Setup Script",
                    "command": "python setup_agent.py --install-emulator"
                },
                {
                    "step": 4,
                    "title": "Start Agent",
                    "command": f"python agent.py --server wss://jarwis.io/api/mobile-agent/ws/{agent_token}"
                }
            ],
            "macos": [
                {
                    "step": 1,
                    "title": "Install Dependencies",
                    "command": "pip3 install frida frida-tools websockets aiohttp psutil"
                },
                {
                    "step": 2,
                    "title": "Install Android Studio (for emulator)",
                    "command": "brew install --cask android-studio"
                },
                {
                    "step": 3,
                    "title": "Download and Run Agent",
                    "command": f"curl -O https://jarwis.io/agent/setup.sh && bash setup.sh {agent_token}"
                }
            ],
            "linux": [
                {
                    "step": 1,
                    "title": "Install Dependencies",
                    "command": "sudo apt install -y python3-pip adb\npip3 install frida frida-tools websockets aiohttp psutil"
                },
                {
                    "step": 2,
                    "title": "Install Android SDK",
                    "command": "wget https://dl.google.com/android/repository/commandlinetools-linux-latest.zip\nunzip commandlinetools-linux-*.zip -d ~/android-sdk"
                },
                {
                    "step": 3,
                    "title": "Start Agent",
                    "command": f"python3 agent.py --server wss://jarwis.io/api/mobile-agent/ws/{agent_token}"
                }
            ]
        }[platform],
        
        "connection_token": agent_token,
        "server_url": f"wss://jarwis.io/api/mobile-agent/ws/{agent_token}",
        
        "troubleshooting": [
            {
                "issue": "Emulator won't start",
                "solution": "Ensure virtualization is enabled in BIOS. On Windows, enable Hyper-V or install HAXM."
            },
            {
                "issue": "Frida can't connect",
                "solution": "Make sure frida-server is running on the device/emulator. Check with 'frida-ps -U'."
            },
            {
                "issue": "Agent can't connect to server",
                "solution": "Check firewall settings. Ensure outbound WebSocket connections on port 443 are allowed."
            }
        ]
    }
    
    return base_instructions
