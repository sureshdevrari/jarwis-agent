# Mobile Security Testing Architecture

## Overview

Jarwis supports **hybrid mobile security testing** that works both for local development and cloud deployment. This document explains the architecture and how to use it.

## The Challenge

Dynamic mobile security testing requires:
1. **Android Emulator** - Runs the app (needs x86 virtualization, 4GB+ RAM)
2. **Frida** - Runtime instrumentation for SSL bypass
3. **MITM Proxy** - Captures HTTPS traffic
4. **ADB** - Android Debug Bridge for device control

When Jarwis runs in the cloud, running emulators server-side is expensive (~$200-500/month per concurrent scan). The solution is a **hybrid architecture**.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      JARWIS SERVER (Cloud)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐ │
│  │ Static      │  │ WebSocket   │  │ Attack Engine               │ │
│  │ Analysis    │  │ Gateway     │  │ (SQLi, XSS, IDOR, etc.)     │ │
│  │ (APK/IPA)   │  │ (wss://)    │  │                             │ │
│  └─────────────┘  └──────┬──────┘  └─────────────────────────────┘ │
└──────────────────────────┼──────────────────────────────────────────┘
                           │ Secure WebSocket (no VPN needed)
┌──────────────────────────┼──────────────────────────────────────────┐
│                      CLIENT MACHINE                                 │
│  ┌─────────────┐  ┌──────┴──────┐  ┌─────────────┐  ┌───────────┐  │
│  │ Jarwis      │◄─┤ Traffic     │◄─┤ MITM Proxy  │◄─┤ Emulator  │  │
│  │ Agent       │  │ Relay       │  │ (local)     │  │ + Frida   │  │
│  │             │  │             │  │             │  │           │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Scan Modes

### 1. Remote Mode (Recommended for Cloud)
- Emulator runs on **your machine** (client)
- Server handles analysis and attack generation
- Traffic relayed via WebSocket (no VPN!)
- Zero cloud emulator costs

### 2. Local Mode (Self-Hosted)
- Everything runs on one machine
- Traditional setup like Burp Suite
- Good for local development

### 3. Static-Only Mode (Fallback)
- No emulator required
- Analyzes APK/IPA file only
- Finds hardcoded secrets, insecure configs
- Limited dynamic testing

## How It Works

### Traffic Flow

1. **App Makes Request**
   ```
   Mobile App → Emulator → MITM Proxy (local)
   ```

2. **Traffic Captured**
   ```
   MITM Proxy → Frida SSL Bypass → Decrypted HTTPS
   ```

3. **Relayed to Server**
   ```
   Traffic Relay → WebSocket → Jarwis Server
   ```

4. **Server Analyzes**
   ```
   Request Store ← Server receives traffic
   Attack Scanner ← Generates attack payloads
   ```

5. **Attack Execution**
   ```
   Server → WebSocket → Agent → MITM → App
   ```

6. **Response Analysis**
   ```
   Agent → WebSocket → Server → Vulnerability Detection
   ```

## Setting Up the Agent

### Prerequisites

- Windows 10/11, macOS 11+, or Ubuntu 20.04+
- 8GB RAM (16GB recommended)
- 20GB free disk space
- Python 3.10+

### Installation

```bash
# 1. Install Python dependencies
pip install frida frida-tools websockets aiohttp psutil

# 2. Check prerequisites
python jarwis_agent.py --check

# 3. Run setup (installs emulator if needed)
python jarwis_agent.py --setup --install-emulator

# 4. Start agent (get token from Jarwis dashboard)
python jarwis_agent.py --server wss://jarwis.io/api/mobile-agent/ws/<YOUR_TOKEN>
```

### Agent Commands

```bash
# Check system prerequisites
python jarwis_agent.py --check

# Run interactive setup
python jarwis_agent.py --setup

# Setup with emulator installation
python jarwis_agent.py --setup --install-emulator

# Connect to server
python jarwis_agent.py --server <URL>

# Custom MITM port
python jarwis_agent.py --server <URL> --mitm-port 8082

# Verbose logging
python jarwis_agent.py --server <URL> --verbose
```

## API Endpoints

### Agent Management

```
GET  /api/mobile-agent/agents          - List your connected agents
GET  /api/mobile-agent/agents/{id}     - Get agent details
POST /api/mobile-agent/agents/{id}/disconnect - Disconnect agent
```

### Scan Control

```
POST /api/mobile-agent/scan/start      - Start scan on agent
POST /api/mobile-agent/scan/{id}/stop  - Stop running scan
```

### Setup Help

```
GET  /api/mobile-agent/setup-instructions?platform=windows
```

## WebSocket Protocol

### Message Types (Agent → Server)

| Type | Description |
|------|-------------|
| `auth_request` | Authentication with token |
| `agent_status` | Agent capabilities and state |
| `traffic_captured` | Single captured request |
| `traffic_batch` | Multiple captured requests |
| `attack_response` | Response to attack request |
| `scan_progress` | Progress updates |
| `scan_complete` | Scan finished |

### Message Types (Server → Agent)

| Type | Description |
|------|-------------|
| `auth_response` | Authentication result |
| `scan_start` | Start a scan |
| `scan_stop` | Stop the scan |
| `attack_request` | Execute attack via proxy |
| `attack_batch` | Multiple attack requests |
| `config_update` | Update agent config |

### Message Format

```json
{
  "type": "traffic_captured",
  "scan_id": "mob_abc123",
  "message_id": "msg_xyz789",
  "timestamp": "2026-01-15T10:30:00Z",
  "data": {
    "request_id": "req_001",
    "url": "https://api.example.com/users",
    "method": "POST",
    "headers": {"Authorization": "Bearer xxx"},
    "body": "{\"username\": \"test\"}",
    "response_status": 200,
    "response_body": "{...}"
  }
}
```

## Security Considerations

### Traffic Security
- All WebSocket traffic is encrypted (WSS)
- Agent authenticates with user's JWT token
- Traffic contains app data - stays encrypted end-to-end

### Agent Security
- Agent ID is unique per installation
- Token is scoped to user account
- Server validates all commands

## Troubleshooting

### Agent Won't Connect

1. Check firewall allows outbound WebSocket (port 443)
2. Verify token hasn't expired
3. Check `--verbose` output for errors

### Emulator Won't Start

1. Enable virtualization in BIOS
2. On Windows: Enable Hyper-V or install HAXM
3. Check available disk space (need 20GB+)

### Frida Can't Connect

1. Ensure frida-server is running on device
2. Check with: `frida-ps -U`
3. Device must be rooted for some features

### No Traffic Captured

1. Verify proxy is configured on device
2. Check MITM CA certificate is installed
3. App may use certificate pinning - enable Frida bypass

## Files Created

```
core/mobile_agent/
├── __init__.py              # Package exports
├── agent_protocol.py        # Message protocol definitions
├── agent_core.py            # Main agent orchestrator
├── traffic_relay.py         # WebSocket traffic bridge
├── local_mitm.py            # Local MITM proxy manager
├── emulator_controller.py   # Emulator/device management
└── frida_manager.py         # Frida server/script management

core/
├── mobile_agent_server.py   # Server-side session manager
└── mobile_remote_executor.py # Remote attack execution

api/routes/
└── mobile_agent.py          # REST + WebSocket endpoints

jarwis_agent.py              # CLI entry point for agent
```

## Next Steps

1. **Test locally** - Run agent on same machine as server
2. **Test remotely** - Run agent on different machine
3. **Add device support** - Support real Android devices
4. **iOS support** - Add iOS simulator/device support
5. **Cloud emulators** - AWS Device Farm integration (premium)
