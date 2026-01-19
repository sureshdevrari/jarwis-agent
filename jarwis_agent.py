#!/usr/bin/env python3
"""
Jarwis Universal Security Agent - CLI Entry Point

Standalone agent that runs on client machine to enable ALL security testing types:
- Web Application Security (OWASP Top 10, API, Auth)
- Mobile Security (Static & Dynamic Analysis)
- Network Security (Port Scanning, Vuln Assessment)
- Cloud Security (AWS, Azure, GCP, Kubernetes)
- SAST (Static Application Security Testing)

The agent is REQUIRED for all scan types to ensure security and compliance.

Usage:
    python jarwis_agent.py --server wss://jarwis.io/api/agent/ws/<token>
    
    # With custom options:
    python jarwis_agent.py --server <url> --data-dir ~/.jarwis-agent
    
    # Check capabilities:
    python jarwis_agent.py --check
"""

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.universal_agent import UniversalJarwisAgent, AgentConfig, UniversalAgentCapabilities


def setup_logging(verbose: bool = False):
    """Configure logging"""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Reduce noise from libraries
    logging.getLogger('websockets').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)


def print_banner():
    """Print agent banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║       ██╗ █████╗ ██████╗ ██╗    ██╗██╗███████╗              ║
    ║       ██║██╔══██╗██╔══██╗██║    ██║██║██╔════╝              ║
    ║       ██║███████║██████╔╝██║ █╗ ██║██║███████╗              ║
    ║  ██   ██║██╔══██║██╔══██╗██║███╗██║██║╚════██║              ║
    ║  ╚█████╔╝██║  ██║██║  ██║╚███╔███╔╝██║███████║              ║
    ║   ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚══════╝              ║
    ║                                                              ║
    ║            Universal Security Testing Agent                  ║
    ║                      Version 2.0.0                           ║
    ║                                                              ║
    ║   Supports: Web | Mobile | Network | Cloud | SAST            ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


async def check_prerequisites() -> dict:
    """Check system prerequisites using UniversalAgentCapabilities"""
    caps = UniversalAgentCapabilities()
    return await caps.detect_all()


async def run_setup(install_emulator: bool = False):
    """Run interactive setup"""
    print("\n🔧 Running Jarwis Universal Agent Setup...\n")
    
    # Check prerequisites using capabilities detection
    caps = await check_prerequisites()
    
    print("=" * 60)
    print("System Information:")
    print("=" * 60)
    system = caps.get("system", {})
    print(f"  OS: {system.get('os', 'Unknown')} {system.get('os_version', '')[:30]}")
    print(f"  Architecture: {system.get('architecture', 'Unknown')}")
    print(f"  Python: {system.get('python_version', 'Unknown')}")
    print(f"  CPU Cores: {system.get('cpu_count', 'Unknown')}")
    print(f"  Memory: {system.get('memory_available_gb', '?')}/{system.get('memory_total_gb', '?')} GB")
    
    print("\n" + "=" * 60)
    print("Capabilities by Scan Type:")
    print("=" * 60)
    
    # Web capabilities
    web = caps.get("web", {})
    print(f"\n📱 WEB APPLICATION TESTING:")
    print(f"  {'✓' if web.get('available') else '✗'} HTTP Client: Available")
    print(f"  {'✓' if web.get('browser_automation') else '✗'} Browser Automation (Playwright)")
    print(f"  {'✓' if web.get('mitmproxy') else '✗'} MITM Proxy")
    
    # Mobile capabilities
    mobile = caps.get("mobile", {})
    print(f"\n📱 MOBILE SECURITY TESTING:")
    print(f"  {'✓' if mobile.get('static_available') else '✗'} Static Analysis")
    print(f"  {'✓' if mobile.get('adb') else '✗'} ADB: {mobile.get('adb_version', 'Not found')[:40] if mobile.get('adb_version') else 'Not found'}")
    print(f"  {'✓' if mobile.get('frida') else '✗'} Frida: {mobile.get('frida_version', 'Not found')}")
    print(f"  {'✓' if mobile.get('dynamic_available') else '✗'} Dynamic Analysis Ready")
    if mobile.get('connected_devices'):
        print(f"    Connected devices: {', '.join(mobile['connected_devices'])}")
    
    # Network capabilities
    network = caps.get("network", {})
    print(f"\n🌐 NETWORK SECURITY TESTING:")
    print(f"  {'✓' if network.get('available') else '✗'} Port Scanning")
    print(f"  {'✓' if network.get('nmap') else '✗'} Nmap")
    print(f"  {'✓' if network.get('raw_sockets') else '✗'} Raw Sockets (SYN scan)")
    if network.get('local_interfaces'):
        print(f"    Network interfaces: {len(network['local_interfaces'])}")
    
    # Cloud capabilities
    cloud = caps.get("cloud", {})
    print(f"\n☁️  CLOUD SECURITY TESTING:")
    print(f"  {'✓' if cloud.get('aws_available') else '✗'} AWS (CLI: {'✓' if cloud.get('aws_cli') else '✗'}, Configured: {'✓' if cloud.get('aws_configured') else '✗'})")
    print(f"  {'✓' if cloud.get('azure_available') else '✗'} Azure (CLI: {'✓' if cloud.get('azure_cli') else '✗'}, Configured: {'✓' if cloud.get('azure_configured') else '✗'})")
    print(f"  {'✓' if cloud.get('gcp_available') else '✗'} GCP (CLI: {'✓' if cloud.get('gcloud_cli') else '✗'}, Configured: {'✓' if cloud.get('gcp_configured') else '✗'})")
    print(f"  {'✓' if cloud.get('k8s_available') else '✗'} Kubernetes (kubectl: {'✓' if cloud.get('kubectl') else '✗'})")
    if cloud.get('k8s_context'):
        print(f"    K8s Context: {cloud['k8s_context']}")
    
    # SAST capabilities
    sast = caps.get("sast", {})
    print(f"\n🔍 SAST (Static Analysis):")
    print(f"  {'✓' if sast.get('available') else '✗'} Pattern Matching")
    print(f"  {'✓' if sast.get('semgrep') else '✗'} Semgrep: {sast.get('semgrep_version', 'Not found')}")
    print(f"  {'✓' if sast.get('bandit') else '✗'} Bandit (Python)")
    print(f"  {'✓' if sast.get('eslint') else '✗'} ESLint (JavaScript)")
    
    print("\n" + "=" * 60)
    print("Supported Scan Types:")
    print("=" * 60)
    scan_types = caps.get("scan_types", [])
    if scan_types:
        for st in scan_types:
            print(f"  ✓ {st}")
    else:
        print("  ⚠️  No scan types fully configured")
    
    # Installation suggestions
    print("\n" + "=" * 60)
    print("Setup Recommendations:")
    print("=" * 60)
    
    suggestions = []
    if not web.get('browser_automation'):
        suggestions.append("Install Playwright: pip install playwright && playwright install")
    if not mobile.get('frida'):
        suggestions.append("Install Frida: pip install frida frida-tools")
    if not mobile.get('adb'):
        suggestions.append("Install Android SDK: Download from developer.android.com")
    if not network.get('nmap'):
        suggestions.append("Install Nmap: https://nmap.org/download.html")
    if not sast.get('semgrep'):
        suggestions.append("Install Semgrep: pip install semgrep")
    if not cloud.get('aws_cli'):
        suggestions.append("Install AWS CLI: https://aws.amazon.com/cli/")
    
    if suggestions:
        for s in suggestions:
            print(f"  • {s}")
    else:
        print("  ✅ All recommended tools are installed!")
    
    print("\n✅ Setup check complete!")
    print("\nTo start the agent, run:")
    print("  python jarwis_agent.py --server <your-server-url>")
    print("\nGet your connection URL from: https://jarwis.io/agent/setup")


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Jarwis Universal Security Testing Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Connect to server:
    python jarwis_agent.py --server wss://jarwis.io/api/agent/ws/<token>
    
  Run capability check:
    python jarwis_agent.py --check
    
  Run setup with recommendations:
    python jarwis_agent.py --setup

Supported Scan Types:
  - Web Application Security (OWASP Top 10, API, Auth)
  - Mobile Security (Static & Dynamic Analysis)
  - Network Security (Port Scanning, Vuln Assessment)
  - Cloud Security (AWS, Azure, GCP, Kubernetes)
  - SAST (Static Application Security Testing)
        """
    )
    
    parser.add_argument(
        "--server", "-s",
        help="Jarwis server WebSocket URL (wss://...)"
    )
    parser.add_argument(
        "--token", "-t",
        help="Authentication token (if not in server URL)"
    )
    parser.add_argument(
        "--agent-id",
        help="Custom agent ID (auto-generated if not provided)"
    )
    parser.add_argument(
        "--agent-name",
        help="Custom agent name (hostname used if not provided)"
    )
    parser.add_argument(
        "--data-dir",
        help="Data directory for agent files (default: ~/.jarwis/agent)"
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run interactive setup and capability check"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check capabilities only"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    print_banner()
    setup_logging(args.verbose)
    
    # Check only
    if args.check:
        caps = await check_prerequisites()
        print("\n📊 Agent Capabilities Summary")
        print("=" * 60)
        
        scan_types = caps.get("scan_types", [])
        print(f"\nSupported scan types: {len(scan_types)}")
        for st in scan_types:
            print(f"  ✓ {st}")
        
        if not scan_types:
            print("  ⚠️  Run --setup for recommendations")
            return 1
        
        print("\n✅ Agent is ready!")
        return 0
    
    # Run setup
    if args.setup:
        await run_setup()
        return 0
    
    # Validate server URL
    if not args.server:
        print("\n❌ Error: --server URL is required")
        print("   Get your connection URL from: https://jarwis.io/agent/setup")
        print("\n   Or run setup first: python jarwis_agent.py --setup")
        return 1
    
    # Extract token from URL if needed
    token = args.token
    if not token and "/ws/" in args.server:
        token = args.server.split("/ws/")[-1]
    
    # Create config
    config = AgentConfig(
        server_url=args.server,
        auth_token=token,
        agent_id=args.agent_id or "",
        agent_name=args.agent_name or "",
        data_dir=args.data_dir or ""
    )
    
    # Check capabilities
    caps = await check_prerequisites()
    scan_types = caps.get("scan_types", [])
    
    if not scan_types:
        print("\n⚠️  No scan types available!")
        print("   Run --setup to see what's missing")
    else:
        print(f"\n✅ Available scan types: {', '.join(scan_types)}")
    
    # Create and run agent
    print(f"\n🚀 Starting Jarwis Universal Agent...")
    print(f"   Server: {args.server.split('/ws/')[0]}/ws/***")
    print(f"   Agent ID: {config.agent_id}")
    print(f"   Agent Name: {config.agent_name}")
    print()
    
    agent = UniversalJarwisAgent(config=config)
    
    try:
        # Connect to server
        connected = await agent.connect()
        if not connected:
            print("\n❌ Failed to connect to server")
            print("   Check your token and server URL")
            return 1
        
        print("✅ Connected to Jarwis server!")
        print("   Waiting for scan commands...\n")
        print("   Press Ctrl+C to stop\n")
        
        # Run main loop
        await agent.run_forever()
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Shutting down agent...")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1
    finally:
        await agent.disconnect()
    
    print("👋 Agent stopped")
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(1)
