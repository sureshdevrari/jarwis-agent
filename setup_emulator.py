"""
Jarwis Emulator Setup Script
Easy-to-use script to download and configure Android emulator for mobile security testing
"""

import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

console = Console()


def print_banner():
    banner = """
    +==============================================================+
    |                                                              |
    |     [BOT] JARWIS Android Emulator Setup                        |
    |                                                              |
    |     Automated setup for mobile security testing:            |
    |     * Android SDK & Emulator                                |
    |     * Frida Server for SSL Bypass                           |
    |     * MITM Proxy Certificate                                |
    |                                                              |
    +==============================================================+
    """
    console.print(banner, style="cyan")


async def main():
    print_banner()
    
    # Import after path setup
    from attacks.mobile.emulator_manager import EmulatorManager, EmulatorConfig
    
    manager = EmulatorManager()
    status = manager.get_status()
    
    # Show current status
    console.print("\n[CHART] [bold]Current Status:[/bold]")
    console.print(f"  SDK Installed: {'[OK]' if status['sdk_installed'] else '[X]'}")
    console.print(f"  Emulator Installed: {'[OK]' if status['emulator_installed'] else '[X]'}")
    console.print(f"  Platform Tools (ADB): {'[OK]' if status['platform_tools_installed'] else '[X]'}")
    console.print(f"  Emulator Running: {'[OK]' if status['running'] else '[X]'}")
    console.print(f"  Frida Installed: {'[OK]' if status['frida_installed'] else '[X]'}")
    console.print()
    
    # Menu
    console.print("[bold]Choose an option:[/bold]")
    console.print("  1. Full Setup (Download & Configure Everything)")
    console.print("  2. Download Android SDK Only")
    console.print("  3. Install SDK Components (Emulator, Platform Tools)")
    console.print("  4. Create Virtual Device (AVD)")
    console.print("  5. Start Emulator")
    console.print("  6. Install Frida Server")
    console.print("  7. Install CA Certificate")
    console.print("  8. Configure Proxy")
    console.print("  9. Stop Emulator")
    console.print("  10. Install APK")
    console.print("  0. Exit")
    console.print()
    
    choice = Prompt.ask("Select option", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"], default="1")
    
    if choice == "0":
        console.print("Goodbye! 👋", style="cyan")
        return
    
    elif choice == "1":
        # Full setup
        headless = Confirm.ask("Run emulator in headless mode (no GUI)?", default=False)
        
        config = EmulatorConfig(
            name="jarwis_test_device",
            api_level="android-33",
            headless=headless,
            ram_mb=4096
        )
        
        console.print("\n[bold cyan]Starting full emulator setup...[/bold cyan]")
        console.print("[dim]This may take 10-30 minutes depending on your internet speed.[/dim]\n")
        
        success = await manager.full_setup(config)
        
        if success:
            console.print(Panel(
                "[bold green][OK] Emulator Setup Complete![/bold green]\n\n"
                "Your emulator is ready for mobile security testing.\n"
                "* Frida SSL bypass is enabled\n"
                "* MITM proxy certificate installed\n"
                "* Proxy configured for traffic interception\n\n"
                "You can now run mobile scans with live traffic capture!",
                title="Success"
            ))
    
    elif choice == "2":
        console.print("\n[cyan]Downloading Android SDK...[/cyan]")
        await manager.download_sdk()
    
    elif choice == "3":
        console.print("\n[cyan]Installing SDK components...[/cyan]")
        await manager.install_sdk_components()
    
    elif choice == "4":
        name = Prompt.ask("AVD name", default="jarwis_test_device")
        api_level = Prompt.ask("API level", choices=["android-30", "android-31", "android-33", "android-34"], default="android-33")
        ram = Prompt.ask("RAM (MB)", default="4096")
        
        config = EmulatorConfig(name=name, api_level=api_level, ram_mb=int(ram))
        await manager.create_avd(config)
    
    elif choice == "5":
        headless = Confirm.ask("Run in headless mode?", default=False)
        await manager.start_emulator(headless=headless)
    
    elif choice == "6":
        if not status['running']:
            console.print("[yellow][!] Emulator not running. Starting emulator first...[/yellow]")
            await manager.start_emulator()
        await manager.install_frida_server()
        await manager.start_frida_server()
    
    elif choice == "7":
        ca_path = Prompt.ask("CA certificate path (leave empty for default)", default="")
        await manager.install_ca_certificate(ca_path if ca_path else None)
    
    elif choice == "8":
        host = Prompt.ask("Proxy host", default="10.0.2.2")
        port = Prompt.ask("Proxy port", default="8080")
        await manager.configure_proxy(host, int(port))
    
    elif choice == "9":
        await manager.stop_emulator()
    
    elif choice == "10":
        apk_path = Prompt.ask("APK file path")
        if os.path.exists(apk_path):
            await manager.install_apk(apk_path)
        else:
            console.print(f"[red][X] File not found: {apk_path}[/red]")
    
    # Show final status
    console.print("\n[CHART] [bold]Final Status:[/bold]")
    final_status = manager.get_status()
    console.print(f"  Emulator Running: {'[OK] ' + final_status['device_id'] if final_status['running'] else '[X]'}")
    console.print(f"  Frida Installed: {'[OK]' if final_status['frida_installed'] else '[X]'}")
    console.print(f"  Proxy Configured: {'[OK]' if final_status['proxy_configured'] else '[X]'}")
    console.print(f"  CA Installed: {'[OK]' if final_status['ca_installed'] else '[X]'}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Setup interrupted[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise
