#!/usr/bin/env python3
"""
Jarwis AGI - Mobile Penetration Testing CLI
Command-line interface for Android and iOS application security testing

Usage:
    python run_mobile_scan.py --apk /path/to/app.apk
    python run_mobile_scan.py --ipa /path/to/app.ipa --bypass-ssl
    python run_mobile_scan.py --apk app.apk --auth email@example.com:password
"""

import os
import sys
import json
import asyncio
import argparse
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.live import Live
from rich.layout import Layout

console = Console()


def print_banner():
    """Print Jarwis mobile scanner banner"""
    banner = """
    +==================================================================+
    |                                                                  |
    |     [AI] Jarwis AGI Mobile Penetration Testing                   |
    |                                                                  |
    |     Full Android & iOS Security Assessment                       |
    |     * Frida SSL Pinning Bypass                                   |
    |     * Emulator/Simulator Integration                             |
    |     * Burp-Style Traffic Interception                            |
    |     * OWASP Mobile Top 10 Coverage                               |
    |                                                                  |
    +==================================================================+
    """
    console.print(banner, style="cyan")


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        description="Jarwis AGI Mobile Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic Android scan:
    python run_mobile_scan.py --apk app.apk

  iOS scan with SSL bypass:
    python run_mobile_scan.py --ipa app.ipa --bypass-ssl

  Full scan with authentication:
    python run_mobile_scan.py --apk app.apk --auth user@email.com:password

  Headless emulator mode:
    python run_mobile_scan.py --apk app.apk --headless --bypass-ssl

  Quick static analysis only:
    python run_mobile_scan.py --apk app.apk --static-only
        """
    )
    
    # Required arguments
    app_group = parser.add_mutually_exclusive_group(required=True)
    app_group.add_argument('--apk', metavar='PATH', help='Path to Android APK file')
    app_group.add_argument('--ipa', metavar='PATH', help='Path to iOS IPA file')
    app_group.add_argument('--app', metavar='PATH', help='Path to APK or IPA file')
    
    # SSL Pinning options
    ssl_group = parser.add_argument_group('SSL Pinning Bypass')
    ssl_group.add_argument('--bypass-ssl', action='store_true', default=True,
                          help='Enable Frida SSL pinning bypass (default: True)')
    ssl_group.add_argument('--no-ssl-bypass', action='store_true',
                          help='Disable SSL pinning bypass')
    
    # Device options
    device_group = parser.add_argument_group('Device/Emulator')
    device_group.add_argument('--device', metavar='ID', help='Target device ID (from adb devices)')
    device_group.add_argument('--use-emulator', action='store_true', default=True,
                             help='Use Android emulator if no device connected')
    device_group.add_argument('--headless', action='store_true',
                             help='Run emulator in headless mode (no GUI)')
    device_group.add_argument('--no-emulator', action='store_true',
                             help='Do not use emulator, require physical device')
    
    # Authentication options
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('--auth', metavar='USER:PASS',
                           help='Credentials as username:password')
    auth_group.add_argument('--auth-type', choices=['email_password', 'phone_otp', 'social'],
                           default='email_password', help='Authentication type')
    auth_group.add_argument('--phone', metavar='NUMBER',
                           help='Phone number for OTP authentication')
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('--static-only', action='store_true',
                           help='Perform static analysis only (no runtime)')
    scan_group.add_argument('--no-crawl', action='store_true',
                           help='Skip app crawling phase')
    scan_group.add_argument('--crawl-duration', type=int, default=120, metavar='SEC',
                           help='Duration for app crawling in seconds (default: 120)')
    scan_group.add_argument('--attacks', nargs='+', metavar='M1-M10',
                           help='Specific OWASP Mobile categories to test')
    scan_group.add_argument('--no-attacks', action='store_true',
                           help='Skip attack scanning phase')
    
    # AI options
    ai_group = parser.add_argument_group('AI Analysis')
    ai_group.add_argument('--ai-analysis', action='store_true', default=True,
                         help='Enable AI-powered security analysis')
    ai_group.add_argument('--no-ai', action='store_true',
                         help='Disable AI analysis')
    
    # Traffic options
    traffic_group = parser.add_argument_group('Traffic Interception')
    traffic_group.add_argument('--mitm', action='store_true', default=True,
                              help='Enable MITM proxy for traffic capture')
    traffic_group.add_argument('--mitm-port', type=int, default=8080, metavar='PORT',
                              help='MITM proxy port (default: 8080)')
    traffic_group.add_argument('--export-traffic', metavar='PATH',
                              help='Export captured traffic to file (HAR/JSON/XML)')
    
    # Output options
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('--output', '-o', metavar='DIR', default='reports/mobile',
                             help='Output directory for reports')
    output_group.add_argument('--format', choices=['html', 'json', 'sarif', 'all'],
                             default='all', help='Report format (default: all)')
    output_group.add_argument('--no-report', action='store_true',
                             help='Skip report generation')
    output_group.add_argument('--quiet', '-q', action='store_true',
                             help='Minimal output')
    output_group.add_argument('--verbose', '-v', action='store_true',
                             help='Verbose output')
    
    return parser


def validate_args(args: argparse.Namespace) -> bool:
    """Validate command-line arguments"""
    # Determine app path
    app_path = args.apk or args.ipa or args.app
    
    if not os.path.exists(app_path):
        console.print(f"[red]Error: File not found: {app_path}[/red]")
        return False
    
    # Validate file extension
    ext = Path(app_path).suffix.lower()
    if ext not in ['.apk', '.ipa', '.app']:
        console.print(f"[red]Error: Invalid file type '{ext}'. Expected .apk or .ipa[/red]")
        return False
    
    # iOS on non-macOS
    if ext in ['.ipa', '.app']:
        import platform
        if platform.system() != 'Darwin':
            console.print("[yellow]Warning: iOS testing requires macOS with Xcode[/yellow]")
    
    return True


async def run_scan(args: argparse.Namespace):
    """Run the mobile security scan"""
    from attacks.mobile.mobile_orchestrator import MobilePenTestOrchestrator, MobileScanConfig
    from attacks.mobile.burp_interceptor import BurpStyleInterceptor
    
    # Determine app path
    app_path = args.apk or args.ipa or args.app
    
    # Build configuration
    config = MobileScanConfig(
        app_path=app_path,
        frida_bypass_enabled=args.bypass_ssl and not args.no_ssl_bypass,
        use_emulator=args.use_emulator and not args.no_emulator,
        headless=args.headless,
        device_id=args.device or "",
        mitm_enabled=args.mitm,
        mitm_port=args.mitm_port,
        crawl_enabled=not args.no_crawl and not args.static_only,
        crawl_duration=args.crawl_duration,
        attacks_enabled=not args.no_attacks and not args.static_only,
        ai_analysis=args.ai_analysis and not args.no_ai,
        output_dir=args.output,
        generate_report=not args.no_report
    )
    
    # Handle authentication
    if args.auth:
        if ':' in args.auth:
            username, password = args.auth.split(':', 1)
            config.auth_enabled = True
            config.auth_type = args.auth_type
            config.username = username
            config.password = password
        else:
            console.print("[yellow]Warning: Auth format should be username:password[/yellow]")
    
    if args.phone:
        config.auth_enabled = True
        config.auth_type = 'phone_otp'
        config.phone = args.phone
    
    # Handle attack categories
    if args.attacks:
        config.attack_categories = args.attacks
    
    # Create orchestrator
    orchestrator = MobilePenTestOrchestrator(config)
    
    # Setup callbacks
    current_phase = ["init"]
    current_progress = [0]
    
    def log_callback(log_type: str, message: str, details: str = None):
        if args.quiet:
            return
        
        style_map = {
            'phase': 'bold cyan',
            'info': 'dim',
            'success': 'green',
            'warning': 'yellow',
            'error': 'red',
            'start': 'bold magenta',
            'complete': 'bold green',
            'request': 'dim blue'
        }
        
        style = style_map.get(log_type, 'white')
        
        if log_type == 'phase':
            console.print(f"\n[{style}]{message}[/{style}]")
        elif log_type in ['success', 'complete']:
            console.print(f"  [{style}]{message}[/{style}]")
        elif log_type == 'error':
            console.print(f"  [{style}][X] {message}[/{style}]")
        elif args.verbose or log_type not in ['detail', 'request']:
            console.print(f"  [{style}]{message}[/{style}]")
    
    def progress_callback(phase: str, progress: int, message: str):
        current_phase[0] = phase
        current_progress[0] = progress
    
    # Create traffic interceptor
    interceptor = BurpStyleInterceptor()
    
    def traffic_callback(entry):
        if args.verbose:
            console.print(f"    [dim blue]-> {entry['method']} {entry['url'][:80]}[/dim blue]")
    
    orchestrator.set_log_callback(log_callback)
    orchestrator.set_progress_callback(progress_callback)
    orchestrator.set_traffic_callback(traffic_callback)
    
    # Show scan info
    if not args.quiet:
        console.print(Panel.fit(
            f"[bold]Target:[/bold] {Path(app_path).name}\n"
            f"[bold]Platform:[/bold] {orchestrator.context.platform.upper()}\n"
            f"[bold]SSL Bypass:[/bold] {'Enabled' if config.frida_bypass_enabled else 'Disabled'}\n"
            f"[bold]Crawling:[/bold] {'Enabled' if config.crawl_enabled else 'Disabled'}\n"
            f"[bold]AI Analysis:[/bold] {'Enabled' if config.ai_analysis else 'Disabled'}",
            title="Scan Configuration"
        ))
    
    # Run scan
    try:
        result = await orchestrator.run()
        
        # Export traffic if requested
        if args.export_traffic and interceptor.history:
            export_path = Path(args.export_traffic)
            
            if export_path.suffix == '.har':
                content = json.dumps(interceptor.export_har(), indent=2)
            elif export_path.suffix == '.xml':
                content = interceptor.export_burp_xml()
            else:
                content = interceptor.export_json()
            
            with open(export_path, 'w') as f:
                f.write(content)
            
            console.print(f"\n[green]Traffic exported to: {export_path}[/green]")
        
        # Display summary
        display_results(result, args)
        
        return result
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        return None
    except Exception as e:
        console.print(f"\n[red]Scan failed: {e}[/red]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        return None


def display_results(result: dict, args: argparse.Namespace):
    """Display scan results summary"""
    if args.quiet:
        summary = result.get('summary', {})
        console.print(f"Vulnerabilities: {summary.get('total_vulnerabilities', 0)} "
                     f"(C:{summary.get('critical', 0)} H:{summary.get('high', 0)} "
                     f"M:{summary.get('medium', 0)} L:{summary.get('low', 0)})")
        return
    
    summary = result.get('summary', {})
    
    # Summary table
    table = Table(title="\n[DOC] Scan Results Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")
    
    table.add_row("Status", f"[green]{result.get('status', 'unknown')}[/green]")
    table.add_row("Duration", f"{result.get('duration_seconds', 0):.1f}s")
    table.add_row("Endpoints Discovered", str(summary.get('total_endpoints', 0)))
    table.add_row("Total Vulnerabilities", str(summary.get('total_vulnerabilities', 0)))
    table.add_row("  -> Critical", f"[red]{summary.get('critical', 0)}[/red]")
    table.add_row("  -> High", f"[yellow]{summary.get('high', 0)}[/yellow]")
    table.add_row("  -> Medium", f"[blue]{summary.get('medium', 0)}[/blue]")
    table.add_row("  -> Low", f"[dim]{summary.get('low', 0)}[/dim]")
    
    console.print(table)
    
    # Top vulnerabilities
    vulnerabilities = result.get('vulnerabilities', [])
    if vulnerabilities:
        console.print("\n[bold cyan][WARN] Top Vulnerabilities:[/bold cyan]")
        
        sorted_vulns = sorted(vulnerabilities, 
                             key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(
                                 x.get('severity', 'info').lower()) 
                             if x.get('severity', 'info').lower() in ['critical', 'high', 'medium', 'low', 'info'] 
                             else 4)
        
        for vuln in sorted_vulns[:10]:
            severity = vuln.get('severity', 'info').upper()
            color = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'blue', 'LOW': 'dim'}.get(severity, 'white')
            console.print(f"  [{color}][{severity}][/{color}] {vuln.get('title', 'Unknown')}")
    
    # Report path
    if result.get('report_path'):
        console.print(f"\n[green][REPORT] Report saved: {result['report_path']}[/green]")


def check_dependencies():
    """Check and display dependency status"""
    deps = {
        'frida': 'Frida (SSL bypass)',
        'adb': 'Android Debug Bridge',
        'aapt': 'Android Asset Packaging Tool',
        'mitmproxy': 'MITM Proxy'
    }
    
    status = {}
    
    # Check Python packages
    try:
        import frida
        status['frida'] = True
    except ImportError:
        status['frida'] = False
    
    # Check CLI tools
    import shutil
    status['adb'] = shutil.which('adb') is not None
    status['aapt'] = shutil.which('aapt') is not None
    status['mitmproxy'] = shutil.which('mitmproxy') is not None or shutil.which('mitmdump') is not None
    
    # Display status
    console.print("\n[bold]Dependency Status:[/bold]")
    for key, name in deps.items():
        icon = "[OK]" if status.get(key) else "[X]"
        color = "green" if status.get(key) else "red"
        console.print(f"  {icon} [{color}]{name}[/{color}]")
    
    missing = [name for key, name in deps.items() if not status.get(key)]
    if missing:
        console.print(f"\n[yellow]Some optional dependencies are missing. "
                     f"Install them for full functionality.[/yellow]")
    
    return all(status.values())


def main():
    """Main entry point"""
    print_banner()
    
    parser = create_parser()
    args = parser.parse_args()
    
    # Validate arguments
    if not validate_args(args):
        sys.exit(1)
    
    # Check dependencies on first run
    if args.verbose:
        check_dependencies()
    
    # Run scan
    try:
        result = asyncio.run(run_scan(args))
        
        if result and result.get('status') == 'completed':
            sys.exit(0)
        else:
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
