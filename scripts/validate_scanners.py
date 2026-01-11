#!/usr/bin/env python3
"""
Scanner Validation Script

Pre-deployment check to validate all scanners are properly configured.
Run this before deploying to catch import errors early.

Usage:
    python scripts/validate_scanners.py
    python scripts/validate_scanners.py --verbose
    python scripts/validate_scanners.py --scan-type web
    python scripts/validate_scanners.py --json
    python scripts/validate_scanners.py --discover   # Show all individual attack scanners
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def print_colored(text: str, color: str = "white"):
    """Print with ANSI colors"""
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "white": "\033[97m",
        "reset": "\033[0m"
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")


def validate_scanners(verbose: bool = False, scan_type: str = None, as_json: bool = False):
    """
    Validate all registered scanners.
    
    Args:
        verbose: Show detailed information
        scan_type: Only check specific scan type (web, mobile, network, cloud)
        as_json: Output as JSON
    """
    try:
        from attacks.unified_registry import scanner_registry, ScanType, ScannerStatus
    except ImportError as e:
        if as_json:
            print(json.dumps({"error": f"Failed to import unified registry: {e}"}))
        else:
            print_colored(f"❌ Failed to import unified registry: {e}", "red")
        return 1
    
    # Validate all scanners (this is now sync)
    results = scanner_registry.validate_all()
    summary = scanner_registry.get_health_summary()
    
    # Filter by scan type if specified
    if scan_type:
        try:
            scan_type_enum = ScanType(scan_type)
            results = {k: v for k, v in results.items() if k == scan_type}
        except ValueError:
            if as_json:
                print(json.dumps({"error": f"Invalid scan type: {scan_type}"}))
            else:
                print_colored(f"❌ Invalid scan type: {scan_type}. Valid options: web, mobile, network, cloud", "red")
            return 1
    
    # JSON output
    if as_json:
        # Convert ScannerHealthResult objects to dicts for JSON serialization
        json_results = {}
        for st, scanner_list in results.items():
            json_results[st] = [
                {
                    "scanner_name": r.scanner_name,
                    "status": r.status.value,
                    "message": r.message,
                    "module_path": r.module_path,
                    "class_name": r.class_name,
                    "fallback_used": r.fallback_used,
                    "error_details": r.error_details
                }
                for r in scanner_list
            ]
        output = {
            "summary": summary,
            "results": json_results
        }
        print(json.dumps(output, indent=2, default=str))
        return 0 if summary.get("unavailable_count", 0) == 0 else 1
    
    # Pretty output
    print_colored("\n" + "=" * 60, "blue")
    print_colored("  JARWIS SCANNER VALIDATION REPORT", "blue")
    print_colored("=" * 60 + "\n", "blue")
    
    # Summary
    print_colored(f"📊 SUMMARY:", "white")
    print_colored(f"   Total Scanners: {summary.get('total_scanners', 0)}", "white")
    print_colored(f"   ✅ Healthy:      {summary.get('healthy_count', 0)}", "green")
    if summary.get("degraded_count", 0) > 0:
        print_colored(f"   ⚠️  Degraded:     {summary.get('degraded_count', 0)}", "yellow")
    if summary.get("unavailable_count", 0) > 0:
        print_colored(f"   ❌ Unavailable:  {summary.get('unavailable_count', 0)}", "red")
    print()
    
    # Detailed results by scan type
    for scan_type_name, scanner_results in results.items():
        # Determine scan type status
        healthy_count = sum(1 for r in scanner_results if r.status == ScannerStatus.HEALTHY)
        degraded_count = sum(1 for r in scanner_results if r.status == ScannerStatus.DEGRADED)
        unavailable_count = sum(1 for r in scanner_results if r.status == ScannerStatus.UNAVAILABLE)
        
        # Status color and icon
        if unavailable_count > 0:
            color = "red"
            icon = "❌"
        elif degraded_count > 0:
            color = "yellow"
            icon = "⚠️"
        else:
            color = "green"
            icon = "✅"
        
        print_colored(f"{icon} {scan_type_name.upper()} ({healthy_count}/{len(scanner_results)} scanners)", color)
        
        if verbose:
            for result in scanner_results:
                scanner_status = result.status
                
                if scanner_status == ScannerStatus.HEALTHY:
                    print_colored(f"   ├─ ✓ {result.scanner_name}: {result.message}", "green")
                elif scanner_status == ScannerStatus.DEGRADED:
                    print_colored(f"   ├─ ⚠ {result.scanner_name}: {result.message}", "yellow")
                else:
                    print_colored(f"   ├─ ✗ {result.scanner_name}: {result.message}", "red")
        print()
    
    # Exit code
    if summary.get("unavailable_count", 0) > 0:
        print_colored("❌ VALIDATION FAILED: Some required scanners are unavailable!", "red")
        return 1
    elif summary.get("degraded_count", 0) > 0:
        print_colored("⚠️  VALIDATION WARNING: Some optional scanners are degraded", "yellow")
        return 0  # Still pass, just warn
    else:
        print_colored("✅ VALIDATION PASSED: All scanners healthy!", "green")
        return 0


def check_dependencies():
    """Check if required dependencies are installed"""
    missing = []
    
    dependencies = [
        ("aiohttp", "aiohttp"),
        ("playwright", "playwright"),
        ("frida", "frida-tools"),
        ("androguard", "androguard"),
        ("nmap", "python-nmap"),
    ]
    
    print_colored("\n📦 DEPENDENCY CHECK:", "blue")
    
    for module_name, pip_name in dependencies:
        try:
            __import__(module_name)
            print_colored(f"   ✓ {module_name}", "green")
        except ImportError:
            print_colored(f"   ✗ {module_name} (install: pip install {pip_name})", "yellow")
            missing.append(pip_name)
    
    if missing:
        print_colored(f"\n   Missing packages: pip install {' '.join(missing)}", "yellow")
    
    print()
    return missing


def discover_all_attack_scanners(as_json: bool = False):
    """
    Discover and validate ALL individual attack scanners.
    Uses the scanner_registry auto-discovery system.
    """
    try:
        from attacks.scanner_registry import discover_all_scanners, get_registry
    except ImportError as e:
        if as_json:
            print(json.dumps({"error": f"Failed to import scanner_registry: {e}"}))
        else:
            print_colored(f"❌ Failed to import scanner_registry: {e}", "red")
        return 1
    
    # Discover all scanners
    total = discover_all_scanners()
    registry = get_registry()
    all_scanners = registry.get_all_scanners()
    
    # Group by module path (pre_login, post_login, mobile, network, cloud)
    by_category = {}
    for name, metadata in all_scanners.items():
        # Extract category from module path
        parts = metadata.module_name.split(".")
        if len(parts) >= 2:
            category = parts[1]  # attacks.pre_login.xxx -> pre_login
        else:
            category = "unknown"
        
        if category not in by_category:
            by_category[category] = []
        by_category[category].append(metadata)
    
    if as_json:
        output = {
            "total": total,
            "by_category": {
                cat: [{"name": m.name, "category": m.category, "description": m.description} 
                      for m in scanners]
                for cat, scanners in by_category.items()
            }
        }
        print(json.dumps(output, indent=2))
        return 0
    
    # Pretty output
    print_colored("\n" + "=" * 60, "blue")
    print_colored("  JARWIS ATTACK SCANNER DISCOVERY", "blue")
    print_colored("=" * 60 + "\n", "blue")
    
    print_colored(f"📊 TOTAL ATTACK SCANNERS: {total}\n", "white")
    
    category_labels = {
        "pre_login": "🔓 PRE-LOGIN SCANNERS (Unauthenticated)",
        "post_login": "🔐 POST-LOGIN SCANNERS (Authenticated)",
        "mobile": "📱 MOBILE SCANNERS",
        "network": "🌐 NETWORK SCANNERS",
        "cloud": "☁️  CLOUD SCANNERS"
    }
    
    for category in ["pre_login", "post_login", "mobile", "network", "cloud"]:
        scanners = by_category.get(category, [])
        label = category_labels.get(category, category.upper())
        print_colored(f"{label}: {len(scanners)} scanners", "blue")
        
        # Group by OWASP category
        owasp_groups = {}
        for scanner in scanners:
            owasp = scanner.category
            if owasp not in owasp_groups:
                owasp_groups[owasp] = []
            owasp_groups[owasp].append(scanner.name)
        
        for owasp, names in sorted(owasp_groups.items()):
            print_colored(f"   {owasp}: {', '.join(sorted(names)[:5])}", "white")
            if len(names) > 5:
                print_colored(f"         ... and {len(names) - 5} more", "white")
        print()
    
    print_colored(f"✅ Successfully discovered {total} attack scanners!", "green")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Validate Jarwis scanner configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scripts/validate_scanners.py              # Basic validation
    python scripts/validate_scanners.py --verbose    # Show all scanners
    python scripts/validate_scanners.py --scan-type web  # Only check web
    python scripts/validate_scanners.py --json       # JSON output for CI
    python scripts/validate_scanners.py --check-deps # Also check pip packages
    python scripts/validate_scanners.py --discover   # Show all attack scanners
        """
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed scanner information"
    )
    
    parser.add_argument(
        "-t", "--scan-type",
        choices=["web", "mobile", "network", "cloud"],
        help="Only validate specific scan type"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON (for CI/CD pipelines)"
    )
    
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="Also check Python dependencies"
    )
    
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Discover and list all individual attack scanners"
    )
    
    args = parser.parse_args()
    
    # Check dependencies if requested
    if args.check_deps and not args.json:
        check_dependencies()
    
    # Discover all attack scanners if requested
    if args.discover:
        exit_code = discover_all_attack_scanners(as_json=args.json)
        sys.exit(exit_code)
    
    # Run orchestrator validation
    exit_code = validate_scanners(
        verbose=args.verbose,
        scan_type=args.scan_type,
        as_json=args.json
    )
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
