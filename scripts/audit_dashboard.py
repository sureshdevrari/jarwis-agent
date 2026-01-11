#!/usr/bin/env python3
"""Comprehensive Jarwis Dashboard API Audit"""
import requests
import json
from rich.console import Console
from rich.table import Table

console = Console()

BASE_URL = "http://localhost:8000"

def login(email, password):
    """Login and get token"""
    r = requests.post(f"{BASE_URL}/api/auth/login", json={"email": email, "password": password})
    if r.status_code == 200:
        return r.json().get("access_token")
    return None

def test_endpoint(path, headers, method="GET"):
    """Test an endpoint and return result"""
    try:
        if method == "GET":
            r = requests.get(f"{BASE_URL}{path}", headers=headers, timeout=10)
        else:
            r = requests.post(f"{BASE_URL}{path}", headers=headers, timeout=10)
        
        return r.status_code, r.json() if r.status_code < 500 else r.text
    except Exception as e:
        return 0, str(e)

def main():
    console.print("\n[bold cyan]═══ JARWIS DASHBOARD API AUDIT ═══[/]\n")
    
    # Test with user2
    token = login("user2@jarwis.ai", "12341234")
    if not token:
        console.print("[red]Failed to login![/]")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    console.print(f"[green]✓ Logged in as user2@jarwis.ai[/]\n")
    
    # Create results table
    table = Table(title="API Endpoints Status")
    table.add_column("Endpoint", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Details")
    
    # Test endpoints
    endpoints = [
        ("/api/health", False, "System health check"),
        ("/api/auth/me", True, "User profile"),
        ("/api/dashboard/overview?days=30", True, "Dashboard overview"),
        ("/api/dashboard/scan-stats?days=30", True, "Scan statistics"),
        ("/api/dashboard/security-score?days=30", True, "Security score"),
        ("/api/scans/all", True, "Scan history (web)"),
        ("/api/vulnerabilities", True, "All vulnerabilities"),
        ("/api/scan/mobile/", True, "Mobile scans"),
        ("/api/network/scans", True, "Network scans"),
        ("/api/scan/cloud/", True, "Cloud scans"),
        ("/api/payments/history", True, "Payment history"),
        ("/api/payments/cards", True, "Saved cards"),
        ("/api/users/me/subscription", True, "Subscription info"),
    ]
    
    all_ok = True
    for path, needs_auth, desc in endpoints:
        h = headers if needs_auth else {}
        status, data = test_endpoint(path, h)
        
        if status == 200:
            # Extract key info
            if isinstance(data, dict):
                if "scans" in data:
                    info = f"{len(data['scans'])} scans"
                elif "vulnerabilities" in data:
                    info = f"{len(data['vulnerabilities'])} vulnerabilities"
                elif "email" in data:
                    info = f"User: {data['email']}, Plan: {data.get('subscription_plan', 'N/A')}"
                elif "total_scans" in data:
                    info = f"total={data['total_scans']}, active={data['active_scans']}"
                elif "status" in data:
                    info = data["status"]
                else:
                    info = "OK"
            else:
                info = "OK"
            table.add_row(path, "[green]✓ 200[/]", info)
        else:
            all_ok = False
            error_msg = data.get("detail", str(data)) if isinstance(data, dict) else str(data)[:50]
            table.add_row(path, f"[red]✗ {status}[/]", error_msg)
    
    console.print(table)
    
    # Now check specific data
    console.print("\n[bold yellow]═══ DETAILED DATA VERIFICATION ═══[/]\n")
    
    # Get scans
    status, scans_data = test_endpoint("/api/scans/all", headers)
    if status == 200 and "scans" in scans_data:
        console.print(f"[cyan]Total Scans: {len(scans_data['scans'])}[/]")
        
        # Show first 5 scans with details
        for i, scan in enumerate(scans_data['scans'][:5]):
            scan_id = scan.get('id', scan.get('scan_id', 'N/A'))[:8]
            target = scan.get('target_url', scan.get('target', 'N/A'))
            status = scan.get('status', 'N/A')
            findings = scan.get('findings_count', scan.get('total_findings', 0))
            
            console.print(f"  [{i+1}] {scan_id}... | {target} | {status} | {findings} findings")
    
    # Get vulnerabilities from fixed endpoint
    status, vuln_data = test_endpoint("/api/vulnerabilities", headers)
    if status == 200:
        vulns = vuln_data.get('vulnerabilities', [])
        summary = vuln_data.get('summary', {})
        console.print(f"\n[cyan]Total Vulnerabilities: {summary.get('total', len(vulns))}[/]")
        
        # Show severity breakdown from summary
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = summary.get(sev, 0)
            if count > 0:
                color = {'critical': 'red', 'high': 'orange3', 'medium': 'yellow', 'low': 'blue', 'info': 'grey70'}.get(sev, 'white')
                console.print(f"  • {sev.upper()}: [{color}]{count}[/]")
    
    # Dashboard stats
    status, stats_data = test_endpoint("/api/dashboard/overview?days=30", headers)
    if status == 200 and stats_data.get('success'):
        data = stats_data.get('data', {})
        scan_stats = data.get('scan_stats', {})
        security = data.get('security_score', {})
        console.print(f"\n[cyan]Dashboard Overview:[/]")
        console.print(f"  • Total Scans: {scan_stats.get('total', 'N/A')}")
        console.print(f"  • Completed: {scan_stats.get('completed', 'N/A')}")
        console.print(f"  • Security Score: {security.get('score', 'N/A')}/100 (Grade: {security.get('grade', 'N/A')})")
        console.print(f"  • Total Vulnerabilities: {security.get('total_vulnerabilities', 'N/A')}")
    
    console.print("\n" + "="*50 + "\n")
    if all_ok:
        console.print("[bold green]✓ ALL ENDPOINTS WORKING[/]")
    else:
        console.print("[bold red]✗ SOME ENDPOINTS FAILED[/]")

if __name__ == "__main__":
    main()
