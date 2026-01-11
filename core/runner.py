"""
Jarwis AGI Pen Test - Main Orchestrator
Coordinates all scanning phases and attack modules
"""

import asyncio
import yaml
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .browser import BrowserController
from .proxy import ProxyInterceptor
from .ai_planner import AIPlanner
from .reporters import ReportGenerator

console = Console()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Represents a single vulnerability finding"""
    id: str
    category: str  # OWASP category (A01, A02, etc.)
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    url: str
    method: str
    parameter: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: str = ""
    poc: str = ""  # Proof of Concept - the exact payload/request used
    reasoning: str = ""  # Why Jarwis detected this as a vulnerability
    request_data: str = ""  # Full request details
    response_snippet: str = ""  # Relevant response snippet
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanContext:
    """Maintains state across scanning phases"""
    target_url: str
    endpoints: List[Dict] = field(default_factory=list)
    cookies: Dict = field(default_factory=dict)
    headers: Dict = field(default_factory=dict)
    findings: List[ScanResult] = field(default_factory=list)
    authenticated: bool = False
    api_endpoints: List[Dict] = field(default_factory=list)
    upload_endpoints: List[Dict] = field(default_factory=list)
    requests: List[Dict] = field(default_factory=list)  # Track HTTP requests for UI
    
    def __post_init__(self):
        """Initialize scope manager for strict domain checking"""
        from .scope import ScopeManager
        self._scope_manager = ScopeManager(self.target_url)
        logger.info(f"Scope set to: {self._scope_manager.get_domain_for_subscription()}")
    
    def is_in_scope(self, url: str) -> bool:
        """Check if URL is within target scope (strict domain matching)"""
        return self._scope_manager.is_in_scope(url)
    
    def get_target_domain(self) -> str:
        """Get the normalized target domain for subscription counting"""
        return self._scope_manager.get_domain_for_subscription()


class PenTestRunner:
    """Main orchestrator for the AI-powered penetration test"""
    
    def __init__(self, config, scan_id: str = None):
        """
        Initialize the runner with configuration.
        
        Args:
            config: Either a path to config file (str) or a config dictionary
            scan_id: Optional scan ID for OTP coordination (2FA handling)
        """
        if isinstance(config, str):
            self.config = self._load_config_file(config)
        elif isinstance(config, dict):
            self.config = self._normalize_config(config)
        else:
            raise ValueError("Config must be a file path or dictionary")
        
        self.scan_id = scan_id  # Store scan ID for 2FA coordination
        self.context = ScanContext(target_url=self.config['target']['url'])
        self.browser: Optional[BrowserController] = None
        self.proxy: Optional[ProxyInterceptor] = None
        self.ai_planner: Optional[AIPlanner] = None
        self.reporter: Optional[ReportGenerator] = None
        
    def _load_config_file(self, config_path: str) -> Dict:
        """Load and validate configuration from file"""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(f"Configuration loaded from {config_path}")
        return self._normalize_config(config)
    
    def _normalize_config(self, config: Dict) -> Dict:
        """Normalize config to ensure all required fields exist with defaults"""
        # Set defaults for any missing values
        defaults = {
            'target': {'url': '', 'scope': ''},
            'proxy': {'host': '127.0.0.1', 'port': 8080},
            'auth': {
                'enabled': False,
                'type': 'form',
                'login_url': '/login',
                'credentials': {'username': '', 'password': ''},
                'selectors': {
                    'username_field': 'input[name="username"], input[name="email"]',
                    'password_field': 'input[name="password"]',
                    'submit_button': 'button[type="submit"]',
                    'success_indicator': '/dashboard'
                }
            },
            'scan': {
                'rate_limit': 10,
                'timeout': 30,
                'modules': ['injection', 'xss', 'misconfig', 'sensitive_data']
            },
            'attacks': {
                'rate_limit': 10,
                'timeout': 30,
                'enabled': {
                    'injection': True,
                    'xss': True,
                    'sensitive_data': True,
                    'misconfig': True,
                    'upload': True,
                    'api': True
                }
            },
            'ai': {
                'enabled': False,
                'provider': 'gemini',
                'model': 'gemini-2.5-flash'
            },
            'browser': {
                'headless': False,  # Set True for headless mode (API), False for visible browser
                'slow_mo': 300
            },
            'api': {
                'swagger_paths': ['/swagger.json', '/api-docs', '/openapi.json'],
                'graphql_paths': ['/graphql', '/api/graphql']
            },
            'reporting': {
                'output_dir': './reports',
                'format': ['html', 'json']
            },
            'output': {
                'directory': './reports',
                'formats': ['html', 'json']
            }
        }
        
        # Deep merge defaults with provided config
        def deep_merge(default, override):
            result = default.copy()
            for key, value in override.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = deep_merge(result[key], value)
                else:
                    result[key] = value
            return result
        
        normalized = deep_merge(defaults, config)
        
        # Map 'output' to 'reporting' for compatibility
        if 'output' in config:
            normalized['reporting'] = {
                'output_dir': config['output'].get('directory', './reports'),
                'format': config['output'].get('formats', ['html', 'json'])
            }
        
        # Map scan modules to attack enabled flags
        if 'scan' in config and 'modules' in config['scan']:
            for module in config['scan']['modules']:
                normalized['attacks']['enabled'][module] = True
        
        return normalized
    
    async def initialize(self):
        """Initialize all components"""
        console.print("[bold blue]Initializing Jarwis Security Testing by BKD Labs...[/bold blue]")
        
        # Check if MITM proxy is enabled for HTTPS interception
        mitm_enabled = self.config.get('proxy', {}).get('mitm', {}).get('enabled', False)
        
        # Only use proxy settings when MITM is enabled
        if mitm_enabled:
            proxy_host = self.config.get('proxy', {}).get('host', '127.0.0.1')
            proxy_port = self.config.get('proxy', {}).get('mitm', {}).get('port', 8080)
        else:
            # No proxy - direct connection
            proxy_host = ""
            proxy_port = 0
        
        # Initialize proxy interceptor (disabled when no proxy)
        self.proxy = ProxyInterceptor(
            host=proxy_host,
            port=proxy_port
        )
        await self.proxy.start()
        
        # Initialize browser with optional MITM proxy for HTTPS interception
        headless_mode = self.config.get('browser', {}).get('headless', False)
        self.browser = BrowserController(
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            use_mitm=mitm_enabled,
            headless=headless_mode
        )
        
        if mitm_enabled:
            console.print("[cyan][!]   MITM proxy enabled for HTTPS interception[/cyan]")
            await self.browser.start(enable_mitm_https=True)
        else:
            console.print("[cyan][OK]  Direct connection mode (no proxy)[/cyan]")
            await self.browser.start()
        
        # Set scan context for 2FA handling
        two_factor_config = self.config.get('auth', {}).get('two_factor')
        if self.scan_id:
            self.browser.set_scan_context(self.scan_id, two_factor_config)
            if two_factor_config and two_factor_config.get('enabled'):
                console.print(f"[cyan][OK]  2FA handling enabled: {two_factor_config.get('type', 'unknown')}[/cyan]")
        
        # Initialize Jarwis Human Intelligence engine
        self.ai_planner = AIPlanner(
            provider=self.config['ai']['provider'],
            model=self.config['ai']['model'],
            api_key=self.config['ai'].get('api_key'),
            base_url=self.config['ai'].get('base_url')
        )
        
        # Set verbose callback on Jarwis planner if we have one
        if hasattr(self, '_verbose_callback') and self._verbose_callback:
            AIPlanner.set_verbose_callback(self._verbose_callback)
        
        # Initialize reporter
        self.reporter = ReportGenerator(
            output_dir=self.config['reporting']['output_dir'],
            formats=self.config['reporting']['format']
        )
        
        console.print("[bold green][OK]  All components initialized[/bold green]")
    
    async def phase_0_website_analysis(self):
        """Phase 0: Jarwis Human Intelligence - Analyze website type and business context"""
        console.print("\n[bold magenta]Phase 0: Jarwis Website Intelligence Analysis[/bold magenta]")
        console.print("[cyan][OK]  Jarwis is using human intelligence to understand the website...[/cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Jarwis analyzing website...", total=None)
            
            # Get initial page content for analysis
            try:
                page = self.browser.page
                await page.goto(self.config['target']['url'], wait_until='domcontentloaded', timeout=30000)
                html_content = await page.content()
                page_title = await page.title()
                
                # Get all links on the page for initial analysis
                links = await page.evaluate('''() => {
                    return Array.from(document.querySelectorAll('a[href]')).map(a => a.href).slice(0, 50);
                }''')
                
                progress.update(task, description="Jarwis analyzing source code and content patterns...")
                
                # Use Jarwis intelligence to analyze the website
                self.website_analysis = await self.ai_planner.analyze_website(
                    html_content=html_content,
                    url=self.config['target']['url'],
                    page_title=page_title,
                    discovered_links=links
                )
                
                progress.update(task, description="[green]Website analysis complete!")
                
            except Exception as e:
                logger.error(f"Website analysis failed: {e}")
                self.website_analysis = {
                    "business_type": "unknown",
                    "website_purpose": "Unable to analyze website",
                    "detected_features": {},
                    "risk_areas": ["General web application security"],
                    "recommended_focus": ["OWASP Top 10 testing"]
                }
        
        # Display analysis results
        console.print("\n[bold cyan][OK]  Jarwis Website Analysis Results:[/bold cyan]")
        console.print(f"  [yellow]Business Type:[/yellow] {self.website_analysis.get('business_type', 'Unknown')}")
        console.print(f"  [yellow]Purpose:[/yellow] {self.website_analysis.get('website_purpose', 'Unknown')}")
        
        features = self.website_analysis.get('detected_features', {})
        detected = []
        if features.get('has_login'): detected.append("Login Page")
        if features.get('has_signup'): detected.append("Signup/Registration")
        if features.get('has_forgot_password'): detected.append("Forgot Password")
        if features.get('has_payment'): detected.append("Payment/Checkout")
        if features.get('has_user_profiles'): detected.append("User Profiles")
        if features.get('has_file_upload'): detected.append("File Upload")
        if features.get('has_api'): detected.append("API Endpoints")
        if features.get('has_admin_panel'): detected.append("Admin Panel")
        
        if detected:
            console.print(f"  [yellow]Detected Features:[/yellow] {', '.join(detected)}")
        
        risk_areas = self.website_analysis.get('risk_areas', [])
        if risk_areas:
            console.print(f"  [yellow]Risk Areas:[/yellow] {', '.join(risk_areas[:5])}")
        
        if self.website_analysis.get('human_observation'):
            console.print(f"  [yellow]Jarwis Observation:[/yellow] {self.website_analysis.get('human_observation')[:200]}")
        
        console.print("[bold green][OK]  Jarwis has completed website intelligence analysis[/bold green]")
    
    async def phase_1_crawl_anonymous(self):
        """Phase 1: Crawl target anonymously and discover endpoints"""
        console.print("\n[bold yellow]Phase 1: Jarwis Reconnaissance - Endpoint Discovery[/bold yellow]")
        console.print("[cyan][OK]  Jarwis is crawling the website to discover all attack surfaces...[/cyan]")
        
        # Display scope information
        target_domain = self.context.get_target_domain()
        console.print(f"[bold cyan][OK]  Scope: {target_domain} (strict domain matching - subdomains excluded)[/bold cyan]")
        console.print("[dim]Note: Each subdomain counts as a separate subscription token[/dim]")
        
        # Enable AI request watcher for analyzing traffic
        if self.config.get('ai', {}).get('request_analysis', True):
            console.print("[dim][OK]  AI traffic analysis enabled - watching request/response patterns[/dim]")
            self.browser.enable_ai_watcher(self.config)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Jarwis discovering endpoints...", total=None)
            
            # Crawl the target using BFS tree method
            discovered = await self.browser.crawl(
                self.config['target']['url'],
                max_depth=5,
                scope=self.config['target']['scope'],
                max_pages=200
            )
            
            self.context.endpoints = discovered['endpoints']
            self.context.upload_endpoints = discovered.get('upload_endpoints', [])
            self.context.api_endpoints = discovered.get('api_endpoints', [])
            
            # Capture HTTP requests for UI tracking
            captured_traffic = self.browser.get_captured_traffic()
            self.context.requests = [
                {'url': t.get('url', ''), 'method': t.get('method', 'GET'), 'status': t.get('status', 200)}
                for t in captured_traffic if t.get('type') == 'response'
            ][:500]  # Limit to last 500 requests
            
            # Get AI findings from traffic analysis
            ai_findings = self.browser.get_ai_findings()
            if ai_findings:
                console.print(f"[cyan][OK]  AI detected {len(ai_findings)} potential issues during crawling[/cyan]")
                for finding in ai_findings:
                    console.print(f"  [dim][OK]  {finding.get('type', 'Unknown')}: {finding.get('url', '')[:60]}[/dim]")
            
            progress.update(task, description="[green]Reconnaissance complete!")
        
        # Display discovered endpoints
        table = Table(title="Discovered Endpoints")
        table.add_column("Method", style="cyan")
        table.add_column("URL", style="green")
        table.add_column("Type", style="yellow")
        
        for ep in self.context.endpoints[:20]:  # Show first 20
            table.add_row(ep['method'], ep['url'], ep.get('type', 'page'))
        
        console.print(table)
        console.print(f"[bold]Total endpoints discovered: {len(self.context.endpoints)}[/bold]")
        console.print("[bold green][OK]  Jarwis reconnaissance phase complete[/bold green]")
    
    async def phase_1b_scan_planning(self):
        """Phase 1b: Jarwis Human Intelligence - Generate scan plan"""
        console.print("\n[bold magenta]Phase 1b: Jarwis Attack Strategy Planning[/bold magenta]")
        console.print("[cyan][OK]  Jarwis is formulating the penetration testing strategy...[/cyan]")
        
        # Get website analysis if not done
        website_analysis = getattr(self, 'website_analysis', {})
        
        # Generate scan plan using Jarwis intelligence
        self.scan_plan = await self.ai_planner.generate_scan_plan(
            website_analysis=website_analysis,
            endpoints=self.context.endpoints
        )
        
        # Display the scan plan like a human would
        console.print("\n[bold cyan][OK]  Jarwis Penetration Testing Strategy:[/bold cyan]")
        console.print(f"\n[white]{self.scan_plan.get('executive_overview', 'Comprehensive security assessment')}[/white]\n")
        
        phases = self.scan_plan.get('phases', [])
        for phase in phases:
            console.print(f"[yellow]Phase {phase.get('phase_number', '?')}:[/yellow] [bold]{phase.get('phase_name', 'Unknown')}[/bold]")
            console.print(f"  [dim]{phase.get('description', '')}[/dim]")
            targets = phase.get('targets', [])
            if targets:
                console.print(f"  [cyan]Targets:[/cyan] {', '.join(targets[:3])}")
        
        priority_attacks = self.scan_plan.get('priority_attacks', [])
        if priority_attacks:
            console.print(f"\n[red][OK]  Priority Attack Vectors:[/red]")
            for attack in priority_attacks[:5]:
                console.print(f"  [OK]  {attack}")
        
        if self.scan_plan.get('human_strategy'):
            console.print(f"\n[magenta][OK]  Jarwis Strategy:[/magenta] {self.scan_plan.get('human_strategy')[:300]}")
        
        console.print("\n[bold green][OK]  Jarwis has prepared the attack strategy[/bold green]")
    
    async def phase_2_prelogin_scan(self):
        """Phase 2: Run OWASP Top 10 attacks on anonymous endpoints"""
        console.print("\n[bold yellow]Phase 2: Jarwis Pre-Login OWASP Top 10 Scan[/bold yellow]")
        console.print("[cyan][!]   Jarwis is executing security tests on unauthenticated surfaces...[/cyan]")
        console.print("[dim][OK]  JavaScript rendering enabled for modern web app testing[/dim]")
        
        from attacks.web.pre_login import PreLoginAttacks
        from core.ai_verifier import AIVerifier
        
        # Pass browser controller for JavaScript rendering support
        attacker = PreLoginAttacks(
            config=self.config['attacks'],
            context=self.context,
            browser_controller=self.browser
        )
        
        findings = await attacker.run_all()
        
        # AI-powered vulnerability verification
        if self.config.get('ai', {}).get('verify_findings', True):
            console.print("[cyan][OK]  Jarwis AGI is verifying findings to reduce false positives...[/cyan]")
            verifier = AIVerifier(self.config)
            
            if verifier.is_available:
                verified_findings = []
                for finding in findings:
                    finding_dict = finding.__dict__ if hasattr(finding, '__dict__') else finding
                    result = await verifier.verify_finding(finding_dict)
                    
                    if result.is_verified:
                        # Update finding with verification info
                        if hasattr(finding, 'reasoning'):
                            finding.reasoning += f"\n\n[AI Verified: {result.confidence:.0%} confidence] {result.reasoning}"
                        verified_findings.append(finding)
                        
                        # Adjust severity if recommended
                        if result.severity_adjustment == "upgrade" and hasattr(finding, 'severity'):
                            severity_order = ['info', 'low', 'medium', 'high', 'critical']
                            current_idx = severity_order.index(finding.severity) if finding.severity in severity_order else 2
                            if current_idx < len(severity_order) - 1:
                                finding.severity = severity_order[current_idx + 1]
                        elif result.severity_adjustment == "downgrade" and hasattr(finding, 'severity'):
                            severity_order = ['info', 'low', 'medium', 'high', 'critical']
                            current_idx = severity_order.index(finding.severity) if finding.severity in severity_order else 2
                            if current_idx > 0:
                                finding.severity = severity_order[current_idx - 1]
                    else:
                        console.print(f"[dim]  [OK]  Filtered false positive: {finding_dict.get('title', 'Unknown')}[/dim]")
                
                console.print(f"[dim]  Verified {len(verified_findings)}/{len(findings)} findings[/dim]")
                findings = verified_findings
            else:
                console.print("[dim]  AI verification unavailable, keeping all findings[/dim]")
        
        self.context.findings.extend(findings)
        
        console.print(f"[bold green][OK]  Jarwis pre-login scan complete. Findings: {len(findings)}[/bold green]")
    
    async def phase_3_authenticate(self):
        """Phase 3: Authenticate to the target with retry logic"""
        if not self.config['auth']['enabled']:
            console.print("[yellow]Authentication disabled, skipping...[/yellow]")
            return
            
        console.print("\n[bold yellow]Phase 3: Jarwis Authentication Testing[/bold yellow]")
        console.print("[cyan][OK]  Jarwis is attempting to authenticate to the target...[/cyan]")
        
        auth_config = self.config['auth']
        login_url = auth_config.get('login_url', '/login')
        
        # Build full login URL
        if not login_url.startswith('http'):
            login_url = self.config['target']['url'].rstrip('/') + '/' + login_url.lstrip('/')
        
        # Get selectors (support both nested and flat formats)
        selectors = auth_config.get('selectors', {})
        credentials = auth_config.get('credentials', {})
        
        # Fallback for flat auth config from interactive mode
        if not credentials.get('username') and auth_config.get('username'):
            credentials = {
                'username': auth_config.get('username', ''),
                'password': auth_config.get('password', '')
            }
        
        if not selectors.get('username_field') and auth_config.get('username_selector'):
            selectors = {
                'username_field': auth_config.get('username_selector', 'input[name="username"]'),
                'password_field': auth_config.get('password_selector', 'input[name="password"]'),
                'submit_button': auth_config.get('submit_selector', 'button[type="submit"]'),
                'success_indicator': auth_config.get('success_indicator', '/dashboard')
            }
        
        success_indicator = selectors.get('success_indicator', auth_config.get('success_indicator', '/dashboard'))
        
        # Retry authentication up to 3 times
        max_retries = 3
        success = False
        
        for attempt in range(1, max_retries + 1):
            console.print(f"[cyan]Authentication attempt {attempt}/{max_retries}...[/cyan]")
            
            success = await self.browser.authenticate(
                login_url=login_url,
                credentials=credentials,
                selectors=selectors,
                success_indicator=success_indicator
            )
            
            if success:
                break
            else:
                if attempt < max_retries:
                    console.print(f"[yellow]Attempt {attempt} failed, retrying...[/yellow]")
                    await asyncio.sleep(2)
        
        if success:
            self.context.authenticated = True
            self.context.cookies = await self.browser.get_cookies()
            self.context.headers = await self.browser.get_auth_headers()
            console.print("[bold green][OK]  Authentication successful[/bold green]")
        else:
            console.print("[bold red][OK]  Authentication failed after all retries[/bold red]")
    
    async def phase_4_crawl_authenticated(self):
        """Phase 4: Re-crawl with authentication"""
        if not self.context.authenticated:
            return
            
        console.print("\n[bold yellow]Phase 4: Jarwis Authenticated Reconnaissance[/bold yellow]")
        console.print("[cyan][OK]  Jarwis is discovering authenticated endpoints using BFS tree crawl...[/cyan]")
        
        # Re-crawl with authentication using BFS tree method
        discovered = await self.browser.crawl(
            self.config['target']['url'],
            max_depth=5,
            scope=self.config['target']['scope'],
            authenticated=True,
            max_pages=200
        )
        
        # Merge new endpoints
        existing_urls = {ep['url'] for ep in self.context.endpoints}
        for ep in discovered['endpoints']:
            if ep['url'] not in existing_urls:
                ep['requires_auth'] = True
                self.context.endpoints.append(ep)
        
        console.print(f"[bold green][OK]  New authenticated endpoints: {len(discovered['endpoints'])}[/bold green]")
    
    async def phase_5_postlogin_scan(self):
        """Phase 5: Run ALL attacks (pre-login + post-login specific) with authentication
        
        This runs ALL 48+ pre-login scanners AGAIN with authenticated context,
        plus post-login specific attacks (IDOR, CSRF, privilege escalation).
        """
        if not self.context.authenticated:
            return
            
        console.print("\n[bold yellow]Phase 5: Jarwis Post-Login Security Scan[/bold yellow]")
        console.print("[cyan][!]   Jarwis is testing authenticated attack surfaces...[/cyan]")
        console.print("[dim][!]   Running ALL scanners with authenticated session for complete coverage[/dim]")
        
        # ========== Run ALL pre-login scanners with auth context ==========
        console.print("\n[cyan]Re-running all OWASP scanners with authentication...[/cyan]")
        from attacks.web.pre_login import PreLoginAttacks
        
        # Pass authenticated cookies and headers to pre-login attacks
        # This allows them to test authenticated-only pages
        pre_login_attacker = PreLoginAttacks(
            config=self.config['attacks'],
            context=self.context,  # Context has auth cookies/headers
            browser_controller=self.browser
        )
        
        # Filter to only test authenticated endpoints (discovered in phase 4)
        auth_endpoints = [ep for ep in self.context.endpoints if ep.get('requires_auth', False)]
        if auth_endpoints:
            console.print(f"[cyan][!]   Testing {len(auth_endpoints)} authenticated endpoints with all scanners...[/cyan]")
            # Temporarily replace endpoints with auth-only ones for targeted testing
            original_endpoints = self.context.endpoints
            self.context.endpoints = auth_endpoints
            
            auth_findings = await pre_login_attacker.run_all()
            
            # Mark these findings as discovered in authenticated context
            for finding in auth_findings:
                if hasattr(finding, 'reasoning'):
                    finding.reasoning = "[AUTHENTICATED] " + (finding.reasoning or "")
                if hasattr(finding, 'description'):
                    finding.description = "[Found in authenticated session] " + finding.description
            
            self.context.findings.extend(auth_findings)
            console.print(f"[green][!]   Authenticated scanner findings: {len(auth_findings)}[/green]")
            
            # Restore all endpoints
            self.context.endpoints = original_endpoints
        
        # ========== Run post-login specific attacks (IDOR, CSRF, PrivEsc) ==========
        console.print("\n[cyan]Running post-login specific attacks (IDOR, CSRF, Privilege Escalation)...[/cyan]")
        from attacks.web.post_login import PostLoginAttacks
        
        attacker = PostLoginAttacks(
            config=self.config['attacks'],
            context=self.context,
            cookies=self.context.cookies,
            headers=self.context.headers
        )
        
        findings = await attacker.run_all()
        self.context.findings.extend(findings)
        
        total_post_login = len(auth_findings) + len(findings) if auth_endpoints else len(findings)
        console.print(f"[bold green][OK]  Jarwis post-login scan complete. Total Findings: {total_post_login}[/bold green]")
    
    async def phase_6_api_testing(self):
        """Phase 6: API-specific testing"""
        console.print("\n[bold yellow]Phase 6: Jarwis API Security Testing[/bold yellow]")
        console.print("[cyan][OK]  Jarwis is scanning API endpoints for vulnerabilities...[/cyan]")
        
        from attacks.web.pre_login.api_scanner import APIScanner
        
        api_scanner = APIScanner(
            config=self.config['api'],
            context=self.context
        )
        
        findings = await api_scanner.run()
        self.context.findings.extend(findings)
        
        console.print(f"[bold green][OK]  Jarwis API scan complete. Findings: {len(findings)}[/bold green]")
    
    async def phase_7_ai_guided_testing(self):
        """Phase 7: Jarwis Human Intelligence guided testing for advanced scenarios"""
        console.print("\n[bold yellow]Phase 7: Jarwis Human Intelligence Advanced Testing[/bold yellow]")
        console.print("[cyan][OK]  Jarwis is using human intelligence to find advanced vulnerabilities...[/cyan]")
        
        max_iterations = 10
        for i in range(max_iterations):
            # Get Jarwis recommendation
            next_test = await self.ai_planner.get_next_test(
                endpoints=self.context.endpoints,
                findings=self.context.findings,
                completed_tests=[]
            )
            
            if not next_test:
                console.print("[green]Jarwis: Comprehensive testing complete - no more high-value targets[/green]")
                break
            
            console.print(f"[cyan]Jarwis recommends: {next_test['tool']} on {next_test['target']}[/cyan]")
            
            # Execute the recommended test
            result = await self._execute_ai_test(next_test)
            if result:
                self.context.findings.append(result)
        
        console.print("[bold green][OK]  Jarwis-guided testing complete[/bold green]")
    
    async def _execute_ai_test(self, test: Dict) -> Optional[ScanResult]:
        """Execute a test recommended by the AI planner"""
        # This would dispatch to the appropriate attack module
        # Implementation depends on the test type
        return None
    
    async def phase_8_ai_verification(self):
        """Phase 8: Jarwis Human Intelligence verification to reduce false positives"""
        console.print("\n[bold yellow]Phase 8: Jarwis Human Intelligence Verification[/bold yellow]")
        console.print("[cyan][OK]  Jarwis is using human intelligence to verify findings and eliminate false positives...[/cyan]")
        
        if not self.context.findings:
            console.print("[yellow]No findings to verify[/yellow]")
            return
        
        console.print(f"[cyan]Jarwis is analyzing {len(self.context.findings)} findings with human intelligence...[/cyan]")
        
        # Batch verify all findings
        verified_results = await self.ai_planner.batch_verify_findings(self.context.findings)
        
        # Filter and update findings based on AI verification
        valid_findings = []
        removed_count = 0
        adjusted_count = 0
        
        for result in verified_results:
            verification = result['verification']
            finding = result['finding']
            
            is_valid = verification.get('is_valid', True)
            confidence = verification.get('confidence', 0.5)
            adjusted_severity = verification.get('adjusted_severity', getattr(finding, 'severity', 'medium'))
            reasoning = verification.get('reasoning', '')
            
            if is_valid and confidence >= 0.4:  # Accept if confidence >= 40%
                # Update finding with Jarwis verification data
                if hasattr(finding, 'reasoning'):
                    finding.reasoning = f"JARWIS VERIFIED ({confidence*100:.0f}% confidence): {reasoning}"
                if hasattr(finding, 'severity') and adjusted_severity != finding.severity:
                    old_sev = finding.severity
                    finding.severity = adjusted_severity
                    adjusted_count += 1
                    logger.info(f"Adjusted severity: {getattr(finding, 'title', 'Finding')} {old_sev} -> {adjusted_severity}")
                
                valid_findings.append(finding)
            else:
                removed_count += 1
                logger.info(f"Removed false positive: {getattr(finding, 'title', 'Finding')} (confidence: {confidence*100:.0f}%)")
        
        # Update context with verified findings
        self.context.findings = valid_findings
        
        console.print(f"[green][OK]  Verification complete:[/green]")
        console.print(f"  [OK]  Valid findings: {len(valid_findings)}")
        console.print(f"  [OK]  Removed false positives: {removed_count}")
        console.print(f"  [OK]  Severity adjustments: {adjusted_count}")
        
        # Store verified results for report generation
        self._verified_results = verified_results
    
    async def phase_9_ai_correlation(self):
        """Phase 9: Jarwis Human Intelligence attack chain correlation"""
        console.print("\n[bold yellow]Phase 9: Jarwis Attack Chain Intelligence[/bold yellow]")
        console.print("[cyan][!]   Jarwis is correlating vulnerabilities to identify attack chains...[/cyan]")
        
        if len(self.context.findings) < 2:
            console.print("[yellow]Not enough findings for correlation analysis[/yellow]")
            return
        
        # Convert findings to dicts for correlation
        findings_dicts = []
        for f in self.context.findings[:20]:  # Limit for performance
            findings_dicts.append({
                'id': getattr(f, 'id', ''),
                'title': getattr(f, 'title', ''),
                'category': getattr(f, 'category', ''),
                'severity': getattr(f, 'severity', ''),
                'url': getattr(f, 'url', ''),
            })
        
        attack_chains = await self.ai_planner.correlate_findings(findings_dicts)
        
        if attack_chains:
            console.print(f"[green][OK]  Jarwis found {len(attack_chains)} potential attack chains[/green]")
            for chain in attack_chains[:3]:
                console.print(f"  [OK]  {chain.get('chain_name', 'Unknown')}: {chain.get('combined_impact', 'N/A')}")
            self._attack_chains = attack_chains
        else:
            console.print("[yellow]No attack chain correlations found[/yellow]")
            self._attack_chains = []
    
    async def phase_10_generate_report(self):
        """Phase 10: Generate final Jarwis intelligence-enhanced report"""
        console.print("\n[bold yellow]Phase 10: Jarwis Report Generation[/bold yellow]")
        console.print("[cyan][OK]  Jarwis is generating comprehensive security reports...[/cyan]")
        
        # Generate executive summary using Jarwis Human Intelligence
        executive_summary = ""
        if hasattr(self, '_verified_results'):
            console.print("[cyan]Jarwis is writing the executive summary with human intelligence...[/cyan]")
            executive_summary = await self.ai_planner.generate_executive_summary(
                self.context.findings,
                self._verified_results
            )
        
        # Get traffic log from browser if available
        traffic_log = []
        if self.browser:
            traffic_log = self.browser.get_captured_traffic()
            console.print(f"[cyan]Captured {len(traffic_log)} request/response entries[/cyan]")
            
            # Include MITM HTTPS traffic if enabled
            if self.browser.is_mitm_enabled():
                mitm_traffic = self.browser.get_mitm_traffic()
                console.print(f"[cyan][!]   MITM HTTPS traffic captured: {len(mitm_traffic)} requests intercepted[/cyan]")
        
        report_paths = []
        try:
            report_paths = await self.reporter.generate(
                findings=self.context.findings,
                context=self.context,
                config=self.config,
                traffic_log=traffic_log,
                executive_summary=executive_summary,
                attack_chains=getattr(self, '_attack_chains', [])
            )
            
            console.print("\n[bold green]" + "=" * 50 + "[/bold green]")
            console.print("[bold green]                    REPORTS GENERATED                        [/bold green]")
            console.print("[bold green]" + "=" * 50 + "[/bold green]")
            for path in report_paths:
                # Convert to absolute path for clarity
                abs_path = Path(path).resolve()
                console.print(f"[bold cyan][OK]  {abs_path}[/bold cyan]")
            
            console.print("[bold green]" + "=" * 50 + "[/bold green]\n")
            
        except Exception as e:
            console.print(f"[bold red][OK]  Report generation failed: {e}[/bold red]")
            logger.error(f"Report generation error: {e}")
        
        return report_paths
        
        # Summary table
        self._print_summary()
    
    def _print_summary(self):
        """Print scan summary"""
        table = Table(title="Scan Summary")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in self.context.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        colors = {'critical': 'red', 'high': 'orange3', 'medium': 'yellow', 'low': 'blue', 'info': 'white'}
        for severity, count in severity_counts.items():
            table.add_row(f"[{colors[severity]}]{severity.upper()}[/{colors[severity]}]", str(count))
        
        console.print(table)
    
    async def cleanup(self):
        """Clean up resources"""
        if self.browser:
            # Save traffic log before stopping
            try:
                output_dir = self.config['reporting'].get('output_dir', './reports')
                self.browser.save_traffic_log(output_dir, "traffic_log.json")
                console.print(f"[green]Traffic log saved to {output_dir}/traffic_log.json[/green]")
            except Exception as e:
                logger.error(f"Failed to save traffic log: {e}")
            await self.browser.stop()
        if self.proxy:
            await self.proxy.stop()
        console.print("[bold blue]Cleanup complete[/bold blue]")
    
    async def run(self, progress_callback=None, verbose_callback=None):
        """Execute the full penetration test with AI verification
        
        Args:
            progress_callback: Optional callback function(phase, progress, message) to report progress
            verbose_callback: Optional callback function(log_type, message, details) for verbose logging
        """
        self._progress_callback = progress_callback
        self._verbose_callback = verbose_callback
        
        def update_progress(phase: str, progress: int, message: str = ""):
            if self._progress_callback:
                try:
                    self._progress_callback(phase, progress, message)
                except:
                    pass
        
        def log_verbose(log_type: str, message: str, details: str = None):
            """Log verbose messages"""
            if self._verbose_callback:
                try:
                    self._verbose_callback(log_type, message, details)
                except:
                    pass
        
        try:
            update_progress("Initializing", 3, "Starting Jarwis...")
            log_verbose("info", "[OK]  Initializing Jarwis Security Testing...")
            await self.initialize()
            log_verbose("success", "[OK]  All Jarwis components initialized")
            
            # Log MITM proxy status
            if self.browser and self.browser.is_mitm_enabled():
                log_verbose("jarwis", "[!]   HTTPS interception enabled via MITM proxy")
                log_verbose("info", "   [OK]  All HTTPS traffic will be captured and analyzed")
            
            # Phase 0: Website Intelligence Analysis (NEW)
            try:
                update_progress("Phase 0: Website Analysis", 5, "Jarwis analyzing website...")
                log_verbose("jarwis", "[OK]  Jarwis is using human intelligence to analyze the website...")
                await self.phase_0_website_analysis()
                website_type = getattr(self, 'website_analysis', {}).get('business_type', 'web application')
                log_verbose("success", f"[OK]  Website identified as: {website_type}")
            except Exception as e:
                logger.error(f"Phase 0 error (continuing): {e}")
                log_verbose("warning", f"[!]   Website analysis had issues, continuing with defaults")
            
            # Phase 1: Reconnaissance
            try:
                update_progress("Phase 1: Reconnaissance", 10, "Jarwis discovering endpoints...")
                log_verbose("jarwis", f"[OK]  Jarwis is scanning {self.config['target']['url']} for attack surfaces...")
                await self.phase_1_crawl_anonymous()
                log_verbose("success", f"[OK]  Reconnaissance complete: {len(self.context.endpoints)} endpoints discovered")
            except Exception as e:
                logger.error(f"Phase 1 error (continuing): {e}")
                log_verbose("warning", f"[!]   Reconnaissance had issues: {str(e)[:100]}")
            
            # Phase 1b: Scan Planning (NEW)
            try:
                update_progress("Phase 1b: Strategy Planning", 15, "Jarwis planning attack strategy...")
                log_verbose("jarwis", "[OK]  Jarwis is formulating the penetration testing strategy...")
                await self.phase_1b_scan_planning()
                log_verbose("success", "[OK]  Attack strategy prepared")
            except Exception as e:
                logger.error(f"Phase 1b error (continuing): {e}")
                log_verbose("warning", f"[!]   Strategy planning had issues, using default strategy")
            
            # Phase 2: Pre-Login Scan
            try:
                update_progress("Phase 2: Pre-Login Scan", 25, "Jarwis testing OWASP Top 10...")
                log_verbose("jarwis", "[!]   Jarwis is executing security tests on unauthenticated surfaces...")
                await self.phase_2_prelogin_scan()
                log_verbose("success", f"[OK]  Pre-login scan complete: {len(self.context.findings)} vulnerabilities found")
            except Exception as e:
                logger.error(f"Phase 2 error (continuing): {e}")
                log_verbose("warning", f"[!]   Pre-login scan had issues: {str(e)[:100]}")
            
            # Phase 3: Authentication
            try:
                update_progress("Phase 3: Authentication", 40, "Jarwis attempting login...")
                if self.config['auth']['enabled']:
                    log_verbose("jarwis", "[OK]  Jarwis is attempting to authenticate...")
                await self.phase_3_authenticate()
                if self.context.authenticated:
                    log_verbose("success", "[OK]  Authentication successful")
            except Exception as e:
                logger.error(f"Phase 3 error (continuing): {e}")
                log_verbose("warning", f"[!]   Authentication had issues: {str(e)[:100]}")
            
            try:
                update_progress("Phase 4: Auth Reconnaissance", 50, "Jarwis discovering authenticated endpoints...")
                log_verbose("jarwis", "[OK]  Jarwis is discovering authenticated endpoints...")
                await self.phase_4_crawl_authenticated()
            except Exception as e:
                logger.error(f"Phase 4 error (continuing): {e}")
                log_verbose("warning", f"[!]   Auth reconnaissance had issues")
            
            try:
                update_progress("Phase 5: Post-Login Scan", 55, "Jarwis testing authenticated surfaces...")
                log_verbose("jarwis", "[!]   Jarwis is testing authenticated attack surfaces...")
                await self.phase_5_postlogin_scan()
            except Exception as e:
                logger.error(f"Phase 5 error (continuing): {e}")
                log_verbose("warning", f"[!]   Post-login scan had issues")
            
            try:
                update_progress("Phase 6: API Testing", 65, "Jarwis scanning API endpoints...")
                log_verbose("jarwis", "[OK]  Jarwis is scanning API endpoints for vulnerabilities...")
                await self.phase_6_api_testing()
            except Exception as e:
                logger.error(f"Phase 6 error (continuing): {e}")
                log_verbose("warning", f"[!]   API testing had issues")
            
            try:
                update_progress("Phase 7: Human Intelligence Testing", 75, "Jarwis advanced analysis...")
                log_verbose("jarwis", "[OK]  Jarwis is using human intelligence for advanced vulnerability discovery...")
                await self.phase_7_ai_guided_testing()
            except Exception as e:
                logger.error(f"Phase 7 error (continuing): {e}")
                log_verbose("warning", f"[!]   Advanced analysis had issues")
            
            try:
                update_progress("Phase 8: Human Intelligence Verification", 85, "Jarwis verifying findings...")
                log_verbose("jarwis", f"[OK]  Jarwis is using human intelligence to verify {len(self.context.findings)} findings...")
                await self.phase_8_ai_verification()
                log_verbose("success", f"[OK]  Jarwis verification complete: {len(self.context.findings)} valid findings")
            except Exception as e:
                logger.error(f"Phase 8 error (continuing): {e}")
                log_verbose("warning", f"[!]   Verification had issues")
            
            try:
                update_progress("Phase 9: Attack Chain Analysis", 90, "Jarwis analyzing attack chains...")
                log_verbose("jarwis", "[!]   Jarwis is correlating vulnerabilities to identify attack chains...")
                await self.phase_9_ai_correlation()
            except Exception as e:
                logger.error(f"Phase 9 error (continuing): {e}")
                log_verbose("warning", f"[!]   Attack chain analysis had issues")
            
            # Phase 10: Reporting - this should always succeed
            update_progress("Phase 10: Reporting", 95, "Jarwis generating reports...")
            log_verbose("jarwis", "[OK]  Jarwis is generating comprehensive security reports...")
            generated_reports = await self.phase_10_generate_report()
            
            update_progress("Complete", 100, "Jarwis scan finished!")
            log_verbose("success", "[OK]  Jarwis penetration test completed successfully!")
            
            # Return results for API - use actual report filename
            report_path = ""
            if generated_reports:
                # Find the HTML report
                html_reports = [r for r in generated_reports if r.endswith('.html')]
                if html_reports:
                    # Return just the filename, not full path
                    report_path = Path(html_reports[0]).name
            
            return {
                'findings': [self._finding_to_dict(f) for f in self.context.findings],
                'summary': {
                    'total_endpoints': len(self.context.endpoints),
                    'total_findings': len(self.context.findings),
                    'authenticated': self.context.authenticated,
                },
                'report_path': report_path
            }
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
        finally:
            # Cleanup browser resources
            try:
                await self.cleanup()
            except Exception as e:
                # Ignore cleanup errors (especially greenlet errors on Windows)
                logger.warning(f"Cleanup error (non-critical): {type(e).__name__}")
    
    def _finding_to_dict(self, finding) -> dict:
        """Convert a ScanResult to dict"""
        if isinstance(finding, dict):
            return finding
        return {
            'id': getattr(finding, 'id', ''),
            'category': getattr(finding, 'category', ''),
            'severity': getattr(finding, 'severity', ''),
            'title': getattr(finding, 'title', ''),
            'description': getattr(finding, 'description', ''),
            'url': getattr(finding, 'url', ''),
            'method': getattr(finding, 'method', ''),
            'parameter': getattr(finding, 'parameter', ''),
            'evidence': getattr(finding, 'evidence', ''),
            'poc': getattr(finding, 'poc', ''),
            'reasoning': getattr(finding, 'reasoning', ''),
        }


def main():
    parser = argparse.ArgumentParser(description="Jarwis AGI Pen Test - OWASP Top 10 Scanner")
    parser.add_argument('--config', '-c', default='config/config.yaml', help='Path to config file')
    parser.add_argument('--phase', '-p', type=int, help='Run specific phase only (1-8)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    runner = PenTestRunner(args.config)
    asyncio.run(runner.run())


if __name__ == "__main__":
    main()
