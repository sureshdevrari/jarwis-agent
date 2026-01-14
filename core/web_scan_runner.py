"""
Jarwis AGI Pen Test - Updated Web Scan Runner
Implements the correct flow:
1. Pre-login crawl with MITM proxy capture
2. Login (if credentials provided)
3. Post-login crawl with MITM proxy capture
4. Run ALL attacks on pre-login requests
5. Run ALL attacks on post-login requests (with token management)
6. Generate report

Features:
- Checkpoint/resume capability for crash recovery
- Partial results saving after each scanner
- Preflight validation before scan starts
- Health monitoring and auto-recovery
"""

import asyncio
import logging
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

from .browser import BrowserController
from .mitm_proxy import JarwisMITMProxy as MITMProxy
from .request_store import RequestStore, CapturedRequest
from .attack_engine import AttackEngine, AttackResult
from .reporters import ReportGenerator

# Import unified executor for running ALL scanners
try:
    from .unified_executor import UnifiedExecutor
    HAS_UNIFIED_EXECUTOR = True
except ImportError:
    HAS_UNIFIED_EXECUTOR = False

# Import checkpoint and recovery systems
try:
    from .scan_checkpoint import ScanCheckpoint, ScanPhase
    from .preflight_validator import PreflightValidator, run_preflight_check
    from .scan_recovery import ScanRecoveryManager, get_global_monitor
    HAS_RESILIENCE = True
except ImportError:
    HAS_RESILIENCE = False

# Import manual auth service for social login / OTP handling
try:
    from services.manual_auth_service import (
        manual_auth_service,
        ManualAuthStatus,
        start_manual_auth_waiting,
        wait_for_manual_auth
    )
    HAS_MANUAL_AUTH_SERVICE = True
except ImportError:
    HAS_MANUAL_AUTH_SERVICE = False

# Import OTP service for 2FA handling
try:
    from services.otp_service import (
        otp_service,
        set_scan_waiting_for_otp,
        wait_for_otp as otp_wait_for_otp,
        set_otp_error,
        clear_scan_otp_state,
        reset_otp_for_retry,
        OTP_TIMEOUT_SECONDS,
        OTP_TIMEOUT_MESSAGE,
        OTP_INVALID_MESSAGE
    )
    HAS_OTP_SERVICE = True
except ImportError:
    HAS_OTP_SERVICE = False

logger = logging.getLogger(__name__)


class WebScanRunner:
    """
    Main orchestrator for web application penetration testing.
    
    Flow:
    ┌─────────────────────────────────────────────────────────────┐
    │  Step 1: Pre-Login Crawl                                    │
    │  - Start MITM proxy                                         │
    │  - Crawl all accessible pages (unauthenticated)             │
    │  - Capture all request/response headers via MITM            │
    │  - Store in RequestStore (pre_login section)                │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Step 2: Login (if credentials provided)                    │
    │  - Use browser to submit login form                         │
    │  - Capture authentication tokens (JWT, session cookies)     │
    │  - Store tokens in RequestStore                             │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Step 3: Post-Login Crawl                                   │
    │  - Crawl pages accessible after authentication              │
    │  - Interact with forms (POST methods) using selectors       │
    │  - Capture all request/response headers via MITM            │
    │  - Store in RequestStore (post_login section)               │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Step 4: Attack Pre-Login Requests                          │
    │  - Run ALL attack modules on pre_login requests             │
    │  - Modify requests, send via MITM, analyze responses        │
    │  - Collect vulnerabilities                                  │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Step 5: Attack Post-Login Requests                         │
    │  - Run ALL attack modules on post_login requests            │
    │  - Same attacks as pre-login + auth-specific tests          │
    │  - Monitor token expiry, refresh if needed                  │
    │  - Test: remove token, invalid token, expired token         │
    │  - Collect vulnerabilities                                  │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Step 6: Generate Report                                    │
    │  - Combine all findings                                     │
    │  - Generate HTML/JSON/SARIF/PDF reports                     │
    │  - Cleanup temporary data                                   │
    └─────────────────────────────────────────────────────────────┘
    """
    
    def __init__(self, config: dict, status_callback=None, resume_from_checkpoint: bool = False):
        """
        Initialize the web scan runner.
        
        Args:
            config: Scan configuration dict
            status_callback: Optional async callback for status updates
                             signature: async def callback(status: str, progress: int, phase: str)
            resume_from_checkpoint: If True, attempt to resume from last checkpoint
        """
        self.config = config
        # Use scan_id from config if provided (for manual auth coordination), else generate new
        self.scan_id = config.get('scan_id') or str(uuid.uuid4())[:8]
        self.start_time = None
        self.end_time = None
        
        # Status callback for notifying API layer
        self.status_callback = status_callback
        
        # Core components
        self.browser: Optional[BrowserController] = None
        self.mitm_proxy: Optional[MITMProxy] = None
        self.request_store: Optional[RequestStore] = None
        self.attack_engine: Optional[AttackEngine] = None
        self.unified_executor: Optional[UnifiedExecutor] = None if HAS_UNIFIED_EXECUTOR else None
        
        # Results
        self.all_results: List[AttackResult] = []
        
        # Login state
        self.is_logged_in = False
        self.login_credentials = config.get('auth', {})
        
        # Resilience: Checkpoint and Recovery
        self.checkpoint: Optional['ScanCheckpoint'] = None
        self.recovery_manager: Optional['ScanRecoveryManager'] = None
        self.resume_from_checkpoint = resume_from_checkpoint
        
        if HAS_RESILIENCE:
            self.checkpoint = ScanCheckpoint(self.scan_id)
            self.recovery_manager = ScanRecoveryManager(self.scan_id, config)
        
        logger.info(f"WebScanRunner initialized. Scan ID: {self.scan_id}")
    
    async def _update_status(self, status: str, progress: int = None, phase: str = None):
        """Update scan status via callback (if set)"""
        if self.status_callback:
            try:
                await self.status_callback(status, progress, phase)
            except Exception as e:
                logger.debug(f"Status callback error: {e}")
    
    def _send_heartbeat(self, phase: str = None, progress: int = None):
        """Send heartbeat to recovery manager"""
        if self.recovery_manager:
            self.recovery_manager.heartbeat(phase, progress)
    
    async def _save_partial_findings(self, findings: List[Any]):
        """Save findings incrementally to checkpoint"""
        if self.checkpoint and findings:
            # Convert to dict format for JSON serialization
            finding_dicts = []
            for f in findings:
                if hasattr(f, '__dict__'):
                    finding_dicts.append(vars(f))
                elif isinstance(f, dict):
                    finding_dicts.append(f)
            
            self.checkpoint.add_findings(finding_dicts)
            logger.debug(f"Saved {len(finding_dicts)} partial findings to checkpoint")
    
    async def run(self) -> Dict[str, Any]:
        """Execute the full scan flow with resilience features"""
        
        self.start_time = datetime.now()
        logger.info(f"Starting web scan: {self.scan_id}")
        
        # Preflight validation
        if HAS_RESILIENCE:
            await self._update_status("Running preflight checks...", 0, "preflight")
            preflight_result = await run_preflight_check(self.config)
            if not preflight_result.passed:
                critical_issues = preflight_result.get_critical_issues()
                error_msg = "; ".join([f"{i.component}: {i.message}" for i in critical_issues])
                logger.error(f"Preflight failed: {error_msg}")
                return {
                    'scan_id': self.scan_id,
                    'status': 'failed',
                    'error': f"Preflight validation failed: {error_msg}",
                    'preflight_issues': [
                        {'component': i.component, 'message': i.message, 'fix': i.fix_suggestion}
                        for i in critical_issues
                    ]
                }
            logger.info("Preflight checks passed")
        
        # Initialize checkpoint
        if self.checkpoint:
            if self.resume_from_checkpoint and self.checkpoint.can_resume():
                logger.info("Resuming from checkpoint...")
                state = self.checkpoint.load()
                if state:
                    # Restore previous findings
                    self.all_results = state.findings
                    logger.info(f"Restored {len(self.all_results)} findings from checkpoint")
            else:
                # Initialize new checkpoint
                target_url = self.config.get('target', {}).get('url', '')
                self.checkpoint.initialize(target_url, self.config)
        
        # Start recovery monitoring
        if self.recovery_manager:
            await self.recovery_manager.start_monitoring()
        
        try:
            # Initialize components
            await self._update_status("running", 10, "Initializing components")
            await self._init_components()
            
            # Step 1: Pre-login crawl
            logger.info("=" * 60)
            logger.info("STEP 1: Pre-Login Crawl")
            logger.info("=" * 60)
            if self.checkpoint:
                self.checkpoint.start_phase("crawl")
            self._send_heartbeat("crawl", 0)
            await self._update_status("running", 15, "Pre-login crawl")
            
            await self._crawl_pre_login()
            
            if self.checkpoint:
                self.checkpoint.complete_phase("crawl", "success")
            self._send_heartbeat("crawl", 100)
            await self._update_status("running", 20, "Crawl complete")
            
            # Step 2: Login (if credentials provided)
            if self._has_credentials():
                logger.info("=" * 60)
                logger.info("STEP 2: Authentication")
                logger.info("=" * 60)
                if self.checkpoint:
                    self.checkpoint.start_phase("authentication")
                self._send_heartbeat("authentication", 0)
                await self._update_status("running", 25, "Authentication")
                
                await self._perform_login()
                
                if self.checkpoint:
                    self.checkpoint.complete_phase("authentication", "success" if self.is_logged_in else "failed")
                self._send_heartbeat("authentication", 100)
                await self._update_status("running", 30, "Authentication complete")
            
            # Step 3: Post-login crawl (if logged in)
            if self.is_logged_in:
                logger.info("=" * 60)
                logger.info("STEP 3: Post-Login Crawl")
                logger.info("=" * 60)
                if self.checkpoint:
                    self.checkpoint.start_phase("post_login_crawl")
                self._send_heartbeat("post_login_crawl", 0)
                await self._update_status("running", 35, "Post-login crawl")
                
                await self._crawl_post_login()
                
                if self.checkpoint:
                    self.checkpoint.complete_phase("post_login_crawl", "success")
                self._send_heartbeat("post_login_crawl", 100)
                await self._update_status("running", 40, "Post-login crawl complete")
            
            # Log captured request statistics
            stats = self.request_store.get_stats()
            logger.info(f"Captured pre-login requests: {stats['pre_login']['total_requests']}")
            logger.info(f"Captured post-login requests: {stats['post_login']['total_requests']}")
            
            # Save endpoints to checkpoint
            if self.checkpoint:
                self.checkpoint.add_endpoints(list(stats.get('unique_urls', [])))
            
            # Ensure traffic log is loaded into RequestStore (backup)
            if self.mitm_proxy:
                traffic_log_path = self.mitm_proxy.get_traffic_log_path()
                loaded = self.request_store.load_from_traffic_log(traffic_log_path, is_post_login=False)
                if loaded > 0:
                    logger.info(f"Loaded {loaded} additional requests from traffic log")
            
            # Step 4: Attack pre-login requests
            logger.info("=" * 60)
            logger.info("STEP 4: Attacking Pre-Login Requests")
            logger.info("=" * 60)
            if self.checkpoint:
                self.checkpoint.start_phase("pre_login_attacks")
            self._send_heartbeat("pre_login_attacks", 0)
            await self._update_status("running", 45, "Running pre-login attacks")
            
            # Run AttackEngine (MITM-based attacks)
            pre_login_results = await self.attack_engine.run_all_attacks(post_login=False)
            await self.attack_engine.finalize()  # Flush any remaining findings
            self.all_results.extend(pre_login_results)
            await self._save_partial_findings(pre_login_results)  # Save incrementally
            logger.info(f"AttackEngine found {len(pre_login_results)} vulnerabilities")
            self._send_heartbeat("pre_login_attacks", 50)
            await self._update_status("running", 55, "Running security scanners")
            
            # Run UnifiedExecutor (ALL scanners) with finding callback for partial saves
            if self.unified_executor:
                logger.info("Running UnifiedExecutor with all registered scanners...")
                # Set up finding callback for partial saves
                self.unified_executor.on_finding_callback = self._save_partial_findings
                
                executor_summary = await self.unified_executor.run(context="pre_login")
                self.all_results.extend(executor_summary.all_findings)
                logger.info(
                    f"UnifiedExecutor: {executor_summary.success}/{executor_summary.total_scanners} scanners succeeded, "
                    f"{executor_summary.total_findings} findings"
                )
            
            if self.checkpoint:
                self.checkpoint.complete_phase("pre_login_attacks", "success")
                self.checkpoint.update_scanner_stats(
                    run=executor_summary.ran if self.unified_executor else 0,
                    failed=executor_summary.failed if self.unified_executor else 0
                )
            self._send_heartbeat("pre_login_attacks", 100)
            await self._update_status("running", 65, "Pre-login attacks complete")
            
            # Step 5: Attack post-login requests
            if self.is_logged_in:
                logger.info("=" * 60)
                logger.info("STEP 5: Attacking Post-Login Requests")
                logger.info("=" * 60)
                if self.checkpoint:
                    self.checkpoint.start_phase("post_login_attacks")
                self._send_heartbeat("post_login_attacks", 0)
                await self._update_status("running", 70, "Running post-login attacks")
                
                # Set token refresh callback
                self.attack_engine.token_refresh_callback = self._refresh_token
                
                # Run AttackEngine (MITM-based attacks)
                post_login_results = await self.attack_engine.run_all_attacks(post_login=True)
                await self.attack_engine.finalize()  # Flush any remaining findings
                self.all_results.extend(post_login_results)
                await self._save_partial_findings(post_login_results)  # Save incrementally
                logger.info(f"AttackEngine found {len(post_login_results)} post-login vulnerabilities")
                self._send_heartbeat("post_login_attacks", 50)
                await self._update_status("running", 80, "Running authenticated scanners")
                
                # Run UnifiedExecutor (ALL scanners) on post-login context
                if self.unified_executor:
                    logger.info("Running UnifiedExecutor on post-login context...")
                    post_executor_summary = await self.unified_executor.run(context="post_login")
                    self.all_results.extend(post_executor_summary.all_findings)
                    logger.info(
                        f"UnifiedExecutor post-login: {post_executor_summary.success}/{post_executor_summary.total_scanners} scanners, "
                        f"{post_executor_summary.total_findings} findings"
                    )
                
                if self.checkpoint:
                    self.checkpoint.complete_phase("post_login_attacks", "success")
                self._send_heartbeat("post_login_attacks", 100)
                await self._update_status("running", 85, "Post-login attacks complete")
            
            # Step 6: Generate report
            logger.info("=" * 60)
            logger.info("STEP 6: Generating Report")
            logger.info("=" * 60)
            if self.checkpoint:
                self.checkpoint.start_phase("reporting")
            self._send_heartbeat("reporting", 0)
            await self._update_status("running", 90, "Generating report")
            
            report = await self._generate_report()
            
            if self.checkpoint:
                self.checkpoint.complete_phase("reporting", "success")
            self._send_heartbeat("reporting", 100)
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            # Mark scan as completed
            if self.checkpoint:
                self.checkpoint.complete_phase("completed", "success")
            
            # Get recovery stats if available
            recovery_stats = None
            if self.recovery_manager:
                recovery_stats = self.recovery_manager.get_summary()
            
            return {
                'scan_id': self.scan_id,
                'status': 'completed',
                'duration_seconds': duration,
                'total_vulnerabilities': len(self.all_results),
                'pre_login_vulns': len([r for r in self.all_results if not getattr(r, 'is_post_login', False)]),
                'post_login_vulns': len([r for r in self.all_results if getattr(r, 'is_post_login', False)]),
                'proxy_enabled': getattr(self, 'proxy_enabled', False),  # Whether MITM proxy was active
                'capture_mode': 'mitm' if getattr(self, 'proxy_enabled', False) else 'browser_only',
                'report': report,
                'stats': stats,
                'recovery_stats': recovery_stats,
                'checkpoint_summary': self.checkpoint.get_summary() if self.checkpoint else None
            }
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            
            # Save error to checkpoint
            if self.checkpoint and hasattr(self.checkpoint, '_state') and self.checkpoint._state:
                current_phase = self.checkpoint._state.current_phase
                self.checkpoint.complete_phase(current_phase, "failed", error_message=str(e))
            
            return {
                'scan_id': self.scan_id,
                'status': 'failed',
                'error': str(e),
                'partial_findings': len(self.all_results),
                'can_resume': self.checkpoint.can_resume() if self.checkpoint else False,
                'checkpoint_summary': self.checkpoint.get_summary() if self.checkpoint else None
            }
            
        finally:
            # Stop recovery monitoring
            if self.recovery_manager:
                self.recovery_manager.stop_monitoring()
            
            await self._cleanup()
    
    async def _init_components(self):
        """Initialize all scan components"""
        
        target_url = self.config.get('target', {}).get('url', '')
        
        # Extract scope pattern from target URL for MITM filtering
        scope_pattern = None
        if target_url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(target_url)
                if parsed.netloc:
                    # Include both exact domain and wildcard subdomains
                    scope_pattern = f"{parsed.netloc},*.{parsed.netloc}"
            except Exception:
                pass
        
        # Initialize request store
        self.request_store = RequestStore(self.scan_id)
        
        # Check if proxy is enabled
        proxy_config = self.config.get('proxy', {})
        proxy_enabled_in_config = proxy_config.get('enabled', True)  # Default True
        proxy_port = proxy_config.get('port', None)  # None = auto-allocate via PortManager
        
        self.proxy_enabled = False
        
        if proxy_enabled_in_config:
            # Initialize MITM proxy with scan_id and scope for multi-tenant isolation
            self.mitm_proxy = MITMProxy(
                port=proxy_port,  # None = auto-allocate
                on_request=self._on_request_captured,
                on_response=self._on_response_captured,
                scan_id=self.scan_id,
                scope=scope_pattern
            )
            mitm_started = await self.mitm_proxy.start()
            self.proxy_enabled = bool(mitm_started and getattr(self.mitm_proxy, "running", False))
            
            # Get the actual allocated port
            if self.proxy_enabled:
                proxy_port = self.mitm_proxy.port
                logger.info(f"MITM proxy started on port {proxy_port} for scan {self.scan_id}")

            if not self.proxy_enabled:
                logger.warning("MITM proxy unavailable, falling back to direct connection. Traffic capture will be limited.")
                self.mitm_proxy = None
        else:
            logger.info("MITM proxy disabled in config, using direct connection")
            self.mitm_proxy = None
            proxy_port = 0
        
        # Initialize browser with proxy settings (BrowserController expects host/port flags)
        # headless defaults to True for production safety (servers without display)
        # Set ENVIRONMENT=development to show browser for debugging
        import os
        default_headless = os.getenv('ENVIRONMENT', 'development') == 'production'
        self.browser = BrowserController(
            proxy_host="127.0.0.1" if self.proxy_enabled else "",
            proxy_port=proxy_port if self.proxy_enabled else 0,
            use_mitm=False,
            headless=self.config.get('browser', {}).get('headless', default_headless)
        )
        await self.browser.start()
        
        # Initialize attack engine with heartbeat callback and scan_id
        self.attack_engine = AttackEngine(
            config=self.config,
            request_store=self.request_store,
            mitm_proxy=self.mitm_proxy,
            scan_id=self.scan_id,
            heartbeat_callback=self._send_heartbeat
        )
        
        # Initialize unified executor for running ALL scanners with heartbeat callback
        if HAS_UNIFIED_EXECUTOR:
            self.unified_executor = UnifiedExecutor(
                config=self.config,
                request_store=self.request_store,
                browser_controller=self.browser,
                status_callback=self.status_callback,
                heartbeat_callback=self._send_heartbeat,
                scan_id=self.scan_id
            )
            logger.info(f"UnifiedExecutor initialized with all registered scanners")
        
        logger.info("All components initialized")
    
    def _on_request_captured(self, url: str, method: str, headers: dict, body: str):
        """Callback when MITM proxy captures a request"""
        
        # Determine if this is post-login based on auth tokens
        has_auth = 'Authorization' in headers or any(
            cookie in headers.get('Cookie', '') 
            for cookie in ['session', 'token', 'jwt']
        )
        
        is_post_login = self.is_logged_in and has_auth
        
        request_id = self.request_store.add_request(
            url=url,
            method=method,
            headers=headers,
            body=body,
            is_post_login=is_post_login
        )
        
        return request_id
    
    def _on_response_captured(self, request_id: str, status: int, headers: dict, body: str):
        """Callback when MITM proxy captures a response"""
        
        # Check if request was post-login
        is_post_login = request_id in [r.id for r in self.request_store.post_login_requests.values()]
        
        self.request_store.add_response(
            request_id=request_id,
            status_code=status,
            headers=headers,
            body=body,
            is_post_login=is_post_login
        )
    
    async def _crawl_pre_login(self):
        """Crawl website without authentication and populate RequestStore with discovered endpoints."""
        
        target_url = self.config.get('target', {}).get('url', '')
        max_pages = self.config.get('crawl', {}).get('max_pages', 50)
        
        logger.info(f"Crawling {target_url} (pre-login)")
        await self._update_status("running", 15, f"Starting crawl of {target_url}")
        
        # Navigate to target first
        await self.browser.goto(target_url)
        await self._update_status("running", 16, "Loaded target page, discovering endpoints...")
        
        # Use full crawl to discover endpoints (not just links)
        crawl_result = await self.browser.crawl(
            start_url=target_url,
            max_depth=3,
            max_pages=max_pages
        )
        
        discovered_urls = crawl_result.get('urls_visited', [])
        discovered_endpoints = crawl_result.get('endpoints', [])
        upload_endpoints = crawl_result.get('upload_endpoints', [])
        api_endpoints = crawl_result.get('api_endpoints', [])
        
        logger.info(f"Discovered {len(discovered_urls)} URLs and {len(discovered_endpoints)} endpoints in pre-login crawl")
        await self._update_status("running", 18, f"Discovered {len(discovered_urls)} URLs, {len(discovered_endpoints)} endpoints")
        
        # CRITICAL: Populate RequestStore with discovered endpoints
        # This ensures scanners have data even if MITM proxy didn't capture requests
        endpoints_added = self.request_store.populate_from_browser_endpoints(
            discovered_endpoints, 
            is_post_login=False
        )
        logger.info(f"Added {endpoints_added} endpoints to RequestStore for attack scanning")
        
        # Also add upload and API endpoints specifically if not already included
        if upload_endpoints:
            self.request_store.populate_from_browser_endpoints(upload_endpoints, is_post_login=False)
        if api_endpoints:
            self.request_store.populate_from_browser_endpoints(api_endpoints, is_post_login=False)
        
        # FALLBACK: If no endpoints discovered, at least add the target URL itself
        if endpoints_added == 0:
            logger.warning("No endpoints discovered from crawl, adding target URL as fallback")
            fallback_endpoints = [
                {'url': target_url, 'method': 'GET', 'params': {}, 'type': 'page', 'has_upload': False}
            ]
            # Also add discovered URLs as basic endpoints
            for url in discovered_urls[:50]:
                fallback_endpoints.append({
                    'url': url, 'method': 'GET', 'params': {}, 'type': 'page', 'has_upload': False
                })
            self.request_store.populate_from_browser_endpoints(fallback_endpoints, is_post_login=False)
            logger.info(f"Added {len(fallback_endpoints)} fallback endpoints from discovered URLs")
        
        # Visit remaining URLs to trigger any JavaScript-based endpoints
        total_urls = len(discovered_urls)
        for idx, url in enumerate(discovered_urls[:min(total_urls, 20)]):  # Visit top 20 for additional capture
            try:
                await self.browser.goto(url)
                await asyncio.sleep(0.3)  # Wait for dynamic content
                
                # CRITICAL: Process MITM traffic in real-time to populate RequestStore immediately
                # This ensures we capture full request/response data as we browse
                if self.mitm_proxy:
                    processed = self.mitm_proxy.process_new_traffic()
                    if processed > 0:
                        logger.debug(f"Processed {processed} new traffic entries from MITM")
                
                # Update progress every 5 URLs
                if idx % 5 == 0 and idx > 0:
                    progress = 18 + int((idx / min(total_urls, 20)) * 2)  # Scale to 18-20%
                    await self._update_status("running", progress, f"Captured {idx}/{min(total_urls, 20)} pages")
            except Exception as e:
                logger.debug(f"Failed to visit {url}: {e}")
        
        # Final MITM traffic processing to capture any remaining traffic
        if self.mitm_proxy:
            final_processed = self.mitm_proxy.process_new_traffic()
            logger.info(f"Final MITM processing: {final_processed} additional traffic entries captured")
        
        await self._update_status("running", 20, f"Crawl complete: {len(discovered_endpoints)} endpoints ready for scanning")
    
    def _has_credentials(self) -> bool:
        """Check if login credentials/auth method is provided"""
        auth = self.login_credentials
        auth_method = auth.get('method', 'username_password')
        
        # For traditional username/password auth
        if auth_method in ('username_password', None, ''):
            return bool(
                auth.get('username') and auth.get('password') and
                auth.get('selectors', {}).get('username') and
                auth.get('selectors', {}).get('password') and
                auth.get('selectors', {}).get('submit')
            )
        
        # For social login - just need the method and optionally providers
        if auth_method == 'social_login':
            return True  # Will pause for manual auth
        
        # For phone OTP - need phone number or at least the method
        if auth_method == 'phone_otp':
            return True  # Will pause for OTP input
        
        # For manual session - need session cookie or token
        if auth_method == 'manual_session':
            return bool(auth.get('session_cookie') or auth.get('session_token'))
        
        # For email magic link
        if auth_method == 'email_magic_link':
            return True  # Will pause for manual auth
        
        return False
    
    async def _perform_login(self):
        """Perform authentication using provided credentials or auth method"""
        
        auth = self.login_credentials
        auth_method = auth.get('method', 'username_password')
        login_url = auth.get('login_url', self.config.get('target', {}).get('url', ''))
        
        logger.info(f"Performing authentication: method={auth_method}, url={login_url}")
        
        try:
            # Route to appropriate auth handler based on method
            if auth_method == 'manual_session':
                await self._perform_manual_session_auth(auth)
            elif auth_method in ('social_login', 'email_magic_link'):
                await self._perform_manual_login(auth, login_url)
            elif auth_method == 'phone_otp':
                await self._perform_phone_otp_auth(auth, login_url)
            else:  # username_password (default)
                await self._perform_form_login(auth, login_url)
                
        except Exception as e:
            logger.error(f"Login failed: {e}")
    
    async def _perform_form_login(self, auth: dict, login_url: str):
        """Traditional username/password form login with 2FA support.
        
        Enhanced flow for handling SPAs and sites where landing page == login page:
        1. Navigate to login URL
        2. Dismiss all popups/overlays (cookie banners, modals, etc.)
        3. Check if login form is visible
        4. If not visible, discover and click login trigger button/link
        5. Auto-discover form selectors if not provided
        6. Fill and submit the login form
        7. Handle 2FA if configured
        """
        
        logger.info(f"Attempting form login at {login_url}")
        
        # Step 1: Navigate to login page
        await self.browser.goto(login_url)
        await asyncio.sleep(1)
        
        # Step 2: Dismiss all popups/overlays before login attempt
        await self.browser.dismiss_all_popups()
        await asyncio.sleep(0.5)
        
        # Step 3: Check if login form is visible
        form_visible = await self.browser.is_login_form_visible()
        
        # Step 4: If form not visible, try to discover and click login trigger
        if not form_visible:
            logger.info("Login form not immediately visible, searching for login trigger...")
            trigger_clicked = await self.browser.discover_and_click_login_trigger()
            
            if trigger_clicked:
                # Wait for form to appear and dismiss any new popups
                await asyncio.sleep(1)
                await self.browser.dismiss_all_popups()
                form_visible = await self.browser.is_login_form_visible()
            
            if not form_visible:
                logger.warning("Could not find or reveal login form - attempting with provided selectors anyway")
        
        # Step 5: Get selectors - use provided ones or auto-discover
        selectors = auth.get('selectors', {})
        username_selector = selectors.get('username')
        password_selector = selectors.get('password')
        submit_selector = selectors.get('submit')
        
        # Auto-discover selectors if not provided
        if not username_selector or not password_selector:
            logger.info("Auto-discovering login form selectors...")
            discovered = await self.browser.find_login_form_elements()
            
            if not username_selector and discovered.get('username_field'):
                username_selector = discovered['username_field']
                logger.info(f"Discovered username selector: {username_selector}")
            
            if not password_selector and discovered.get('password_field'):
                password_selector = discovered['password_field']
                logger.info(f"Discovered password selector: {password_selector}")
            
            if not submit_selector and discovered.get('submit_button'):
                submit_selector = discovered['submit_button']
                logger.info(f"Discovered submit selector: {submit_selector}")
        
        # Validate we have minimum required selectors
        if not username_selector or not password_selector:
            raise Exception("Could not determine login form selectors. Please provide them manually.")
        
        # Default submit selector if still not found
        if not submit_selector:
            submit_selector = 'button[type="submit"]'
            logger.debug(f"Using default submit selector: {submit_selector}")
        
        # Step 6: Fill login form
        await self.browser.fill_form({
            username_selector: auth['username'],
            password_selector: auth['password']
        })
        
        # Submit
        await self.browser.click(submit_selector)
        await asyncio.sleep(2)  # Wait for redirect
        
        # Step 7: Check if 2FA is enabled and handle it
        # 2FA config can be at auth['two_factor'] or config['two_factor']
        two_factor_config = auth.get('two_factor') or self.config.get('two_factor', {})
        if two_factor_config.get('enabled') and HAS_OTP_SERVICE:
            await self._handle_2fa_after_login(two_factor_config)
        
        # Check if login successful
        await self._verify_and_store_session()
    
    async def _handle_2fa_after_login(self, two_factor_config: dict):
        """Handle 2FA/OTP verification after initial login form submission
        
        IMPORTANT: During OTP wait, we DO NOT make any requests to the target site
        to avoid rate limiting. We only poll our own backend for the OTP code.
        """
        
        logger.info(f"Checking for 2FA page (2FA enabled: type={two_factor_config.get('type')})")
        
        # Check if we landed on a 2FA page
        is_2fa_page = await self.browser._detect_2fa_page()
        
        if not is_2fa_page:
            logger.info("No 2FA page detected after login - proceeding with scan")
            return
        
        logger.info("2FA page detected - pausing all target requests while waiting for OTP")
        
        otp_type = two_factor_config.get('type', 'sms')
        contact = two_factor_config.get('email') or two_factor_config.get('phone') or ''
        
        # Set scan as waiting for OTP and notify frontend
        set_scan_waiting_for_otp(self.scan_id, otp_type, contact, timeout_seconds=OTP_TIMEOUT_SECONDS)
        await self._update_status('waiting_for_otp', 15, f'Waiting for {otp_type.upper()} OTP code')
        
        max_attempts = 3
        for attempt in range(max_attempts):
            # Wait for user to provide OTP (blocks for up to 3 minutes)
            # CRITICAL: During this wait, we only poll our own OTP service
            # NO requests are made to the target site to avoid rate limiting
            otp = await otp_wait_for_otp(
                scan_id=self.scan_id,
                timeout=OTP_TIMEOUT_SECONDS,
                poll_interval=2.0  # Poll our backend every 2 seconds (not target!)
            )
            
            if not otp:
                # Timeout or max attempts - fail the scan
                error_msg = OTP_TIMEOUT_MESSAGE
                logger.error(f"2FA failed: {error_msg}")
                await self._update_status('error', 15, error_msg)
                raise Exception(error_msg)
            
            logger.info(f"OTP received, attempting to enter code (attempt {attempt + 1}/{max_attempts})")
            
            # Find and fill the OTP input
            otp_selector = await self.browser._find_otp_input()
            if not otp_selector:
                error_msg = "Could not find OTP input field on target website"
                set_otp_error(self.scan_id, error_msg)
                logger.error(error_msg)
                raise Exception(error_msg)
            
            # Enter the OTP
            await self.browser._page_fill(otp_selector, otp)
            await asyncio.sleep(0.5)
            
            # Submit the OTP
            submitted = await self._submit_otp_form()
            if not submitted:
                # Try pressing Enter as fallback
                await self.browser._page_press(otp_selector, 'Enter')
            
            await asyncio.sleep(2)  # Wait for response
            
            # Check if OTP was valid (still on 2FA page = invalid)
            still_on_2fa = await self.browser._detect_2fa_page()
            has_error = await self._check_for_otp_error()
            
            if still_on_2fa or has_error:
                if attempt < max_attempts - 1:
                    # Wrong OTP - allow retry
                    error_msg = OTP_INVALID_MESSAGE
                    logger.warning(f"OTP attempt {attempt + 1} failed - waiting for new code")
                    reset_otp_for_retry(self.scan_id, error_msg)
                    await self._update_status('waiting_for_otp', 15, f'Invalid OTP - please enter new code (attempt {attempt + 2}/{max_attempts})')
                    continue
                else:
                    # Max attempts reached
                    error_msg = "Maximum OTP attempts exceeded. Please restart the scan."
                    set_otp_error(self.scan_id, error_msg)
                    logger.error(error_msg)
                    await self._update_status('error', 15, error_msg)
                    raise Exception(error_msg)
            
            # OTP verified successfully
            logger.info("2FA verification successful!")
            clear_scan_otp_state(self.scan_id)
            await self._update_status('running', 20, '2FA verification complete - resuming scan')
            return
        
        # Should not reach here, but handle just in case
        raise Exception("2FA verification failed after all attempts")
    
    async def _submit_otp_form(self) -> bool:
        """Try to submit the OTP form by clicking a submit button"""
        submit_selectors = [
            'button[type="submit"]',
            'button:has-text("Verify")',
            'button:has-text("Submit")',
            'button:has-text("Continue")',
            'button:has-text("Confirm")',
            'button:has-text("Next")',
            'input[type="submit"]',
            '#verify-btn',
            '#submit-otp',
            '.otp-submit',
        ]
        
        for selector in submit_selectors:
            try:
                btn = await self.browser._page_query_selector(selector)
                if btn and await self.browser._element_is_visible(btn):
                    await self.browser._element_click(btn)
                    logger.info(f"Clicked OTP submit button: {selector}")
                    return True
            except:
                continue
        
        return False
    
    async def _check_for_otp_error(self) -> bool:
        """Check if the page shows an OTP error message"""
        error_selectors = [
            '.error',
            '.alert-danger',
            '.error-message',
            '[role="alert"]',
            '.invalid-feedback',
            '.text-danger',
            '.otp-error',
        ]
        
        for selector in error_selectors:
            try:
                element = await self.browser._page_query_selector(selector)
                if element and await self.browser._element_is_visible(element):
                    error_text = await self.browser._element_text_content(element)
                    if error_text:
                        error_lower = error_text.lower()
                        if any(word in error_lower for word in ['invalid', 'incorrect', 'expired', 'wrong', 'error', 'failed']):
                            logger.warning(f"OTP error detected: {error_text.strip()}")
                            return True
            except:
                continue
        
        return False
    
    async def _perform_manual_session_auth(self, auth: dict):
        """Inject pre-captured session cookie/token"""
        
        session_cookie = auth.get('session_cookie')
        session_token = auth.get('session_token')
        
        if session_cookie:
            logger.info("Injecting session cookie")
            try:
                # Parse cookie string (format: "name=value" or JSON)
                if isinstance(session_cookie, str):
                    if '=' in session_cookie:
                        name, value = session_cookie.split('=', 1)
                        await self.browser.add_cookie({
                            'name': name.strip(),
                            'value': value.strip(),
                            'domain': self._get_target_domain(),
                            'path': '/'
                        })
                    else:
                        # Assume it's just the value, use common name
                        await self.browser.add_cookie({
                            'name': 'session',
                            'value': session_cookie.strip(),
                            'domain': self._get_target_domain(),
                            'path': '/'
                        })
                        
                self.request_store.update_auth_token('session', session_cookie)
                self.is_logged_in = True
                logger.info("Session cookie injected successfully")
            except Exception as e:
                logger.error(f"Failed to inject session cookie: {e}")
                
        if session_token:
            logger.info("Setting session token for requests")
            self.request_store.update_auth_token('Authorization', f'Bearer {session_token}')
            self.is_logged_in = True
            
    def _get_target_domain(self) -> str:
        """Extract domain from target URL"""
        from urllib.parse import urlparse
        target_url = self.config.get('target', {}).get('url', '')
        parsed = urlparse(target_url)
        return parsed.netloc
    
    async def _perform_manual_login(self, auth: dict, login_url: str):
        """
        Manual login for social providers (Google/Facebook/etc).
        Opens login page and waits for user to complete authentication.
        """
        
        if not HAS_MANUAL_AUTH_SERVICE:
            logger.error("Manual auth service not available - cannot perform social login")
            return
        
        auth_method = auth.get('method', 'social_login')
        social_providers = auth.get('social_providers', [])
        
        logger.info(f"Starting manual login flow: {auth_method} with providers: {social_providers}")
        
        # Navigate to login page
        await self.browser.goto(login_url)
        await asyncio.sleep(1)
        
        # Start waiting for manual auth (registers with service)
        start_manual_auth_waiting(
            scan_id=self.scan_id,
            auth_method=auth_method,
            login_url=login_url,
            social_providers=social_providers,
            timeout_seconds=600  # 10 minutes
        )
        
        # Update scan status to waiting
        await self._update_status('waiting_for_manual_auth', 15, f'Waiting for {auth_method} login')
        
        logger.info(f"Scan {self.scan_id} paused - waiting for user to complete {auth_method}")
        
        # Wait for user to complete login (blocks until user clicks "I'm Logged In")
        auth_result = await wait_for_manual_auth(self.scan_id, timeout=600)
        
        # Resume scanning status
        await self._update_status('running', 20, 'Manual auth completed, resuming scan')
        
        if auth_result and auth_result.status.value == 'completed':
            logger.info(f"Manual auth completed for scan {self.scan_id}")
            
            # If user provided cookies via API, inject them
            if auth_result.session_cookies:
                for name, value in auth_result.session_cookies.items():
                    await self.browser.add_cookie({
                        'name': name,
                        'value': value,
                        'domain': self._get_target_domain(),
                        'path': '/'
                    })
            
            # Capture current browser session
            await self._verify_and_store_session()
        else:
            logger.warning(f"Manual auth failed or timed out for scan {self.scan_id}")
    
    async def _perform_phone_otp_auth(self, auth: dict, login_url: str):
        """
        Phone OTP authentication flow.
        Navigates to login, enters phone, waits for OTP from user.
        """
        
        if not HAS_MANUAL_AUTH_SERVICE:
            logger.error("Manual auth service not available - cannot perform phone OTP auth")
            return
        
        phone_number = auth.get('phone_number', '')
        phone_selectors = auth.get('selectors', {})
        
        logger.info(f"Starting phone OTP flow for {phone_number[:3]}***")
        
        # Navigate to login page
        await self.browser.goto(login_url)
        await asyncio.sleep(1)
        
        # If we have phone input selector, enter the phone number
        phone_input_selector = phone_selectors.get('phone_input')
        phone_submit_selector = phone_selectors.get('phone_submit')
        
        if phone_input_selector and phone_number:
            await self.browser.fill_form({phone_input_selector: phone_number})
            if phone_submit_selector:
                await self.browser.click(phone_submit_selector)
                await asyncio.sleep(2)  # Wait for OTP to be sent
        
        # Start waiting for OTP input from user
        start_manual_auth_waiting(
            scan_id=self.scan_id,
            auth_method='phone_otp',
            login_url=login_url,
            phone_number=phone_number,
            timeout_seconds=300  # 5 minutes for OTP
        )
        
        # Update scan status to waiting for OTP
        await self._update_status('waiting_for_otp', 15, 'Waiting for OTP input')
        
        logger.info(f"Scan {self.scan_id} paused - waiting for OTP input")
        
        # Wait for user to provide OTP
        auth_result = await wait_for_manual_auth(self.scan_id, timeout=300)
        
        # Resume scanning status
        await self._update_status('running', 20, 'OTP submitted, resuming scan')
        
        # Wait for user to provide OTP
        auth_result = await wait_for_manual_auth(self.scan_id, timeout=300)
        
        if auth_result and auth_result.status.value == 'completed':
            logger.info(f"OTP auth completed for scan {self.scan_id}")
            
            # OTP was submitted via API - capture session
            await self._verify_and_store_session()
        else:
            logger.warning(f"OTP auth failed or timed out for scan {self.scan_id}")
    
    async def _verify_and_store_session(self):
        """Verify login success and store session cookies/tokens"""
        
        current_url = await self.browser.current_url()
        cookies = await self.browser.get_cookies()
        
        # Look for session/auth cookies
        auth_cookies = [c for c in cookies if any(
            name in c.get('name', '').lower() 
            for name in ['session', 'token', 'jwt', 'auth']
        )]
        
        login_url = self.login_credentials.get('login_url', '')
        
        if auth_cookies or (login_url and login_url not in current_url):
            self.is_logged_in = True
            
            # Store auth tokens
            for cookie in auth_cookies:
                self.request_store.update_auth_token(
                    cookie.get('name', 'session'),
                    cookie.get('value', '')
                )
            
            logger.info(f"Login successful. Found {len(auth_cookies)} auth cookies")
        else:
            logger.warning("Login may have failed - no auth cookies found")
    
    async def _crawl_post_login(self):
        """Crawl website after authentication and populate RequestStore with authenticated endpoints."""
        
        target_url = self.config.get('target', {}).get('url', '')
        max_pages = self.config.get('crawl', {}).get('max_pages', 100)
        
        logger.info("Starting post-login crawl")
        
        # Use full crawl to discover authenticated endpoints
        crawl_result = await self.browser.crawl(
            start_url=target_url,
            max_depth=4,
            max_pages=max_pages,
            authenticated=True
        )
        
        discovered_urls = crawl_result.get('urls_visited', [])
        discovered_endpoints = crawl_result.get('endpoints', [])
        
        logger.info(f"Discovered {len(discovered_urls)} URLs and {len(discovered_endpoints)} endpoints in post-login crawl")
        
        # CRITICAL: Populate RequestStore with authenticated endpoints
        endpoints_added = self.request_store.populate_from_browser_endpoints(
            discovered_endpoints, 
            is_post_login=True
        )
        logger.info(f"Added {endpoints_added} post-login endpoints to RequestStore")
        
        # Visit key URLs and interact with forms
        # ENHANCED: Removed artificial 30 URL limit - now uses config-based limits
        max_urls_to_visit = self.config.get('crawl', {}).get('max_form_urls', 100)
        max_forms_per_page = self.config.get('crawl', {}).get('max_forms_per_page', 10)
        
        for url in discovered_urls[:max_urls_to_visit]:
            try:
                await self.browser.goto(url)
                await asyncio.sleep(0.5)
                
                # CRITICAL: Process MITM traffic in real-time to capture authenticated requests
                if self.mitm_proxy:
                    processed = self.mitm_proxy.process_new_traffic()
                    if processed > 0:
                        logger.debug(f"Post-login: Processed {processed} new traffic entries from MITM")
                
                # Look for forms and interact with them
                forms = await self.browser.find_forms()
                
                for form in forms[:max_forms_per_page]:
                    await self._interact_with_form(form)
                    
                    # Process MITM traffic after form interaction to capture POST data
                    if self.mitm_proxy:
                        self.mitm_proxy.process_new_traffic()
                    
            except Exception as e:
                logger.debug(f"Failed to visit {url}: {e}")
        
        # Final MITM traffic processing for post-login phase
        if self.mitm_proxy:
            final_processed = self.mitm_proxy.process_new_traffic()
            logger.info(f"Post-login MITM processing complete: {final_processed} additional entries")
    
    async def _interact_with_form(self, form: dict):
        """
        Interact with a form to capture POST request.
        Fill with intelligent test data and submit.
        
        ENHANCED: Now uses FormFiller for contextual test data generation.
        """
        # Import FormFiller for intelligent data generation
        try:
            from .form_filler import FormFiller
            form_filler = FormFiller()
        except ImportError:
            form_filler = None
        
        form_inputs = form.get('inputs', [])
        form_action = form.get('action', '')
        
        # Skip dangerous forms
        dangerous_patterns = ['logout', 'signout', 'delete', 'remove', 'cancel']
        if any(pattern in form_action.lower() for pattern in dangerous_patterns):
            logger.debug(f"Skipping dangerous form: {form_action}")
            return
        
        # Generate test data for each input
        test_data = {}
        for inp in form_inputs:
            input_type = inp.get('type', 'text')
            input_name = inp.get('name', '')
            selector = inp.get('selector', '')
            
            if not selector or not input_name:
                continue
            
            # Use FormFiller if available for intelligent data generation
            if form_filler:
                value = form_filler.generate_value(input_name, input_type)
                if value:
                    test_data[selector] = value
            else:
                # Fallback to basic type-based generation
                if input_type == 'email':
                    test_data[selector] = 'test@jarwis-scan.com'
                elif input_type == 'password':
                    test_data[selector] = 'TestPassword123!'
                elif input_type == 'number':
                    test_data[selector] = '12345'
                elif input_type == 'tel':
                    test_data[selector] = '1234567890'
                elif input_type == 'date':
                    test_data[selector] = '2025-01-15'
                elif input_type == 'url':
                    test_data[selector] = 'https://jarwis-test.com'
                else:
                    test_data[selector] = f'jarwis_test_{input_name}'
        
        # Fill and submit form
        try:
            await self.browser.fill_form(test_data)
            
            # Find submit button
            submit_selector = form.get('submit_selector', 'button[type="submit"]')
            await self.browser.click(submit_selector)
            
            await asyncio.sleep(1)  # Wait for response
            
        except Exception as e:
            logger.debug(f"Form interaction failed: {e}")
    
    async def _refresh_token(self) -> Optional[str]:
        """Re-login to get fresh auth token"""
        
        if not self._has_credentials():
            return None
        
        logger.info("Refreshing authentication token...")
        
        await self._perform_login()
        
        # Return the new token
        return self.request_store.get_current_auth_token()
    
    async def _generate_report(self) -> dict:
        """Generate vulnerability report"""
        
        # Save captured requests to disk
        self.request_store.save_to_disk()
        
        # Generate report using ReportGenerator
        # Use absolute path to data/reports for consistency
        default_output_dir = str(Path(__file__).parent.parent / 'data' / 'reports')
        output_dir = self.config.get('report', {}).get('output_dir', default_output_dir)
        formats = self.config.get('report', {}).get('formats', ['html', 'json'])
        reporter = ReportGenerator(
            output_dir=output_dir,
            formats=formats
        )
        
        # Convert AttackResults to report format - handle different result types
        findings = []
        for result in self.all_results:
            # Handle both dict and dataclass results
            if isinstance(result, dict):
                finding = result
            else:
                finding = {
                    'id': getattr(result, 'id', ''),
                    'category': getattr(result, 'category', ''),
                    'severity': getattr(result, 'severity', 'info'),
                    'title': getattr(result, 'title', ''),
                    'description': getattr(result, 'description', ''),
                    'url': getattr(result, 'url', ''),
                    'method': getattr(result, 'method', 'GET'),
                    'parameter': getattr(result, 'parameter', ''),
                    'payload': getattr(result, 'payload', getattr(result, 'poc', '')),  # Try payload, fallback to poc
                    'evidence': getattr(result, 'evidence', ''),
                    'remediation': getattr(result, 'remediation', ''),
                    'cwe_id': getattr(result, 'cwe_id', ''),
                    'is_post_login': getattr(result, 'is_post_login', False),
                }
            findings.append(finding)
        
        # Create a simple context object for the reporter
        class ReportContext:
            def __init__(self, target_url, scan_id):
                self.target_url = target_url
                self.scan_id = scan_id
                self.endpoints = []
                
        context_obj = ReportContext(
            target_url=self.config.get('target', {}).get('url', ''),
            scan_id=self.scan_id
        )
        
        # Generate reports using the correct method signature
        report_paths_list = await reporter.generate(
            findings=findings,
            context=context_obj,
            config=self.config
        )
        
        # Convert list of paths to dict keyed by format (html, json, sarif)
        # ReportGenerator.generate() returns List[str], but crud expects dict
        report_paths_dict = {}
        for path in report_paths_list:
            path_lower = path.lower()
            if path_lower.endswith('.html'):
                report_paths_dict['html'] = path
            elif path_lower.endswith('.json'):
                report_paths_dict['json'] = path
            elif path_lower.endswith('.sarif'):
                report_paths_dict['sarif'] = path
            elif path_lower.endswith('.pdf'):
                report_paths_dict['pdf'] = path
        
        return {
            'findings_count': len(findings),
            'by_severity': {
                'critical': len([f for f in findings if f.get('severity') == 'critical']),
                'high': len([f for f in findings if f.get('severity') == 'high']),
                'medium': len([f for f in findings if f.get('severity') == 'medium']),
                'low': len([f for f in findings if f.get('severity') == 'low']),
                'info': len([f for f in findings if f.get('severity') == 'info']),
            },
            'report_paths': report_paths_dict
        }
    
    async def _cleanup(self):
        """Cleanup resources including browser and any orphaned processes."""
        
        try:
            if self.browser:
                await self.browser.close()
            
            if self.mitm_proxy:
                await self.mitm_proxy.stop()
            
            # Safety net: kill any orphaned Playwright Chrome processes older than 30 min
            # This catches processes from failed previous scans
            try:
                from core.browser import BrowserController
                cleanup_result = await BrowserController.cleanup_orphaned_browsers_async(
                    max_age_minutes=30, 
                    force=False
                )
                if cleanup_result['killed'] > 0:
                    logger.info(f"Cleaned up {cleanup_result['killed']} orphaned browser processes")
            except Exception as e:
                logger.debug(f"Orphaned browser cleanup skipped: {e}")
            
            logger.info("Cleanup complete")
            
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
