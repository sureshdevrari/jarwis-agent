"""
JARWIS AGI PEN TEST - Browser Controller
Playwright-based browser automation for crawling and authentication
Supports MITM proxy for HTTPS interception
Enhanced with AI-powered request/response analysis
"""

import asyncio
import logging
import re
import json
import sys
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from playwright.async_api import async_playwright, Browser, BrowserContext, Page

# Fix for Windows asyncio subprocess (Playwright compatibility)
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

logger = logging.getLogger(__name__)


@dataclass
class Endpoint:
    """Represents a discovered endpoint"""
    url: str
    method: str
    params: Dict
    headers: Dict
    content_type: str = ""
    requires_auth: bool = False
    has_upload: bool = False
    endpoint_type: str = "page"  # page, api, upload, form


class BrowserController:
    """Controls headless browser for crawling and authentication"""
    
    # Class-level registry of browser instances by scan_id for force cleanup
    _instances: Dict[str, 'BrowserController'] = {}
    
    def __init__(
        self,
        proxy_host: str = "",  # Empty by default - no proxy
        proxy_port: int = 0,   # 0 by default - no proxy
        use_mitm: bool = False,
        headless: bool = False,
        force_async_windows: bool = None,  # Auto-detect based on Python version
    ):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.use_mitm = use_mitm  # Whether to use MITM proxy for HTTPS interception
        
        # Python 3.14+ on Windows has broken async subprocess support
        # Auto-detect and use sync mode when needed
        if force_async_windows is None:
            if sys.platform == 'win32' and sys.version_info >= (3, 14):
                # Python 3.14+ on Windows: use sync mode due to asyncio subprocess bug
                force_async_windows = False
                logger.info("Python 3.14+ detected on Windows - using sync Playwright mode")
            else:
                force_async_windows = True
        
        self.force_async_windows = force_async_windows  # Avoid sync Playwright greenlet issues on Windows
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self._discovered_urls: Set[str] = set()
        self._endpoints: List[Dict] = []
        self._captured_traffic: List[Dict] = []  # Store all request/response headers
        self.headless = headless  # Now configurable - True for headless, False to see browser
        self._mitm_proxy = None  # MITM proxy instance
        self._is_windows = sys.platform == 'win32'  # Track Windows mode for sync/async handling
        self._executor = None  # Thread pool executor for Windows sync operations
        
        # 2FA handling for target websites
        self._scan_id: Optional[str] = None  # Current scan ID for OTP handling
        self._2fa_config: Optional[Dict] = None  # 2FA configuration
        self._ai_watcher = None  # AI request watcher for analyzing traffic
        self._ai_findings: List[Dict] = []  # Findings from AI traffic analysis
    
    async def _run_sync(self, func, *args, **kwargs):
        """Run a sync function in the executor (for Windows Playwright sync API)"""
        if self._is_windows and self._executor:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                self._executor, 
                lambda: func(*args, **kwargs)
            )
        else:
            # For async Playwright, just await the coroutine
            result = func(*args, **kwargs)
            if asyncio.iscoroutine(result):
                return await result
            return result
    
    # ========== Page operation wrappers for Windows compatibility ==========
    async def _page_goto(self, url: str, **kwargs):
        """Navigate page to URL - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(self.page.goto, url, **kwargs)
        return await self.page.goto(url, **kwargs)

    # ===== Public convenience APIs used by WebScanRunner =====
    async def goto(self, url: str, **kwargs):
        """Navigate to a URL (wrapper around Playwright goto)."""
        return await self._page_goto(url, **kwargs)

    async def current_url(self) -> str:
        """Return the current page URL."""
        if self._is_windows:
            return await self._run_sync(lambda: self.page.url)
        return self.page.url

    async def fill_form(self, field_map: Dict[str, str]):
        """Fill multiple fields given a selector->value map."""
        for selector, value in field_map.items():
            try:
                await self._page_fill(selector, value)
            except Exception as e:
                logger.debug(f"Fill failed for {selector}: {e}")

    async def click(self, selector: str):
        """Click an element by selector."""
        return await self._page_click(selector)

    async def discover_links(self, base_url: str, max_depth: int = 3, max_urls: int = 50):
        """Run a crawl and return discovered URLs."""
        result = await self.crawl(start_url=base_url, max_depth=max_depth, max_pages=max_urls)
        return result.get('urls_visited', [])

    async def find_forms(self):
        """Extract forms on the current page."""
        return await self._extract_forms()

    async def close(self):
        """Gracefully close browser resources.
        
        Handles both Windows sync mode (using ThreadPoolExecutor) and
        standard async mode. Ensures all resources are properly released:
        - Browser context
        - Browser instance
        - Playwright instance
        - MITM proxy (if active)
        - Thread executor (Windows only)
        """
        try:
            # Windows sync mode: run cleanup in executor
            if self._is_windows and hasattr(self, '_executor') and self._executor:
                def close_sync():
                    """Sync cleanup for Windows Playwright objects"""
                    try:
                        if self.context:
                            self.context.close()
                        if self.browser:
                            self.browser.close()
                        if self.playwright:
                            self.playwright.stop()
                    except Exception as e:
                        logger.debug(f"Sync browser close error (non-critical): {e}")
                
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(self._executor, close_sync)
                except Exception as e:
                    logger.debug(f"Executor cleanup error: {e}")
                
                # Shutdown the executor
                try:
                    self._executor.shutdown(wait=True, cancel_futures=True)
                except TypeError:
                    # Python < 3.9 doesn't have cancel_futures
                    self._executor.shutdown(wait=True)
                except Exception as e:
                    logger.debug(f"Executor shutdown error: {e}")
                    
                logger.info("Browser closed (Windows sync mode)")
            else:
                # Standard async mode cleanup
                if self.context:
                    try:
                        await self.context.close()
                    except Exception as e:
                        logger.debug(f"Context close error: {e}")
                        
                if self.browser:
                    try:
                        await self.browser.close()
                    except Exception as e:
                        logger.debug(f"Browser close error: {e}")
                        
                if self.playwright:
                    try:
                        await self.playwright.stop()
                    except Exception as e:
                        logger.debug(f"Playwright stop error: {e}")
                        
                logger.info("Browser closed (async mode)")
            
            # Stop MITM proxy if it was running
            if self._mitm_proxy:
                try:
                    await self._mitm_proxy.stop()
                except Exception as e:
                    logger.debug(f"MITM proxy stop error: {e}")
                self._mitm_proxy = None
                
        except Exception as e:
            logger.warning(f"Browser close error (non-critical): {type(e).__name__}: {e}")
        finally:
            # Unregister from instance registry
            if self._scan_id and self._scan_id in BrowserController._instances:
                BrowserController._instances.pop(self._scan_id, None)
                logger.debug(f"Unregistered browser for scan {self._scan_id}")
            
            # Clear all references
            self.context = None
            self.browser = None
            self.playwright = None
            self.page = None
            self._executor = None
    
    async def __aenter__(self):
        """Async context manager entry - starts the browser.
        
        Usage:
            async with BrowserController() as browser:
                await browser.goto('https://example.com')
                # Browser automatically closed on exit
        """
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - ensures browser cleanup.
        
        Always closes the browser, even if an exception occurred.
        """
        await self.close()
        return False  # Don't suppress exceptions
    
    @staticmethod
    def kill_orphaned_browsers(max_age_minutes: int = 30, force: bool = False) -> dict:
        """Kill orphaned Playwright Chrome processes as a safety net.
        
        This is a process-level cleanup for browsers that weren't properly closed.
        Useful for long-running servers to prevent resource leaks.
        
        Args:
            max_age_minutes: Only kill processes older than this (default 30 min).
                            Set to 0 to kill all Playwright Chrome processes.
            force: If True, kill all Playwright Chrome regardless of age.
            
        Returns:
            dict with 'killed' count and 'details' list
        """
        import subprocess
        from datetime import datetime, timedelta
        
        result = {'killed': 0, 'skipped': 0, 'details': [], 'errors': []}
        
        if sys.platform == 'win32':
            try:
                # Use WMIC to get Chrome processes with command line info
                cmd = 'wmic process where "name=\'chrome.exe\'" get ProcessId,CreationDate,CommandLine /format:csv'
                output = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    shell=True,
                    timeout=30
                )
                
                if output.returncode != 0:
                    result['errors'].append(f"WMIC failed: {output.stderr}")
                    return result
                
                lines = output.stdout.strip().split('\n')
                cutoff_time = datetime.now() - timedelta(minutes=max_age_minutes)
                
                for line in lines[1:]:  # Skip header
                    if not line.strip():
                        continue
                    
                    parts = line.strip().split(',')
                    if len(parts) < 4:
                        continue
                    
                    # CSV format: Node,CommandLine,CreationDate,ProcessId
                    command_line = parts[1] if len(parts) > 1 else ''
                    creation_date_str = parts[2] if len(parts) > 2 else ''
                    pid_str = parts[3] if len(parts) > 3 else ''
                    
                    # Check if this is a Playwright-launched Chrome
                    is_playwright = (
                        '--disable-blink-features=AutomationControlled' in command_line or
                        '--headless' in command_line and '--remote-debugging' in command_line
                    )
                    
                    if not is_playwright:
                        continue
                    
                    try:
                        pid = int(pid_str.strip())
                    except (ValueError, TypeError):
                        continue
                    
                    # Parse creation date (format: YYYYMMDDHHMMSS.ffffff+offset)
                    should_kill = force or max_age_minutes == 0
                    
                    if not should_kill and creation_date_str:
                        try:
                            # Parse WMIC date format
                            date_part = creation_date_str.split('.')[0]
                            if len(date_part) >= 14:
                                creation_time = datetime.strptime(date_part[:14], '%Y%m%d%H%M%S')
                                should_kill = creation_time < cutoff_time
                        except (ValueError, IndexError):
                            # If we can't parse date and force is False, skip
                            pass
                    
                    if should_kill:
                        try:
                            subprocess.run(
                                f'taskkill /F /PID {pid}',
                                capture_output=True,
                                shell=True,
                                timeout=10
                            )
                            result['killed'] += 1
                            result['details'].append({
                                'pid': pid,
                                'action': 'killed',
                                'age_check': 'older than limit' if not force else 'forced'
                            })
                            logger.info(f"Killed orphaned Chrome process: PID {pid}")
                        except Exception as e:
                            result['errors'].append(f"Failed to kill PID {pid}: {e}")
                    else:
                        result['skipped'] += 1
                        
            except subprocess.TimeoutExpired:
                result['errors'].append("Process enumeration timed out")
            except Exception as e:
                result['errors'].append(f"Windows cleanup error: {e}")
                
        else:
            # Linux/macOS implementation
            try:
                # Find Chrome processes with Playwright markers
                cmd = "ps aux | grep -E 'chrome.*--disable-blink-features|chromium.*--disable-blink-features' | grep -v grep"
                output = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    shell=True,
                    timeout=30
                )
                
                lines = output.stdout.strip().split('\n')
                
                for line in lines:
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    
                    try:
                        pid = int(parts[1])
                        
                        # For Unix, we can check process age via /proc
                        should_kill = force or max_age_minutes == 0
                        
                        if not should_kill:
                            try:
                                import os
                                stat_info = os.stat(f'/proc/{pid}')
                                proc_start = datetime.fromtimestamp(stat_info.st_ctime)
                                cutoff = datetime.now() - timedelta(minutes=max_age_minutes)
                                should_kill = proc_start < cutoff
                            except (OSError, FileNotFoundError):
                                # Process might have already exited
                                continue
                        
                        if should_kill:
                            subprocess.run(
                                f'kill -9 {pid}',
                                capture_output=True,
                                shell=True,
                                timeout=10
                            )
                            result['killed'] += 1
                            result['details'].append({'pid': pid, 'action': 'killed'})
                            logger.info(f"Killed orphaned Chrome process: PID {pid}")
                        else:
                            result['skipped'] += 1
                            
                    except (ValueError, subprocess.TimeoutExpired) as e:
                        result['errors'].append(f"Error processing line: {e}")
                        
            except subprocess.TimeoutExpired:
                result['errors'].append("Process enumeration timed out")
            except Exception as e:
                result['errors'].append(f"Unix cleanup error: {e}")
        
        if result['killed'] > 0:
            logger.info(f"Orphaned browser cleanup: killed {result['killed']}, skipped {result['skipped']}")
        
        return result
    
    @staticmethod
    async def cleanup_orphaned_browsers_async(max_age_minutes: int = 30, force: bool = False) -> dict:
        """Async wrapper for kill_orphaned_browsers.
        
        Runs the cleanup in a thread executor to avoid blocking the event loop.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: BrowserController.kill_orphaned_browsers(max_age_minutes, force)
        )

    @classmethod
    async def force_close_by_scan_id(cls, scan_id: str) -> bool:
        """Force close the browser instance associated with a scan.
        
        Args:
            scan_id: The scan ID whose browser should be closed
            
        Returns:
            True if browser was found and closed, False otherwise
        """
        instance = cls._instances.get(scan_id)
        if instance:
            try:
                logger.info(f"Force-closing browser for scan {scan_id}")
                await instance.close()
                return True
            except Exception as e:
                logger.warning(f"Error force-closing browser for scan {scan_id}: {e}")
                # Try to remove from registry anyway
                cls._instances.pop(scan_id, None)
                return False
        else:
            logger.debug(f"No browser instance found for scan {scan_id}")
            return False
    
    @classmethod
    def get_active_browsers(cls) -> Dict[str, 'BrowserController']:
        """Get all active browser instances (for debugging/monitoring)"""
        return cls._instances.copy()

    async def _page_title(self):
        """Get page title - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(self.page.title)
        return await self.page.title()
    
    async def _page_evaluate(self, expression):
        """Evaluate JavaScript on page - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(self.page.evaluate, expression)
        return await self.page.evaluate(expression)
    
    async def _page_query_selector(self, selector: str):
        """Query for a single element - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(self.page.query_selector, selector)
        return await self.page.query_selector(selector)
    
    async def _page_query_selector_all(self, selector: str):
        """Query for all matching elements - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(self.page.query_selector_all, selector)
        return await self.page.query_selector_all(selector)
    
    async def _element_click(self, element):
        """Click an element - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(element.click)
        return await element.click()
    
    async def _element_is_visible(self, element):
        """Check if element is visible - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(element.is_visible)
        return await element.is_visible()
    
    async def _element_inner_text(self, element):
        """Get element's inner text - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(element.inner_text)
        return await element.inner_text()
    
    async def _element_fill(self, element, value: str):
        """Fill an input element - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(element.fill, value)
        return await element.fill(value)
    
    async def _element_press(self, element, key: str):
        """Press a key on element - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(element.press, key)
        return await element.press(key)
    
    async def _element_get_attribute(self, element, name: str):
        """Get attribute from element - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(element.get_attribute, name)
        return await element.get_attribute(name)
    
    async def _element_text_content(self, element):
        """Get element's text content - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(element.text_content)
        return await element.text_content()
    
    async def _page_fill(self, selector: str, value: str):
        """Fill input by selector - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(self.page.fill, selector, value)
        return await self.page.fill(selector, value)
    
    async def _page_click(self, selector: str):
        """Click element by selector - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(self.page.click, selector)
        return await self.page.click(selector)
    
    async def _page_press(self, selector: str, key: str):
        """Press key on element by selector - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(self.page.press, selector, key)
        return await self.page.press(selector, key)
    
    async def _page_wait_for_selector(self, selector: str, **kwargs):
        """Wait for selector - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(self.page.wait_for_selector, selector, **kwargs)
        return await self.page.wait_for_selector(selector, **kwargs)
    
    async def _page_wait_for_load_state(self, state: str = 'load', **kwargs):
        """Wait for page load state - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(self.page.wait_for_load_state, state, **kwargs)
        return await self.page.wait_for_load_state(state, **kwargs)
    
    async def _page_content(self):
        """Get page HTML content - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(self.page.content)
        return await self.page.content()
    
    async def _keyboard_press(self, key: str):
        """Press keyboard key - works on both Windows and non-Windows"""
        if self._is_windows:
            return await self._run_sync(self.page.keyboard.press, key)
        return await self.page.keyboard.press(key)
        
    async def start(self, enable_mitm_https: bool = False):
        """Start the browser instance
        
        Args:
            enable_mitm_https: If True, start MITM proxy for full HTTPS interception
        """
        # Windows: default to async Playwright to avoid greenlet/thread issues. Use sync mode only if explicitly requested.
        if sys.platform == 'win32' and not self.force_async_windows:
            import concurrent.futures
            from playwright.sync_api import sync_playwright
            
            def start_playwright_sync():
                """Start Playwright in sync mode (Windows workaround)"""
                pw = sync_playwright().start()
                browser = pw.chromium.launch(
                    headless=self.headless,
                    slow_mo=300,
                    args=[
                        '--disable-blink-features=AutomationControlled',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--no-sandbox',
                        '--ignore-certificate-errors',  # Accept MITM proxy certificates
                        '--ignore-certificate-errors-spki-list',  # Suppress cert pinning
                        '--disable-features=IsolateOrigins,site-per-process',  # Better MITM compatibility
                    ]
                )
                # Configure proxy for MITM capture if available
                context_options = {
                    'viewport': {'width': 1920, 'height': 1080},
                    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'ignore_https_errors': True
                }
                # Add proxy configuration if available (critical for MITM traffic capture)
                if self.proxy_host and self.proxy_host.strip() and self.proxy_port and self.proxy_port > 0:
                    context_options['proxy'] = {'server': f'http://{self.proxy_host}:{self.proxy_port}'}
                    logger.info(f"Windows sync mode: Using proxy {self.proxy_host}:{self.proxy_port}")
                context = browser.new_context(**context_options)
                # Create page for Windows
                page = context.new_page()
                return pw, browser, context, page
            
            # Run sync Playwright in thread pool - store executor to keep it alive
            loop = asyncio.get_event_loop()
            self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            self.playwright, self.browser, self.context, self.page = await loop.run_in_executor(
                self._executor, start_playwright_sync
            )
            
            # Set up request/response interception for Windows (sync wrapper)
            def setup_interception_sync():
                # Capture responses for traffic log - including body for vulnerability detection
                def on_response(response):
                    try:
                        # Capture response body for vulnerability detection (SQL errors, XSS reflection, etc.)
                        body = ''
                        content_type = response.headers.get('content-type', '')
                        # Only capture body for text-based responses (HTML, JSON, XML, text)
                        if any(ct in content_type.lower() for ct in ['text/', 'json', 'xml', 'javascript']):
                            try:
                                body = response.text()[:100000]  # Limit to 100KB
                            except Exception:
                                pass
                        
                        self._captured_traffic.append({
                            'type': 'response',
                            'url': response.url,
                            'method': response.request.method,
                            'status': response.status,
                            'headers': dict(response.headers),
                            'request_headers': dict(response.request.headers),
                            'body': body  # Include body for vulnerability detection
                        })
                    except Exception as e:
                        logger.debug(f"Error capturing response: {e}")
                
                self.page.on('response', on_response)
            
            await loop.run_in_executor(self._executor, setup_interception_sync)
            logger.info("Browser started successfully (Windows sync mode)")
            return
        
        # Original async implementation for non-Windows
        self.playwright = await async_playwright().start()
        
        # Start MITM proxy if requested
        if enable_mitm_https or self.use_mitm:
            await self._start_mitm_proxy()
        
        self.browser = await self.playwright.chromium.launch(
            headless=self.headless,
            slow_mo=300,  # Reduced from 500ms for faster execution
            args=[
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
                '--ignore-certificate-errors',  # Accept MITM proxy certificates
                '--ignore-certificate-errors-spki-list',  # Suppress cert pinning
                '--disable-features=IsolateOrigins,site-per-process',  # Better MITM compatibility
            ],
            timeout=60000  # 60 second timeout for browser launch
        )
        
        # Configure browser context with proxy if available
        context_options = {
            'ignore_https_errors': True,  # Accept MITM-generated certificates
            'user_agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        # Use MITM proxy if enabled
        if self._mitm_proxy and self._mitm_proxy.running:
            proxy_settings = self._mitm_proxy.get_proxy_settings()
            logger.info(f"Using MITM proxy for HTTPS interception: {proxy_settings['server']}")
            context_options['proxy'] = {
                "server": proxy_settings['server']
            }
        # Or use external proxy if configured
        elif self.proxy_host and self.proxy_host.strip() and self.proxy_port and self.proxy_port > 0:
            logger.info(f"Using proxy: {self.proxy_host}:{self.proxy_port}")
            context_options['proxy'] = {
                "server": f"http://{self.proxy_host}:{self.proxy_port}"
            }
        else:
            logger.info("No proxy configured - direct connection (built-in interception only)")
        
        self.context = await self.browser.new_context(**context_options)
        
        # Set default timeouts
        self.context.set_default_timeout(30000)  # 30 seconds default
        self.context.set_default_navigation_timeout(60000)  # 60 seconds for navigation
        
        self.page = await self.context.new_page()
        
        # Set up request/response interception for traffic capture
        self.page.on('response', self._capture_response)
        await self.page.route("**/*", self._intercept_request)
        
        logger.info("Browser started successfully" + (" with MITM HTTPS interception" if self._mitm_proxy else ""))
    
    async def _start_mitm_proxy(self):
        """Start the MITM proxy for HTTPS interception"""
        try:
            from .mitm_proxy import JarwisMITMProxy
            
            self._mitm_proxy = JarwisMITMProxy(host="127.0.0.1", port=8080)
            success = await self._mitm_proxy.start()
            
            if success:
                logger.info(f"MITM proxy started for HTTPS interception")
                logger.info(f"CA Certificate: {self._mitm_proxy.ca_cert_path}")
            else:
                logger.warning("Failed to start MITM proxy, using built-in interception only")
                self._mitm_proxy = None
        except ImportError as e:
            logger.warning(f"MITM proxy module not available: {e}")
            self._mitm_proxy = None
        except Exception as e:
            logger.error(f"Failed to start MITM proxy: {e}")
            self._mitm_proxy = None
    
    def enable_ai_watcher(self, config: dict):
        """Enable AI-powered request/response analysis"""
        try:
            from core.ai_verifier import AIRequestWatcher
            self._ai_watcher = AIRequestWatcher(config)
            logger.info("AI Request Watcher enabled for traffic analysis")
        except Exception as e:
            logger.warning(f"Could not enable AI watcher: {e}")
            self._ai_watcher = None
    
    def get_ai_findings(self) -> List[Dict]:
        """Get vulnerabilities discovered by AI during crawling"""
        if self._ai_watcher:
            return self._ai_watcher.get_findings()
        return []
    
    async def _intercept_request(self, route):
        """Intercept and log all requests for endpoint discovery"""
        try:
            request = route.request
            headers = dict(request.headers)
            
            # AI-powered header modification for testing
            if self._ai_watcher:
                try:
                    modified_headers, _ = await self._ai_watcher.watch_request(
                        request.method, request.url, headers, request.post_data or ""
                    )
                    headers = modified_headers
                except Exception as e:
                    logger.debug(f"AI header modification failed: {e}")
            
            endpoint = {
                'url': request.url,
                'method': request.method,
                'headers': headers,
                'post_data': request.post_data,
                'type': self._classify_request(request)
            }
            
            # Check for file upload
            if 'multipart/form-data' in request.headers.get('content-type', ''):
                endpoint['has_upload'] = True
                endpoint['type'] = 'upload'
            
            self._endpoints.append(endpoint)
            
            # Capture request headers for traffic log
            self._captured_traffic.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'request',
                'url': request.url,
                'method': request.method,
                'headers': headers,
                'post_data': request.post_data
            })
            
            await route.continue_()
        except Exception as e:
            logger.debug(f"Request intercept error: {e}")
            try:
                await route.continue_()
            except:
                pass
    
    def _capture_response(self, response):
        """Capture response headers and body for vulnerability detection"""
        try:
            # Capture response body for vulnerability detection (SQL errors, XSS reflection, etc.)
            body = ''
            content_type = response.headers.get('content-type', '')
            # Only capture body for text-based responses (HTML, JSON, XML, text)
            if any(ct in content_type.lower() for ct in ['text/', 'json', 'xml', 'javascript']):
                try:
                    # Use asyncio to get body in sync context
                    import asyncio
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        # Schedule body capture - will be captured async
                        async def get_body():
                            try:
                                return await response.text()
                            except:
                                return ''
                        body_future = asyncio.ensure_future(get_body())
                        # Store future for later resolution if needed
                    else:
                        body = loop.run_until_complete(response.text())[:100000]
                except Exception:
                    pass
            
            self._captured_traffic.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'response',
                'url': response.url,
                'status': response.status,
                'status_text': response.status_text,
                'headers': dict(response.headers),
                'body': body  # Include body for vulnerability detection
            })
        except Exception as e:
            logger.debug(f"Error capturing response: {e}")
    
    def _classify_request(self, request) -> str:
        """Classify the request type"""
        content_type = request.headers.get('content-type', '')
        url = request.url.lower()
        
        if '/api/' in url or 'graphql' in url:
            return 'api'
        elif 'application/json' in content_type:
            return 'api'
        elif 'multipart/form-data' in content_type:
            return 'upload'
        elif request.method == 'POST':
            return 'form'
        else:
            return 'page'
    
    async def crawl(
        self, 
        start_url: str, 
        max_depth: int = 5,
        scope: Optional[Dict] = None,
        authenticated: bool = False,
        max_pages: int = 200
    ) -> Dict:
        """
        Crawl the target website using BFS tree traversal to discover all endpoints.
        
        Uses breadth-first search to ensure we reach all pages at each depth level
        before going deeper. Excludes duplicate URLs and out-of-scope links.
        
        Args:
            start_url: Starting URL to crawl
            max_depth: Maximum depth to crawl (default 5 for comprehensive coverage)
            scope: Optional scope restrictions
            authenticated: Whether this is an authenticated crawl
            max_pages: Maximum number of pages to visit (default 200)
        """
        self._discovered_urls = set()
        self._endpoints = []
        self._pending_urls: List[tuple] = []  # (url, depth) tuples for BFS
        
        logger.info(f"Starting comprehensive BFS crawl of: {start_url}")
        logger.info(f"Settings: max_depth={max_depth}, max_pages={max_pages}")
        
        # Initial page load with popup handling
        try:
            # Use sync wrapper for Windows
            if self._is_windows:
                await self._run_sync(self.page.goto, start_url, wait_until='domcontentloaded', timeout=30000)
            else:
                await self.page.goto(start_url, wait_until='domcontentloaded', timeout=30000)
            
            # Handle popups on initial page load (critical for e-commerce sites)
            logger.info("Checking for initial popups/modals...")
            for attempt in range(3):
                await self._handle_popups_and_modals()
                overlay = await self._find_blocking_overlay()
                if not overlay:
                    break
                logger.info(f"Popup still visible, retry {attempt + 1}/3")
                await asyncio.sleep(1)
            
        except Exception as e:
            logger.warning(f"Initial page load error: {e}")
        
        # Use BFS (Breadth-First Search) for comprehensive tree crawling
        await self._crawl_bfs(start_url, max_depth, scope, max_pages)
        
        # Deduplicate endpoints by URL+method
        seen_endpoints = set()
        unique_endpoints = []
        for ep in self._endpoints:
            key = f"{ep.get('url', '')}|{ep.get('method', 'GET')}"
            if key not in seen_endpoints:
                seen_endpoints.add(key)
                unique_endpoints.append(ep)
        
        self._endpoints = unique_endpoints
        
        # Categorize endpoints
        upload_endpoints = [ep for ep in self._endpoints if ep.get('has_upload')]
        api_endpoints = [ep for ep in self._endpoints if ep.get('type') == 'api']
        
        logger.info(f"Crawl complete: {len(self._discovered_urls)} pages visited, {len(self._endpoints)} endpoints found")
        
        return {
            'endpoints': self._endpoints,
            'upload_endpoints': upload_endpoints,
            'api_endpoints': api_endpoints,
            'urls_visited': list(self._discovered_urls)
        }
    
    async def _crawl_bfs(
        self, 
        start_url: str,
        max_depth: int,
        scope: Optional[Dict],
        max_pages: int
    ):
        """
        Breadth-First Search crawling - visits all pages at each depth level
        before going deeper. This ensures comprehensive endpoint discovery.
        """
        from collections import deque
        
        # Queue holds (url, depth) tuples
        queue = deque([(start_url, 0)])
        
        while queue and len(self._discovered_urls) < max_pages:
            url, depth = queue.popleft()
            
            # Skip if already visited or too deep
            if url in self._discovered_urls:
                continue
            if depth > max_depth:
                continue
            
            # Normalize URL to avoid duplicates
            normalized_url = self._normalize_url(url)
            if normalized_url in self._discovered_urls:
                continue
                
            # Check scope
            if scope and not self._is_in_scope(url, scope):
                continue
            
            # Mark as visited
            self._discovered_urls.add(normalized_url)
            
            try:
                # Visit the page - use sync wrapper for Windows
                if self._is_windows:
                    response = await self._run_sync(self.page.goto, url, wait_until='domcontentloaded', timeout=15000)
                else:
                    response = await self.page.goto(url, wait_until='domcontentloaded', timeout=15000)
                    
                if not response:
                    continue
                
                # Log progress every 10 pages
                if len(self._discovered_urls) % 10 == 0:
                    logger.info(f"Crawled {len(self._discovered_urls)} pages, queue size: {len(queue)}, depth: {depth}")
                
                # Brief wait for dynamic content
                await asyncio.sleep(0.3)
                
                # Handle popups
                await self._handle_popups_and_modals()
                
                # Extract ALL link types from page
                links = await self._extract_all_links()
                
                # Extract forms as endpoints
                forms = await self._extract_forms()
                for form in forms:
                    self._endpoints.append(form)
                
                # Extract API endpoints from scripts
                api_urls = await self._extract_api_endpoints()
                for api_url in api_urls:
                    if api_url not in [ep.get('url') for ep in self._endpoints]:
                        self._endpoints.append({
                            'url': api_url,
                            'method': 'GET',
                            'type': 'api',
                            'params': {},
                            'has_upload': False
                        })
                
                # CRITICAL: Submit discovered forms to capture POST traffic via MITM
                # This is essential for discovering dynamic endpoints and attack surfaces
                await self._submit_discovered_forms(forms, url)
                
                # Add discovered links to queue for BFS traversal
                for link in links:
                    if self._is_same_domain(start_url, link):
                        normalized_link = self._normalize_url(link)
                        if normalized_link not in self._discovered_urls:
                            queue.append((link, depth + 1))
                    
            except Exception as e:
                logger.debug(f"Error crawling {url}: {e}")
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL to avoid visiting duplicates with different fragments/params"""
        parsed = urlparse(url)
        # Remove fragment and normalize
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        # Remove trailing slash for consistency
        if normalized.endswith('/') and len(normalized) > len(f"{parsed.scheme}://{parsed.netloc}/"):
            normalized = normalized[:-1]
        return normalized.lower()
    
    async def _extract_all_links(self) -> List[str]:
        """Extract ALL types of links from the page - comprehensive discovery"""
        js_code = '''() => {
            const links = new Set();
            
            // Standard anchor links
            document.querySelectorAll('a[href]').forEach(a => {
                if (a.href && !a.href.startsWith('javascript:') && !a.href.startsWith('mailto:') && !a.href.startsWith('tel:')) {
                    links.add(a.href);
                }
            });
            
            // Links in onclick handlers
            document.querySelectorAll('[onclick]').forEach(el => {
                const onclick = el.getAttribute('onclick') || '';
                const matches = onclick.match(/(?:location\\.href|window\\.open|navigate)\\s*[=\\(]\\s*['"]([^'"]+)['"]/gi);
                if (matches) {
                    matches.forEach(match => {
                        const urlMatch = match.match(/['"]([^'"]+)['"]/);
                        if (urlMatch) {
                            try {
                                const url = new URL(urlMatch[1], window.location.href);
                                links.add(url.href);
                            } catch(e) {}
                        }
                    });
                }
            });
            
            // Links in data attributes
            document.querySelectorAll('[data-href], [data-url], [data-link], [data-target]').forEach(el => {
                ['data-href', 'data-url', 'data-link', 'data-target'].forEach(attr => {
                    const val = el.getAttribute(attr);
                    if (val && val.startsWith('/')) {
                        try {
                            const url = new URL(val, window.location.href);
                            links.add(url.href);
                        } catch(e) {}
                    } else if (val && val.startsWith('http')) {
                        links.add(val);
                    }
                });
            });
            
            // Form actions
            document.querySelectorAll('form[action]').forEach(form => {
                try {
                    const url = new URL(form.action, window.location.href);
                    links.add(url.href);
                } catch(e) {}
            });
            
            // Iframe sources
            document.querySelectorAll('iframe[src]').forEach(iframe => {
                if (iframe.src && !iframe.src.startsWith('about:')) {
                    links.add(iframe.src);
                }
            });
            
            // Script src (for discovering API patterns)
            document.querySelectorAll('script[src]').forEach(script => {
                if (script.src) {
                    links.add(script.src);
                }
            });
            
            // Meta refresh URLs
            document.querySelectorAll('meta[http-equiv="refresh"]').forEach(meta => {
                const content = meta.getAttribute('content') || '';
                const urlMatch = content.match(/url=(.+)/i);
                if (urlMatch) {
                    try {
                        const url = new URL(urlMatch[1].trim(), window.location.href);
                        links.add(url.href);
                    } catch(e) {}
                }
            });
            
            // Area map links
            document.querySelectorAll('area[href]').forEach(area => {
                links.add(area.href);
            });
            
            // Base tag consideration
            document.querySelectorAll('link[href]').forEach(link => {
                const rel = link.getAttribute('rel') || '';
                if (rel.includes('canonical') || rel.includes('alternate')) {
                    try {
                        const url = new URL(link.href, window.location.href);
                        links.add(url.href);
                    } catch(e) {}
                }
            });
            
            return Array.from(links);
        }'''
        
        if self._is_windows:
            return await self._run_sync(self.page.evaluate, js_code)
        else:
            return await self.page.evaluate(js_code)
    
    async def _extract_api_endpoints(self) -> List[str]:
        """Extract API endpoints from inline scripts and fetch patterns"""
        js_code = '''() => {
            const apiUrls = new Set();
            const apiPatterns = [
                /fetch\\s*\\(\\s*['"`]([^'"`]+)['"`]/g,
                /axios\\.[a-z]+\\s*\\(\\s*['"`]([^'"`]+)['"`]/g,
                /\\$\\.(ajax|get|post)\\s*\\(\\s*['"`]([^'"`]+)['"`]/g,
                /XMLHttpRequest.*open\\s*\\(\\s*['"`]\\w+['"`]\\s*,\\s*['"`]([^'"`]+)['"`]/g,
                /['"`](\\/api\\/[^'"`\\s]+)['"`]/g,
                /['"`](\\/rest\\/[^'"`\\s]+)['"`]/g,
                /['"`](\\/graphql[^'"`\\s]*)['"`]/g,
                /['"`](\\/v[0-9]+\\/[^'"`\\s]+)['"`]/g,
            ];
            
            // Check all script contents
            document.querySelectorAll('script').forEach(script => {
                const content = script.textContent || '';
                apiPatterns.forEach(pattern => {
                    let match;
                    while ((match = pattern.exec(content)) !== null) {
                        const url = match[1] || match[2];
                        if (url && (url.startsWith('/') || url.startsWith('http'))) {
                            try {
                                const fullUrl = new URL(url, window.location.href);
                                apiUrls.add(fullUrl.href);
                            } catch(e) {}
                        }
                    }
                });
            });
            
            return Array.from(apiUrls);
        }'''
        
        if self._is_windows:
            return await self._run_sync(self.page.evaluate, js_code)
        else:
            return await self.page.evaluate(js_code)

    async def _crawl_recursive(
        self, 
        url: str, 
        depth: int, 
        max_depth: int,
        scope: Optional[Dict]
    ):
        """Recursively crawl pages (legacy method - now uses BFS instead)"""
        if depth > max_depth or url in self._discovered_urls:
            return
        
        if scope and not self._is_in_scope(url, scope):
            return
        
        self._discovered_urls.add(url)
        
        try:
            # Navigate to URL
            if self._is_windows:
                response = await self._run_sync(self.page.goto, url, wait_until='domcontentloaded', timeout=15000)
            else:
                response = await self.page.goto(url, wait_until='domcontentloaded', timeout=15000)
            if not response:
                return
            
            # Brief wait for dynamic content then handle popups
            await asyncio.sleep(0.5)
            
            # Handle any popups, modals, location selectors, or cookie banners
            # Try multiple times to ensure we can interact with the page
            for popup_attempt in range(2):
                await self._handle_popups_and_modals()
                overlay = await self._find_blocking_overlay()
                if not overlay:
                    break
                await asyncio.sleep(0.5)
            
            # Extract all links
            js_code = '''() => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    links.push(a.href);
                });
                return links;
            }'''
            if self._is_windows:
                links = await self._run_sync(self.page.evaluate, js_code)
            else:
                links = await self.page.evaluate(js_code)
            
            # Extract forms
            forms = await self._extract_forms()
            for form in forms:
                self._endpoints.append(form)
            
            # Track out-of-scope URLs for reporting
            out_of_scope_count = 0
            
            # Recursively crawl discovered links (only same domain)
            for link in links:
                if self._is_same_domain(url, link):
                    await self._crawl_recursive(link, depth + 1, max_depth, scope)
                else:
                    out_of_scope_count += 1
                    logger.debug(f"Skipping out-of-scope URL: {link}")
            
            if out_of_scope_count > 0:
                logger.info(f"Skipped {out_of_scope_count} out-of-scope URLs from {url}")
                    
        except Exception as e:
            logger.debug(f"Error crawling {url}: {e}")
    
    async def _extract_forms(self) -> List[Dict]:
        """Extract form endpoints from current page"""
        js_code = '''() => {
            const forms = [];
            document.querySelectorAll('form').forEach(form => {
                const formData = {
                    url: form.action || window.location.href,
                    method: (form.method || 'GET').toUpperCase(),
                    type: 'form',
                    params: {},
                    has_upload: false
                };
                
                form.querySelectorAll('input, textarea, select').forEach(input => {
                    if (input.name) {
                        formData.params[input.name] = input.type || 'text';
                        if (input.type === 'file') {
                            formData.has_upload = true;
                            formData.type = 'upload';
                        }
                    }
                });
                
                forms.push(formData);
            });
            return forms;
        }'''
        
        if self._is_windows:
            return await self._run_sync(self.page.evaluate, js_code)
        else:
            return await self.page.evaluate(js_code)
    
    async def _submit_discovered_forms(self, forms: List[Dict], current_url: str, max_forms_per_page: int = 5):
        """
        Submit discovered forms to capture POST/dynamic traffic via MITM proxy.
        
        This is CRITICAL for discovering attack surfaces that only appear after form submission:
        - Login panels (submit to see authenticated areas)
        - Search forms (submit to see results endpoints)
        - Contact forms (capture POST parameters)
        - Registration forms (discover validation endpoints)
        
        Args:
            forms: List of form dicts from _extract_forms()
            current_url: Current page URL for navigation back
            max_forms_per_page: Limit forms per page to avoid crawl explosion
        """
        from .form_filler import FormFiller, FormData, FormField, FormExtractor
        
        if not forms:
            return
        
        form_filler = FormFiller()
        submitted_count = 0
        
        # Track original URL to navigate back after form submissions
        original_url = current_url
        
        for form_dict in forms[:max_forms_per_page]:  # Limit forms per page
            try:
                # Skip forms with dangerous actions
                action_url = form_dict.get('url', '')
                dangerous_patterns = [
                    'logout', 'signout', 'log-out', 'sign-out',
                    'delete', 'remove', 'unsubscribe', 'cancel',
                    'deactivate', 'disable', 'terminate', 'destroy',
                    'payment', 'checkout', 'purchase', 'order'
                ]
                
                if any(pattern in action_url.lower() for pattern in dangerous_patterns):
                    logger.debug(f"Skipping dangerous form action: {action_url}")
                    continue
                
                # Skip file upload forms (handled separately)
                if form_dict.get('has_upload'):
                    logger.debug(f"Skipping file upload form: {action_url}")
                    continue
                
                # Get detailed form info using FormExtractor
                try:
                    detailed_forms = await FormExtractor.extract_forms(self.page)
                    matching_form = None
                    for df in detailed_forms:
                        if df.action == action_url or (not df.action and action_url == current_url):
                            matching_form = df
                            break
                    
                    if not matching_form:
                        # Create FormData from basic form_dict
                        fields = []
                        for param_name, param_type in form_dict.get('params', {}).items():
                            fields.append(FormField(
                                name=param_name,
                                field_type=param_type,
                                selector=f'[name="{param_name}"]',
                                required=False
                            ))
                        matching_form = FormData(
                            action=action_url,
                            method=form_dict.get('method', 'POST'),
                            fields=fields
                        )
                except Exception as e:
                    logger.debug(f"Error extracting detailed form: {e}")
                    continue
                
                # Check if form should be submitted
                if not form_filler.should_submit_form(matching_form):
                    logger.debug(f"FormFiller says skip form: {action_url}")
                    continue
                
                # Detect form type for logging
                form_type = form_filler.detect_form_type(matching_form)
                logger.info(f"Submitting {form_type} form: {action_url} [{matching_form.method}]")
                
                # Generate field values
                field_values = form_filler.fill_form(matching_form)
                
                # Fill all form fields
                for selector, value in field_values.items():
                    try:
                        if self._is_windows:
                            await self._run_sync(self.page.fill, selector, value)
                        else:
                            await self.page.fill(selector, value)
                        logger.debug(f"Filled {selector} = {value[:20]}..." if len(value) > 20 else f"Filled {selector} = {value}")
                    except Exception as e:
                        logger.debug(f"Could not fill {selector}: {e}")
                
                # Submit the form
                try:
                    # Try clicking submit button first
                    if matching_form.submit_selector:
                        if self._is_windows:
                            await self._run_sync(self.page.click, matching_form.submit_selector)
                        else:
                            await self.page.click(matching_form.submit_selector)
                    else:
                        # Try common submit patterns
                        submit_selectors = [
                            'form button[type="submit"]',
                            'form input[type="submit"]',
                            'form button:not([type])',
                            'form [class*="submit" i]',
                            'button:has-text("Submit")',
                            'button:has-text("Search")',
                            'button:has-text("Send")',
                            'button:has-text("Login")',
                            'button:has-text("Sign")',
                        ]
                        
                        submitted = False
                        for submit_sel in submit_selectors:
                            try:
                                element = await self._page_query_selector(submit_sel)
                                if element and await self._element_is_visible(element):
                                    await self._element_click(element)
                                    submitted = True
                                    break
                            except:
                                continue
                        
                        # If no button found, try pressing Enter on last field
                        if not submitted and field_values:
                            try:
                                last_selector = list(field_values.keys())[-1]
                                if self._is_windows:
                                    await self._run_sync(self.page.press, last_selector, 'Enter')
                                else:
                                    await self.page.press(last_selector, 'Enter')
                            except:
                                pass
                    
                    # Wait for form submission and any JS processing
                    await asyncio.sleep(1.0)
                    
                    submitted_count += 1
                    logger.info(f"Form submitted successfully ({submitted_count}/{max_forms_per_page})")
                    
                    # Capture any new endpoints from the response page
                    try:
                        new_forms = await self._extract_forms()
                        for nf in new_forms:
                            if nf not in self._endpoints:
                                self._endpoints.append(nf)
                    except:
                        pass
                    
                except Exception as e:
                    logger.debug(f"Form submission failed: {e}")
                
                # Navigate back to continue crawling
                try:
                    if self._is_windows:
                        await self._run_sync(self.page.goto, original_url, wait_until='domcontentloaded', timeout=10000)
                    else:
                        await self.page.goto(original_url, wait_until='domcontentloaded', timeout=10000)
                    await asyncio.sleep(0.3)
                except Exception as e:
                    logger.debug(f"Could not navigate back: {e}")
                    break  # Stop form submission for this page if we can't navigate back
                    
            except Exception as e:
                logger.debug(f"Error processing form: {e}")
        
        if submitted_count > 0:
            logger.info(f"Submitted {submitted_count} forms on {current_url}")
    
    def _is_in_scope(self, url: str, scope: Dict) -> bool:
        """Check if URL is within defined scope"""
        includes = scope.get('include', [])
        excludes = scope.get('exclude', [])
        
        # Check excludes first
        for pattern in excludes:
            if re.match(pattern.replace('*', '.*'), url):
                return False
        
        # Check includes
        for pattern in includes:
            if re.match(pattern.replace('*', '.*'), url):
                return True
        
        return len(includes) == 0  # If no includes, allow all
    
    def _is_same_domain(self, base_url: str, test_url: str) -> bool:
        """
        Check if URLs are on the same domain.
        
        STRICT MATCHING: Subdomains are treated as different domains.
        www.example.com and example.com are considered the same.
        api.example.com and example.com are considered DIFFERENT.
        
        This is important for subscription token counting - each subdomain
        is a separate token.
        """
        try:
            from .scope import ScopeManager
            return ScopeManager(base_url).is_same_domain(base_url, test_url)
        except Exception as e:
            logger.warning(f"Domain comparison failed: {e}")
            # Fallback to strict netloc comparison
            try:
                base_domain = urlparse(base_url).netloc.lower()
                test_domain = urlparse(test_url).netloc.lower()
                # Strip www. prefix for comparison
                if base_domain.startswith('www.'):
                    base_domain = base_domain[4:]
                if test_domain.startswith('www.'):
                    test_domain = test_domain[4:]
                return base_domain == test_domain
            except:
                return False
    
    async def _handle_popups_and_modals(self):
        """
        Handle common popups, modals, location selectors, and cookie banners.
        This is crucial for e-commerce sites that require location selection.
        Strategy: First try to INTERACT with popups (select something), then try to CLOSE them.
        
        Now supports Windows mode using sync wrappers for Playwright operations.
        """
        try:
            # Brief wait for popups to appear
            await asyncio.sleep(0.5)
            
            # Log current page state for debugging
            try:
                page_title = await self._page_title()
                logger.info(f"Handling popups on page: {page_title}")
            except:
                pass
            
            # 1. Handle cookie consent banners first (works on Windows via simplified approach)
            await self._dismiss_cookie_banners_safe()
            await asyncio.sleep(0.3)
            
            # 2. Handle location/city/area selector popups (CRITICAL for e-commerce)
            # On Windows, use simplified popup handling that works with sync API
            if self._is_windows:
                await self._handle_popups_windows_safe()
            else:
                location_handled = await self._handle_location_selector_interactive()
                if not location_handled:
                    await self._handle_location_selector()
            
            # 3. Handle any remaining generic modals
            await self._dismiss_generic_modals()
            
            # 5. Handle newsletter/subscription popups
            await self._dismiss_newsletter_popups()
            
            # 6. Final check - try to click any visible "Continue" or "Proceed" buttons
            await self._click_continue_buttons()
            
            logger.debug("Popup handling completed")
            
        except Exception as e:
            logger.debug(f"Popup handling error (non-fatal): {e}")
    
    async def _handle_location_selector_interactive(self) -> bool:
        """
        Interactively handle location selectors by selecting items in the popup.
        Returns True if handled successfully.
        """
        try:
            # Step 1: Check if any modal/popup is blocking the page
            blocking_overlay = await self._find_blocking_overlay()
            if not blocking_overlay:
                return False
            
            logger.info("Found blocking popup/modal, attempting to interact with it")
            
            # Step 2: Try to find and click any selectable items in the popup
            # These are common patterns for location/city selection
            clickable_item_selectors = [
                # List items - most common pattern
                '[class*="modal" i] li:not([class*="disabled"])',
                '[class*="popup" i] li:not([class*="disabled"])',
                '[class*="dialog" i] li:not([class*="disabled"])',
                '[role="dialog"] li',
                '[role="menu"] li',
                '[role="listbox"] [role="option"]',
                # City/Location specific
                '[class*="city" i]:not(input):not(select)',
                '[class*="location" i]:not(input):not(select)',
                '[class*="area" i]:not(input):not(select)',
                '[data-city]',
                '[data-location]',
                '[data-area]',
                # Card/button style options
                '[class*="modal" i] [class*="card" i]',
                '[class*="modal" i] [class*="item" i]',
                '[class*="modal" i] [class*="option" i]',
                '[class*="popup" i] [class*="card" i]',
                '[class*="popup" i] [class*="tile" i]',
                # Generic clickable items in modal
                '[class*="modal" i] button:not([class*="close" i])',
                '[class*="modal" i] a:not([class*="close" i])',
                '[class*="popup" i] button:not([class*="close" i])',
                # Radio buttons and checkboxes
                '[class*="modal" i] input[type="radio"]',
                '[class*="modal" i] label',
                '[class*="popup" i] input[type="radio"]',
                # Specific e-commerce patterns
                '[class*="service" i][class*="area" i]',
                '[class*="delivery" i][class*="zone" i]',
                '[class*="pin" i][class*="code" i]',
            ]
            
            for selector in clickable_item_selectors:
                try:
                    items = await self.page.query_selector_all(selector)
                    for item in items:
                        if await item.is_visible():
                            # Get text for logging
                            text = await item.inner_text()
                            text = text.strip()[:50] if text else "unknown"
                            
                            # Click the item
                            await item.click()
                            logger.info(f"Clicked popup item: '{text}' using selector: {selector}")
                            await asyncio.sleep(1)
                            
                            # Check if popup closed
                            if not await self._find_blocking_overlay():
                                logger.info("Popup successfully closed after selection")
                                return True
                            
                            # Sometimes need to click a confirm button after selection
                            await self._click_confirm_in_modal()
                            await asyncio.sleep(0.5)
                            
                            if not await self._find_blocking_overlay():
                                return True
                except Exception as e:
                    continue
            
            # Step 3: Try filling pincode/zipcode if present
            pincode_filled = await self._fill_pincode_in_modal()
            if pincode_filled:
                await asyncio.sleep(1)
                if not await self._find_blocking_overlay():
                    return True
            
            return False
            
        except Exception as e:
            logger.debug(f"Interactive location handler: {e}")
            return False
    
    async def _handle_popups_windows_safe(self):
        """
        Windows-safe popup handling that uses sync wrappers.
        Simplified approach that works with the ThreadPoolExecutor-based Playwright.
        """
        try:
            # Use JavaScript to find and click common popup close elements
            js_dismiss_popups = '''() => {
                let dismissed = 0;
                
                // Common close button patterns
                const closeSelectors = [
                    // Cookie banners
                    'button[id*="cookie" i][id*="accept" i]',
                    'button[class*="cookie" i][class*="accept" i]',
                    '#onetrust-accept-btn-handler',
                    '.cc-btn.cc-dismiss',
                    
                    // Generic close buttons
                    '[class*="modal" i] [class*="close" i]',
                    '[class*="popup" i] [class*="close" i]',
                    '[class*="modal" i] button[aria-label*="close" i]',
                    '[role="dialog"] button[aria-label*="close" i]',
                    
                    // X buttons
                    '.close-button',
                    '.btn-close',
                    '[data-dismiss="modal"]',
                    
                    // Accept/OK buttons (prioritized)
                    'button:not([disabled])',
                ];
                
                // Try accept buttons first
                const acceptPatterns = ['accept', 'ok', 'got it', 'agree', 'continue', 'skip'];
                document.querySelectorAll('button, a.btn, [role="button"]').forEach(el => {
                    const text = (el.innerText || '').toLowerCase().trim();
                    if (acceptPatterns.some(p => text.includes(p)) && el.offsetParent !== null) {
                        try {
                            el.click();
                            dismissed++;
                        } catch(e) {}
                    }
                });
                
                // Then try close buttons on modals
                closeSelectors.forEach(sel => {
                    try {
                        const el = document.querySelector(sel);
                        if (el && el.offsetParent !== null) {
                            el.click();
                            dismissed++;
                        }
                    } catch(e) {}
                });
                
                return dismissed;
            }'''
            
            dismissed = await self._page_evaluate(js_dismiss_popups)
            if dismissed > 0:
                logger.info(f"Windows popup handler dismissed {dismissed} element(s)")
                await asyncio.sleep(0.5)
                
        except Exception as e:
            logger.debug(f"Windows popup handler error: {e}")
    
    async def _dismiss_cookie_banners_safe(self):
        """Dismiss cookie consent banners - safe for both Windows and non-Windows"""
        try:
            # Use JavaScript approach which works on both platforms
            js_dismiss_cookies = '''() => {
                const acceptPatterns = [
                    'accept all', 'accept cookies', 'i accept', 'got it', 
                    'ok', 'agree', 'allow all', 'allow cookies', 'accept'
                ];
                
                let found = false;
                document.querySelectorAll('button, a, [role="button"]').forEach(el => {
                    if (found) return;
                    const text = (el.innerText || '').toLowerCase().trim();
                    if (acceptPatterns.some(p => text.includes(p)) && el.offsetParent !== null) {
                        // Check if likely a cookie button (near cookie-related text)
                        const parent = el.closest('[class*="cookie" i], [class*="consent" i], [class*="gdpr" i], [id*="cookie" i]');
                        if (parent || text.includes('cookie')) {
                            try {
                                el.click();
                                found = true;
                            } catch(e) {}
                        }
                    }
                });
                
                // Also try common cookie banner selectors
                const cookieSelectors = [
                    '#onetrust-accept-btn-handler',
                    '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
                    '.cc-btn.cc-dismiss',
                    '[data-testid="cookie-policy-manage-dialog-accept-button"]',
                ];
                
                if (!found) {
                    for (const sel of cookieSelectors) {
                        const el = document.querySelector(sel);
                        if (el && el.offsetParent !== null) {
                            el.click();
                            found = true;
                            break;
                        }
                    }
                }
                
                return found;
            }'''
            
            result = await self._page_evaluate(js_dismiss_cookies)
            if result:
                logger.debug("Cookie banner dismissed")
                
        except Exception as e:
            logger.debug(f"Cookie banner handling: {e}")
    
    async def _find_blocking_overlay(self):
        """Check if there's a blocking modal/popup overlay - works on Windows via JS"""
        # Use JavaScript approach which works on both platforms
        js_find_overlay = '''() => {
            const overlaySelectors = [
                '[class*="modal" i][class*="open" i]',
                '[class*="modal" i][class*="show" i]',
                '[class*="modal" i][class*="active" i]',
                '[class*="popup" i][class*="open" i]',
                '[class*="popup" i][class*="show" i]',
                '[class*="popup" i][class*="visible" i]',
                '[class*="overlay" i][class*="open" i]',
                '[role="dialog"][aria-modal="true"]',
                '[role="dialog"]:not([aria-hidden="true"])',
                '.modal.show',
                '.modal.in',
                '.popup.active',
            ];
            
            for (const sel of overlaySelectors) {
                const el = document.querySelector(sel);
                if (el && el.offsetParent !== null) {
                    return true;
                }
            }
            return false;
        }'''
        
        try:
            has_overlay = await self._page_evaluate(js_find_overlay)
            return has_overlay
        except:
            return False
    
    async def _click_confirm_in_modal(self):
        """Click confirm/submit/apply buttons inside a modal"""
        confirm_selectors = [
            '[class*="modal" i] button:has-text("Confirm")',
            '[class*="modal" i] button:has-text("Submit")',
            '[class*="modal" i] button:has-text("Apply")',
            '[class*="modal" i] button:has-text("Continue")',
            '[class*="modal" i] button:has-text("Done")',
            '[class*="modal" i] button:has-text("Save")',
            '[class*="modal" i] button:has-text("Select")',
            '[class*="modal" i] button:has-text("Proceed")',
            '[class*="modal" i] button[type="submit"]',
            '[class*="popup" i] button:has-text("Confirm")',
            '[class*="popup" i] button:has-text("Apply")',
            '[class*="popup" i] button:has-text("Continue")',
            '[class*="modal" i] input[type="submit"]',
            '[class*="modal" i] [class*="submit" i]',
            '[class*="modal" i] [class*="confirm" i]',
        ]
        
        for selector in confirm_selectors:
            try:
                element = await self.page.query_selector(selector)
                if element and await element.is_visible():
                    await element.click()
                    logger.debug(f"Clicked confirm button: {selector}")
                    await asyncio.sleep(0.5)
                    return True
            except:
                continue
        return False
    
    async def _fill_pincode_in_modal(self) -> bool:
        """Fill pincode/zipcode input in modal"""
        pincode_selectors = [
            '[class*="modal" i] input[type="text"]',
            '[class*="modal" i] input[type="tel"]',
            '[class*="modal" i] input[type="number"]',
            '[class*="popup" i] input[type="text"]',
            'input[name*="pincode" i]',
            'input[name*="zipcode" i]',
            'input[name*="postalcode" i]',
            'input[placeholder*="pincode" i]',
            'input[placeholder*="zip" i]',
            'input[placeholder*="postal" i]',
            'input[placeholder*="enter" i][placeholder*="code" i]',
            'input[id*="pincode" i]',
            'input[id*="zipcode" i]',
            '[class*="pincode" i] input',
            '[class*="zipcode" i] input',
        ]
        
        # Test pincodes for different countries
        test_pincodes = [
            '110001',  # Delhi, India
            '400001',  # Mumbai, India
            '10001',   # New York, USA
            '560001',  # Bangalore, India
            '122001',  # Gurgaon, India
            'SW1A 1AA',  # London, UK
        ]
        
        import random
        
        for selector in pincode_selectors:
            try:
                element = await self.page.query_selector(selector)
                if element and await element.is_visible():
                    # Check if it looks like a pincode input
                    placeholder = await element.get_attribute('placeholder') or ''
                    name = await element.get_attribute('name') or ''
                    
                    pincode = random.choice(test_pincodes)
                    await element.fill(pincode)
                    logger.info(f"Entered pincode: {pincode}")
                    
                    # Try pressing Enter or clicking a submit button
                    await element.press('Enter')
                    await asyncio.sleep(0.5)
                    
                    # Also try clicking any nearby submit button
                    await self._click_confirm_in_modal()
                    return True
            except:
                continue
        return False
    
    async def _click_continue_buttons(self):
        """Click any visible continue/proceed buttons that might be blocking"""
        continue_selectors = [
            'button:has-text("Continue")',
            'button:has-text("Proceed")',
            'button:has-text("Start")',
            'button:has-text("Get Started")',
            'button:has-text("Let\'s Go")',
            'button:has-text("Explore")',
            'button:has-text("Shop Now")',
            'button:has-text("Browse")',
            'a:has-text("Continue")',
            'a:has-text("Skip")',
            'button:has-text("Skip")',
        ]
        
        for selector in continue_selectors:
            try:
                element = await self.page.query_selector(selector)
                if element and await element.is_visible():
                    await element.click()
                    logger.debug(f"Clicked continue button: {selector}")
                    await asyncio.sleep(0.5)
                    return
            except:
                continue
    
    async def _dismiss_cookie_banners(self):
        """Dismiss cookie consent banners"""
        try:
            # Common cookie consent button selectors
            cookie_selectors = [
                'button[id*="cookie" i][id*="accept" i]',
                'button[class*="cookie" i][class*="accept" i]',
                'button:has-text("Accept")',
                'button:has-text("Accept All")',
                'button:has-text("Accept Cookies")',
                'button:has-text("I Accept")',
                'button:has-text("Got it")',
                'button:has-text("OK")',
                'button:has-text("Agree")',
                'a:has-text("Accept")',
                '[data-testid*="cookie" i] button',
                '.cookie-banner button',
                '#cookie-banner button',
                '.gdpr-banner button',
                '#onetrust-accept-btn-handler',
                '.cc-btn.cc-dismiss',
                '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
            ]
            
            for selector in cookie_selectors:
                try:
                    element = await self.page.query_selector(selector)
                    if element and await element.is_visible():
                        await element.click()
                        logger.debug(f"Dismissed cookie banner with: {selector}")
                        await asyncio.sleep(0.5)
                        return
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Cookie banner handling: {e}")
    
    async def _handle_location_selector(self):
        """
        Handle location/city selector popups common in e-commerce sites.
        Automatically selects a random available location to continue.
        """
        try:
            # Common location/city popup selectors
            location_popup_selectors = [
                '[class*="location" i][class*="modal" i]',
                '[class*="city" i][class*="selector" i]',
                '[class*="pincode" i]',
                '[class*="zipcode" i]',
                '[id*="location" i][id*="popup" i]',
                '[id*="city" i][id*="modal" i]',
                '[class*="delivery" i][class*="location" i]',
                '[data-testid*="location" i]',
                '.location-popup',
                '.city-selector',
                '#location-modal',
                '[class*="area" i][class*="select" i]',
            ]
            
            # Check if a location popup is visible
            popup_found = False
            for selector in location_popup_selectors:
                try:
                    element = await self.page.query_selector(selector)
                    if element and await element.is_visible():
                        popup_found = True
                        logger.debug(f"Found location popup: {selector}")
                        break
                except:
                    continue
            
            if popup_found:
                # Try to find and click a location/city option
                await self._select_random_location()
            else:
                # Check for "detect location" or "use current location" buttons
                await self._try_auto_detect_location()
                
        except Exception as e:
            logger.debug(f"Location selector handling: {e}")
    
    async def _select_random_location(self):
        """Select a random location from available options"""
        try:
            # Common location option selectors
            location_option_selectors = [
                # Clickable city/location items
                '[class*="city" i] li',
                '[class*="location" i] li',
                '[class*="city" i][class*="item" i]',
                '[class*="location" i][class*="item" i]',
                '[class*="city" i][class*="option" i]',
                '[data-city]',
                '[data-location]',
                '[class*="pincode" i] li',
                '.city-list li',
                '.location-list li',
                # Dropdown options
                '[class*="location" i] option',
                '[name*="city" i] option',
                '[name*="location" i] option',
                # Cards/buttons for areas
                '[class*="area" i][class*="card" i]',
                '[class*="zone" i][class*="item" i]',
            ]
            
            for selector in location_option_selectors:
                try:
                    options = await self.page.query_selector_all(selector)
                    if options and len(options) > 0:
                        # Click the first visible option
                        for option in options:
                            if await option.is_visible():
                                await option.click()
                                logger.info(f"Selected location using: {selector}")
                                await asyncio.sleep(1)
                                return True
                except:
                    continue
            
            # Try to find and fill a pincode/zipcode input
            pincode_selectors = [
                'input[name*="pincode" i]',
                'input[name*="zipcode" i]',
                'input[placeholder*="pincode" i]',
                'input[placeholder*="zip" i]',
                'input[placeholder*="postal" i]',
                'input[id*="pincode" i]',
                'input[id*="zipcode" i]',
            ]
            
            # Common test pincodes (Indian cities as example)
            test_pincodes = ['110001', '400001', '560001', '700001', '600001']  # Delhi, Mumbai, Bangalore, Kolkata, Chennai
            
            for selector in pincode_selectors:
                try:
                    element = await self.page.query_selector(selector)
                    if element and await element.is_visible():
                        import random
                        pincode = random.choice(test_pincodes)
                        await element.fill(pincode)
                        await element.press('Enter')
                        logger.info(f"Entered test pincode: {pincode}")
                        await asyncio.sleep(1)
                        return True
                except:
                    continue
            
            return False
            
        except Exception as e:
            logger.debug(f"Random location selection: {e}")
            return False
    
    async def _try_auto_detect_location(self):
        """Try to click 'detect my location' or 'use current location' buttons"""
        try:
            detect_location_selectors = [
                'button:has-text("Detect")',
                'button:has-text("Use Current Location")',
                'button:has-text("Auto Detect")',
                'button:has-text("Use My Location")',
                'a:has-text("Detect")',
                '[class*="detect" i][class*="location" i]',
                '[class*="gps" i]',
                '[class*="current" i][class*="location" i]',
            ]
            
            for selector in detect_location_selectors:
                try:
                    element = await self.page.query_selector(selector)
                    if element and await element.is_visible():
                        await element.click()
                        logger.debug(f"Clicked auto-detect location: {selector}")
                        await asyncio.sleep(1)
                        return
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Auto-detect location: {e}")
    
    async def _dismiss_generic_modals(self):
        """Dismiss generic modals and overlay popups"""
        try:
            # Common close button selectors for modals
            close_selectors = [
                'button[class*="close" i]',
                'button[aria-label*="close" i]',
                'button[aria-label*="dismiss" i]',
                '[class*="modal" i] [class*="close" i]',
                '[class*="popup" i] [class*="close" i]',
                '[class*="overlay" i] [class*="close" i]',
                '.modal .close',
                '.modal-close',
                '.popup-close',
                'button.close',
                '[data-dismiss="modal"]',
                '.modal button:has-text("x")',
                '.modal button:has-text("✕")',
                'svg[class*="close" i]',
                '[class*="modal" i] svg',
            ]
            
            for selector in close_selectors:
                try:
                    element = await self.page.query_selector(selector)
                    if element and await element.is_visible():
                        await element.click()
                        logger.debug(f"Closed modal with: {selector}")
                        await asyncio.sleep(0.5)
                        return
                except:
                    continue
            
            # Try pressing Escape key to close modals
            try:
                await self.page.keyboard.press('Escape')
                await asyncio.sleep(0.3)
            except:
                pass
                    
        except Exception as e:
            logger.debug(f"Generic modal handling: {e}")
    
    async def _dismiss_newsletter_popups(self):
        """Dismiss newsletter and subscription popups"""
        try:
            newsletter_close_selectors = [
                '[class*="newsletter" i] [class*="close" i]',
                '[class*="subscribe" i] [class*="close" i]',
                '[class*="signup" i] [class*="close" i]',
                'button:has-text("No Thanks")',
                'button:has-text("No, thanks")',
                'button:has-text("Maybe Later")',
                'button:has-text("Not Now")',
                'a:has-text("No Thanks")',
                '[class*="newsletter" i] button[class*="dismiss" i]',
            ]
            
            for selector in newsletter_close_selectors:
                try:
                    element = await self.page.query_selector(selector)
                    if element and await element.is_visible():
                        await element.click()
                        logger.debug(f"Dismissed newsletter popup: {selector}")
                        await asyncio.sleep(0.5)
                        return
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Newsletter popup handling: {e}")

    async def _auto_detect_login_form(self) -> Dict:
        """Auto-detect login form fields by inspecting the page source"""
        js_code = '''() => {
            const result = {
                username_field: null,
                password_field: null,
                submit_button: null,
                form_action: null,
                debug_info: []
            };
            
            // Find all forms on the page
            const forms = document.querySelectorAll('form');
            let loginForm = null;
            
            // Try to find the login form
            for (const form of forms) {
                const hasPassword = form.querySelector('input[type="password"]');
                if (hasPassword) {
                    loginForm = form;
                    result.form_action = form.action || window.location.href;
                    break;
                }
            }
            
            // If no form with password, search the whole page
            const searchContext = loginForm || document;
            
            // Find password field (most reliable indicator of login form)
            const passwordSelectors = [
                'input[type="password"]',
                'input[name*="pass" i]',
                'input[name*="pwd" i]',
                'input[id*="pass" i]',
                'input[id*="pwd" i]'
            ];
            
            for (const selector of passwordSelectors) {
                const el = searchContext.querySelector(selector);
                if (el) {
                    // Build a unique selector for this element
                    if (el.id) {
                        result.password_field = '#' + el.id;
                    } else if (el.name) {
                        result.password_field = 'input[name="' + el.name + '"]';
                    } else {
                        result.password_field = selector;
                    }
                    result.debug_info.push('Password field found: ' + result.password_field);
                    break;
                }
            }
            
            // Find username/email field
            const usernameSelectors = [
                'input[type="text"][name*="user" i]',
                'input[type="text"][name*="login" i]',
                'input[type="text"][name*="name" i]',
                'input[type="text"][name*="email" i]',
                'input[type="email"]',
                'input[name*="uname" i]',
                'input[name*="username" i]',
                'input[name*="user" i]',
                'input[name*="login" i]',
                'input[name*="email" i]',
                'input[id*="user" i]',
                'input[id*="login" i]',
                'input[id*="email" i]',
                'input[type="text"]:not([name*="pass"]):not([name*="pwd"])'
            ];
            
            for (const selector of usernameSelectors) {
                const el = searchContext.querySelector(selector);
                if (el && el !== searchContext.querySelector(result.password_field)) {
                    if (el.id) {
                        result.username_field = '#' + el.id;
                    } else if (el.name) {
                        result.username_field = 'input[name="' + el.name + '"]';
                    } else {
                        result.username_field = selector;
                    }
                    result.debug_info.push('Username field found: ' + result.username_field);
                    break;
                }
            }
            
            // Find submit button
            const submitSelectors = [
                'input[type="submit"]',
                'button[type="submit"]',
                'button:contains("Login")',
                'button:contains("Sign in")',
                'input[value*="Login" i]',
                'input[value*="Sign" i]',
                'input[value*="Submit" i]',
                'button[name*="login" i]',
                'button[name*="submit" i]',
                '#login-btn',
                '.login-btn',
                '.submit-btn',
                'button',
                'input[type="button"]'
            ];
            
            for (const selector of submitSelectors) {
                try {
                    const el = searchContext.querySelector(selector);
                    if (el) {
                        if (el.id) {
                            result.submit_button = '#' + el.id;
                        } else if (el.name) {
                            result.submit_button = (el.tagName.toLowerCase() === 'input' ? 'input' : 'button') + '[name="' + el.name + '"]';
                        } else if (el.type === 'submit') {
                            result.submit_button = el.tagName.toLowerCase() + '[type="submit"]';
                        } else {
                            result.submit_button = selector;
                        }
                        result.debug_info.push('Submit button found: ' + result.submit_button);
                        break;
                    }
                } catch (e) {
                    // Some selectors like :contains may not work, skip them
                }
            }
            
            // Fallback: find first visible text input before password as username
            if (!result.username_field && result.password_field) {
                const allInputs = Array.from(searchContext.querySelectorAll('input[type="text"], input:not([type])'));
                const passwordEl = searchContext.querySelector(result.password_field);
                for (const input of allInputs) {
                    if (input !== passwordEl && input.offsetParent !== null) {
                        if (input.id) {
                            result.username_field = '#' + input.id;
                        } else if (input.name) {
                            result.username_field = 'input[name="' + input.name + '"]';
                        }
                        result.debug_info.push('Username fallback: ' + result.username_field);
                        break;
                    }
                }
            }
            
            return result;
        }'''
        
        if self._is_windows:
            detected = await self._run_sync(self.page.evaluate, js_code)
        else:
            detected = await self.page.evaluate(js_code)
        
        return detected
    
    async def _close_popups(self):
        """Close common popups, modals, cookie banners, and welcome dialogs"""
        # On Windows, skip popup handling due to threading issues with complex element queries
        if self._is_windows:
            logger.debug("Popup closing skipped on Windows (sync API)")
            return
            
        popup_selectors = [
            # Juice Shop specific
            'button[aria-label="Close Welcome Banner"]',
            'a[aria-label="dismiss cookie message"]',
            'button.close-dialog',
            'mat-dialog-container button.close',
            '.cdk-overlay-backdrop',
            'button[aria-label="Close"]',
            
            # Generic popup/modal close buttons
            '.modal .close',
            '.modal-close',
            '.popup-close',
            '[data-dismiss="modal"]',
            '.cookie-banner .close',
            '.cookie-consent .accept',
            '.cookie-notice .accept',
            '#cookie-accept',
            '.accept-cookies',
            'button.accept-all',
            
            # Dialog close buttons
            '[role="dialog"] button[aria-label="Close"]',
            '[role="dialog"] .close-button',
            '.dialog-close',
            '.overlay-close',
            
            # Notification close
            '.notification .close',
            '.toast .close',
            '.alert .close',
        ]
        
        for selector in popup_selectors:
            try:
                elements = await self.page.query_selector_all(selector)
                for element in elements:
                    if await element.is_visible():
                        await element.click()
                        logger.info(f"Closed popup: {selector}")
                        await asyncio.sleep(0.3)
            except Exception as e:
                logger.debug(f"Popup close failed for {selector}: {e}")
        
        # Also try pressing Escape key to close any modal
        try:
            await self.page.keyboard.press('Escape')
            await asyncio.sleep(0.2)
        except:
            pass
        
        # Click outside modals to close them
        try:
            overlay = await self.page.query_selector('.cdk-overlay-backdrop, .modal-backdrop')
            if overlay and await overlay.is_visible():
                await overlay.click()
                await asyncio.sleep(0.3)
        except:
            pass

    async def dismiss_all_popups(self):
        """
        Comprehensive popup/overlay dismissal for login flow.
        Works on both Windows and non-Windows platforms using JavaScript.
        Call this before attempting login form detection.
        """
        logger.debug("Dismissing all popups and overlays before login...")
        
        # JavaScript-based approach that works on both platforms
        js_dismiss_all = '''() => {
            let dismissed = 0;
            
            // 1. Cookie banners - accept or dismiss
            const cookiePatterns = [
                'accept all', 'accept cookies', 'i accept', 'got it', 
                'ok', 'agree', 'allow all', 'allow cookies', 'accept',
                'continue', 'dismiss', 'close'
            ];
            
            const cookieContainers = document.querySelectorAll(
                '[class*="cookie" i], [class*="consent" i], [class*="gdpr" i], ' +
                '[id*="cookie" i], [id*="consent" i], [class*="privacy" i]'
            );
            
            cookieContainers.forEach(container => {
                const buttons = container.querySelectorAll('button, a, [role="button"]');
                buttons.forEach(btn => {
                    const text = (btn.innerText || '').toLowerCase().trim();
                    if (cookiePatterns.some(p => text.includes(p)) && btn.offsetParent !== null) {
                        try { btn.click(); dismissed++; } catch(e) {}
                    }
                });
            });
            
            // 2. Known cookie banner selectors
            const knownCookieSelectors = [
                '#onetrust-accept-btn-handler',
                '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',
                '.cc-btn.cc-dismiss',
                '[data-testid="cookie-policy-manage-dialog-accept-button"]',
                '#cookie-accept',
                '.cookie-accept',
                '#accept-cookies',
                '.accept-cookies-btn',
            ];
            
            knownCookieSelectors.forEach(sel => {
                const el = document.querySelector(sel);
                if (el && el.offsetParent !== null) {
                    try { el.click(); dismissed++; } catch(e) {}
                }
            });
            
            // 3. Generic modal close buttons
            const closeSelectors = [
                '[class*="modal" i] [class*="close" i]',
                '[class*="popup" i] [class*="close" i]',
                '[class*="overlay" i] [class*="close" i]',
                '[role="dialog"] [aria-label*="close" i]',
                '[role="dialog"] [class*="close" i]',
                '.modal .close',
                '.modal-close',
                '.popup-close',
                '[data-dismiss="modal"]',
                'button[aria-label="Close"]',
                'button[aria-label="close"]',
                '.close-button',
                '.dialog-close',
                '.btn-close',
                // Material UI / Angular
                'button.close-dialog',
                'mat-dialog-container button.close',
                '.cdk-overlay-pane button[mat-icon-button]',
            ];
            
            closeSelectors.forEach(sel => {
                document.querySelectorAll(sel).forEach(el => {
                    if (el.offsetParent !== null) {
                        try { el.click(); dismissed++; } catch(e) {}
                    }
                });
            });
            
            // 4. Click backdrop to close modals
            const backdropSelectors = [
                '.modal-backdrop',
                '.cdk-overlay-backdrop',
                '.overlay-backdrop',
                '[class*="backdrop" i]',
            ];
            
            backdropSelectors.forEach(sel => {
                const el = document.querySelector(sel);
                if (el && el.offsetParent !== null) {
                    try { el.click(); dismissed++; } catch(e) {}
                }
            });
            
            // 5. Newsletter/subscription popups
            const newsletterCloseSelectors = [
                '[class*="newsletter" i] [class*="close" i]',
                '[class*="subscribe" i] [class*="close" i]',
                '[class*="signup" i][class*="popup" i] [class*="close" i]',
                '[class*="promo" i] [class*="close" i]',
            ];
            
            newsletterCloseSelectors.forEach(sel => {
                document.querySelectorAll(sel).forEach(el => {
                    if (el.offsetParent !== null) {
                        try { el.click(); dismissed++; } catch(e) {}
                    }
                });
            });
            
            // 6. Welcome/onboarding dialogs
            const welcomeSelectors = [
                '[class*="welcome" i] [class*="close" i]',
                '[class*="welcome" i] button:last-child',
                '[class*="onboarding" i] [class*="skip" i]',
                '[class*="tour" i] [class*="skip" i]',
                '[class*="intro" i] [class*="close" i]',
            ];
            
            welcomeSelectors.forEach(sel => {
                document.querySelectorAll(sel).forEach(el => {
                    if (el.offsetParent !== null) {
                        try { el.click(); dismissed++; } catch(e) {}
                    }
                });
            });
            
            return dismissed;
        }'''
        
        try:
            dismissed = await self._page_evaluate(js_dismiss_all)
            if dismissed > 0:
                logger.info(f"Dismissed {dismissed} popup/overlay element(s)")
                await asyncio.sleep(0.5)
        except Exception as e:
            logger.debug(f"Popup dismissal error: {e}")
        
        # Also try pressing Escape key
        try:
            await self._page_press('body', 'Escape')
            await asyncio.sleep(0.2)
        except:
            pass

    async def is_login_form_visible(self) -> bool:
        """
        Check if a login form is currently visible on the page.
        Returns True if a password field is visible (main indicator of login form).
        """
        js_check_login_form = '''() => {
            // Password field is the primary indicator of a login form
            const passwordSelectors = [
                'input[type="password"]',
                'input[name*="pass" i]',
                'input[id*="pass" i]',
                'input[autocomplete="current-password"]',
                'input[autocomplete="new-password"]',
            ];
            
            for (const sel of passwordSelectors) {
                const el = document.querySelector(sel);
                if (el && el.offsetParent !== null) {
                    // Check if actually visible (not hidden)
                    const style = window.getComputedStyle(el);
                    if (style.display !== 'none' && 
                        style.visibility !== 'hidden' && 
                        style.opacity !== '0') {
                        return true;
                    }
                }
            }
            return false;
        }'''
        
        try:
            is_visible = await self._page_evaluate(js_check_login_form)
            return bool(is_visible)
        except Exception as e:
            logger.debug(f"Login form visibility check error: {e}")
            return False

    async def discover_and_click_login_trigger(self) -> bool:
        """
        Find and click login buttons/links to reveal the login form.
        Use this when the login form is not immediately visible on the page
        (common in SPAs where landing page == login page).
        
        Returns True if a login trigger was found and clicked.
        """
        logger.info("Searching for login trigger elements...")
        
        # JavaScript to find login-related clickable elements
        js_find_login_triggers = '''() => {
            const triggers = [];
            
            // Text patterns that indicate login buttons/links
            const loginTextPatterns = [
                'log in', 'login', 'sign in', 'signin', 'sign-in',
                'account', 'my account', 'member login', 'user login',
                'already have an account', 'existing user', 'returning customer'
            ];
            
            // Elements to check: links, buttons, divs with click handlers
            const clickableSelectors = [
                'a', 'button', '[role="button"]', '[onclick]',
                '[class*="login" i]', '[class*="signin" i]',
                '[id*="login" i]', '[id*="signin" i]',
                '[data-action*="login" i]', '[data-action*="signin" i]',
            ];
            
            const allClickables = document.querySelectorAll(clickableSelectors.join(', '));
            
            allClickables.forEach(el => {
                // Skip if not visible
                if (el.offsetParent === null) return;
                
                const text = (el.innerText || el.textContent || '').toLowerCase().trim();
                const href = (el.getAttribute('href') || '').toLowerCase();
                const className = (el.className || '').toLowerCase();
                const id = (el.id || '').toLowerCase();
                const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
                
                let score = 0;
                let matchReason = [];
                
                // Check text content
                for (const pattern of loginTextPatterns) {
                    if (text.includes(pattern)) {
                        score += 10;
                        matchReason.push('text:' + pattern);
                    }
                }
                
                // Check href
                if (href.includes('login') || href.includes('signin') || href.includes('sign-in')) {
                    score += 8;
                    matchReason.push('href');
                }
                
                // Check class/id
                if (className.includes('login') || className.includes('signin')) {
                    score += 5;
                    matchReason.push('class');
                }
                if (id.includes('login') || id.includes('signin')) {
                    score += 5;
                    matchReason.push('id');
                }
                
                // Check aria-label
                if (ariaLabel.includes('login') || ariaLabel.includes('sign in')) {
                    score += 7;
                    matchReason.push('aria');
                }
                
                // Penalize if it looks like a registration/signup button
                if (text.includes('register') || text.includes('sign up') || 
                    text.includes('signup') || text.includes('create account') ||
                    text.includes('new account') || text.includes('join')) {
                    score -= 15;
                }
                
                // Penalize if it's in a footer (less likely to be main login)
                if (el.closest('footer') || el.closest('[class*="footer" i]')) {
                    score -= 3;
                }
                
                // Boost if in header/nav (more likely to be main login)
                if (el.closest('header') || el.closest('nav') || 
                    el.closest('[class*="header" i]') || el.closest('[class*="nav" i]')) {
                    score += 3;
                }
                
                if (score > 0) {
                    // Build a selector for this element
                    let selector = '';
                    if (el.id) {
                        selector = '#' + CSS.escape(el.id);
                    } else if (el.className && typeof el.className === 'string') {
                        const classes = el.className.split(/\\s+/).filter(c => c).slice(0, 2);
                        if (classes.length > 0) {
                            selector = el.tagName.toLowerCase() + '.' + classes.map(c => CSS.escape(c)).join('.');
                        }
                    }
                    if (!selector) {
                        selector = el.tagName.toLowerCase();
                        if (text.length < 30) {
                            selector += ':has-text("' + text.substring(0, 20) + '")';
                        }
                    }
                    
                    triggers.push({
                        selector: selector,
                        text: text.substring(0, 50),
                        score: score,
                        reason: matchReason.join(', ')
                    });
                }
            });
            
            // Sort by score descending
            triggers.sort((a, b) => b.score - a.score);
            
            return triggers.slice(0, 10); // Return top 10 candidates
        }'''
        
        try:
            triggers = await self._page_evaluate(js_find_login_triggers)
            
            if not triggers:
                logger.debug("No login triggers found on page")
                return False
            
            logger.info(f"Found {len(triggers)} potential login trigger(s)")
            
            # Try clicking the highest-scored trigger
            for trigger in triggers:
                logger.debug(f"Trying login trigger: {trigger.get('text', '')[:30]} (score: {trigger.get('score')}, reason: {trigger.get('reason')})")
                
                try:
                    # Try to click by selector
                    selector = trigger.get('selector', '')
                    if selector:
                        await self._page_click(selector, timeout=3000)
                        await asyncio.sleep(1)  # Wait for form to appear
                        
                        # Check if login form is now visible
                        if await self.is_login_form_visible():
                            logger.info(f"Login form revealed after clicking: {trigger.get('text', '')[:30]}")
                            return True
                        
                        # Check if we navigated to a different page
                        # (some sites redirect to login page instead of showing modal)
                        await asyncio.sleep(0.5)
                        if await self.is_login_form_visible():
                            logger.info("Login form visible after navigation")
                            return True
                            
                except Exception as e:
                    logger.debug(f"Failed to click trigger '{trigger.get('selector')}': {e}")
                    continue
            
            logger.warning("Clicked login triggers but no login form appeared")
            return False
            
        except Exception as e:
            logger.error(f"Login trigger discovery failed: {e}")
            return False

    async def find_login_form_elements(self) -> Dict[str, Optional[str]]:
        """
        Dynamically discover login form elements (username, password, submit).
        Returns a dict with selectors for each element found.
        
        Use this when the user hasn't provided explicit selectors.
        """
        js_find_login_elements = '''() => {
            const result = {
                username_field: null,
                password_field: null,
                submit_button: null,
                form: null,
                debug_info: []
            };
            
            // Find password field first (most reliable indicator)
            const passwordSelectors = [
                'input[type="password"]',
                'input[name*="pass" i]',
                'input[autocomplete="current-password"]',
            ];
            
            for (const sel of passwordSelectors) {
                const el = document.querySelector(sel);
                if (el && el.offsetParent !== null) {
                    result.password_field = sel;
                    result.debug_info.push('Password: ' + sel);
                    
                    // Look for form containing this password field
                    const form = el.closest('form');
                    if (form) {
                        result.form = form.id ? '#' + form.id : 
                            (form.name ? 'form[name="' + form.name + '"]' : 'form');
                    }
                    break;
                }
            }
            
            if (!result.password_field) {
                result.debug_info.push('No password field found');
                return result;
            }
            
            // Find username/email field
            const usernameSelectors = [
                'input[type="email"]',
                'input[name*="email" i]',
                'input[name*="user" i]',
                'input[name*="login" i]',
                'input[autocomplete="email"]',
                'input[autocomplete="username"]',
                'input[type="text"][name]',
                'input[type="text"][id]',
            ];
            
            // Get password field element for proximity check
            const passwordEl = document.querySelector(result.password_field);
            const form = passwordEl ? passwordEl.closest('form') : null;
            
            for (const sel of usernameSelectors) {
                const elements = form ? 
                    form.querySelectorAll(sel) : 
                    document.querySelectorAll(sel);
                    
                for (const el of elements) {
                    if (el && el.offsetParent !== null && el.type !== 'password') {
                        // Prefer elements before password field in DOM
                        if (!passwordEl || 
                            el.compareDocumentPosition(passwordEl) & Node.DOCUMENT_POSITION_FOLLOWING) {
                            result.username_field = el.id ? '#' + el.id : 
                                (el.name ? 'input[name="' + el.name + '"]' : sel);
                            result.debug_info.push('Username: ' + result.username_field);
                            break;
                        }
                    }
                }
                if (result.username_field) break;
            }
            
            // Find submit button
            const submitSelectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Log in")',
                'button:has-text("Login")',
                'button:has-text("Sign in")',
                'button:has-text("Submit")',
                'button:has-text("Continue")',
                '[role="button"]:has-text("Log in")',
                '[role="button"]:has-text("Sign in")',
            ];
            
            const searchIn = form || document;
            
            for (const sel of submitSelectors) {
                try {
                    const el = searchIn.querySelector(sel);
                    if (el && el.offsetParent !== null) {
                        result.submit_button = el.id ? '#' + el.id : sel;
                        result.debug_info.push('Submit: ' + result.submit_button);
                        break;
                    }
                } catch (e) {
                    // :has-text is Playwright-specific, skip in browser
                }
            }
            
            // Fallback: find any button in form
            if (!result.submit_button && form) {
                const btn = form.querySelector('button') || 
                           form.querySelector('input[type="submit"]');
                if (btn && btn.offsetParent !== null) {
                    result.submit_button = btn.id ? '#' + btn.id : 
                        (btn.type === 'submit' ? 'button[type="submit"]' : 'button');
                    result.debug_info.push('Submit (fallback): ' + result.submit_button);
                }
            }
            
            return result;
        }'''
        
        try:
            result = await self._page_evaluate(js_find_login_elements)
            logger.debug(f"Login form discovery: {result.get('debug_info', [])}")
            return result
        except Exception as e:
            logger.error(f"Login form element discovery failed: {e}")
            return {
                'username_field': None,
                'password_field': None,
                'submit_button': None,
                'form': None,
                'debug_info': [f'Error: {e}']
            }

    def set_scan_context(self, scan_id: str, two_factor_config: Optional[Dict] = None):
        """Set scan context for 2FA handling
        
        Args:
            scan_id: The scan ID for OTP coordination
            two_factor_config: 2FA configuration dict with keys:
                - enabled: bool
                - type: 'email', 'sms', or 'authenticator'
                - email: email address (for email type)
                - phone: phone number (for sms type)
        """
        # Unregister from old scan_id if changing
        if self._scan_id and self._scan_id in BrowserController._instances:
            BrowserController._instances.pop(self._scan_id, None)
        
        self._scan_id = scan_id
        self._2fa_config = two_factor_config or {}
        
        # Register this instance for force-cleanup capability
        if scan_id:
            BrowserController._instances[scan_id] = self
            logger.debug(f"Registered browser for scan {scan_id}")
        
        if self._2fa_config.get('enabled'):
            logger.info(f"2FA enabled for scan {scan_id}: type={self._2fa_config.get('type')}")

    async def _detect_2fa_page(self) -> bool:
        """Detect if the current page is a 2FA/OTP verification page"""
        # Common 2FA page indicators
        otp_indicators = [
            # Input fields for OTP
            'input[name*="otp"]',
            'input[name*="code"]',
            'input[name*="token"]',
            'input[name*="verification"]',
            'input[name*="2fa"]',
            'input[name*="mfa"]',
            'input[placeholder*="code"]',
            'input[placeholder*="OTP"]',
            'input[placeholder*="verification"]',
            'input[type="tel"][maxlength="6"]',
            'input[maxlength="6"][pattern="[0-9]*"]',
            
            # Common 2FA labels/text
            'label:has-text("verification code")',
            'label:has-text("OTP")',
            'label:has-text("two-factor")',
            'label:has-text("2FA")',
            
            # Common container classes
            '.otp-input',
            '.verification-code',
            '.two-factor',
            '.mfa-form',
            '#otp-form',
            '#verification-form',
        ]
        
        for selector in otp_indicators:
            try:
                element = await self._page_query_selector(selector)
                if element and await self._element_is_visible(element):
                    logger.info(f"2FA page detected via: {selector}")
                    return True
            except:
                continue
        
        # Also check page content for 2FA keywords
        try:
            page_content = await self._page_content()
            content_lower = page_content.lower()
            keywords = [
                'verification code',
                'enter the code',
                'two-factor',
                '2fa',
                'one-time password',
                'otp',
                'sent to your email',
                'sent to your phone',
                'sms code',
                'authenticator app'
            ]
            for keyword in keywords:
                if keyword in content_lower:
                    # Make sure we're not on login page
                    if 'password' not in content_lower or 'verification' in content_lower:
                        logger.info(f"2FA page detected via keyword: {keyword}")
                        return True
        except:
            pass
        
        return False

    async def _find_otp_input(self) -> Optional[str]:
        """Find the OTP input field selector"""
        otp_input_selectors = [
            'input[name*="otp"]',
            'input[name*="code"]',
            'input[name*="token"]',
            'input[name*="verification"]',
            'input[name*="2fa"]',
            'input[name*="mfa"]',
            'input[placeholder*="code"]',
            'input[placeholder*="OTP"]',
            'input[type="tel"][maxlength="6"]',
            'input[maxlength="6"][pattern]',
            'input[maxlength="6"]',
            'input[maxlength="4"]',
            '.otp-input input',
            '#otp',
            '#verification-code',
            '#code',
        ]
        
        for selector in otp_input_selectors:
            try:
                element = await self._page_query_selector(selector)
                if element and await self._element_is_visible(element):
                    return selector
            except:
                continue
        
        return None

    async def _handle_2fa(self, success_indicator: str) -> bool:
        """Handle 2FA authentication if detected
        
        Returns True if 2FA was handled successfully, False otherwise
        """
        # Check if 2FA is enabled for this scan
        if not self._2fa_config or not self._2fa_config.get('enabled'):
            logger.debug("2FA not configured for this scan")
            return False
        
        # Check if we're on a 2FA page
        is_2fa_page = await self._detect_2fa_page()
        if not is_2fa_page:
            return False
        
        logger.info("2FA page detected, waiting for user to provide OTP...")
        
        # Import the OTP handling functions from services layer (not routes!)
        try:
            from services.otp_service import (
                wait_for_otp, set_otp_error, clear_scan_otp_state,
                set_scan_waiting_for_otp, reset_otp_for_retry
            )
        except ImportError:
            logger.error("Could not import OTP service module")
            return False
        
        if not self._scan_id:
            logger.error("No scan ID set for OTP handling")
            return False
        
        # Get 2FA type and contact info
        otp_type = self._2fa_config.get('type', 'email')
        contact = self._2fa_config.get('email') or self._2fa_config.get('phone') or ''
        
        # Set scan as waiting for OTP
        set_scan_waiting_for_otp(self._scan_id, otp_type, contact, timeout_seconds=300)
        
        # Wait for user to submit OTP (this blocks until OTP is provided or timeout)
        max_attempts = 3
        for attempt in range(max_attempts):
            otp = await wait_for_otp(
                scan_id=self._scan_id,
                timeout=300,  # 5 minutes
                poll_interval=2.0
            )
            
            if not otp:
                logger.warning("OTP timeout - no code received from user")
                return False
            
            logger.info(f"OTP received, attempting to enter code (attempt {attempt + 1}/{max_attempts})")
            
            # Find the OTP input field
            otp_selector = await self._find_otp_input()
            if not otp_selector:
                logger.error("Could not find OTP input field")
                set_otp_error(self._scan_id, "Could not find OTP input field on target website")
                return False
            
            # Enter the OTP
            try:
                await self._page_fill(otp_selector, otp)
                await asyncio.sleep(0.5)
                
                # Submit the OTP form
                submit_clicked = False
                submit_selectors = [
                    'button[type="submit"]',
                    'button:has-text("Verify")',
                    'button:has-text("Submit")',
                    'button:has-text("Continue")',
                    'button:has-text("Confirm")',
                    'input[type="submit"]',
                    '#verify-btn',
                    '#submit-otp',
                ]
                
                for submit_sel in submit_selectors:
                    try:
                        btn = await self._page_query_selector(submit_sel)
                        if btn and await self._element_is_visible(btn):
                            await self._element_click(btn)
                            submit_clicked = True
                            logger.info(f"Clicked OTP submit button: {submit_sel}")
                            break
                    except:
                        continue
                
                if not submit_clicked:
                    # Try pressing Enter
                    await self._page_press(otp_selector, 'Enter')
                    logger.info("Submitted OTP via Enter key")
                
                # Wait for navigation
                try:
                    await self._page_wait_for_load_state('networkidle', timeout=10000)
                except:
                    pass
                await asyncio.sleep(2)
                
                # Check if still on 2FA page (OTP might be invalid)
                still_on_2fa = await self._detect_2fa_page()
                
                # Look for error messages
                error_selectors = [
                    '.error',
                    '.alert-danger',
                    '.error-message',
                    '[role="alert"]',
                    '.invalid-feedback',
                ]
                
                has_error = False
                for err_sel in error_selectors:
                    try:
                        err_el = await self._page_query_selector(err_sel)
                        if err_el and await self._element_is_visible(err_el):
                            error_text = await self._element_text_content(err_el)
                            if error_text and ('invalid' in error_text.lower() or 
                                             'incorrect' in error_text.lower() or
                                             'expired' in error_text.lower() or
                                             'wrong' in error_text.lower()):
                                has_error = True
                                set_otp_error(self._scan_id, f"OTP verification failed: {error_text.strip()}")
                                logger.warning(f"OTP error detected: {error_text}")
                                break
                    except:
                        continue
                
                if still_on_2fa or has_error:
                    if attempt < max_attempts - 1:
                        logger.info("OTP verification failed, waiting for new code...")
                        # Reset for retry - already imported at top of function
                        reset_otp_for_retry(self._scan_id)
                        continue
                    else:
                        logger.error("Max OTP attempts reached")
                        set_otp_error(self._scan_id, "Maximum OTP attempts reached")
                        return False
                
                # Check for success
                current_url = self.page.url
                success = success_indicator in current_url
                
                if success:
                    logger.info("2FA authentication successful!")
                    clear_scan_otp_state(self._scan_id)
                    return True
                
                # Also check for logout button as success indicator
                logout_indicators = [
                    'button:has-text("Logout")',
                    'a:has-text("Logout")',
                    'button:has-text("Sign out")',
                    'a:has-text("Sign out")',
                ]
                for indicator in logout_indicators:
                    try:
                        el = await self._page_query_selector(indicator)
                        if el and await self._element_is_visible(el):
                            logger.info("2FA authentication successful (logout button found)!")
                            clear_scan_otp_state(self._scan_id)
                            return True
                    except:
                        continue
                
                # If we got here and we're not on 2FA page anymore, assume success
                if not still_on_2fa:
                    logger.info("2FA authentication likely successful (left 2FA page)")
                    clear_scan_otp_state(self._scan_id)
                    return True
                
            except Exception as e:
                logger.error(f"Error during OTP entry: {e}")
                set_otp_error(self._scan_id, f"Error entering OTP: {str(e)}")
                if attempt < max_attempts - 1:
                    continue
                return False
        
        return False

    async def authenticate(
        self,
        login_url: str,
        credentials: Dict,
        selectors: Dict,
        success_indicator: str
    ) -> bool:
        """Perform authentication with smart form detection"""
        try:
            # Navigate to login page
            if self._is_windows:
                await self._run_sync(self.page.goto, login_url, wait_until='networkidle', timeout=30000)
            else:
                await self.page.goto(login_url, wait_until='networkidle', timeout=30000)
            
            # Wait for page to fully load
            await asyncio.sleep(1)
            
            # Close any popups/modals that might interfere
            await self._close_popups()
            await asyncio.sleep(0.5)
            
            # Auto-detect form fields
            detected = await self._auto_detect_login_form()
            logger.info(f"Auto-detected form fields: {detected}")
            
            # Use detected selectors, fallback to provided selectors
            username_selector = detected.get('username_field') or selectors.get('username_field')
            password_selector = detected.get('password_field') or selectors.get('password_field')
            submit_selector = detected.get('submit_button') or selectors.get('submit_button')
            
            if not username_selector or not password_selector:
                logger.error(f"Could not detect login form fields. Detected: {detected}")
                return False
            
            logger.info(f"Using selectors - Username: {username_selector}, Password: {password_selector}, Submit: {submit_selector}")
            
            # Wait for elements to be available
            try:
                if self._is_windows:
                    await self._run_sync(self.page.wait_for_selector, username_selector, timeout=5000)
                    await self._run_sync(self.page.wait_for_selector, password_selector, timeout=5000)
                else:
                    await self.page.wait_for_selector(username_selector, timeout=5000)
                    await self.page.wait_for_selector(password_selector, timeout=5000)
            except Exception as e:
                logger.error(f"Form fields not found after detection: {e}")
                return False

            # Fill credentials
            if self._is_windows:
                await self._run_sync(self.page.fill, username_selector, credentials['username'])
                await self._run_sync(self.page.fill, password_selector, credentials['password'])
            else:
                await self.page.fill(username_selector, credentials['username'])
                await self.page.fill(password_selector, credentials['password'])
            
            logger.info(f"Filled credentials for user: {credentials['username']}")

            # Submit form - try multiple methods
            submitted = False
            
            # Method 1: Click submit button if found
            if submit_selector:
                try:
                    if self._is_windows:
                        await self._run_sync(self.page.click, submit_selector)
                    else:
                        await self.page.click(submit_selector)
                    submitted = True
                    logger.info("Submitted form via button click")
                except Exception as e:
                    logger.debug(f"Submit button click failed: {e}")
            
            # Method 2: Press Enter on password field
            if not submitted:
                try:
                    if self._is_windows:
                        await self._run_sync(self.page.press, password_selector, 'Enter')
                    else:
                        await self.page.press(password_selector, 'Enter')
                    submitted = True
                    logger.info("Submitted form via Enter key")
                except Exception as e:
                    logger.debug(f"Enter key submit failed: {e}")
            
            # Method 3: Submit the form directly
            if not submitted:
                try:
                    js_code = '''() => {
                        const form = document.querySelector('form');
                        if (form) form.submit();
                    }'''
                    if self._is_windows:
                        await self._run_sync(self.page.evaluate, js_code)
                    else:
                        await self.page.evaluate(js_code)
                    submitted = True
                    logger.info("Submitted form via JavaScript")
                except Exception as e:
                    logger.error(f"All form submit methods failed: {e}")
                    return False

            # Wait for navigation with timeout
            try:
                if self._is_windows:
                    await self._run_sync(self.page.wait_for_load_state, 'networkidle', timeout=15000)
                else:
                    await self.page.wait_for_load_state('networkidle', timeout=15000)
            except Exception as e:
                logger.debug(f"Networkidle timeout, continuing: {e}")
            await asyncio.sleep(2)  # Extra wait for redirects and SPA navigation

            # ========== 2FA CHECK ==========
            # Check if the target website requires 2FA after initial login
            if self._2fa_config and self._2fa_config.get('enabled'):
                is_2fa_page = await self._detect_2fa_page()
                if is_2fa_page:
                    logger.info("Target website requires 2FA, initiating OTP flow...")
                    twofa_success = await self._handle_2fa(success_indicator)
                    if twofa_success:
                        logger.info("2FA authentication completed successfully")
                        return True
                    else:
                        logger.error("2FA authentication failed")
                        return False
            # ================================

            # Check for success using multiple methods
            current_url = self.page.url
            logger.info(f"Post-login URL: {current_url}")
            
            success = False
            
            # Method 1: Check for common logged-in indicators (logout button, user menu, etc.)
            logged_in_indicators = [
                'button:has-text("Logout")',
                'a:has-text("Logout")',
                'button:has-text("Log out")',
                'a:has-text("Log out")',
                'button:has-text("Sign out")',
                'a:has-text("Sign out")',
                '[aria-label="Logout"]',
                '[aria-label="Account"]',
                'button:has-text("Account")',
                'a:has-text("Account")',
                'a:has-text("My Account")',
                'button:has-text("My Account")',
                '.user-menu',
                '.account-menu',
                '#userMenu',
                '#accountMenu',
                '[data-testid="user-menu"]',
                'mat-icon:has-text("account_circle")',
                'button[mattooltip="Account"]',
                'button[aria-label="Show the shopping cart"]',  # Juice Shop specific
            ]
            
            for indicator in logged_in_indicators:
                try:
                    element = await self._page_query_selector(indicator)
                    if element and await self._element_is_visible(element):
                        success = True
                        logger.info(f"Login confirmed via indicator: {indicator}")
                        break
                except Exception as e:
                    logger.debug(f"Indicator check failed for {indicator}: {e}")
            
            # Method 2: Check URL-based success indicator
            if not success:
                is_url_indicator = (
                    success_indicator.startswith('/') or
                    success_indicator.startswith('http') or
                    success_indicator.startswith('#') or
                    '.php' in success_indicator or
                    '.html' in success_indicator or
                    '.aspx' in success_indicator or
                    '.jsp' in success_indicator or
                    '/' in success_indicator
                )
                
                if is_url_indicator:
                    success = success_indicator in current_url
                    logger.info(f"URL-based check: '{success_indicator}' in '{current_url}' = {success}")
                else:
                    # Treat as CSS selector
                    try:
                        element = await self._page_query_selector(success_indicator)
                        success = element is not None
                        logger.info(f"Selector-based check: '{success_indicator}' found = {success}")
                    except Exception as e:
                        logger.debug(f"Selector check failed: {e}")
            
            # Method 3: Check if login form is gone (we're no longer on login page)
            if not success:
                login_form_visible = False
                try:
                    login_form = await self._page_query_selector('input[type="password"]:visible')
                    login_form_visible = login_form is not None and await self._element_is_visible(login_form)
                except:
                    pass
                
                if not login_form_visible and '/login' not in current_url.lower():
                    success = True
                    logger.info("Login confirmed: password field no longer visible and not on login page")
            
            if success:
                logger.info("Authentication successful!")
            else:
                logger.warning(f"Authentication may have failed. Current URL: {current_url}, Expected indicator: {success_indicator}")
                
                # Try to signup if login failed
                logger.info("Attempting automatic signup...")
                signup_success = await self._try_signup(login_url, credentials)
                
                if signup_success:
                    logger.info("Signup successful! Retrying login...")
                    # Navigate back to login page and retry
                    await self._page_goto(login_url, wait_until='networkidle', timeout=30000)
                    await asyncio.sleep(1)
                    
                    # Close popups again on login page
                    await self._close_popups()
                    await asyncio.sleep(0.5)
                    
                    # Re-detect form and fill credentials
                    detected = await self._auto_detect_login_form()
                    username_selector = detected.get('username_field') or selectors.get('username_field')
                    password_selector = detected.get('password_field') or selectors.get('password_field')
                    submit_selector = detected.get('submit_button') or selectors.get('submit_button')
                    
                    await self._page_wait_for_selector(username_selector, timeout=5000)
                    await self._page_fill(username_selector, credentials['username'])
                    await self._page_fill(password_selector, credentials['password'])
                    
                    if submit_selector:
                        await self._page_click(submit_selector)
                    else:
                        await self._page_press(password_selector, 'Enter')
                    
                    try:
                        await self._page_wait_for_load_state('networkidle', timeout=15000)
                    except:
                        pass
                    await asyncio.sleep(1)
                    
                    # Check success again
                    current_url = self.page.url
                    if is_url_indicator:
                        success = success_indicator in current_url
                    else:
                        try:
                            success = await self._page_query_selector(success_indicator) is not None
                        except:
                            success = False
                    
                    if success:
                        logger.info("Login after signup successful!")
            
            return success

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False
    
    async def _try_signup(self, login_url: str, credentials: Dict) -> bool:
        """Attempt to signup/register with the provided credentials"""
        try:
            # Common signup link selectors
            signup_link_selectors = [
                'a:has-text("Not yet a customer")',
                'a:has-text("Sign up")',
                'a:has-text("Register")',
                'a:has-text("Create account")',
                'a:has-text("Create an account")',
                'a:has-text("New customer")',
                'a:has-text("New user")',
                'a[href*="register"]',
                'a[href*="signup"]',
                'a[href*="sign-up"]',
                'a[href*="registration"]',
                'button:has-text("Sign up")',
                'button:has-text("Register")',
            ]
            
            # Try to find and click signup link
            signup_clicked = False
            for selector in signup_link_selectors:
                try:
                    element = await self._page_query_selector(selector)
                    if element:
                        await self._element_click(element)
                        signup_clicked = True
                        logger.info(f"Clicked signup link: {selector}")
                        break
                except Exception as e:
                    logger.debug(f"Signup selector {selector} failed: {e}")
            
            if not signup_clicked:
                logger.warning("Could not find signup link")
                return False
            
            # Wait for signup page to load
            try:
                await self._page_wait_for_load_state('networkidle', timeout=10000)
            except:
                pass
            await asyncio.sleep(1)
            
            # Close any popups on registration page
            await self._close_popups()
            await asyncio.sleep(0.5)
            
            # Detect registration form fields
            reg_fields = await self._page_evaluate('''() => {
                const result = {
                    email_field: null,
                    password_field: null,
                    confirm_password_field: null,
                    submit_button: null,
                    security_question: null,
                    security_answer: null,
                    debug_info: []
                };
                
                // Find email field
                const emailSelectors = [
                    'input#emailControl',
                    'input[type="email"]',
                    'input[name*="email" i]',
                    'input[id*="email" i]',
                    'input[placeholder*="email" i]'
                ];
                for (const sel of emailSelectors) {
                    const el = document.querySelector(sel);
                    if (el) {
                        result.email_field = el.id ? '#' + el.id : (el.name ? 'input[name="' + el.name + '"]' : sel);
                        result.debug_info.push('Email: ' + result.email_field);
                        break;
                    }
                }
                
                // Find password fields (there may be two for confirmation)
                const passwordFields = document.querySelectorAll('input[type="password"]');
                if (passwordFields.length >= 1) {
                    const p1 = passwordFields[0];
                    result.password_field = p1.id ? '#' + p1.id : (p1.name ? 'input[name="' + p1.name + '"]' : 'input[type="password"]');
                    result.debug_info.push('Password: ' + result.password_field);
                }
                if (passwordFields.length >= 2) {
                    const p2 = passwordFields[1];
                    result.confirm_password_field = p2.id ? '#' + p2.id : (p2.name ? 'input[name="' + p2.name + '"]' : null);
                    result.debug_info.push('Confirm password: ' + result.confirm_password_field);
                }
                
                // Find security question dropdown (Juice Shop specific)
                const securitySelect = document.querySelector('select, mat-select, [role="listbox"]');
                if (securitySelect) {
                    result.security_question = securitySelect.id ? '#' + securitySelect.id : 'mat-select';
                    result.debug_info.push('Security question: ' + result.security_question);
                }
                
                // Find security answer field
                const answerSelectors = [
                    'input#securityAnswerControl',
                    'input[name*="security" i]',
                    'input[name*="answer" i]',
                    'input[placeholder*="answer" i]'
                ];
                for (const sel of answerSelectors) {
                    const el = document.querySelector(sel);
                    if (el) {
                        result.security_answer = el.id ? '#' + el.id : sel;
                        result.debug_info.push('Security answer: ' + result.security_answer);
                        break;
                    }
                }
                
                // Find submit button
                const submitSelectors = [
                    'button#registerButton',
                    'button[type="submit"]',
                    'button:contains("Register")',
                    'button:contains("Sign up")',
                    'button:contains("Create")',
                    'input[type="submit"]'
                ];
                for (const sel of submitSelectors) {
                    try {
                        const el = document.querySelector(sel);
                        if (el) {
                            result.submit_button = el.id ? '#' + el.id : sel;
                            result.debug_info.push('Submit: ' + result.submit_button);
                            break;
                        }
                    } catch (e) {}
                }
                
                return result;
            }''')
            
            logger.info(f"Detected registration form: {reg_fields}")
            
            # Fill registration form
            if reg_fields.get('email_field'):
                await self._page_fill(reg_fields['email_field'], credentials['username'])
                logger.info(f"Filled email: {credentials['username']}")
            
            if reg_fields.get('password_field'):
                await self._page_fill(reg_fields['password_field'], credentials['password'])
                logger.info("Filled password")
            
            if reg_fields.get('confirm_password_field'):
                await self._page_fill(reg_fields['confirm_password_field'], credentials['password'])
                logger.info("Filled confirm password")
            
            # Handle security question (Juice Shop specific)
            if reg_fields.get('security_question'):
                try:
                    # Click to open dropdown
                    await self._page_click(reg_fields['security_question'])
                    await asyncio.sleep(0.5)
                    # Select first option
                    option = await self._page_query_selector('mat-option, option, [role="option"]')
                    if option:
                        await self._element_click(option)
                        logger.info("Selected security question")
                        await asyncio.sleep(0.3)
                except Exception as e:
                    logger.debug(f"Security question selection failed: {e}")
            
            if reg_fields.get('security_answer'):
                await self._page_fill(reg_fields['security_answer'], 'test123')
                logger.info("Filled security answer")
            
            # Submit registration
            if reg_fields.get('submit_button'):
                try:
                    await self._page_click(reg_fields['submit_button'])
                    logger.info("Clicked register button")
                except Exception as e:
                    logger.debug(f"Register button click failed: {e}")
                    # Try pressing Enter
                    await self._keyboard_press('Enter')
            
            # Wait for registration to complete
            try:
                await self._page_wait_for_load_state('networkidle', timeout=10000)
            except:
                pass
            await asyncio.sleep(2)
            
            # Check if registration was successful (look for success message or redirect)
            current_url = self.page.url
            page_content = await self._page_content()
            
            success_indicators = [
                'Registration completed successfully',
                'Account created',
                'successfully registered',
                'login' in current_url.lower(),
                'signin' in current_url.lower()
            ]
            
            for indicator in success_indicators:
                if isinstance(indicator, bool):
                    if indicator:
                        logger.info("Registration appears successful!")
                        return True
                elif indicator.lower() in page_content.lower() or indicator.lower() in current_url.lower():
                    logger.info(f"Registration successful! Indicator found: {indicator}")
                    return True
            
            # Also check if we got redirected to login page
            if '/login' in current_url or '/#/login' in current_url:
                logger.info("Redirected to login page after registration")
                return True
            
            logger.warning("Registration may have failed")
            return False
            
        except Exception as e:
            logger.error(f"Signup attempt failed: {e}")
            return False
    
    async def get_cookies(self) -> Dict:
        """Get current session cookies"""
        cookies = await self.context.cookies()
        return {c['name']: c['value'] for c in cookies}
    
    async def add_cookie(self, cookie: Dict):
        """
        Add a cookie to the browser context.
        
        Args:
            cookie: Dict with keys 'name', 'value', 'domain', optionally 'path', 'secure', etc.
        """
        try:
            # Ensure required fields
            if 'name' not in cookie or 'value' not in cookie:
                logger.error("Cookie must have 'name' and 'value'")
                return
            
            # Build cookie dict with defaults
            cookie_data = {
                'name': cookie['name'],
                'value': cookie['value'],
                'domain': cookie.get('domain', ''),
                'path': cookie.get('path', '/'),
            }
            
            # Add optional fields if present
            if cookie.get('secure'):
                cookie_data['secure'] = cookie['secure']
            if cookie.get('httpOnly'):
                cookie_data['httpOnly'] = cookie['httpOnly']
            if cookie.get('sameSite'):
                cookie_data['sameSite'] = cookie['sameSite']
            if cookie.get('expires'):
                cookie_data['expires'] = cookie['expires']
            
            await self.context.add_cookies([cookie_data])
            logger.debug(f"Added cookie: {cookie['name']}")
            
        except Exception as e:
            logger.error(f"Failed to add cookie: {e}")
    
    async def get_auth_headers(self) -> Dict:
        """Get authentication headers (Bearer token, etc.)"""
        # This could be extended to extract tokens from localStorage, headers, etc.
        return {}
    
    async def execute_request(
        self,
        url: str,
        method: str = 'GET',
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ):
        """Execute a specific HTTP request"""
        if method == 'GET':
            return await self.page.goto(url)
        else:
            # Use page.evaluate for POST requests
            return await self.page.evaluate(f'''
                async () => {{
                    const response = await fetch("{url}", {{
                        method: "{method}",
                        headers: {headers or {}},
                        body: JSON.stringify({data or {}})
                    }});
                    return await response.text();
                }}
            ''')
    
    async def stop(self):
        """Stop the browser and MITM proxy.
        
        This method delegates to close() for consistent cleanup behavior
        across both Windows and non-Windows platforms.
        """
        await self.close()
    
    def is_mitm_enabled(self) -> bool:
        """Check if MITM proxy is active"""
        return self._mitm_proxy is not None and self._mitm_proxy.running
    
    def get_mitm_traffic(self) -> List[Dict]:
        """Get traffic captured by MITM proxy (includes full HTTPS decrypted traffic)"""
        if self._mitm_proxy:
            return self._mitm_proxy.get_captured_traffic()
        return []
    
    def save_traffic_log(self, output_dir: str, filename: str = "traffic_log.json"):
        """Save all captured request/response headers to a file"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Combine browser-captured and MITM-captured traffic
        all_traffic = self._captured_traffic.copy()
        
        # Add MITM traffic if available (for full HTTPS body capture)
        mitm_traffic = self.get_mitm_traffic()
        if mitm_traffic:
            for entry in mitm_traffic:
                entry['source'] = 'mitm_proxy'  # Mark as MITM-captured
            all_traffic.extend(mitm_traffic)
            logger.info(f"Included {len(mitm_traffic)} MITM-captured entries")
        
        filepath = output_path / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(all_traffic, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Traffic log saved to {filepath} ({len(all_traffic)} entries)")
        return filepath
    
    def get_captured_traffic(self) -> List[Dict]:
        """Get all captured traffic data (browser + MITM if enabled)"""
        all_traffic = self._captured_traffic.copy()
        mitm_traffic = self.get_mitm_traffic()
        if mitm_traffic:
            all_traffic.extend(mitm_traffic)
        return all_traffic    
    # ========== JavaScript Rendering Methods for Attack Scanners ==========
    
    async def render_page(self, url: str, wait_for: str = 'networkidle', timeout: int = 30000) -> Dict:
        """
        Fetch a URL and render JavaScript, returning the fully rendered content.
        This is essential for modern SPAs and JavaScript-heavy sites.
        
        Returns:
            Dict with 'html', 'text', 'status', 'headers', 'cookies', 'scripts', 'links'
        """
        try:
            # Handle popups first
            await self._handle_popups_and_modals()
            
            response = await self.page.goto(url, wait_until=wait_for, timeout=timeout)
            
            if not response:
                return {'html': '', 'text': '', 'status': 0, 'error': 'No response'}
            
            # Handle any popups that appeared after navigation
            await self._handle_popups_and_modals()
            
            # Wait for any dynamic content to load
            await asyncio.sleep(1)
            
            # Get the fully rendered HTML (after JavaScript execution)
            html_content = await self.page.content()
            
            # Get visible text content
            text_content = await self.page.evaluate('() => document.body ? document.body.innerText : ""')
            
            # Get all scripts (both inline and external)
            scripts = await self.page.evaluate('''() => {
                const scripts = [];
                document.querySelectorAll('script').forEach(s => {
                    scripts.push({
                        src: s.src || null,
                        inline: s.src ? null : s.textContent.substring(0, 1000)
                    });
                });
                return scripts;
            }''')
            
            # Get all links
            links = await self.page.evaluate('''() => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => links.push(a.href));
                return [...new Set(links)];
            }''')
            
            # Get forms with all fields
            forms = await self._extract_forms()
            
            # Get cookies
            cookies = await self.context.cookies()
            
            return {
                'html': html_content,
                'text': text_content,
                'status': response.status,
                'headers': dict(response.headers),
                'cookies': cookies,
                'scripts': scripts,
                'links': links,
                'forms': forms,
                'url': self.page.url,  # Final URL after redirects
                'title': await self.page.title()
            }
            
        except Exception as e:
            logger.error(f"Error rendering page {url}: {e}")
            return {'html': '', 'text': '', 'status': 0, 'error': str(e)}
    
    async def render_with_payload(
        self, 
        url: str, 
        method: str = 'GET',
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        wait_time: float = 2.0
    ) -> Dict:
        """
        Navigate to a URL with optional POST data and return rendered content.
        Useful for testing form submissions with JavaScript.
        """
        try:
            if method.upper() == 'POST' and data:
                # For POST requests, we need to submit a form programmatically
                result = await self.page.evaluate(f'''async () => {{
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.action = '{url}';
                    
                    const data = {json.dumps(data)};
                    for (const [key, value] of Object.entries(data)) {{
                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = key;
                        input.value = value;
                        form.appendChild(input);
                    }}
                    
                    document.body.appendChild(form);
                    form.submit();
                }}''')
                
                # Wait for navigation
                await self.page.wait_for_load_state('networkidle', timeout=30000)
            else:
                await self.page.goto(url, wait_until='networkidle', timeout=30000)
            
            # Handle popups
            await self._handle_popups_and_modals()
            
            # Wait for dynamic content
            await asyncio.sleep(wait_time)
            
            # Get rendered content
            html_content = await self.page.content()
            text_content = await self.page.evaluate('() => document.body ? document.body.innerText : ""')
            
            return {
                'html': html_content,
                'text': text_content,
                'url': self.page.url,
                'title': await self.page.title()
            }
            
        except Exception as e:
            logger.error(f"Error rendering with payload: {e}")
            return {'html': '', 'text': '', 'error': str(e)}
    
    async def check_xss_in_dom(self, url: str, payload: str, param: str) -> Dict:
        """
        Check if an XSS payload executes in the DOM.
        Returns evidence of XSS if found.
        """
        try:
            # Inject the payload into the URL
            if '?' in url:
                test_url = f"{url}&{param}={payload}"
            else:
                test_url = f"{url}?{param}={payload}"
            
            # Set up alert/prompt/confirm detection
            alerts_detected = []
            
            async def handle_dialog(dialog):
                alerts_detected.append({
                    'type': dialog.type,
                    'message': dialog.message
                })
                await dialog.dismiss()
            
            self.page.on('dialog', handle_dialog)
            
            try:
                await self.page.goto(test_url, wait_until='networkidle', timeout=15000)
                await asyncio.sleep(1)  # Wait for any delayed XSS
            except:
                pass
            
            # Check if any alerts fired
            if alerts_detected:
                return {
                    'vulnerable': True,
                    'evidence': f"XSS executed: {alerts_detected}",
                    'payload': payload,
                    'alerts': alerts_detected
                }
            
            # Check if payload is in DOM (even if not executed)
            html = await self.page.content()
            if payload in html:
                return {
                    'vulnerable': True,
                    'evidence': 'Payload reflected in DOM without encoding',
                    'payload': payload,
                    'reflected': True
                }
            
            return {'vulnerable': False}
            
        except Exception as e:
            logger.debug(f"XSS DOM check error: {e}")
            return {'vulnerable': False, 'error': str(e)}
        finally:
            # Remove the dialog handler
            self.page.remove_listener('dialog', handle_dialog)
    
    async def extract_dynamic_endpoints(self) -> List[Dict]:
        """
        Extract API endpoints from JavaScript code and network requests.
        This finds endpoints that are only visible after JS execution.
        """
        try:
            # Get all XHR/Fetch calls made by the page
            api_calls = await self.page.evaluate('''() => {
                // Try to find API endpoints in JavaScript code
                const endpoints = [];
                const scripts = document.querySelectorAll('script');
                
                scripts.forEach(script => {
                    const text = script.textContent || '';
                    
                    // Find API URL patterns
                    const apiPatterns = [
                        /["'](\\/api\\/[^"'\\s]+)["']/g,
                        /["'](https?:\\/\\/[^"'\\s]*\\/api\\/[^"'\\s]+)["']/g,
                        /fetch\\(["']([^"']+)["']/g,
                        /axios\\.[a-z]+\\(["']([^"']+)["']/g,
                        /\\.get\\(["']([^"']+)["']/g,
                        /\\.post\\(["']([^"']+)["']/g,
                        /XMLHttpRequest.*\\.open\\([^,]+,\\s*["']([^"']+)["']/g,
                    ];
                    
                    apiPatterns.forEach(pattern => {
                        let match;
                        while ((match = pattern.exec(text)) !== null) {
                            if (match[1] && !endpoints.includes(match[1])) {
                                endpoints.push(match[1]);
                            }
                        }
                    });
                });
                
                return endpoints;
            }''')
            
            # Also check for endpoints in data attributes
            data_endpoints = await self.page.evaluate('''() => {
                const endpoints = [];
                document.querySelectorAll('[data-url], [data-api], [data-endpoint], [data-action]').forEach(el => {
                    const url = el.dataset.url || el.dataset.api || el.dataset.endpoint || el.dataset.action;
                    if (url && !endpoints.includes(url)) {
                        endpoints.push(url);
                    }
                });
                return endpoints;
            }''')
            
            all_endpoints = list(set(api_calls + data_endpoints))
            
            return [{'url': ep, 'type': 'api', 'source': 'javascript'} for ep in all_endpoints]
            
        except Exception as e:
            logger.error(f"Error extracting dynamic endpoints: {e}")
            return []
    
    async def get_page_state(self) -> Dict:
        """
        Get the current state of the page including localStorage, sessionStorage, and cookies.
        Useful for detecting state-based vulnerabilities.
        """
        try:
            state = await self.page.evaluate('''() => {
                const state = {
                    localStorage: {},
                    sessionStorage: {},
                    cookies: document.cookie
                };
                
                // Get localStorage
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    state.localStorage[key] = localStorage.getItem(key);
                }
                
                // Get sessionStorage
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    state.sessionStorage[key] = sessionStorage.getItem(key);
                }
                
                return state;
            }''')
            
            return state
            
        except Exception as e:
            logger.error(f"Error getting page state: {e}")
            return {}
    
    # ===== VISIBLE ATTACK METHODS FOR DEBUGGING =====
    # These methods type payloads into input fields visibly for debugging
    
    async def visible_attack_xss(self, url: str, selector: str, payload: str, submit: bool = True) -> Dict:
        """
        Perform a VISIBLE XSS attack by typing payload into an input field.
        Useful for debugging and demonstrating attacks.
        
        Args:
            url: Target page URL
            selector: CSS selector for input field (e.g., '#search', '[name="q"]')
            payload: XSS payload to inject
            submit: Whether to submit the form after typing
            
        Returns:
            Dict with attack results and evidence
        """
        logger.info(f"[VISIBLE] XSS Attack on {selector} with payload: {payload[:50]}...")
        
        result = {
            'type': 'xss',
            'selector': selector,
            'payload': payload,
            'vulnerable': False,
            'evidence': '',
            'alerts': []
        }
        
        try:
            # Navigate to the page
            await self.page.goto(url, wait_until='networkidle', timeout=30000)
            await asyncio.sleep(1)
            
            # Set up alert detection
            alerts = []
            async def handle_dialog(dialog):
                alerts.append({
                    'type': dialog.type,
                    'message': dialog.message
                })
                logger.info(f"[VISIBLE] ⚠ ALERT TRIGGERED: {dialog.message}")
                await dialog.dismiss()
            
            self.page.on('dialog', handle_dialog)
            
            # Find the input field
            input_element = await self.page.wait_for_selector(selector, timeout=5000)
            
            if not input_element:
                logger.warning(f"[VISIBLE] Input field not found: {selector}")
                result['error'] = f"Input field not found: {selector}"
                return result
            
            # Clear existing content
            await input_element.click()
            await self.page.keyboard.press('Control+A')
            await asyncio.sleep(0.2)
            
            # Type the payload CHARACTER BY CHARACTER (visible)
            logger.info(f"[VISIBLE] Typing payload into {selector}...")
            await input_element.type(payload, delay=50)  # 50ms delay between chars
            await asyncio.sleep(0.5)
            
            # Highlight the input (visual feedback)
            await self.page.evaluate(f'''(selector) => {{
                const el = document.querySelector(selector);
                if (el) {{
                    el.style.border = '3px solid red';
                    el.style.backgroundColor = '#ffcccc';
                }}
            }}''', selector)
            await asyncio.sleep(0.5)
            
            # Submit if requested
            if submit:
                logger.info(f"[VISIBLE] Submitting form...")
                await self.page.keyboard.press('Enter')
                await asyncio.sleep(2)  # Wait for response
            
            # Check results
            result['alerts'] = alerts
            
            if alerts:
                result['vulnerable'] = True
                result['evidence'] = f"XSS executed! Alerts: {alerts}"
                logger.info(f"[VISIBLE] ✓ VULNERABLE! XSS payload executed.")
            else:
                # Check if payload is in page
                html = await self.page.content()
                if payload in html:
                    result['vulnerable'] = True
                    result['evidence'] = "Payload reflected in page without encoding"
                    logger.info(f"[VISIBLE] ✓ Payload reflected in page")
                else:
                    logger.info(f"[VISIBLE] ✗ Payload not reflected or encoded")
            
            return result
            
        except Exception as e:
            logger.error(f"[VISIBLE] XSS attack error: {e}")
            result['error'] = str(e)
            return result
        finally:
            self.page.remove_listener('dialog', handle_dialog)
    
    async def visible_attack_sqli(self, url: str, selector: str, payload: str, submit: bool = True) -> Dict:
        """
        Perform a VISIBLE SQL Injection attack by typing payload into an input field.
        
        Args:
            url: Target page URL
            selector: CSS selector for input field
            payload: SQLi payload to inject
            submit: Whether to submit the form after typing
            
        Returns:
            Dict with attack results and evidence
        """
        import re
        
        logger.info(f"[VISIBLE] SQLi Attack on {selector} with payload: {payload}")
        
        sql_error_patterns = [
            (r'SQL syntax', 'MySQL'),
            (r'mysql_', 'MySQL PHP'),
            (r'PostgreSQL.*ERROR', 'PostgreSQL'),
            (r'ORA-\d{5}', 'Oracle'),
            (r'SQLITE_ERROR', 'SQLite'),
            (r'Unclosed quotation mark', 'MSSQL'),
            (r'syntax error', 'Generic SQL'),
        ]
        
        result = {
            'type': 'sqli',
            'selector': selector,
            'payload': payload,
            'vulnerable': False,
            'evidence': '',
            'db_type': None
        }
        
        try:
            # Navigate to the page
            await self.page.goto(url, wait_until='networkidle', timeout=30000)
            await asyncio.sleep(1)
            
            # Find the input field
            input_element = await self.page.wait_for_selector(selector, timeout=5000)
            
            if not input_element:
                result['error'] = f"Input field not found: {selector}"
                return result
            
            # Clear and type payload
            await input_element.click()
            await self.page.keyboard.press('Control+A')
            await asyncio.sleep(0.2)
            
            logger.info(f"[VISIBLE] Typing SQLi payload into {selector}...")
            await input_element.type(payload, delay=30)
            await asyncio.sleep(0.3)
            
            # Visual feedback
            await self.page.evaluate(f'''(selector) => {{
                const el = document.querySelector(selector);
                if (el) {{
                    el.style.border = '3px solid orange';
                    el.style.backgroundColor = '#fff3cd';
                }}
            }}''', selector)
            await asyncio.sleep(0.3)
            
            if submit:
                logger.info(f"[VISIBLE] Submitting form...")
                await self.page.keyboard.press('Enter')
                await asyncio.sleep(2)
            
            # Check for SQL errors
            html = await self.page.content()
            
            for pattern, db_type in sql_error_patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    result['vulnerable'] = True
                    result['db_type'] = db_type
                    result['evidence'] = f"SQL error detected: {db_type}"
                    logger.info(f"[VISIBLE] ✓ VULNERABLE! SQL error ({db_type}) detected.")
                    break
            
            if not result['vulnerable']:
                logger.info(f"[VISIBLE] ✗ No SQL error detected")
            
            return result
            
        except Exception as e:
            logger.error(f"[VISIBLE] SQLi attack error: {e}")
            result['error'] = str(e)
            return result
    
    async def visible_attack_batch(self, url: str, selector: str, payloads: List[Dict], delay_between: float = 1.0) -> List[Dict]:
        """
        Run a batch of visible attacks with different payloads.
        
        Args:
            url: Target page URL
            selector: CSS selector for input field
            payloads: List of {'type': 'xss'|'sqli', 'payload': '...'}
            delay_between: Delay in seconds between attacks
            
        Returns:
            List of attack results
        """
        results = []
        
        logger.info(f"[VISIBLE] Starting batch attack with {len(payloads)} payloads on {selector}")
        
        for i, p in enumerate(payloads):
            attack_type = p.get('type', 'xss')
            payload = p.get('payload', '')
            
            logger.info(f"[VISIBLE] Attack {i+1}/{len(payloads)}: {attack_type} - {payload[:40]}...")
            
            if attack_type == 'xss':
                result = await self.visible_attack_xss(url, selector, payload)
            elif attack_type == 'sqli':
                result = await self.visible_attack_sqli(url, selector, payload)
            else:
                result = await self.visible_attack_xss(url, selector, payload)
            
            results.append(result)
            
            if delay_between > 0:
                await asyncio.sleep(delay_between)
        
        # Summary
        vulns = [r for r in results if r.get('vulnerable')]
        logger.info(f"[VISIBLE] Batch complete: {len(vulns)}/{len(results)} vulnerable")
        
        return results