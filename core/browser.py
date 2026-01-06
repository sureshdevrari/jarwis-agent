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
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from playwright.async_api import async_playwright, Browser, BrowserContext, Page

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
    
    def __init__(self, proxy_host: str = "127.0.0.1", proxy_port: int = 8080, use_mitm: bool = False, headless: bool = False):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.use_mitm = use_mitm  # Whether to use MITM proxy for HTTPS interception
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self._discovered_urls: Set[str] = set()
        self._endpoints: List[Dict] = []
        self._captured_traffic: List[Dict] = []  # Store all request/response headers
        self.headless = headless  # Now configurable - True for headless, False to see browser
        self._mitm_proxy = None  # MITM proxy instance
        
        # 2FA handling for target websites
        self._scan_id: Optional[str] = None  # Current scan ID for OTP handling
        self._2fa_config: Optional[Dict] = None  # 2FA configuration
        self._ai_watcher = None  # AI request watcher for analyzing traffic
        self._ai_findings: List[Dict] = []  # Findings from AI traffic analysis
        
    async def start(self, enable_mitm_https: bool = False):
        """Start the browser instance
        
        Args:
            enable_mitm_https: If True, start MITM proxy for full HTTPS interception
        """
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
                '--no-sandbox'
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
        """Capture response headers"""
        try:
            self._captured_traffic.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'response',
                'url': response.url,
                'status': response.status,
                'status_text': response.status_text,
                'headers': dict(response.headers)
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
        max_depth: int = 3,
        scope: Optional[Dict] = None,
        authenticated: bool = False
    ) -> Dict:
        """Crawl the target website and discover endpoints"""
        self._discovered_urls = set()
        self._endpoints = []
        
        # Initial page load with popup handling
        logger.info(f"Starting crawl of: {start_url}")
        try:
            await self.page.goto(start_url, wait_until='domcontentloaded', timeout=30000)
            
            # Handle popups on initial page load (critical for e-commerce sites)
            logger.info("Checking for initial popups/modals...")
            for attempt in range(3):  # Try up to 3 times
                await self._handle_popups_and_modals()
                # Check if popups are still blocking
                overlay = await self._find_blocking_overlay()
                if not overlay:
                    break
                logger.info(f"Popup still visible, retry {attempt + 1}/3")
                await asyncio.sleep(1)
            
        except Exception as e:
            logger.warning(f"Initial page load error: {e}")
        
        await self._crawl_recursive(start_url, 0, max_depth, scope)
        
        # Process and deduplicate endpoints
        upload_endpoints = [ep for ep in self._endpoints if ep.get('has_upload')]
        api_endpoints = [ep for ep in self._endpoints if ep['type'] == 'api']
        
        return {
            'endpoints': self._endpoints,
            'upload_endpoints': upload_endpoints,
            'api_endpoints': api_endpoints,
            'urls_visited': list(self._discovered_urls)
        }
    
    async def _crawl_recursive(
        self, 
        url: str, 
        depth: int, 
        max_depth: int,
        scope: Optional[Dict]
    ):
        """Recursively crawl pages"""
        if depth > max_depth or url in self._discovered_urls:
            return
        
        if scope and not self._is_in_scope(url, scope):
            return
        
        self._discovered_urls.add(url)
        
        try:
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
            links = await self.page.evaluate('''() => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    links.push(a.href);
                });
                return links;
            }''')
            
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
        return await self.page.evaluate('''() => {
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
        }''')
    
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
        """
        try:
            # Brief wait for popups to appear
            await asyncio.sleep(0.5)
            
            # Log current page state for debugging
            page_title = await self.page.title()
            logger.info(f"Handling popups on page: {page_title}")
            
            # 1. Handle cookie consent banners first
            await self._dismiss_cookie_banners()
            await asyncio.sleep(0.5)
            
            # 2. Handle location/city/area selector popups (CRITICAL for e-commerce)
            # This is the main issue - we need to SELECT something, not just close
            location_handled = await self._handle_location_selector_interactive()
            
            # 3. If location popup still exists, try more aggressive methods
            if not location_handled:
                await self._handle_location_selector()
            
            # 4. Handle any remaining generic modals
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
    
    async def _find_blocking_overlay(self):
        """Check if there's a blocking modal/popup overlay"""
        overlay_selectors = [
            '[class*="modal" i][class*="open" i]',
            '[class*="modal" i][class*="show" i]',
            '[class*="modal" i][class*="active" i]',
            '[class*="popup" i][class*="open" i]',
            '[class*="popup" i][class*="show" i]',
            '[class*="popup" i][class*="visible" i]',
            '[class*="overlay" i][class*="open" i]',
            '[class*="dialog" i][class*="open" i]',
            '[role="dialog"][aria-modal="true"]',
            '[role="dialog"]:not([aria-hidden="true"])',
            '.modal.show',
            '.modal.in',
            '.popup.active',
            '[class*="backdrop" i][class*="show" i]',
            # Specific common patterns
            '[class*="location" i][class*="modal" i]',
            '[class*="city" i][class*="popup" i]',
            '[class*="pincode" i][class*="modal" i]',
            '[id*="location" i][id*="modal" i]',
        ]
        
        for selector in overlay_selectors:
            try:
                element = await self.page.query_selector(selector)
                if element and await element.is_visible():
                    return element
            except:
                continue
        return None
    
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
        detected = await self.page.evaluate('''() => {
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
        }''')
        
        return detected
    
    async def _close_popups(self):
        """Close common popups, modals, cookie banners, and welcome dialogs"""
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
        self._scan_id = scan_id
        self._2fa_config = two_factor_config or {}
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
                element = await self.page.query_selector(selector)
                if element and await element.is_visible():
                    logger.info(f"2FA page detected via: {selector}")
                    return True
            except:
                continue
        
        # Also check page content for 2FA keywords
        try:
            page_content = await self.page.content()
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
                element = await self.page.query_selector(selector)
                if element and await element.is_visible():
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
        
        # Import the OTP handling functions
        try:
            from api.routes.scan_otp import wait_for_otp, set_otp_error, clear_scan_otp_state
        except ImportError:
            logger.error("Could not import OTP handling module")
            return False
        
        if not self._scan_id:
            logger.error("No scan ID set for OTP handling")
            return False
        
        # Get 2FA type and contact info
        otp_type = self._2fa_config.get('type', 'email')
        contact = self._2fa_config.get('email') or self._2fa_config.get('phone') or ''
        
        # Wait for user to submit OTP (this blocks until OTP is provided or timeout)
        max_attempts = 3
        for attempt in range(max_attempts):
            otp = await wait_for_otp(
                scan_id=self._scan_id,
                otp_type=otp_type,
                contact=contact,
                timeout_seconds=300,  # 5 minutes
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
                await self.page.fill(otp_selector, otp)
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
                        btn = await self.page.query_selector(submit_sel)
                        if btn and await btn.is_visible():
                            await btn.click()
                            submit_clicked = True
                            logger.info(f"Clicked OTP submit button: {submit_sel}")
                            break
                    except:
                        continue
                
                if not submit_clicked:
                    # Try pressing Enter
                    await self.page.press(otp_selector, 'Enter')
                    logger.info("Submitted OTP via Enter key")
                
                # Wait for navigation
                try:
                    await self.page.wait_for_load_state('networkidle', timeout=10000)
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
                        err_el = await self.page.query_selector(err_sel)
                        if err_el and await err_el.is_visible():
                            error_text = await err_el.text_content()
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
                        # Reset for retry - don't call reset_otp_for_retry, just continue
                        from api.routes.scan_otp import reset_otp_for_retry
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
                        el = await self.page.query_selector(indicator)
                        if el and await el.is_visible():
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
                await self.page.wait_for_selector(username_selector, timeout=5000)
                await self.page.wait_for_selector(password_selector, timeout=5000)
            except Exception as e:
                logger.error(f"Form fields not found after detection: {e}")
                return False

            # Fill credentials
            await self.page.fill(username_selector, credentials['username'])
            await self.page.fill(password_selector, credentials['password'])
            
            logger.info(f"Filled credentials for user: {credentials['username']}")

            # Submit form - try multiple methods
            submitted = False
            
            # Method 1: Click submit button if found
            if submit_selector:
                try:
                    await self.page.click(submit_selector)
                    submitted = True
                    logger.info("Submitted form via button click")
                except Exception as e:
                    logger.debug(f"Submit button click failed: {e}")
            
            # Method 2: Press Enter on password field
            if not submitted:
                try:
                    await self.page.press(password_selector, 'Enter')
                    submitted = True
                    logger.info("Submitted form via Enter key")
                except Exception as e:
                    logger.debug(f"Enter key submit failed: {e}")
            
            # Method 3: Submit the form directly
            if not submitted:
                try:
                    await self.page.evaluate('''() => {
                        const form = document.querySelector('form');
                        if (form) form.submit();
                    }''')
                    submitted = True
                    logger.info("Submitted form via JavaScript")
                except Exception as e:
                    logger.error(f"All form submit methods failed: {e}")
                    return False

            # Wait for navigation with timeout
            try:
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
                    element = await self.page.query_selector(indicator)
                    if element and await element.is_visible():
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
                        element = await self.page.query_selector(success_indicator)
                        success = element is not None
                        logger.info(f"Selector-based check: '{success_indicator}' found = {success}")
                    except Exception as e:
                        logger.debug(f"Selector check failed: {e}")
            
            # Method 3: Check if login form is gone (we're no longer on login page)
            if not success:
                login_form_visible = False
                try:
                    login_form = await self.page.query_selector('input[type="password"]:visible')
                    login_form_visible = login_form is not None and await login_form.is_visible()
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
                    await self.page.goto(login_url, wait_until='networkidle', timeout=30000)
                    await asyncio.sleep(1)
                    
                    # Close popups again on login page
                    await self._close_popups()
                    await asyncio.sleep(0.5)
                    
                    # Re-detect form and fill credentials
                    detected = await self._auto_detect_login_form()
                    username_selector = detected.get('username_field') or selectors.get('username_field')
                    password_selector = detected.get('password_field') or selectors.get('password_field')
                    submit_selector = detected.get('submit_button') or selectors.get('submit_button')
                    
                    await self.page.wait_for_selector(username_selector, timeout=5000)
                    await self.page.fill(username_selector, credentials['username'])
                    await self.page.fill(password_selector, credentials['password'])
                    
                    if submit_selector:
                        await self.page.click(submit_selector)
                    else:
                        await self.page.press(password_selector, 'Enter')
                    
                    try:
                        await self.page.wait_for_load_state('networkidle', timeout=15000)
                    except:
                        pass
                    await asyncio.sleep(1)
                    
                    # Check success again
                    current_url = self.page.url
                    if is_url_indicator:
                        success = success_indicator in current_url
                    else:
                        try:
                            success = await self.page.query_selector(success_indicator) is not None
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
                    element = await self.page.query_selector(selector)
                    if element:
                        await element.click()
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
                await self.page.wait_for_load_state('networkidle', timeout=10000)
            except:
                pass
            await asyncio.sleep(1)
            
            # Close any popups on registration page
            await self._close_popups()
            await asyncio.sleep(0.5)
            
            # Detect registration form fields
            reg_fields = await self.page.evaluate('''() => {
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
                await self.page.fill(reg_fields['email_field'], credentials['username'])
                logger.info(f"Filled email: {credentials['username']}")
            
            if reg_fields.get('password_field'):
                await self.page.fill(reg_fields['password_field'], credentials['password'])
                logger.info("Filled password")
            
            if reg_fields.get('confirm_password_field'):
                await self.page.fill(reg_fields['confirm_password_field'], credentials['password'])
                logger.info("Filled confirm password")
            
            # Handle security question (Juice Shop specific)
            if reg_fields.get('security_question'):
                try:
                    # Click to open dropdown
                    await self.page.click(reg_fields['security_question'])
                    await asyncio.sleep(0.5)
                    # Select first option
                    option = await self.page.query_selector('mat-option, option, [role="option"]')
                    if option:
                        await option.click()
                        logger.info("Selected security question")
                        await asyncio.sleep(0.3)
                except Exception as e:
                    logger.debug(f"Security question selection failed: {e}")
            
            if reg_fields.get('security_answer'):
                await self.page.fill(reg_fields['security_answer'], 'test123')
                logger.info("Filled security answer")
            
            # Submit registration
            if reg_fields.get('submit_button'):
                try:
                    await self.page.click(reg_fields['submit_button'])
                    logger.info("Clicked register button")
                except Exception as e:
                    logger.debug(f"Register button click failed: {e}")
                    # Try pressing Enter
                    await self.page.keyboard.press('Enter')
            
            # Wait for registration to complete
            try:
                await self.page.wait_for_load_state('networkidle', timeout=10000)
            except:
                pass
            await asyncio.sleep(2)
            
            # Check if registration was successful (look for success message or redirect)
            current_url = self.page.url
            page_content = await self.page.content()
            
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
        """Stop the browser and MITM proxy"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        
        # Stop MITM proxy if it was running
        if self._mitm_proxy:
            await self._mitm_proxy.stop()
            self._mitm_proxy = None
        
        logger.info("Browser stopped")
    
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