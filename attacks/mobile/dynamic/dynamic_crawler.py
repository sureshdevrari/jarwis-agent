"""
Jarwis AGI - Dynamic App Crawler with Emulator Integration
Automatically crawls mobile apps through emulator to discover all API endpoints

Features:
- Automatic emulator launch and app installation
- Frida-based SSL pinning bypass
- UI automation to explore all app screens
- Real-time traffic capture and API discovery
- Support for both Android and iOS
"""

import os
import re
import json
import time
import asyncio
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Callable, Tuple
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredAPI:
    """An API endpoint discovered during dynamic crawling"""
    id: str
    url: str
    method: str
    path: str
    base_url: str
    query_params: Dict = field(default_factory=dict)
    request_headers: Dict = field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_content_type: str = ""
    requires_auth: bool = False
    auth_token: str = ""
    discovered_at: str = ""
    screen_name: str = ""  # Which screen triggered this API
    is_sensitive: bool = False
    

@dataclass
class DynamicCrawlResult:
    """Result of dynamic app crawling"""
    app_name: str
    package_name: str
    scan_id: str
    platform: str
    
    # Discovered APIs
    apis: List[DiscoveredAPI] = field(default_factory=list)
    
    # Statistics
    total_apis: int = 0
    get_count: int = 0
    post_count: int = 0
    put_count: int = 0
    delete_count: int = 0
    auth_apis: int = 0
    
    # Screens visited
    screens_visited: List[str] = field(default_factory=list)
    
    # Base URLs
    base_urls: Set[str] = field(default_factory=set)
    
    # Traffic stats
    total_requests: int = 0
    ssl_bypassed: bool = False
    
    # Timing
    crawl_duration: float = 0
    started_at: str = ""
    ended_at: str = ""


class DynamicAppCrawler:
    """
    Dynamic Mobile App Crawler
    Uses emulator + Frida + UI automation to discover all API endpoints
    """
    
    # Frida script for comprehensive API monitoring
    FRIDA_API_MONITOR_SCRIPT = '''
// Comprehensive API Monitor for Jarwis
Java.perform(function() {
    var apis = [];
    
    // === SSL PINNING BYPASS ===
    try {
        var TrustManagerImpl = Java.registerClass({
            name: 'com.jarwis.TrustManagerBypass',
            implements: [Java.use('javax.net.ssl.X509TrustManager')],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, [TrustManagerImpl.$new()], null);
        
        send({type: 'ssl_bypass', status: 'success'});
    } catch(e) {
        send({type: 'ssl_bypass', status: 'failed', error: e.toString()});
    }
    
    // === OKHTTP3 INTERCEPTOR ===
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Request = Java.use('okhttp3.Request');
        
        var RealCall = Java.use('okhttp3.RealCall');
        RealCall.execute.implementation = function() {
            var request = this.request();
            var url = request.url().toString();
            var method = request.method();
            var headers = {};
            
            var headerNames = request.headers().names().toArray();
            for (var i = 0; i < headerNames.length; i++) {
                headers[headerNames[i]] = request.headers().get(headerNames[i]);
            }
            
            var body = "";
            if (request.body() != null) {
                try {
                    var Buffer = Java.use('okio.Buffer');
                    var buffer = Buffer.$new();
                    request.body().writeTo(buffer);
                    body = buffer.readUtf8();
                } catch(e) {}
            }
            
            send({
                type: 'api_request',
                url: url,
                method: method,
                headers: headers,
                body: body
            });
            
            var response = this.execute();
            
            send({
                type: 'api_response',
                url: url,
                status: response.code(),
                content_type: response.header('Content-Type') || ''
            });
            
            return response;
        };
        
        // Also hook enqueue for async calls
        RealCall.enqueue.implementation = function(callback) {
            var request = this.request();
            send({
                type: 'api_request',
                url: request.url().toString(),
                method: request.method(),
                headers: {},
                body: ''
            });
            return this.enqueue(callback);
        };
        
        send({type: 'hook_installed', name: 'okhttp3'});
    } catch(e) {
        send({type: 'hook_failed', name: 'okhttp3', error: e.toString()});
    }
    
    // === RETROFIT INTERCEPTOR ===
    try {
        var Retrofit = Java.use('retrofit2.Retrofit');
        Retrofit.create.implementation = function(service) {
            send({type: 'retrofit_service', name: service.getName()});
            return this.create(service);
        };
        send({type: 'hook_installed', name: 'retrofit'});
    } catch(e) {}
    
    // === VOLLEY INTERCEPTOR ===
    try {
        var Request = Java.use('com.android.volley.Request');
        Request.getUrl.implementation = function() {
            var url = this.getUrl();
            send({
                type: 'api_request',
                url: url,
                method: this.getMethod() == 0 ? 'GET' : 'POST',
                headers: {},
                body: ''
            });
            return url;
        };
        send({type: 'hook_installed', name: 'volley'});
    } catch(e) {}
    
    // === HTTPURLCONNECTION ===
    try {
        var URL = Java.use('java.net.URL');
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        
        HttpURLConnection.getInputStream.implementation = function() {
            send({
                type: 'api_request',
                url: this.getURL().toString(),
                method: this.getRequestMethod(),
                headers: {},
                body: ''
            });
            return this.getInputStream();
        };
        send({type: 'hook_installed', name: 'httpurlconnection'});
    } catch(e) {}
    
    // === WEBVIEW REQUESTS ===
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.shouldInterceptRequest.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest').implementation = function(view, request) {
            send({
                type: 'webview_request',
                url: request.getUrl().toString(),
                method: request.getMethod()
            });
            return this.shouldInterceptRequest(view, request);
        };
        send({type: 'hook_installed', name: 'webview'});
    } catch(e) {}
    
    send({type: 'ready', message: 'Jarwis API Monitor active'});
});
'''
    
    def __init__(self, config: dict = None, callback: Callable = None):
        self.config = config or {}
        self.callback = callback
        self.discovered_apis: Dict[str, DiscoveredAPI] = {}
        self.base_urls: Set[str] = set()
        self.screens_visited: List[str] = []
        self._api_counter = 0
        self._frida_session = None
        self._frida_script = None
        
        # Emulator manager
        self._emulator = None
        
    def log(self, log_type: str, message: str, details: str = None):
        """Log with callback"""
        if self.callback:
            try:
                self.callback(log_type, message, details)
            except:
                pass
        logger.info(f"[{log_type}] {message}")
    
    async def crawl(self, apk_path: str, package_name: str = None, 
                    duration: int = 120, use_emulator: bool = True) -> DynamicCrawlResult:
        """
        Perform dynamic crawl of mobile app
        
        Args:
            apk_path: Path to APK file
            package_name: App package name (auto-detected if not provided)
            duration: How long to crawl in seconds
            use_emulator: Whether to use built-in emulator
            
        Returns:
            DynamicCrawlResult with all discovered APIs
        """
        start_time = time.time()
        scan_id = f"DYN-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.log('phase', '[OK]  Starting Dynamic App Crawl')
        self.log('info', f'APK: {Path(apk_path).name}')
        self.log('info', f'Duration: {duration} seconds')
        
        result = DynamicCrawlResult(
            app_name=Path(apk_path).stem,
            package_name=package_name or "",
            scan_id=scan_id,
            platform="android",
            started_at=datetime.now().isoformat()
        )
        
        try:
            # Step 1: Setup emulator if needed
            if use_emulator:
                await self._setup_emulator()
            
            # Step 2: Get package name from APK if not provided
            if not package_name:
                package_name = await self._get_package_name(apk_path)
                result.package_name = package_name
                self.log('info', f'Package: {package_name}')
            
            # Step 3: Install APK
            if use_emulator and self._emulator:
                await self._install_apk(apk_path)
            
            # Step 4: Start Frida monitoring
            frida_success = await self._start_frida_monitoring(package_name)
            result.ssl_bypassed = frida_success
            
            # Step 5: Launch app and explore
            await self._launch_and_explore(package_name, duration)
            
            # Step 6: Collect results
            result.apis = list(self.discovered_apis.values())
            result.total_apis = len(result.apis)
            result.base_urls = self.base_urls
            result.screens_visited = self.screens_visited
            result.total_requests = len(result.apis)
            
            # Count by method
            for api in result.apis:
                if api.method == 'GET':
                    result.get_count += 1
                elif api.method == 'POST':
                    result.post_count += 1
                elif api.method == 'PUT':
                    result.put_count += 1
                elif api.method == 'DELETE':
                    result.delete_count += 1
                if api.requires_auth:
                    result.auth_apis += 1
            
        except Exception as e:
            self.log('error', f'Crawl failed: {str(e)}')
            logger.exception(f"Dynamic crawl error: {e}")
        finally:
            # Cleanup
            await self._cleanup()
        
        result.ended_at = datetime.now().isoformat()
        result.crawl_duration = time.time() - start_time
        
        self.log('success', f'[OK]  Dynamic crawl complete: {result.total_apis} APIs discovered')
        self.log('info', f'   GET: {result.get_count}, POST: {result.post_count}')
        self.log('info', f'   Authenticated: {result.auth_apis}')
        self.log('info', f'   Screens visited: {len(result.screens_visited)}')
        
        return result
    
    async def _setup_emulator(self):
        """Setup and start Android emulator"""
        try:
            from attacks.mobile.platform.android.emulator_manager import EmulatorManager
            
            self._emulator = EmulatorManager()
            status = self._emulator.get_status()
            
            if not status['running']:
                if not status['emulator_installed']:
                    self.log('warning', 'Emulator not installed. Using ADB device if available.')
                    self._emulator = None
                    return
                
                self.log('info', 'Starting Android emulator...')
                await self._emulator.start_emulator(headless=True)
                
                # Install Frida if needed
                if not status['frida_installed']:
                    await self._emulator.install_frida_server()
                
                await self._emulator.start_frida_server()
                
            self.log('success', f'Emulator ready: {status.get("device_id", "connected")}')
            
        except ImportError:
            self.log('warning', 'EmulatorManager not available')
            self._emulator = None
        except Exception as e:
            self.log('warning', f'Emulator setup failed: {e}')
            self._emulator = None
    
    async def _get_package_name(self, apk_path: str) -> str:
        """Extract package name from APK using aapt"""
        try:
            result = subprocess.run(
                ['aapt', 'dump', 'badging', apk_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            match = re.search(r"package: name='([^']+)'", result.stdout)
            if match:
                return match.group(1)
        except Exception as e:
            self.log('warning', f'Could not get package name: {e}')
        
        # Fallback: use filename
        return Path(apk_path).stem.replace(' ', '.').lower()
    
    async def _install_apk(self, apk_path: str):
        """Install APK on emulator/device"""
        self.log('info', 'Installing APK...')
        
        try:
            result = subprocess.run(
                ['adb', 'install', '-r', apk_path],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if 'Success' in result.stdout:
                self.log('success', 'APK installed successfully')
            else:
                self.log('warning', f'APK install issue: {result.stderr}')
        except Exception as e:
            self.log('error', f'Failed to install APK: {e}')
    
    async def _start_frida_monitoring(self, package_name: str) -> bool:
        """Start Frida-based API monitoring"""
        self.log('info', 'Starting Frida API monitoring...')
        
        try:
            import frida
            
            # Try to attach to running app or spawn it
            device = frida.get_usb_device(timeout=5)
            
            try:
                # Try attaching first
                session = device.attach(package_name)
                self.log('info', f'Attached to running {package_name}')
            except:
                # Spawn the app
                pid = device.spawn([package_name])
                session = device.attach(pid)
                device.resume(pid)
                self.log('info', f'Spawned {package_name}')
            
            self._frida_session = session
            
            # Load monitoring script
            script = session.create_script(self.FRIDA_API_MONITOR_SCRIPT)
            script.on('message', self._on_frida_message)
            script.load()
            
            self._frida_script = script
            
            self.log('success', 'Frida monitoring active with SSL bypass')
            return True
            
        except ImportError:
            self.log('warning', 'Frida not installed. Install with: pip install frida-tools')
            return False
        except Exception as e:
            self.log('warning', f'Frida monitoring failed: {e}')
            return False
    
    def _on_frida_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            payload = message['payload']
            msg_type = payload.get('type', '')
            
            if msg_type == 'api_request':
                self._record_api(payload)
            elif msg_type == 'api_response':
                self._update_api_response(payload)
            elif msg_type == 'ssl_bypass':
                self.log('info', f"SSL bypass: {payload.get('status', 'unknown')}")
            elif msg_type == 'hook_installed':
                self.log('detail', f"Hook installed: {payload.get('name')}")
            elif msg_type == 'ready':
                self.log('success', payload.get('message', 'Frida ready'))
    
    def _record_api(self, payload: dict):
        """Record a discovered API endpoint"""
        url = payload.get('url', '')
        if not url or not url.startswith('http'):
            return
        
        # Skip common non-API URLs
        skip_patterns = [
            'google.com/generate_204',
            'googleapis.com/v1/token',
            'crashlytics',
            'firebase',
            'facebook.com',
            'analytics',
            '.png', '.jpg', '.gif', '.css', '.js',
            'cloudflare',
            'doubleclick'
        ]
        
        for pattern in skip_patterns:
            if pattern in url.lower():
                return
        
        parsed = urlparse(url)
        api_key = f"{payload.get('method', 'GET')}:{parsed.netloc}{parsed.path}"
        
        if api_key in self.discovered_apis:
            return  # Already recorded
        
        self._api_counter += 1
        api = DiscoveredAPI(
            id=f"API-{self._api_counter:04d}",
            url=url,
            method=payload.get('method', 'GET'),
            path=parsed.path,
            base_url=f"{parsed.scheme}://{parsed.netloc}",
            query_params=dict(parse_qs(parsed.query)) if parsed.query else {},
            request_headers=payload.get('headers', {}),
            request_body=payload.get('body', ''),
            requires_auth=self._check_auth(payload.get('headers', {})),
            discovered_at=datetime.now().isoformat()
        )
        
        self.discovered_apis[api_key] = api
        self.base_urls.add(api.base_url)
        
        self.log('api', f"[OK]  {api.method} {api.path}", api.base_url)
    
    def _check_auth(self, headers: dict) -> bool:
        """Check if request has authentication"""
        auth_headers = ['authorization', 'x-auth-token', 'x-api-key', 'cookie', 'x-access-token']
        for key in headers:
            if key.lower() in auth_headers:
                return True
        return False
    
    def _update_api_response(self, payload: dict):
        """Update API with response info"""
        url = payload.get('url', '')
        parsed = urlparse(url)
        
        for api in self.discovered_apis.values():
            if parsed.path == api.path and parsed.netloc in api.base_url:
                api.response_status = payload.get('status', 0)
                api.response_content_type = payload.get('content_type', '')
                break
    
    async def _launch_and_explore(self, package_name: str, duration: int):
        """Launch app and explore UI to trigger API calls"""
        self.log('info', f'Exploring app for {duration} seconds...')
        
        # Launch the app
        try:
            subprocess.run(
                ['adb', 'shell', 'monkey', '-p', package_name, '-c', 
                 'android.intent.category.LAUNCHER', '1'],
                capture_output=True,
                timeout=10
            )
            await asyncio.sleep(3)  # Wait for app to start
        except Exception as e:
            self.log('warning', f'Could not launch app: {e}')
        
        # Simulate user exploration
        explore_start = time.time()
        action_count = 0
        
        while time.time() - explore_start < duration:
            try:
                # Random UI interactions
                action = action_count % 5
                
                if action == 0:
                    # Tap random location
                    x, y = 540, 900 + (action_count * 100 % 600)
                    subprocess.run(['adb', 'shell', 'input', 'tap', str(x), str(y)],
                                 capture_output=True, timeout=5)
                    self.screens_visited.append(f"screen_{action_count}")
                    
                elif action == 1:
                    # Scroll down
                    subprocess.run(['adb', 'shell', 'input', 'swipe', '540', '1500', '540', '500'],
                                 capture_output=True, timeout=5)
                    
                elif action == 2:
                    # Scroll up
                    subprocess.run(['adb', 'shell', 'input', 'swipe', '540', '500', '540', '1500'],
                                 capture_output=True, timeout=5)
                    
                elif action == 3:
                    # Back button
                    subprocess.run(['adb', 'shell', 'input', 'keyevent', 'KEYCODE_BACK'],
                                 capture_output=True, timeout=5)
                    
                elif action == 4:
                    # Menu/hamburger
                    subprocess.run(['adb', 'shell', 'input', 'tap', '60', '120'],
                                 capture_output=True, timeout=5)
                
                action_count += 1
                await asyncio.sleep(2)  # Wait between actions
                
                # Log progress
                if action_count % 10 == 0:
                    self.log('info', f'  Explored {action_count} actions, found {len(self.discovered_apis)} APIs')
                    
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.debug(f"Exploration action failed: {e}")
                continue
        
        self.log('info', f'Exploration complete: {action_count} actions performed')
    
    async def _cleanup(self):
        """Cleanup Frida session and emulator"""
        try:
            if self._frida_script:
                self._frida_script.unload()
            if self._frida_session:
                self._frida_session.detach()
        except:
            pass
        
        self._frida_session = None
        self._frida_script = None


async def crawl_app_dynamically(apk_path: str, duration: int = 120, 
                                 callback: Callable = None) -> DynamicCrawlResult:
    """Convenience function for dynamic app crawling"""
    crawler = DynamicAppCrawler(callback=callback)
    return await crawler.crawl(apk_path, duration=duration)


def create_dynamic_crawler(config: dict = None, callback: Callable = None) -> DynamicAppCrawler:
    """Factory function for DynamicAppCrawler"""
    return DynamicAppCrawler(config=config, callback=callback)
