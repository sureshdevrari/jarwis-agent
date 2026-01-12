"""
Jarwis AGI Pen Test - Frida Request Bridge

Bridges Frida-captured HTTP traffic to MobileRequestStoreDB.
This is the critical link between Frida instrumentation and the attack pipeline.

Flow:
1. Frida hooks intercept HTTP calls (OkHttp, Retrofit, Alamofire, etc.)
2. Frida sends request data via send() to Python
3. FridaRequestBridge receives messages
4. Parses and stores in MobileRequestStoreDB
5. Scanners can now iterate and attack stored requests

Features:
- Real-time request capture from multiple Frida hooks
- Automatic auth token extraction and storage
- Request deduplication
- Binary content handling (protobuf, msgpack)
- WebSocket frame capture

Usage:
    bridge = FridaRequestBridge(
        request_store=mobile_request_store,
        app_package="com.example.app"
    )
    
    # Register as Frida message handler
    frida_script.on('message', bridge.on_frida_message)
    
    # Or run standalone listener
    await bridge.start_listening()
"""

import asyncio
import json
import logging
import base64
import re
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from core.mobile_request_store import MobileRequestStoreDB, StoredMobileRequest

logger = logging.getLogger(__name__)


@dataclass
class FridaHttpMessage:
    """Parsed HTTP message from Frida hook"""
    type: str                    # http_request, http_response, auth_token
    hook_source: str             # okhttp3, retrofit, alamofire, urlsession, etc.
    url: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_bytes: bytes = b""      # For binary content
    content_type: str = ""
    
    # Response data (if type == http_response)
    status_code: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    
    # Auth token capture
    token_type: str = ""
    token_value: str = ""
    token_header: str = ""
    
    # Metadata
    timestamp: str = ""
    request_id: str = ""         # For correlating request/response
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class FridaRequestBridge:
    """
    Bridges Frida HTTP captures to MobileRequestStoreDB.
    
    Handles messages from various Frida hooks:
    - Android: OkHttp3, OkHttp2, Retrofit, Volley, HttpURLConnection
    - iOS: NSURLSession, AFNetworking, Alamofire
    - Cross-platform: React Native, Flutter
    """
    
    # Known Frida hook sources
    HOOK_SOURCES = {
        'okhttp3': 'Android OkHttp3',
        'okhttp2': 'Android OkHttp2 (Legacy)',
        'retrofit': 'Android Retrofit',
        'volley': 'Android Volley',
        'httpurlconnection': 'Android HttpURLConnection',
        'urlsession': 'iOS NSURLSession',
        'afnetworking': 'iOS AFNetworking',
        'alamofire': 'iOS Alamofire',
        'react_native': 'React Native',
        'flutter': 'Flutter (Dart)',
        'webview': 'WebView Traffic',
        'unknown': 'Unknown Source'
    }
    
    # Auth header patterns for token extraction
    AUTH_PATTERNS = [
        (r'^Bearer\s+(.+)$', 'bearer'),
        (r'^Basic\s+(.+)$', 'basic'),
        (r'^Token\s+(.+)$', 'token'),
        (r'^JWT\s+(.+)$', 'jwt'),
        (r'^ApiKey\s+(.+)$', 'api_key'),
    ]
    
    # Headers that typically contain auth tokens
    AUTH_HEADERS = [
        'authorization', 'x-auth-token', 'x-access-token', 'x-api-key',
        'api-key', 'apikey', 'token', 'x-token', 'auth-token',
        'x-csrf-token', 'x-xsrf-token'
    ]
    
    def __init__(
        self,
        request_store: MobileRequestStoreDB,
        app_package: str = "",
        platform: str = "android",
        capture_responses: bool = True,
        extract_auth: bool = True,
        deduplicate: bool = True,
        on_request_captured: Optional[Callable] = None,
        on_auth_captured: Optional[Callable] = None
    ):
        """
        Initialize Frida Request Bridge.
        
        Args:
            request_store: MobileRequestStoreDB instance
            app_package: App package/bundle ID
            platform: android or ios
            capture_responses: Also capture responses
            extract_auth: Extract and store auth tokens
            deduplicate: Skip duplicate requests
            on_request_captured: Callback when request captured
            on_auth_captured: Callback when auth token captured
        """
        self.request_store = request_store
        self.app_package = app_package
        self.platform = platform
        self.capture_responses = capture_responses
        self.extract_auth = extract_auth
        self.deduplicate = deduplicate
        self.on_request_captured = on_request_captured
        self.on_auth_captured = on_auth_captured
        
        # Request/response correlation
        self._pending_requests: Dict[str, str] = {}  # frida_request_id -> db_request_id
        
        # Stats
        self.stats = {
            'requests_captured': 0,
            'responses_captured': 0,
            'auth_tokens_captured': 0,
            'duplicates_skipped': 0,
            'parse_errors': 0,
            'by_hook': {}
        }
        
        # Message queue for async processing
        self._message_queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        
        logger.info(f"FridaRequestBridge initialized for {app_package} ({platform})")
    
    def on_frida_message(self, message: Dict, data: Any = None):
        """
        Frida message handler - call from script.on('message', bridge.on_frida_message)
        
        This is synchronous as required by Frida, but queues for async processing.
        """
        if message.get('type') == 'send':
            payload = message.get('payload', {})
            if isinstance(payload, dict):
                # Queue for async processing
                try:
                    self._message_queue.put_nowait((payload, data))
                except asyncio.QueueFull:
                    logger.warning("Message queue full, dropping message")
        elif message.get('type') == 'error':
            logger.error(f"Frida error: {message.get('stack', message)}")
    
    async def process_message_queue(self):
        """Process queued Frida messages asynchronously"""
        while self._running:
            try:
                payload, data = await asyncio.wait_for(
                    self._message_queue.get(),
                    timeout=1.0
                )
                await self._process_frida_payload(payload, data)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error processing message: {e}")
                self.stats['parse_errors'] += 1
    
    async def start_listening(self):
        """Start async message processing loop"""
        self._running = True
        logger.info("FridaRequestBridge started listening")
        await self.process_message_queue()
    
    def stop_listening(self):
        """Stop message processing"""
        self._running = False
        logger.info(f"FridaRequestBridge stopped. Stats: {self.stats}")
    
    async def _process_frida_payload(self, payload: Dict, data: Any = None):
        """Process a Frida message payload"""
        msg_type = payload.get('type', '')
        
        if msg_type == 'http_request':
            await self._handle_http_request(payload, data)
        
        elif msg_type == 'http_response':
            await self._handle_http_response(payload)
        
        elif msg_type == 'auth_token':
            await self._handle_auth_token(payload)
        
        elif msg_type == 'ssl_bypass':
            # SSL bypass notification - log only
            logger.debug(f"SSL bypass: {payload.get('library')} for {payload.get('hostname')}")
        
        elif msg_type == 'websocket_frame':
            await self._handle_websocket(payload)
        
        else:
            # Unknown message type - may still contain HTTP data
            if 'url' in payload and 'method' in payload:
                await self._handle_http_request(payload, data)
    
    async def _handle_http_request(self, payload: Dict, data: Any = None):
        """Handle captured HTTP request"""
        try:
            url = payload.get('url', '')
            method = payload.get('method', 'GET').upper()
            headers = payload.get('headers', {})
            body = payload.get('body', '')
            hook_source = payload.get('hook', payload.get('source', 'unknown'))
            frida_request_id = payload.get('request_id', '')
            
            # Handle binary body
            if data and isinstance(data, bytes):
                body = self._decode_binary_body(data, headers.get('Content-Type', ''))
            elif payload.get('body_base64'):
                try:
                    body = base64.b64decode(payload['body_base64']).decode('utf-8', errors='replace')
                except:
                    body = payload.get('body_base64', '')
            
            # Skip non-HTTP URLs
            if not url or not url.startswith(('http://', 'https://')):
                return
            
            # Extract cookies
            cookies = self._parse_cookies(headers)
            
            # Store in database
            request_id = await self.request_store.add_request(
                url=url,
                method=method,
                headers=headers,
                body=body,
                cookies=cookies,
                source='frida',
                frida_hook=hook_source,
                app_package=self.app_package,
                platform=self.platform,
                deduplicate=self.deduplicate
            )
            
            if request_id:
                self.stats['requests_captured'] += 1
                self.stats['by_hook'][hook_source] = self.stats['by_hook'].get(hook_source, 0) + 1
                
                # Store for response correlation
                if frida_request_id:
                    self._pending_requests[frida_request_id] = request_id
                
                # Extract auth token if present
                if self.extract_auth:
                    await self._extract_auth_from_request(headers)
                
                # Callback
                if self.on_request_captured:
                    try:
                        self.on_request_captured(request_id, url, method)
                    except:
                        pass
                
                logger.debug(f"Captured: {method} {url[:80]} ({hook_source})")
            else:
                self.stats['duplicates_skipped'] += 1
                
        except Exception as e:
            logger.error(f"Error handling HTTP request: {e}")
            self.stats['parse_errors'] += 1
    
    async def _handle_http_response(self, payload: Dict):
        """Handle captured HTTP response"""
        if not self.capture_responses:
            return
        
        try:
            frida_request_id = payload.get('request_id', '')
            status_code = payload.get('status_code', 0)
            headers = payload.get('headers', {})
            body = payload.get('body', '')
            response_time_ms = payload.get('response_time_ms', 0)
            
            # Find corresponding request
            request_id = self._pending_requests.get(frida_request_id)
            if not request_id:
                # Try to match by other means
                logger.debug(f"No matching request for response {frida_request_id}")
                return
            
            # Store response
            await self.request_store.add_response(
                request_id=request_id,
                status_code=status_code,
                headers=headers,
                body=body[:50000] if body else "",
                response_time_ms=response_time_ms
            )
            
            self.stats['responses_captured'] += 1
            
            # Cleanup pending
            del self._pending_requests[frida_request_id]
            
        except Exception as e:
            logger.error(f"Error handling HTTP response: {e}")
    
    async def _handle_auth_token(self, payload: Dict):
        """Handle captured auth token"""
        try:
            token_type = payload.get('token_type', 'bearer')
            token_value = payload.get('token_value', '')
            header_name = payload.get('header_name', 'Authorization')
            header_prefix = payload.get('header_prefix', 'Bearer')
            
            if not token_value:
                return
            
            await self.request_store.store_auth_token(
                token_type=token_type,
                token_value=token_value,
                header_name=header_name,
                header_prefix=header_prefix,
                source='frida'
            )
            
            self.stats['auth_tokens_captured'] += 1
            
            # Callback
            if self.on_auth_captured:
                try:
                    self.on_auth_captured(token_type, token_value)
                except:
                    pass
            
            logger.info(f"Captured auth token: {token_type}")
            
        except Exception as e:
            logger.error(f"Error handling auth token: {e}")
    
    async def _handle_websocket(self, payload: Dict):
        """Handle WebSocket frame capture"""
        # Future: Store WebSocket messages for testing
        frame_type = payload.get('frame_type', 'text')
        data = payload.get('data', '')
        logger.debug(f"WebSocket {frame_type} frame captured: {len(data)} bytes")
    
    async def _extract_auth_from_request(self, headers: Dict[str, str]):
        """Extract auth tokens from request headers"""
        headers_lower = {k.lower(): (k, v) for k, v in headers.items()}
        
        for auth_header in self.AUTH_HEADERS:
            if auth_header in headers_lower:
                orig_key, value = headers_lower[auth_header]
                
                # Parse token type and value
                token_type = 'custom'
                token_value = value
                header_prefix = ''
                
                for pattern, t_type in self.AUTH_PATTERNS:
                    match = re.match(pattern, value, re.IGNORECASE)
                    if match:
                        token_type = t_type
                        token_value = match.group(1)
                        header_prefix = value[:value.find(token_value)].strip()
                        break
                
                await self.request_store.store_auth_token(
                    token_type=token_type,
                    token_value=token_value,
                    header_name=orig_key,
                    header_prefix=header_prefix,
                    source='frida_extract'
                )
                
                self.stats['auth_tokens_captured'] += 1
                break  # Only capture first auth header
    
    def _parse_cookies(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Parse cookies from headers"""
        cookies = {}
        cookie_header = headers.get('Cookie', headers.get('cookie', ''))
        
        if cookie_header:
            for part in cookie_header.split(';'):
                part = part.strip()
                if '=' in part:
                    name, value = part.split('=', 1)
                    cookies[name.strip()] = value.strip()
        
        return cookies
    
    def _decode_binary_body(self, data: bytes, content_type: str) -> str:
        """Decode binary body based on content type"""
        content_type_lower = content_type.lower()
        
        # Try UTF-8 first
        try:
            return data.decode('utf-8')
        except:
            pass
        
        # Protobuf - encode as base64
        if 'protobuf' in content_type_lower or 'x-protobuf' in content_type_lower:
            return f"[protobuf:{base64.b64encode(data).decode()}]"
        
        # MessagePack
        if 'msgpack' in content_type_lower:
            try:
                import msgpack
                return json.dumps(msgpack.unpackb(data, raw=False))
            except:
                return f"[msgpack:{base64.b64encode(data).decode()}]"
        
        # Generic binary
        return f"[binary:{len(data)} bytes:{base64.b64encode(data[:100]).decode()}...]"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get bridge statistics"""
        return {
            **self.stats,
            'pending_responses': len(self._pending_requests)
        }


# ==================== Frida Scripts ====================

# JavaScript to inject into Android apps via Frida
ANDROID_HTTP_INTERCEPT_SCRIPT = '''
/*
 * Jarwis Android HTTP Interceptor
 * Captures HTTP traffic from OkHttp, Retrofit, Volley, etc.
 * Sends to Python via Frida send()
 */

var requestCounter = 0;

Java.perform(function() {
    
    // ====== OkHttp3 Interceptor ======
    try {
        var Interceptor = Java.use('okhttp3.Interceptor');
        var Chain = Java.use('okhttp3.Interceptor$Chain');
        var Buffer = Java.use('okio.Buffer');
        
        var RealInterceptorChain = Java.use('okhttp3.internal.http.RealInterceptorChain');
        var originalProceed = RealInterceptorChain.proceed.overload('okhttp3.Request');
        
        originalProceed.implementation = function(request) {
            var requestId = 'req_' + (++requestCounter) + '_' + Date.now();
            
            // Capture request
            var url = request.url().toString();
            var method = request.method();
            var headers = {};
            var headerList = request.headers();
            for (var i = 0; i < headerList.size(); i++) {
                headers[headerList.name(i)] = headerList.value(i);
            }
            
            var body = '';
            var requestBody = request.body();
            if (requestBody != null) {
                try {
                    var buffer = Buffer.$new();
                    requestBody.writeTo(buffer);
                    body = buffer.readUtf8();
                } catch(e) {}
            }
            
            send({
                type: 'http_request',
                hook: 'okhttp3',
                request_id: requestId,
                url: url,
                method: method,
                headers: headers,
                body: body
            });
            
            // Execute request
            var startTime = Date.now();
            var response = originalProceed.call(this, request);
            var responseTime = Date.now() - startTime;
            
            // Capture response
            try {
                var responseHeaders = {};
                var respHeaderList = response.headers();
                for (var i = 0; i < respHeaderList.size(); i++) {
                    responseHeaders[respHeaderList.name(i)] = respHeaderList.value(i);
                }
                
                var responseBody = '';
                var respBody = response.body();
                if (respBody != null) {
                    var source = respBody.source();
                    source.request(Long.MAX_VALUE);
                    var buffer = source.buffer().clone();
                    responseBody = buffer.readUtf8();
                }
                
                send({
                    type: 'http_response',
                    hook: 'okhttp3',
                    request_id: requestId,
                    status_code: response.code(),
                    headers: responseHeaders,
                    body: responseBody.substring(0, 10000),
                    response_time_ms: responseTime
                });
            } catch(e) {}
            
            return response;
        };
        
        send({type: 'hook_installed', hook: 'okhttp3'});
    } catch(e) {
        send({type: 'hook_failed', hook: 'okhttp3', error: e.toString()});
    }
    
    // ====== Retrofit Interceptor ======
    try {
        var RetrofitCall = Java.use('retrofit2.OkHttpCall');
        var originalExecute = RetrofitCall.execute;
        
        originalExecute.implementation = function() {
            send({type: 'retrofit_call', message: 'Retrofit request executing'});
            return originalExecute.call(this);
        };
        
        send({type: 'hook_installed', hook: 'retrofit'});
    } catch(e) {}
    
    // ====== Volley Interceptor ======
    try {
        var VolleyRequest = Java.use('com.android.volley.toolbox.HurlStack');
        var performRequest = VolleyRequest.performRequest;
        
        performRequest.implementation = function(request, additionalHeaders) {
            var url = request.getUrl();
            var method = request.getMethod();
            
            send({
                type: 'http_request',
                hook: 'volley',
                url: url,
                method: method == 0 ? 'GET' : method == 1 ? 'POST' : 'UNKNOWN',
                headers: additionalHeaders || {}
            });
            
            return performRequest.call(this, request, additionalHeaders);
        };
        
        send({type: 'hook_installed', hook: 'volley'});
    } catch(e) {}
    
    // ====== Auth Token Capture (SharedPreferences) ======
    try {
        var SharedPreferences = Java.use('android.content.SharedPreferences');
        var Editor = Java.use('android.content.SharedPreferences$Editor');
        
        Editor.putString.implementation = function(key, value) {
            var keyLower = key.toLowerCase();
            if (keyLower.includes('token') || keyLower.includes('auth') || 
                keyLower.includes('session') || keyLower.includes('jwt')) {
                send({
                    type: 'auth_token',
                    token_type: 'shared_pref',
                    token_value: value,
                    header_name: key,
                    source: 'shared_preferences'
                });
            }
            return this.putString(key, value);
        };
        
        send({type: 'hook_installed', hook: 'shared_prefs'});
    } catch(e) {}
    
    send({type: 'initialization_complete', hooks: requestCounter});
});
'''

# JavaScript to inject into iOS apps via Frida
IOS_HTTP_INTERCEPT_SCRIPT = '''
/*
 * Jarwis iOS HTTP Interceptor
 * Captures HTTP traffic from NSURLSession, AFNetworking, Alamofire
 */

var requestCounter = 0;

// ====== NSURLSession Interceptor ======
try {
    var NSURLSession = ObjC.classes.NSURLSession;
    var dataTaskWithRequest = NSURLSession['- dataTaskWithRequest:completionHandler:'];
    
    Interceptor.attach(dataTaskWithRequest.implementation, {
        onEnter: function(args) {
            var request = ObjC.Object(args[2]);
            var requestId = 'req_' + (++requestCounter) + '_' + Date.now();
            
            var url = request.URL().absoluteString().toString();
            var method = request.HTTPMethod().toString();
            
            var headers = {};
            var allHeaders = request.allHTTPHeaderFields();
            if (allHeaders) {
                var keys = allHeaders.allKeys();
                for (var i = 0; i < keys.count(); i++) {
                    var key = keys.objectAtIndex_(i).toString();
                    headers[key] = allHeaders.objectForKey_(key).toString();
                }
            }
            
            var body = '';
            var httpBody = request.HTTPBody();
            if (httpBody) {
                body = ObjC.classes.NSString.alloc().initWithData_encoding_(httpBody, 4).toString();
            }
            
            send({
                type: 'http_request',
                hook: 'urlsession',
                request_id: requestId,
                url: url,
                method: method,
                headers: headers,
                body: body
            });
            
            this.requestId = requestId;
        }
    });
    
    send({type: 'hook_installed', hook: 'urlsession'});
} catch(e) {
    send({type: 'hook_failed', hook: 'urlsession', error: e.toString()});
}

// ====== Alamofire Interceptor ======
try {
    var SessionManager = ObjC.classes.Alamofire.SessionManager;
    if (SessionManager) {
        var request = SessionManager['- request:method:parameters:encoding:headers:'];
        Interceptor.attach(request.implementation, {
            onEnter: function(args) {
                var url = ObjC.Object(args[2]).toString();
                send({
                    type: 'http_request',
                    hook: 'alamofire',
                    url: url
                });
            }
        });
        send({type: 'hook_installed', hook: 'alamofire'});
    }
} catch(e) {}

send({type: 'initialization_complete', platform: 'ios'});
'''


def get_android_intercept_script() -> str:
    """Get Android HTTP interception Frida script"""
    return ANDROID_HTTP_INTERCEPT_SCRIPT


def get_ios_intercept_script() -> str:
    """Get iOS HTTP interception Frida script"""
    return IOS_HTTP_INTERCEPT_SCRIPT


def get_combined_script(platform: str = "android", include_ssl_bypass: bool = True) -> str:
    """
    Get combined Frida script with SSL bypass + HTTP interception.
    
    Args:
        platform: android or ios
        include_ssl_bypass: Include SSL pinning bypass
        
    Returns:
        Complete Frida JavaScript
    """
    scripts = []
    
    if include_ssl_bypass:
        # Import SSL bypass from frida_ssl_bypass.py (reference only)
        scripts.append("// SSL Bypass included from frida_ssl_bypass.py")
    
    if platform == "android":
        scripts.append(ANDROID_HTTP_INTERCEPT_SCRIPT)
    else:
        scripts.append(IOS_HTTP_INTERCEPT_SCRIPT)
    
    return "\n\n".join(scripts)
