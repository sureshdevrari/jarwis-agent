"""
Jarwis AGI - Frida SSL Pinning Bypass Module
Comprehensive SSL/TLS certificate pinning bypass for Android and iOS apps

Features:
- Multiple bypass techniques for different libraries
- Universal SSL bypass for OkHttp, Retrofit, Volley, HttpURLConnection
- iOS bypass for AFNetworking, Alamofire, NSURLSession
- Custom pinning implementation detection and bypass
- Real-time certificate interception logging
"""

import os
import re
import json
import asyncio
import logging
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class SSLBypassResult:
    """Result of SSL pinning bypass attempt"""
    success: bool
    method_used: str
    libraries_bypassed: List[str] = field(default_factory=list)
    error: str = ""
    hooks_installed: int = 0
    requests_intercepted: int = 0


@dataclass
class InterceptedSSLRequest:
    """SSL request intercepted after bypass"""
    timestamp: str
    url: str
    method: str
    host: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    response_code: int = 0
    response_body: str = ""
    certificate_chain: List[str] = field(default_factory=list)
    original_pins: List[str] = field(default_factory=list)


class FridaSSLBypass:
    """
    Comprehensive Frida-based SSL Pinning Bypass
    Supports Android and iOS applications
    """
    
    # Android SSL Pinning Bypass Scripts
    ANDROID_BYPASS_SCRIPTS = {
        'universal': '''
/*
 * Jarwis Universal Android SSL Pinning Bypass
 * Bypasses multiple SSL pinning implementations
 */

Java.perform(function() {
    var bypassCount = 0;
    var interceptedRequests = 0;
    
    // ====== TRUSTMANAGER BYPASS ======
    try {
        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        
        var TrustManagerImpl = Java.registerClass({
            name: 'com.jarwis.bypass.TrustManager',
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        
        var TrustManagers = [TrustManagerImpl.$new()];
        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, TrustManagers, null);
        
        bypassCount++;
        send({type: 'bypass_installed', target: 'TrustManager', status: 'success'});
    } catch(e) {
        send({type: 'bypass_failed', target: 'TrustManager', error: e.toString()});
    }
    
    // ====== OKHTTP3 BYPASS ======
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            send({type: 'ssl_bypass', library: 'OkHttp3', hostname: hostname});
            interceptedRequests++;
            return;
        };
        
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, peerCertificates) {
            send({type: 'ssl_bypass', library: 'OkHttp3', hostname: hostname});
            interceptedRequests++;
            return;
        };
        
        bypassCount++;
        send({type: 'bypass_installed', target: 'OkHttp3.CertificatePinner', status: 'success'});
    } catch(e) {
        send({type: 'bypass_failed', target: 'OkHttp3', error: e.toString()});
    }
    
    // ====== OKHTTP (Legacy) BYPASS ======
    try {
        var CertificatePinnerOld = Java.use('com.squareup.okhttp.CertificatePinner');
        CertificatePinnerOld.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            send({type: 'ssl_bypass', library: 'OkHttp2', hostname: hostname});
            interceptedRequests++;
            return;
        };
        bypassCount++;
        send({type: 'bypass_installed', target: 'OkHttp2.CertificatePinner', status: 'success'});
    } catch(e) {}
    
    // ====== RETROFIT BYPASS ======
    try {
        var Retrofit = Java.use('retrofit2.Retrofit$Builder');
        var originalClient = Retrofit.client;
        Retrofit.client.implementation = function(client) {
            send({type: 'retrofit_client', message: 'Intercepting Retrofit client setup'});
            return originalClient.call(this, client);
        };
        bypassCount++;
        send({type: 'bypass_installed', target: 'Retrofit', status: 'success'});
    } catch(e) {}
    
    // ====== TRUSTKIT BYPASS ======
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.TrustKit');
        TrustKit.getInstance.implementation = function() {
            send({type: 'ssl_bypass', library: 'TrustKit', message: 'Bypassed TrustKit initialization'});
            return null;
        };
        bypassCount++;
        send({type: 'bypass_installed', target: 'TrustKit', status: 'success'});
    } catch(e) {}
    
    // ====== NETWORK SECURITY CONFIG BYPASS ======
    try {
        var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
        NetworkSecurityConfig.isCleartextTrafficPermitted.overload().implementation = function() {
            return true;
        };
        bypassCount++;
        send({type: 'bypass_installed', target: 'NetworkSecurityConfig', status: 'success'});
    } catch(e) {}
    
    // ====== CONSCRYPT BYPASS ======
    try {
        var ConscryptTrustManager = Java.use('com.google.android.gms.org.conscrypt.TrustManagerImpl');
        ConscryptTrustManager.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            send({type: 'ssl_bypass', library: 'Conscrypt', hostname: host});
            interceptedRequests++;
            return untrustedChain;
        };
        bypassCount++;
        send({type: 'bypass_installed', target: 'Conscrypt', status: 'success'});
    } catch(e) {}
    
    // ====== APACHE HTTP BYPASS ======
    try {
        var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function(host, cns, subjectAlts, strictWithSubDomains) {
            send({type: 'ssl_bypass', library: 'ApacheHTTP', hostname: host});
            interceptedRequests++;
            return;
        };
        bypassCount++;
        send({type: 'bypass_installed', target: 'ApacheHTTP', status: 'success'});
    } catch(e) {}
    
    // ====== HOSTNAMEVERIFIER BYPASS ======
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var SSLSession = Java.use('javax.net.ssl.SSLSession');
        
        var HostnameVerifierImpl = Java.registerClass({
            name: 'com.jarwis.bypass.HostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    send({type: 'ssl_bypass', library: 'HostnameVerifier', hostname: hostname});
                    return true;
                }
            }
        });
        
        // Hook HttpsURLConnection
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            return this.setDefaultHostnameVerifier(HostnameVerifierImpl.$new());
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function(verifier) {
            return this.setHostnameVerifier(HostnameVerifierImpl.$new());
        };
        
        bypassCount++;
        send({type: 'bypass_installed', target: 'HostnameVerifier', status: 'success'});
    } catch(e) {}
    
    // ====== WEBVIEW SSL ERROR BYPASS ======
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            send({type: 'ssl_bypass', library: 'WebView', message: 'Accepting SSL error in WebView'});
            handler.proceed();
            return;
        };
        bypassCount++;
        send({type: 'bypass_installed', target: 'WebView', status: 'success'});
    } catch(e) {}
    
    // ====== REQUEST INTERCEPTOR ======
    try {
        var RealCall = Java.use('okhttp3.RealCall');
        
        RealCall.execute.implementation = function() {
            var request = this.request();
            var url = request.url().toString();
            var method = request.method();
            var headers = {};
            
            try {
                var headerNames = request.headers().names().toArray();
                for (var i = 0; i < headerNames.length; i++) {
                    headers[headerNames[i]] = request.headers().get(headerNames[i]);
                }
            } catch(e) {}
            
            var body = "";
            try {
                if (request.body() != null) {
                    var Buffer = Java.use('okio.Buffer');
                    var buffer = Buffer.$new();
                    request.body().writeTo(buffer);
                    body = buffer.readUtf8();
                }
            } catch(e) {}
            
            send({
                type: 'http_request',
                url: url,
                method: method,
                headers: headers,
                body: body,
                timestamp: new Date().toISOString()
            });
            
            var response = this.execute();
            
            var responseBody = "";
            try {
                var source = response.body().source();
                source.request(Long.MAX_VALUE);
                var buffer = source.buffer().clone();
                responseBody = buffer.readUtf8();
            } catch(e) {}
            
            send({
                type: 'http_response',
                url: url,
                status: response.code(),
                body: responseBody.substring(0, 5000),  // Limit response size
                timestamp: new Date().toISOString()
            });
            
            interceptedRequests++;
            return response;
        };
        
        // Also hook async calls
        RealCall.enqueue.implementation = function(callback) {
            var request = this.request();
            send({
                type: 'http_request',
                url: request.url().toString(),
                method: request.method(),
                async: true,
                timestamp: new Date().toISOString()
            });
            return this.enqueue(callback);
        };
        
        send({type: 'bypass_installed', target: 'RequestInterceptor', status: 'success'});
    } catch(e) {}
    
    send({
        type: 'bypass_summary',
        total_bypasses: bypassCount,
        message: 'Jarwis SSL Bypass initialized'
    });
});
''',
        
        'flutter': '''
/*
 * Jarwis Flutter SSL Pinning Bypass
 * For Flutter/Dart applications
 */

// Flutter uses BoringSSL, need to hook native functions
Interceptor.attach(Module.findExportByName("libflutter.so", "ssl_crypto_x509_session_verify_cert_chain") || 
                   Module.findExportByName("libflutter.so", "ssl_verify_peer_cert"), {
    onEnter: function(args) {
        send({type: 'ssl_bypass', library: 'Flutter-BoringSSL', message: 'Intercepting cert verification'});
    },
    onLeave: function(retval) {
        retval.replace(0);  // Return success
        send({type: 'ssl_bypass', library: 'Flutter-BoringSSL', message: 'Certificate verification bypassed'});
    }
});

// Alternative: Hook Dart HTTP client
Java.perform(function() {
    try {
        var DartHttpClient = Java.use('io.flutter.plugin.common.MethodChannel');
        send({type: 'bypass_installed', target: 'Flutter', status: 'partial'});
    } catch(e) {}
});

send({type: 'bypass_summary', target: 'Flutter', message: 'Flutter bypass initialized'});
''',

        'react_native': '''
/*
 * Jarwis React Native SSL Pinning Bypass
 */

Java.perform(function() {
    // OkHttp is commonly used in React Native
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            send({type: 'ssl_bypass', library: 'ReactNative-OkHttp', hostname: hostname});
            return;
        };
        send({type: 'bypass_installed', target: 'ReactNative-OkHttp', status: 'success'});
    } catch(e) {}
    
    // React Native Pinning Library
    try {
        var RNPinning = Java.use('com.toyberman.RNSslPinningModule');
        RNPinning.fetch.implementation = function(hostname, options, callback) {
            send({type: 'ssl_bypass', library: 'RNSslPinning', hostname: hostname});
            return this.fetch(hostname, options, callback);
        };
        send({type: 'bypass_installed', target: 'RNSslPinning', status: 'success'});
    } catch(e) {}
});

send({type: 'bypass_summary', target: 'ReactNative', message: 'React Native bypass initialized'});
'''
    }
    
    # iOS SSL Pinning Bypass Scripts
    IOS_BYPASS_SCRIPTS = {
        'universal': '''
/*
 * Jarwis Universal iOS SSL Pinning Bypass
 */

if (ObjC.available) {
    var bypassCount = 0;
    
    // ====== NSURLSession Bypass ======
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        
        // Hook URLSession delegate method
        var URLSessionClass = ObjC.classes.NSURLSession;
        Interceptor.attach(ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
            onEnter: function(args) {
                var request = new ObjC.Object(args[2]);
                send({type: 'http_request', url: request.URL().absoluteString().toString(), method: request.HTTPMethod().toString()});
            }
        });
        
        bypassCount++;
        send({type: 'bypass_installed', target: 'NSURLSession', status: 'success'});
    } catch(e) {
        send({type: 'bypass_failed', target: 'NSURLSession', error: e.toString()});
    }
    
    // ====== AFNetworking Bypass ======
    try {
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            // Bypass SSL Pinning Mode
            Interceptor.attach(AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
                onEnter: function(args) {
                    args[2] = ptr(0);  // AFSSLPinningModeNone
                    send({type: 'ssl_bypass', library: 'AFNetworking', message: 'Set pinning mode to None'});
                }
            });
            
            // Bypass certificate evaluation
            Interceptor.attach(AFSecurityPolicy['- evaluateServerTrust:forDomain:'].implementation, {
                onLeave: function(retval) {
                    retval.replace(1);
                    send({type: 'ssl_bypass', library: 'AFNetworking', message: 'Certificate evaluation bypassed'});
                }
            });
            
            bypassCount++;
            send({type: 'bypass_installed', target: 'AFNetworking', status: 'success'});
        }
    } catch(e) {}
    
    // ====== Alamofire Bypass ======
    try {
        var AlamofireServerTrust = ObjC.classes.ServerTrustManager;
        if (AlamofireServerTrust) {
            Interceptor.attach(AlamofireServerTrust['- serverTrustEvaluator:didEvaluate:forHost:'].implementation, {
                onLeave: function(retval) {
                    retval.replace(1);
                    send({type: 'ssl_bypass', library: 'Alamofire', message: 'Trust evaluation bypassed'});
                }
            });
            bypassCount++;
            send({type: 'bypass_installed', target: 'Alamofire', status: 'success'});
        }
    } catch(e) {}
    
    // ====== TrustKit Bypass ======
    try {
        var TrustKit = ObjC.classes.TrustKit;
        if (TrustKit) {
            Interceptor.attach(TrustKit['+ initSharedInstanceWithConfiguration:'].implementation, {
                onEnter: function(args) {
                    send({type: 'ssl_bypass', library: 'TrustKit', message: 'Intercepting TrustKit init'});
                }
            });
            bypassCount++;
            send({type: 'bypass_installed', target: 'TrustKit', status: 'success'});
        }
    } catch(e) {}
    
    // ====== SecTrust Bypass (Low-level) ======
    try {
        var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onLeave: function(retval) {
                    retval.replace(0);  // errSecSuccess
                    send({type: 'ssl_bypass', library: 'SecTrust', message: 'SecTrustEvaluate bypassed'});
                }
            });
            bypassCount++;
            send({type: 'bypass_installed', target: 'SecTrust', status: 'success'});
        }
        
        var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
        if (SecTrustEvaluateWithError) {
            Interceptor.attach(SecTrustEvaluateWithError, {
                onLeave: function(retval) {
                    retval.replace(1);  // true = success
                    send({type: 'ssl_bypass', library: 'SecTrust', message: 'SecTrustEvaluateWithError bypassed'});
                }
            });
        }
    } catch(e) {}
    
    // ====== SSL_CTX Bypass (BoringSSL/OpenSSL) ======
    try {
        var SSL_CTX_set_custom_verify = Module.findExportByName(null, "SSL_CTX_set_custom_verify");
        if (SSL_CTX_set_custom_verify) {
            Interceptor.attach(SSL_CTX_set_custom_verify, {
                onEnter: function(args) {
                    // Set callback to null (no verification)
                    args[2] = ptr(0);
                    send({type: 'ssl_bypass', library: 'BoringSSL', message: 'Custom verify disabled'});
                }
            });
            bypassCount++;
            send({type: 'bypass_installed', target: 'BoringSSL', status: 'success'});
        }
    } catch(e) {}
    
    send({
        type: 'bypass_summary',
        total_bypasses: bypassCount,
        platform: 'iOS',
        message: 'Jarwis iOS SSL Bypass initialized'
    });
    
} else {
    send({type: 'error', message: 'Objective-C runtime not available'});
}
''',
        
        'flutter_ios': '''
/*
 * Jarwis iOS Flutter SSL Bypass
 */

// Flutter iOS uses BoringSSL
var ssl_verify = Module.findExportByName("Flutter", "ssl_crypto_x509_session_verify_cert_chain");
if (ssl_verify) {
    Interceptor.attach(ssl_verify, {
        onLeave: function(retval) {
            retval.replace(0);
            send({type: 'ssl_bypass', library: 'Flutter-iOS', message: 'Certificate chain verification bypassed'});
        }
    });
    send({type: 'bypass_installed', target: 'Flutter-iOS', status: 'success'});
}

send({type: 'bypass_summary', target: 'Flutter-iOS', message: 'Flutter iOS bypass initialized'});
'''
    }
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.frida = None
        self.device = None
        self.session = None
        self.script = None
        self.is_connected = False
        
        # Callbacks
        self._request_callback: Optional[Callable] = None
        self._log_callback: Optional[Callable] = None
        
        # Captured data
        self.intercepted_requests: List[InterceptedSSLRequest] = []
        self.bypass_results: List[Dict] = []
        
        self._check_frida()
    
    def _check_frida(self) -> bool:
        """Check if Frida is available"""
        try:
            import frida
            self.frida = frida
            return True
        except ImportError:
            logger.warning("Frida not installed. Install with: pip install frida-tools")
            return False
    
    def set_request_callback(self, callback: Callable):
        """Set callback for intercepted requests"""
        self._request_callback = callback
    
    def set_log_callback(self, callback: Callable):
        """Set callback for logging"""
        self._log_callback = callback
    
    def _log(self, log_type: str, message: str, details: str = None):
        """Log with callback"""
        if self._log_callback:
            try:
                self._log_callback(log_type, message, details)
            except:
                pass
        logger.info(f"[{log_type}] {message}")
    
    async def connect_device(self, device_id: str = None, device_type: str = "usb") -> bool:
        """
        Connect to a device for instrumentation
        
        Args:
            device_id: Specific device ID (optional)
            device_type: 'usb', 'local', 'remote'
            
        Returns:
            True if connected successfully
        """
        if not self.frida:
            self._log('error', 'Frida not available')
            return False
        
        try:
            if device_id:
                self.device = self.frida.get_device(device_id)
            elif device_type == "usb":
                self.device = self.frida.get_usb_device(timeout=10)
            elif device_type == "local":
                self.device = self.frida.get_local_device()
            else:
                # Try USB first, then local
                try:
                    self.device = self.frida.get_usb_device(timeout=5)
                except:
                    self.device = self.frida.get_local_device()
            
            self.is_connected = True
            self._log('success', f'Connected to device: {self.device.name}')
            return True
            
        except Exception as e:
            self._log('error', f'Failed to connect to device: {e}')
            return False
    
    async def attach_and_bypass(
        self,
        package_name: str,
        platform: str = "android",
        spawn: bool = False,
        additional_scripts: List[str] = None
    ) -> SSLBypassResult:
        """
        Attach to an app and inject SSL bypass scripts
        
        Args:
            package_name: App package name (com.example.app)
            platform: 'android' or 'ios'
            spawn: If True, spawn the app; if False, attach to running app
            additional_scripts: Extra Frida scripts to inject
            
        Returns:
            SSLBypassResult with bypass status
        """
        result = SSLBypassResult(
            success=False,
            method_used="frida_injection"
        )
        
        if not self.is_connected:
            await self.connect_device()
        
        if not self.device:
            result.error = "No device connected"
            return result
        
        try:
            # Spawn or attach
            if spawn:
                self._log('info', f'Spawning {package_name}...')
                pid = self.device.spawn([package_name])
                self.session = self.device.attach(pid)
                self.device.resume(pid)
            else:
                self._log('info', f'Attaching to {package_name}...')
                self.session = self.device.attach(package_name)
            
            # Select appropriate bypass script
            if platform.lower() == "android":
                scripts = [self.ANDROID_BYPASS_SCRIPTS['universal']]
            else:
                scripts = [self.IOS_BYPASS_SCRIPTS['universal']]
            
            # Add additional scripts
            if additional_scripts:
                scripts.extend(additional_scripts)
            
            # Inject all scripts
            for script_code in scripts:
                script = self.session.create_script(script_code)
                script.on('message', self._on_frida_message)
                script.load()
                self.script = script
            
            result.success = True
            result.hooks_installed = len(self.bypass_results)
            result.libraries_bypassed = [r.get('target', '') for r in self.bypass_results if r.get('status') == 'success']
            
            self._log('success', f'SSL bypass active: {len(result.libraries_bypassed)} libraries bypassed')
            
        except Exception as e:
            result.error = str(e)
            self._log('error', f'Bypass failed: {e}')
        
        return result
    
    def _on_frida_message(self, message: Dict, data: Any):
        """Handle messages from Frida scripts"""
        if message['type'] == 'send':
            payload = message.get('payload', {})
            msg_type = payload.get('type', '')
            
            if msg_type == 'bypass_installed':
                self.bypass_results.append(payload)
                self._log('success', f"[OK]  Bypass: {payload.get('target', 'unknown')}")
                
            elif msg_type == 'ssl_bypass':
                hostname = payload.get('hostname', payload.get('message', ''))
                library = payload.get('library', 'unknown')
                self._log('info', f"[OK]  SSL bypass triggered: {library} [OK]  {hostname}")
                
            elif msg_type == 'http_request':
                request = InterceptedSSLRequest(
                    timestamp=payload.get('timestamp', datetime.now().isoformat()),
                    url=payload.get('url', ''),
                    method=payload.get('method', 'GET'),
                    host=self._extract_host(payload.get('url', '')),
                    headers=payload.get('headers', {}),
                    body=payload.get('body', '')
                )
                self.intercepted_requests.append(request)
                
                if self._request_callback:
                    self._request_callback(request)
                
                self._log('request', f"{request.method} {request.url}")
                
            elif msg_type == 'http_response':
                # Update last request with response
                url = payload.get('url', '')
                for req in reversed(self.intercepted_requests):
                    if req.url == url:
                        req.response_code = payload.get('status', 0)
                        req.response_body = payload.get('body', '')[:5000]
                        break
                
            elif msg_type == 'bypass_summary':
                total = payload.get('total_bypasses', 0)
                self._log('success', f"[!]   SSL bypass ready: {total} methods active")
                
            elif msg_type == 'error':
                self._log('error', payload.get('message', 'Unknown error'))
        
        elif message['type'] == 'error':
            self._log('error', message.get('description', str(message)))
    
    def _extract_host(self, url: str) -> str:
        """Extract hostname from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return ""
    
    async def bypass_with_emulator(
        self,
        apk_path: str,
        package_name: str = None,
        emulator_config: Dict = None
    ) -> Tuple[SSLBypassResult, List[InterceptedSSLRequest]]:
        """
        Full workflow: Start emulator, install APK, bypass SSL, capture traffic
        
        Args:
            apk_path: Path to APK file
            package_name: App package name (auto-detected if not provided)
            emulator_config: Emulator configuration
            
        Returns:
            Tuple of (bypass result, intercepted requests)
        """
        from .emulator_manager import EmulatorManager, EmulatorConfig
        
        self._log('phase', '[OK]  Starting full SSL bypass workflow')
        
        result = SSLBypassResult(success=False, method_used="emulator_frida")
        
        try:
            # Step 1: Setup emulator
            self._log('info', 'Setting up emulator...')
            emulator = EmulatorManager()
            
            status = emulator.get_status()
            if not status['running']:
                config = EmulatorConfig(**(emulator_config or {}))
                await emulator.start_emulator(headless=config.headless)
            
            # Step 2: Install Frida server
            if not status['frida_installed']:
                self._log('info', 'Installing Frida server on emulator...')
                await emulator.install_frida_server()
            
            await emulator.start_frida_server()
            
            # Step 3: Install APK
            self._log('info', f'Installing APK: {Path(apk_path).name}')
            await emulator.install_apk(apk_path)
            
            # Step 4: Get package name if not provided
            if not package_name:
                package_name = await self._get_package_name(apk_path)
            
            # Step 5: Connect to device
            await self.connect_device(device_type="usb")
            
            # Step 6: Launch app and inject bypass
            await emulator.launch_app(package_name)
            await asyncio.sleep(2)  # Wait for app to start
            
            result = await self.attach_and_bypass(package_name, platform="android")
            
            self._log('success', '[OK]  SSL bypass workflow complete')
            
        except Exception as e:
            result.error = str(e)
            self._log('error', f'Workflow failed: {e}')
        
        return result, self.intercepted_requests
    
    async def _get_package_name(self, apk_path: str) -> str:
        """Extract package name from APK"""
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
            logger.warning(f"Could not extract package name: {e}")
        
        return ""
    
    def get_intercepted_requests(self) -> List[InterceptedSSLRequest]:
        """Get all intercepted requests"""
        return self.intercepted_requests
    
    def get_burp_style_traffic(self) -> List[Dict]:
        """Get traffic in Burp-style format for analysis"""
        traffic = []
        for req in self.intercepted_requests:
            entry = {
                "id": len(traffic) + 1,
                "method": req.method,
                "url": req.url,
                "host": req.host,
                "request": self._format_request(req),
                "response": self._format_response(req),
                "timestamp": req.timestamp
            }
            traffic.append(entry)
        return traffic
    
    def _format_request(self, req: InterceptedSSLRequest) -> str:
        """Format request in Burp style"""
        from urllib.parse import urlparse
        parsed = urlparse(req.url)
        
        lines = [
            f"{req.method} {parsed.path or '/'} HTTP/1.1",
            f"Host: {req.host}"
        ]
        
        for key, value in req.headers.items():
            lines.append(f"{key}: {value}")
        
        if req.body:
            lines.append("")
            lines.append(req.body)
        
        return "\n".join(lines)
    
    def _format_response(self, req: InterceptedSSLRequest) -> str:
        """Format response in Burp style"""
        lines = [f"HTTP/1.1 {req.response_code} OK"]
        
        if req.response_body:
            lines.append("")
            lines.append(req.response_body)
        
        return "\n".join(lines)
    
    def cleanup(self):
        """Cleanup Frida session"""
        if self.script:
            try:
                self.script.unload()
            except:
                pass
        
        if self.session:
            try:
                self.session.detach()
            except:
                pass
        
        self.is_connected = False


# Convenience functions
async def bypass_ssl_pinning(
    package_name: str,
    platform: str = "android",
    device_id: str = None
) -> SSLBypassResult:
    """Quick SSL pinning bypass"""
    bypasser = FridaSSLBypass()
    await bypasser.connect_device(device_id)
    return await bypasser.attach_and_bypass(package_name, platform)


def create_ssl_bypass() -> FridaSSLBypass:
    """Create SSL bypass instance"""
    return FridaSSLBypass()
