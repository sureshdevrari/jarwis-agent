"""
Jarwis AGI - Mobile Runtime Instrumentation Engine
Uses Frida for dynamic analysis of mobile applications

Features:
- SSL Pinning Bypass
- Function Hooking
- API Monitoring
- Crypto Operations Tracking
"""

import os
import re
import json
import asyncio
import logging
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any

logger = logging.getLogger(__name__)


@dataclass
class RuntimeFinding:
    """Finding from runtime analysis"""
    id: str
    category: str
    severity: str
    title: str
    description: str
    function_name: str
    arguments: List[Any] = field(default_factory=list)
    return_value: Any = None
    stack_trace: str = ""
    timestamp: str = ""


@dataclass
class InterceptedRequest:
    """Intercepted network request during runtime"""
    id: str
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    response_status: int = 0
    response_body: str = ""
    is_https: bool = False
    certificate_info: Dict = field(default_factory=dict)


class RuntimeAnalyzer:
    """
    Runtime Instrumentation Engine using Frida
    Performs dynamic analysis on running mobile applications
    """
    
    # Frida scripts for different analyses
    FRIDA_SCRIPTS = {
        'ssl_pinning_bypass': '''
// SSL Pinning Bypass for Android
Java.perform(function() {
    // TrustManager bypass
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManagerImpl = Java.registerClass({
        name: 'com.jarwis.TrustManager',
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
    
    // OkHttp bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            send({type: 'ssl_bypass', hostname: hostname});
            return;
        };
    } catch(e) {}
    
    send({type: 'hook_installed', name: 'ssl_pinning_bypass'});
});
''',
        
        'api_monitor': '''
// API Call Monitor
Java.perform(function() {
    // Monitor OkHttp requests
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Request = Java.use('okhttp3.Request');
        var Call = Java.use('okhttp3.Call');
        
        var RealCall = Java.use('okhttp3.RealCall');
        RealCall.execute.implementation = function() {
            var request = this.request();
            send({
                type: 'http_request',
                url: request.url().toString(),
                method: request.method(),
                headers: request.headers().toString()
            });
            var response = this.execute();
            send({
                type: 'http_response',
                url: request.url().toString(),
                code: response.code()
            });
            return response;
        };
    } catch(e) {}
    
    // Monitor HttpURLConnection
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.connect.implementation = function() {
            send({
                type: 'http_request',
                url: this.getURL().toString(),
                method: this.getRequestMethod()
            });
            return this.connect();
        };
    } catch(e) {}
    
    send({type: 'hook_installed', name: 'api_monitor'});
});
''',
        
        'crypto_monitor': '''
// Crypto Operations Monitor
Java.perform(function() {
    // Monitor encryption
    var Cipher = Java.use('javax.crypto.Cipher');
    
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var result = this.doFinal(input);
        var mode = this.getOpmode() == 1 ? 'ENCRYPT' : 'DECRYPT';
        send({
            type: 'crypto_operation',
            mode: mode,
            algorithm: this.getAlgorithm(),
            input_length: input.length,
            output_length: result.length
        });
        return result;
    };
    
    // Monitor key generation
    var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
    KeyGenerator.generateKey.implementation = function() {
        var key = this.generateKey();
        send({
            type: 'key_generation',
            algorithm: this.getAlgorithm()
        });
        return key;
    };
    
    send({type: 'hook_installed', name: 'crypto_monitor'});
});
''',
        
        'auth_monitor': '''
// Authentication Monitor
Java.perform(function() {
    // SharedPreferences monitor
    var SharedPreferences = Java.use('android.content.SharedPreferences');
    var Editor = Java.use('android.content.SharedPreferences$Editor');
    
    Editor.putString.implementation = function(key, value) {
        if (key.toLowerCase().includes('token') || 
            key.toLowerCase().includes('session') ||
            key.toLowerCase().includes('auth') ||
            key.toLowerCase().includes('password')) {
            send({
                type: 'sensitive_storage',
                key: key,
                value_length: value ? value.length : 0
            });
        }
        return this.putString(key, value);
    };
    
    // KeyStore monitor
    try {
        var KeyStore = Java.use('java.security.KeyStore');
        KeyStore.getKey.implementation = function(alias, password) {
            send({
                type: 'keystore_access',
                alias: alias
            });
            return this.getKey(alias, password);
        };
    } catch(e) {}
    
    send({type: 'hook_installed', name: 'auth_monitor'});
});
''',

        'ios_ssl_bypass': '''
// iOS SSL Pinning Bypass
if (ObjC.available) {
    try {
        // NSURLSession bypass
        var NSURLSession = ObjC.classes.NSURLSession;
        Interceptor.attach(NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'].implementation, {
            onEnter: function(args) {
                send({type: 'ssl_bypass', target: 'NSURLSession'});
            }
        });
    } catch(e) {}
    
    try {
        // AFNetworking bypass
        var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (AFSecurityPolicy) {
            Interceptor.attach(AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
                onEnter: function(args) {
                    args[2] = ptr(0); // AFSSLPinningModeNone
                    send({type: 'ssl_bypass', target: 'AFNetworking'});
                }
            });
        }
    } catch(e) {}
    
    send({type: 'hook_installed', name: 'ios_ssl_bypass'});
}
'''
    }
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.frida_available = False
        self.device = None
        self.session = None
        self.script = None
        self.findings: List[RuntimeFinding] = []
        self.requests: List[InterceptedRequest] = []
        self._message_handler: Optional[Callable] = None
        self._check_frida()
    
    def _check_frida(self):
        """Check if Frida is available"""
        try:
            import frida
            self.frida_available = True
            logger.info("Frida is available for runtime analysis")
        except ImportError:
            self.frida_available = False
            logger.warning("Frida not installed. Runtime analysis limited.")
    
    def set_message_handler(self, handler: Callable):
        """Set callback for Frida messages"""
        self._message_handler = handler
    
    async def connect_device(self, device_id: str = None) -> bool:
        """Connect to a device for instrumentation"""
        if not self.frida_available:
            logger.error("Frida not available")
            return False
        
        try:
            import frida
            
            if device_id:
                self.device = frida.get_device(device_id)
            else:
                # Try USB first, then local
                try:
                    self.device = frida.get_usb_device(timeout=5)
                except:
                    self.device = frida.get_local_device()
            
            logger.info(f"Connected to device: {self.device.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to device: {e}")
            return False
    
    async def attach_to_app(self, package_name: str) -> bool:
        """Attach to a running application"""
        if not self.device:
            logger.error("No device connected")
            return False
        
        try:
            self.session = self.device.attach(package_name)
            logger.info(f"Attached to {package_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to attach to {package_name}: {e}")
            return False
    
    async def spawn_app(self, package_name: str) -> bool:
        """Spawn and attach to an application"""
        if not self.device:
            logger.error("No device connected")
            return False
        
        try:
            pid = self.device.spawn([package_name])
            self.session = self.device.attach(pid)
            self.device.resume(pid)
            logger.info(f"Spawned and attached to {package_name} (PID: {pid})")
            return True
        except Exception as e:
            logger.error(f"Failed to spawn {package_name}: {e}")
            return False
    
    def _on_message(self, message: dict, data: bytes):
        """Handle messages from Frida scripts"""
        if message['type'] == 'send':
            payload = message['payload']
            
            if payload.get('type') == 'http_request':
                request = InterceptedRequest(
                    id=f"REQ-{len(self.requests)+1:04d}",
                    url=payload.get('url', ''),
                    method=payload.get('method', 'GET'),
                    headers=payload.get('headers', {}),
                    is_https=payload.get('url', '').startswith('https')
                )
                self.requests.append(request)
                
            elif payload.get('type') == 'ssl_bypass':
                self.findings.append(RuntimeFinding(
                    id=f"M3-SSL-{len(self.findings)+1:03d}",
                    category="M3",
                    severity="info",
                    title="SSL Pinning Bypassed",
                    description=f"SSL pinning bypassed for: {payload.get('hostname', 'unknown')}",
                    function_name="SSL Certificate Validation"
                ))
                
            elif payload.get('type') == 'sensitive_storage':
                self.findings.append(RuntimeFinding(
                    id=f"M2-STORE-{len(self.findings)+1:03d}",
                    category="M2",
                    severity="medium",
                    title="Sensitive Data in Storage",
                    description=f"Sensitive key stored: {payload.get('key')}",
                    function_name="SharedPreferences.putString"
                ))
                
            elif payload.get('type') == 'crypto_operation':
                logger.info(f"Crypto: {payload.get('mode')} using {payload.get('algorithm')}")
            
            if self._message_handler:
                self._message_handler(payload)
                
        elif message['type'] == 'error':
            logger.error(f"Frida error: {message.get('description')}")
    
    async def inject_script(self, script_name: str) -> bool:
        """Inject a Frida script"""
        if not self.session:
            logger.error("No session active")
            return False
        
        script_code = self.FRIDA_SCRIPTS.get(script_name)
        if not script_code:
            logger.error(f"Unknown script: {script_name}")
            return False
        
        try:
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_message)
            self.script.load()
            logger.info(f"Injected script: {script_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to inject script: {e}")
            return False
    
    async def inject_custom_script(self, script_code: str) -> bool:
        """Inject a custom Frida script"""
        if not self.session:
            logger.error("No session active")
            return False
        
        try:
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_message)
            self.script.load()
            logger.info("Injected custom script")
            return True
        except Exception as e:
            logger.error(f"Failed to inject custom script: {e}")
            return False
    
    async def run_full_analysis(
        self, 
        package_name: str, 
        duration: int = 60,
        bypass_ssl_pinning: bool = False
    ) -> tuple[List[RuntimeFinding], List[InterceptedRequest]]:
        """
        Run full runtime analysis on an app
        
        Args:
            package_name: Package name of the app
            duration: How long to monitor (seconds)
            bypass_ssl_pinning: Whether to bypass SSL pinning using Frida
            
        Returns:
            Tuple of (findings, intercepted_requests)
        """
        self.findings = []
        self.requests = []
        
        if not self.frida_available:
            logger.warning("Frida not available, skipping runtime analysis")
            return [], []
        
        # Connect to device
        if not await self.connect_device():
            return [], []
        
        # Spawn or attach to app
        try:
            if not await self.spawn_app(package_name):
                # Try attaching if spawn fails
                if not await self.attach_to_app(package_name):
                    return [], []
        except:
            return [], []
        
        # Inject analysis scripts
        # Only include SSL pinning bypass if requested by user
        scripts = ['api_monitor', 'crypto_monitor', 'auth_monitor']
        if bypass_ssl_pinning:
            logger.info("[OK]  SSL Pinning Bypass ENABLED - Injecting Frida scripts")
            scripts.insert(0, 'ssl_pinning_bypass')  # Add SSL bypass first
        else:
            logger.info("[!]   SSL Pinning Bypass DISABLED - Skipping SSL bypass scripts")
        
        for script_name in scripts:
            await self.inject_script(script_name)
        
        # Monitor for specified duration
        logger.info(f"Monitoring app for {duration} seconds...")
        await asyncio.sleep(duration)
        
        # Cleanup
        if self.session:
            self.session.detach()
        
        return self.findings, self.requests
    
    async def bypass_ssl_pinning(self, package_name: str) -> bool:
        """
        Bypass SSL pinning for an app
        Useful for intercepting HTTPS traffic
        """
        if not await self.connect_device():
            return False
        
        if not await self.attach_to_app(package_name):
            return False
        
        platform = self.device.type
        if platform == 'ios':
            return await self.inject_script('ios_ssl_bypass')
        else:
            return await self.inject_script('ssl_pinning_bypass')
    
    def get_findings(self) -> List[RuntimeFinding]:
        """Get all runtime findings"""
        return self.findings
    
    def get_requests(self) -> List[InterceptedRequest]:
        """Get all intercepted requests"""
        return self.requests
    
    async def cleanup(self):
        """Cleanup resources"""
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
