"""
Jarwis Mobile Agent - Frida Manager

Manages Frida server lifecycle and SSL bypass scripts for mobile testing.
"""

import asyncio
import logging
import os
import platform
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


# SSL Bypass script for common frameworks
SSL_BYPASS_SCRIPT = '''
/*
 * Jarwis Universal SSL Pinning Bypass
 * Supports: OkHttp, Retrofit, TrustManager, Conscrypt, and more
 */

Java.perform(function() {
    console.log("[Jarwis] SSL Bypass script loaded");
    
    var hooked_count = 0;
    
    // === TrustManager (Universal Java SSL) ===
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        
        var TrustManager = Java.registerClass({
            name: 'com.jarwis.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        
        var TrustManagers = [TrustManager.$new()];
        var sslContext = SSLContext.getInstance('TLS');
        sslContext.init(null, TrustManagers, null);
        
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
            .implementation = function(km, tm, sr) {
                console.log("[Jarwis] Bypassing TrustManager");
                return this.init(km, TrustManagers, sr);
            };
        
        hooked_count++;
        console.log("[Jarwis] TrustManager hooked");
    } catch(e) {
        console.log("[Jarwis] TrustManager not found: " + e);
    }
    
    // === OkHttp3 CertificatePinner ===
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[Jarwis] Bypassing OkHttp3 pinning for: " + hostname);
            return;
        };
        
        try {
            CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0')
                .implementation = function(hostname, peerCertificates) {
                    console.log("[Jarwis] Bypassing OkHttp3 check$okhttp for: " + hostname);
                    return;
                };
        } catch(e) {}
        
        hooked_count++;
        console.log("[Jarwis] OkHttp3 CertificatePinner hooked");
    } catch(e) {
        console.log("[Jarwis] OkHttp3 not found: " + e);
    }
    
    // === OkHttp (older versions) ===
    try {
        var OkHttpClient = Java.use('com.squareup.okhttp.OkHttpClient');
        OkHttpClient.setCertificatePinner.implementation = function(certificatePinner) {
            console.log("[Jarwis] Bypassing OkHttp setCertificatePinner");
            return this;
        };
        hooked_count++;
        console.log("[Jarwis] OkHttp hooked");
    } catch(e) {}
    
    // === Retrofit ===
    try {
        var OkHttpClient3 = Java.use('okhttp3.OkHttpClient$Builder');
        OkHttpClient3.certificatePinner.implementation = function(certificatePinner) {
            console.log("[Jarwis] Bypassing OkHttpClient.Builder certificatePinner");
            return this;
        };
        hooked_count++;
        console.log("[Jarwis] OkHttpClient.Builder hooked");
    } catch(e) {}
    
    // === Network Security Config (Android 7+) ===
    try {
        var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
        NetworkSecurityConfig.isCertificateTransparencyVerificationRequired
            .implementation = function() {
                console.log("[Jarwis] Bypassing Certificate Transparency");
                return false;
            };
        hooked_count++;
    } catch(e) {}
    
    // === TrustKit ===
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
            console.log("[Jarwis] Bypassing TrustKit for: " + hostname);
            return true;
        };
        hooked_count++;
        console.log("[Jarwis] TrustKit hooked");
    } catch(e) {}
    
    // === Conscrypt ===
    try {
        var ConscryptTrustManager = Java.use('com.google.android.gms.org.conscrypt.TrustManagerImpl');
        ConscryptTrustManager.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[Jarwis] Bypassing Conscrypt for: " + host);
            return untrustedChain;
        };
        hooked_count++;
        console.log("[Jarwis] Conscrypt hooked");
    } catch(e) {}
    
    // === Apache HTTP Client ===
    try {
        var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean')
            .implementation = function(host, cns, subjectAlts, strictWithSubDomains) {
                console.log("[Jarwis] Bypassing Apache HTTP for: " + host);
                return;
            };
        hooked_count++;
        console.log("[Jarwis] Apache HTTP hooked");
    } catch(e) {}
    
    // === WebView SSL Errors ===
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[Jarwis] Bypassing WebView SSL error");
            handler.proceed();
        };
        hooked_count++;
        console.log("[Jarwis] WebView SSL hooked");
    } catch(e) {}
    
    // === HostnameVerifier ===
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[Jarwis] Bypassing setDefaultHostnameVerifier");
            return;
        };
        
        HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[Jarwis] Bypassing setHostnameVerifier");
            return;
        };
        hooked_count++;
        console.log("[Jarwis] HostnameVerifier hooked");
    } catch(e) {}
    
    console.log("[Jarwis] SSL Bypass complete. Hooked " + hooked_count + " methods.");
});
'''


class FridaManager:
    """
    Manages Frida server and scripts for mobile security testing.
    
    Responsibilities:
    - Push and start Frida server on device
    - Apply SSL bypass scripts
    - Monitor Frida output
    - Cleanup on shutdown
    """
    
    FRIDA_VERSION = "16.1.4"
    
    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = Path(data_dir) if data_dir else Path.home() / ".jarwis" / "agent"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self._frida_session = None
        self._frida_script = None
        self._device = None
        self._is_running = False
        self._version = ""
        
        # ADB helper
        self._adb_path = "adb"
    
    @property
    def is_running(self) -> bool:
        return self._is_running
    
    @property
    def version(self) -> str:
        return self._version
    
    def set_adb_path(self, path: str):
        """Set path to ADB executable"""
        self._adb_path = path
    
    async def _run_adb(self, *args, device_id: Optional[str] = None, timeout: int = 30) -> tuple:
        """Run ADB command"""
        cmd = [self._adb_path]
        if device_id:
            cmd.extend(["-s", device_id])
        cmd.extend(args)
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode(), stderr.decode(), proc.returncode
        except Exception as e:
            return "", str(e), -1
    
    async def check_frida_installed(self) -> bool:
        """Check if Frida is installed locally"""
        try:
            import frida
            self._version = frida.__version__
            return True
        except ImportError:
            return False
    
    async def ensure_server_running(self, device_id: str) -> bool:
        """Ensure Frida server is running on device"""
        logger.info(f"Ensuring Frida server on device: {device_id}")
        
        # Check if server is already running
        if await self._is_server_running(device_id):
            logger.info("Frida server already running")
            self._is_running = True
            return True
        
        # Check if server binary exists
        if not await self._is_server_installed(device_id):
            logger.info("Frida server not found, installing...")
            if not await self._install_server(device_id):
                return False
        
        # Start server
        return await self._start_server(device_id)
    
    async def _is_server_running(self, device_id: str) -> bool:
        """Check if Frida server is running"""
        stdout, _, _ = await self._run_adb(
            "shell", "ps | grep frida-server",
            device_id=device_id
        )
        return "frida-server" in stdout
    
    async def _is_server_installed(self, device_id: str) -> bool:
        """Check if Frida server is installed"""
        stdout, _, rc = await self._run_adb(
            "shell", "ls /data/local/tmp/frida-server",
            device_id=device_id
        )
        return rc == 0 and "No such file" not in stdout
    
    async def _install_server(self, device_id: str) -> bool:
        """Download and install Frida server on device"""
        # Determine architecture
        stdout, _, _ = await self._run_adb(
            "shell", "getprop", "ro.product.cpu.abi",
            device_id=device_id
        )
        arch = stdout.strip()
        
        arch_map = {
            "x86_64": "x86_64",
            "x86": "x86",
            "arm64-v8a": "arm64",
            "armeabi-v7a": "arm",
        }
        
        frida_arch = arch_map.get(arch, "x86_64")
        
        # Download Frida server
        server_path = self.data_dir / f"frida-server-{self.FRIDA_VERSION}-android-{frida_arch}"
        
        if not server_path.exists():
            url = f"https://github.com/frida/frida/releases/download/{self.FRIDA_VERSION}/frida-server-{self.FRIDA_VERSION}-android-{frida_arch}.xz"
            logger.info(f"Downloading Frida server from: {url}")
            
            try:
                import urllib.request
                import lzma
                
                xz_path = server_path.with_suffix(".xz")
                urllib.request.urlretrieve(url, xz_path)
                
                # Decompress
                with lzma.open(xz_path, 'rb') as f:
                    server_path.write_bytes(f.read())
                
                xz_path.unlink()
                logger.info("Frida server downloaded")
                
            except Exception as e:
                logger.error(f"Failed to download Frida server: {e}")
                return False
        
        # Push to device
        _, _, rc = await self._run_adb(
            "push", str(server_path), "/data/local/tmp/frida-server",
            device_id=device_id,
            timeout=60
        )
        
        if rc != 0:
            logger.error("Failed to push Frida server to device")
            return False
        
        # Make executable
        await self._run_adb(
            "shell", "chmod", "755", "/data/local/tmp/frida-server",
            device_id=device_id
        )
        
        logger.info("Frida server installed on device")
        return True
    
    async def _start_server(self, device_id: str) -> bool:
        """Start Frida server on device"""
        logger.info("Starting Frida server...")
        
        # Kill any existing instance
        await self._run_adb(
            "shell", "pkill -9 frida-server || true",
            device_id=device_id
        )
        
        # Start server in background
        # Use nohup to keep it running after shell exits
        proc = await asyncio.create_subprocess_exec(
            self._adb_path, "-s", device_id,
            "shell", "su -c '/data/local/tmp/frida-server -D' &",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        
        # Alternative for non-rooted (but usually fails)
        if await proc.wait() != 0:
            proc = await asyncio.create_subprocess_exec(
                self._adb_path, "-s", device_id,
                "shell", "/data/local/tmp/frida-server -D &",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
        
        # Wait for server to start
        await asyncio.sleep(2)
        
        if await self._is_server_running(device_id):
            logger.info("Frida server started")
            self._is_running = True
            return True
        else:
            logger.error("Frida server failed to start")
            return False
    
    async def apply_ssl_bypass(self, package: str) -> bool:
        """Apply SSL pinning bypass to target app"""
        logger.info(f"Applying SSL bypass to: {package}")
        
        try:
            import frida
            
            # Get device
            if self._device is None:
                self._device = frida.get_usb_device()
            
            # Attach to process
            try:
                # Try to attach to running process
                self._frida_session = self._device.attach(package)
            except frida.ProcessNotFoundError:
                # Spawn and attach
                logger.info(f"Spawning {package}...")
                pid = self._device.spawn([package])
                self._frida_session = self._device.attach(pid)
                self._device.resume(pid)
            
            # Load SSL bypass script
            self._frida_script = self._frida_session.create_script(SSL_BYPASS_SCRIPT)
            self._frida_script.on('message', self._on_frida_message)
            self._frida_script.load()
            
            logger.info("SSL bypass applied successfully")
            return True
            
        except ImportError:
            logger.error("Frida not installed. Run: pip install frida frida-tools")
            return False
        except Exception as e:
            logger.error(f"Failed to apply SSL bypass: {e}")
            return False
    
    def _on_frida_message(self, message: dict, data: Any):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            logger.debug(f"[Frida] {message.get('payload', '')}")
        elif message['type'] == 'error':
            logger.error(f"[Frida Error] {message.get('description', '')}")
    
    async def run_custom_script(self, script_code: str, package: str) -> bool:
        """Run custom Frida script on app"""
        try:
            import frida
            
            if self._device is None:
                self._device = frida.get_usb_device()
            
            session = self._device.attach(package)
            script = session.create_script(script_code)
            script.on('message', self._on_frida_message)
            script.load()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to run custom script: {e}")
            return False
    
    async def cleanup(self):
        """Cleanup Frida resources"""
        logger.info("Cleaning up Frida resources...")
        
        try:
            if self._frida_script:
                self._frida_script.unload()
                self._frida_script = None
            
            if self._frida_session:
                self._frida_session.detach()
                self._frida_session = None
            
            self._device = None
            self._is_running = False
            
        except Exception as e:
            logger.error(f"Error during Frida cleanup: {e}")
    
    async def stop_server(self, device_id: str):
        """Stop Frida server on device"""
        await self._run_adb(
            "shell", "pkill -9 frida-server || true",
            device_id=device_id
        )
        self._is_running = False


class FridaHTTPHook:
    """
    Frida script for capturing HTTP requests from app.
    Used to capture traffic that might not go through proxy.
    """
    
    HTTP_CAPTURE_SCRIPT = '''
/*
 * Jarwis HTTP Traffic Capture Hook
 * Captures OkHttp, Retrofit, Volley requests
 */

Java.perform(function() {
    console.log("[Jarwis] HTTP Capture script loaded");
    
    // === OkHttp3 Interceptor ===
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Builder = Java.use('okhttp3.OkHttpClient$Builder');
        var Interceptor = Java.use('okhttp3.Interceptor');
        var Chain = Java.use('okhttp3.Interceptor$Chain');
        var Request = Java.use('okhttp3.Request');
        var Response = Java.use('okhttp3.Response');
        
        var RealCall = Java.use('okhttp3.RealCall');
        RealCall.execute.implementation = function() {
            var request = this.request();
            
            var url = request.url().toString();
            var method = request.method();
            var headers = {};
            
            var headerNames = request.headers().names().toArray();
            for (var i = 0; i < headerNames.length; i++) {
                headers[headerNames[i]] = request.header(headerNames[i]);
            }
            
            var body = "";
            if (request.body() != null) {
                var Buffer = Java.use('okio.Buffer');
                var buffer = Buffer.$new();
                request.body().writeTo(buffer);
                body = buffer.readUtf8();
            }
            
            // Send to Jarwis
            send({
                type: "http_request",
                hook: "okhttp3",
                url: url,
                method: method,
                headers: headers,
                body: body
            });
            
            var response = this.execute();
            
            // Capture response
            send({
                type: "http_response",
                hook: "okhttp3",
                url: url,
                status: response.code(),
                headers: {}
            });
            
            return response;
        };
        
        console.log("[Jarwis] OkHttp3 RealCall hooked");
    } catch(e) {
        console.log("[Jarwis] OkHttp3 hook error: " + e);
    }
    
    // === Retrofit ===
    try {
        var ServiceMethod = Java.use('retrofit2.ServiceMethod');
        ServiceMethod.invoke.implementation = function(args) {
            console.log("[Jarwis] Retrofit call intercepted");
            return this.invoke(args);
        };
    } catch(e) {}
    
    console.log("[Jarwis] HTTP Capture initialized");
});
'''
    
    def __init__(self, on_request_callback: callable):
        self.on_request = on_request_callback
    
    def get_script(self) -> str:
        return self.HTTP_CAPTURE_SCRIPT
