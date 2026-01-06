"""
Jarwis AGI - Android-Specific Security Attacks
Trending and common Android vulnerability scanners

Covers:
- Intent Injection & Deep Link Abuse
- Content Provider Exploitation
- WebView Vulnerabilities (XSS, JS Interface)
- Task Hijacking
- Tapjacking & Overlay Attacks
- Broadcast Receiver Abuse
- Backup Extraction
- Root Detection Bypass
- Debuggable App Exploitation
"""

import re
import json
import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class AndroidVulnerability:
    """Represents an Android-specific vulnerability"""
    id: str
    category: str  # intent, content_provider, webview, etc.
    severity: str
    title: str
    description: str
    affected_component: str
    attack_vector: str
    poc: str = ""  # Proof of concept
    remediation: str = ""
    cwe_id: str = ""
    owasp_mobile: str = ""  # M1-M10


class AndroidAttackScanner:
    """
    Scanner for Android-specific vulnerabilities
    """
    
    # Dangerous permissions that indicate attack surface
    DANGEROUS_PERMISSIONS = {
        'android.permission.READ_SMS': ('high', 'Can read SMS messages - phishing risk'),
        'android.permission.RECEIVE_SMS': ('high', 'Can intercept SMS - OTP bypass risk'),
        'android.permission.SEND_SMS': ('high', 'Can send SMS - financial fraud risk'),
        'android.permission.READ_CONTACTS': ('medium', 'Contact data exposure'),
        'android.permission.READ_CALL_LOG': ('medium', 'Call history exposure'),
        'android.permission.CAMERA': ('medium', 'Camera access'),
        'android.permission.RECORD_AUDIO': ('high', 'Microphone access - eavesdropping'),
        'android.permission.ACCESS_FINE_LOCATION': ('medium', 'Precise location tracking'),
        'android.permission.READ_EXTERNAL_STORAGE': ('medium', 'External storage access'),
        'android.permission.WRITE_EXTERNAL_STORAGE': ('medium', 'Can write to shared storage'),
        'android.permission.INSTALL_PACKAGES': ('critical', 'Can install apps silently'),
        'android.permission.SYSTEM_ALERT_WINDOW': ('high', 'Overlay attacks possible'),
        'android.permission.BIND_ACCESSIBILITY_SERVICE': ('critical', 'Full device control possible'),
        'android.permission.REQUEST_INSTALL_PACKAGES': ('high', 'Can request app installation'),
        'android.permission.READ_PHONE_STATE': ('medium', 'Device identifiers exposure'),
        'android.permission.PROCESS_OUTGOING_CALLS': ('high', 'Can intercept/modify calls'),
    }
    
    # Dangerous WebView settings
    WEBVIEW_DANGERS = {
        'setJavaScriptEnabled(true)': ('high', 'JavaScript enabled - XSS risk if loading untrusted content'),
        'setAllowFileAccess(true)': ('high', 'File access enabled - local file theft possible'),
        'setAllowFileAccessFromFileURLs(true)': ('critical', 'Cross-file access - severe vulnerability'),
        'setAllowUniversalAccessFromFileURLs(true)': ('critical', 'Universal file access - critical vulnerability'),
        'addJavascriptInterface': ('high', 'JS interface exposed - possible RCE on old Android'),
        'setWebContentsDebuggingEnabled(true)': ('high', 'WebView debugging enabled in production'),
        'setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)': ('medium', 'Mixed content allowed - MITM risk'),
    }
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.findings: List[AndroidVulnerability] = []
        self._finding_counter = 0
    
    def _generate_id(self) -> str:
        """Generate unique finding ID"""
        self._finding_counter += 1
        return f"ANDROID-{self._finding_counter:04d}"
    
    async def scan(
        self, 
        manifest_info: dict,
        extracted_path: str = None,
        decompiled_code: str = None
    ) -> List[AndroidVulnerability]:
        """
        Scan for Android-specific vulnerabilities
        
        Args:
            manifest_info: Parsed AndroidManifest.xml data
            extracted_path: Path to extracted APK contents
            decompiled_code: Path to decompiled Java/Smali code
        """
        self.findings = []
        
        # Scan manifest for issues
        await self._scan_manifest(manifest_info)
        
        # Scan exported components
        await self._scan_exported_components(manifest_info)
        
        # Scan permissions
        await self._scan_permissions(manifest_info)
        
        # If we have decompiled code, do deeper analysis
        if extracted_path or decompiled_code:
            code_path = Path(decompiled_code or extracted_path)
            if code_path.exists():
                await self._scan_webview_vulnerabilities(code_path)
                await self._scan_intent_vulnerabilities(code_path)
                await self._scan_crypto_issues(code_path)
                await self._scan_logging_issues(code_path)
                await self._scan_sql_injection(code_path)
                await self._scan_insecure_storage(code_path)
        
        return self.findings
    
    async def _scan_manifest(self, manifest_info: dict):
        """Scan manifest for security issues"""
        
        # Check if app is debuggable
        if manifest_info.get('debuggable', False):
            self.findings.append(AndroidVulnerability(
                id=self._generate_id(),
                category="configuration",
                severity="critical",
                title="Application is Debuggable",
                description="The app has android:debuggable='true' in the manifest. This allows debugging in production, exposing sensitive runtime data and enabling arbitrary code execution.",
                affected_component="AndroidManifest.xml",
                attack_vector="adb connect, then attach debugger to process",
                poc="adb shell run-as <package_name>",
                remediation="Set android:debuggable='false' in release builds",
                cwe_id="CWE-489",
                owasp_mobile="M1"
            ))
        
        # Check backup settings
        if manifest_info.get('allowBackup', True):
            self.findings.append(AndroidVulnerability(
                id=self._generate_id(),
                category="configuration",
                severity="medium",
                title="Application Allows Backup",
                description="The app allows ADB backup which can expose application data including databases, shared preferences, and cached data.",
                affected_component="AndroidManifest.xml",
                attack_vector="adb backup -f backup.ab <package_name>",
                poc="adb backup -apk -shared -all -f backup.ab <package>",
                remediation="Set android:allowBackup='false' in manifest",
                cwe_id="CWE-530",
                owasp_mobile="M2"
            ))
        
        # Check cleartext traffic
        if manifest_info.get('usesCleartextTraffic', True):
            self.findings.append(AndroidVulnerability(
                id=self._generate_id(),
                category="network",
                severity="medium",
                title="Cleartext Traffic Allowed",
                description="The app allows unencrypted HTTP traffic. Sensitive data could be intercepted by attackers on the same network.",
                affected_component="AndroidManifest.xml",
                attack_vector="MITM proxy to intercept HTTP traffic",
                poc="Configure device proxy and intercept with mitmproxy/Burp",
                remediation="Set android:usesCleartextTraffic='false' and implement Network Security Config",
                cwe_id="CWE-319",
                owasp_mobile="M3"
            ))
    
    async def _scan_exported_components(self, manifest_info: dict):
        """Scan for vulnerable exported components"""
        
        exported = manifest_info.get('exported_components', [])
        
        for comp_type, comp_name in exported:
            severity = "high" if comp_type in ["provider", "service"] else "medium"
            
            # Content Provider specific checks
            if comp_type == "provider":
                self.findings.append(AndroidVulnerability(
                    id=self._generate_id(),
                    category="content_provider",
                    severity="high",
                    title=f"Exported Content Provider: {comp_name.split('.')[-1]}",
                    description=f"Content Provider '{comp_name}' is exported and accessible by other apps. This could allow unauthorized data access or SQL injection.",
                    affected_component=comp_name,
                    attack_vector="content:// URI queries from malicious app",
                    poc=f"adb shell content query --uri content://<authority>/\nadb shell content read --uri content://<authority>/path",
                    remediation="Set android:exported='false' or implement proper permission checks",
                    cwe_id="CWE-926",
                    owasp_mobile="M1"
                ))
            
            # Activity specific checks (Task Hijacking / Deep Link Abuse)
            elif comp_type == "activity":
                self.findings.append(AndroidVulnerability(
                    id=self._generate_id(),
                    category="intent",
                    severity="medium",
                    title=f"Exported Activity: {comp_name.split('.')[-1]}",
                    description=f"Activity '{comp_name}' is exported. May be vulnerable to intent injection, task hijacking, or unauthorized access to functionality.",
                    affected_component=comp_name,
                    attack_vector="Launch activity with crafted intent from malicious app",
                    poc=f"adb shell am start -n <package>/{comp_name} --es param value",
                    remediation="Validate all incoming intent extras and implement signature-level permissions",
                    cwe_id="CWE-927",
                    owasp_mobile="M1"
                ))
            
            # Service specific checks
            elif comp_type == "service":
                self.findings.append(AndroidVulnerability(
                    id=self._generate_id(),
                    category="service",
                    severity="high",
                    title=f"Exported Service: {comp_name.split('.')[-1]}",
                    description=f"Service '{comp_name}' is exported. Malicious apps could bind to it and abuse its functionality.",
                    affected_component=comp_name,
                    attack_vector="Bind to service from malicious app",
                    poc=f"adb shell am startservice -n <package>/{comp_name}",
                    remediation="Use signature-level permissions or set android:exported='false'",
                    cwe_id="CWE-926",
                    owasp_mobile="M1"
                ))
            
            # Broadcast Receiver specific checks
            elif comp_type == "receiver":
                self.findings.append(AndroidVulnerability(
                    id=self._generate_id(),
                    category="broadcast",
                    severity="medium",
                    title=f"Exported Broadcast Receiver: {comp_name.split('.')[-1]}",
                    description=f"Broadcast Receiver '{comp_name}' is exported. Could be triggered by any app with crafted broadcasts.",
                    affected_component=comp_name,
                    attack_vector="Send crafted broadcast intent",
                    poc=f"adb shell am broadcast -a <action> -n <package>/{comp_name}",
                    remediation="Implement permission checks or use LocalBroadcastManager",
                    cwe_id="CWE-925",
                    owasp_mobile="M1"
                ))
    
    async def _scan_permissions(self, manifest_info: dict):
        """Scan for dangerous permission usage"""
        
        permissions = manifest_info.get('permissions', [])
        
        for perm in permissions:
            if perm in self.DANGEROUS_PERMISSIONS:
                severity, description = self.DANGEROUS_PERMISSIONS[perm]
                perm_name = perm.split('.')[-1]
                
                self.findings.append(AndroidVulnerability(
                    id=self._generate_id(),
                    category="permissions",
                    severity=severity,
                    title=f"Dangerous Permission: {perm_name}",
                    description=f"{description}. Permission: {perm}",
                    affected_component="AndroidManifest.xml",
                    attack_vector="Abuse granted permission if app is compromised",
                    remediation="Review if this permission is strictly necessary",
                    owasp_mobile="M1"
                ))
        
        # Check for custom permissions that are not protected
        if 'android.permission.SYSTEM_ALERT_WINDOW' in permissions:
            self.findings.append(AndroidVulnerability(
                id=self._generate_id(),
                category="overlay",
                severity="high",
                title="Tapjacking / Overlay Attack Possible",
                description="App has SYSTEM_ALERT_WINDOW permission which enables drawing over other apps. Could be used for tapjacking attacks.",
                affected_component="AndroidManifest.xml",
                attack_vector="Display fake UI overlay over legitimate apps",
                poc="Create transparent overlay to capture user taps on banking apps",
                remediation="Implement filterTouchesWhenObscured='true' on sensitive views",
                cwe_id="CWE-1021",
                owasp_mobile="M1"
            ))
    
    async def _scan_webview_vulnerabilities(self, code_path: Path):
        """Scan for WebView security issues"""
        logger.info("Scanning for WebView vulnerabilities...")
        
        webview_files = list(code_path.rglob("*.java")) + list(code_path.rglob("*.kt")) + list(code_path.rglob("*.smali"))
        
        for file_path in webview_files:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Check for dangerous WebView settings
                for pattern, (severity, description) in self.WEBVIEW_DANGERS.items():
                    if pattern in content:
                        # Find line number
                        line_num = 1
                        for i, line in enumerate(content.split('\n'), 1):
                            if pattern in line:
                                line_num = i
                                break
                        
                        self.findings.append(AndroidVulnerability(
                            id=self._generate_id(),
                            category="webview",
                            severity=severity,
                            title=f"Insecure WebView: {pattern.split('(')[0]}",
                            description=description,
                            affected_component=f"{file_path.name}:{line_num}",
                            attack_vector="Load malicious page in WebView to exploit",
                            remediation="Disable dangerous settings or implement strict URL validation",
                            cwe_id="CWE-749",
                            owasp_mobile="M7"
                        ))
                
                # Check for JavaScript interface on older Android versions
                if 'addJavascriptInterface' in content and '@JavascriptInterface' not in content:
                    self.findings.append(AndroidVulnerability(
                        id=self._generate_id(),
                        category="webview",
                        severity="critical",
                        title="Vulnerable JavaScript Interface (Pre-4.2)",
                        description="addJavascriptInterface without @JavascriptInterface annotation is vulnerable to arbitrary code execution on Android < 4.2 (API 17)",
                        affected_component=file_path.name,
                        attack_vector="Inject JavaScript to call Java methods via reflection",
                        poc="<script>object.getClass().forName('java.lang.Runtime').getRuntime().exec('command')</script>",
                        remediation="Add @JavascriptInterface to exposed methods and set minSdkVersion >= 17",
                        cwe_id="CWE-749",
                        owasp_mobile="M7"
                    ))
                    
            except Exception as e:
                logger.debug(f"Could not read {file_path}: {e}")
    
    async def _scan_intent_vulnerabilities(self, code_path: Path):
        """Scan for Intent-related vulnerabilities"""
        logger.info("Scanning for Intent vulnerabilities...")
        
        patterns = {
            r'getIntent\(\)\.get(String|Int|Boolean|Parcelable)Extra': {
                'title': 'Unvalidated Intent Extra',
                'severity': 'medium',
                'description': 'Intent extras are used without validation. Malicious apps could inject unexpected data.',
                'cwe': 'CWE-20'
            },
            r'startActivity\(.*getIntent\(\)': {
                'title': 'Intent Redirection',
                'severity': 'high',
                'description': 'Activity started with data from incoming intent. Could allow redirecting to arbitrary activities.',
                'cwe': 'CWE-926'
            },
            r'PendingIntent\.get(Activity|Service|Broadcast).*FLAG_MUTABLE': {
                'title': 'Mutable PendingIntent',
                'severity': 'high',
                'description': 'Mutable PendingIntent can be modified by receiving apps, potentially leading to privilege escalation.',
                'cwe': 'CWE-927'
            },
            r'intent\.setData\(Uri\.parse\(.*getIntent\(\)': {
                'title': 'Intent Data Injection',
                'severity': 'high',
                'description': 'URI data from untrusted intent is used directly. Could lead to data theft or redirection.',
                'cwe': 'CWE-601'
            }
        }
        
        code_files = list(code_path.rglob("*.java")) + list(code_path.rglob("*.kt"))
        
        for file_path in code_files:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                for pattern, info in patterns.items():
                    if re.search(pattern, content):
                        self.findings.append(AndroidVulnerability(
                            id=self._generate_id(),
                            category="intent",
                            severity=info['severity'],
                            title=info['title'],
                            description=info['description'],
                            affected_component=file_path.name,
                            attack_vector="Send crafted intent from malicious app",
                            remediation="Validate all intent data before use",
                            cwe_id=info['cwe'],
                            owasp_mobile="M1"
                        ))
                        break  # One finding per file per pattern type
                        
            except Exception as e:
                logger.debug(f"Could not read {file_path}: {e}")
    
    async def _scan_crypto_issues(self, code_path: Path):
        """Scan for weak cryptography"""
        logger.info("Scanning for cryptography issues...")
        
        weak_crypto = {
            r'DES|DESede|Blowfish': ('high', 'Weak Cipher Algorithm', 'Uses deprecated DES/3DES/Blowfish cipher'),
            r'ECB': ('high', 'Insecure Cipher Mode', 'ECB mode is deterministic and insecure'),
            r'MD5|SHA1': ('medium', 'Weak Hash Algorithm', 'MD5/SHA1 are cryptographically broken'),
            r'SecureRandom\(\)': ('medium', 'Default SecureRandom', 'Should use SecureRandom.getInstanceStrong()'),
            r'new Random\(\)': ('high', 'Predictable Random', 'Using java.util.Random for security is insecure'),
            r'PKCS1Padding': ('medium', 'Vulnerable Padding', 'PKCS1 padding is vulnerable to padding oracle attacks'),
            r'TrustAllCertificates|X509TrustManager.*checkServerTrusted.*\{\s*\}': ('critical', 'Certificate Validation Disabled', 'All certificates are trusted'),
        }
        
        code_files = list(code_path.rglob("*.java")) + list(code_path.rglob("*.kt"))
        
        for file_path in code_files:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                for pattern, (severity, title, description) in weak_crypto.items():
                    if re.search(pattern, content, re.IGNORECASE):
                        self.findings.append(AndroidVulnerability(
                            id=self._generate_id(),
                            category="crypto",
                            severity=severity,
                            title=title,
                            description=description,
                            affected_component=file_path.name,
                            attack_vector="Cryptographic attack to break weak encryption",
                            remediation="Use AES-256-GCM with secure key management",
                            cwe_id="CWE-327",
                            owasp_mobile="M5"
                        ))
                        
            except Exception as e:
                logger.debug(f"Could not read {file_path}: {e}")
    
    async def _scan_logging_issues(self, code_path: Path):
        """Scan for sensitive data logging"""
        logger.info("Scanning for logging issues...")
        
        sensitive_log_patterns = [
            r'Log\.(d|v|i|w|e)\([^,]+,\s*[^)]*password[^)]*\)',
            r'Log\.(d|v|i|w|e)\([^,]+,\s*[^)]*token[^)]*\)',
            r'Log\.(d|v|i|w|e)\([^,]+,\s*[^)]*secret[^)]*\)',
            r'Log\.(d|v|i|w|e)\([^,]+,\s*[^)]*credit[^)]*\)',
            r'Log\.(d|v|i|w|e)\([^,]+,\s*[^)]*ssn[^)]*\)',
            r'System\.out\.println',
            r'printStackTrace\(\)',
        ]
        
        code_files = list(code_path.rglob("*.java")) + list(code_path.rglob("*.kt"))
        
        for file_path in code_files:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                for pattern in sensitive_log_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        self.findings.append(AndroidVulnerability(
                            id=self._generate_id(),
                            category="logging",
                            severity="medium",
                            title="Sensitive Data in Logs",
                            description="Potentially sensitive data is being logged. Logs can be read by any app with READ_LOGS permission.",
                            affected_component=file_path.name,
                            attack_vector="Read logcat output: adb logcat",
                            remediation="Remove sensitive logging or use ProGuard/R8 to strip logs in release builds",
                            cwe_id="CWE-532",
                            owasp_mobile="M2"
                        ))
                        break  # One finding per file
                        
            except Exception as e:
                logger.debug(f"Could not read {file_path}: {e}")
    
    async def _scan_sql_injection(self, code_path: Path):
        """Scan for SQL injection vulnerabilities"""
        logger.info("Scanning for SQL injection...")
        
        sqli_patterns = [
            r'rawQuery\s*\([^?]*\+',  # String concatenation in rawQuery
            r'execSQL\s*\([^?]*\+',   # String concatenation in execSQL
            r'"SELECT\s.*"\s*\+',      # SELECT with concatenation
            r'"INSERT\s.*"\s*\+',      # INSERT with concatenation
            r'"UPDATE\s.*"\s*\+',      # UPDATE with concatenation
            r'"DELETE\s.*"\s*\+',      # DELETE with concatenation
        ]
        
        code_files = list(code_path.rglob("*.java")) + list(code_path.rglob("*.kt"))
        
        for file_path in code_files:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                for pattern in sqli_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.findings.append(AndroidVulnerability(
                            id=self._generate_id(),
                            category="sqli",
                            severity="high",
                            title="Potential SQL Injection",
                            description="SQL query built with string concatenation instead of parameterized queries.",
                            affected_component=file_path.name,
                            attack_vector="Inject SQL via user input",
                            poc="'; DROP TABLE users; --",
                            remediation="Use parameterized queries with SQLiteDatabase.query() or ContentValues",
                            cwe_id="CWE-89",
                            owasp_mobile="M7"
                        ))
                        break
                        
            except Exception as e:
                logger.debug(f"Could not read {file_path}: {e}")
    
    async def _scan_insecure_storage(self, code_path: Path):
        """Scan for insecure data storage"""
        logger.info("Scanning for insecure storage...")
        
        storage_issues = {
            r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE': {
                'severity': 'critical',
                'title': 'World-Accessible Storage',
                'description': 'Files created with world-readable/writable permissions can be accessed by any app.',
            },
            r'getExternalStorage|Environment\.getExternalStorageDirectory': {
                'severity': 'medium',
                'title': 'External Storage Usage',
                'description': 'Storing data on external storage makes it accessible to all apps with storage permission.',
            },
            r'SharedPreferences.*password|SharedPreferences.*token|SharedPreferences.*secret': {
                'severity': 'high',
                'title': 'Secrets in SharedPreferences',
                'description': 'Sensitive data stored in SharedPreferences which is stored as plain XML on device.',
            },
            r'openFileOutput.*Context\.MODE_PRIVATE.*\n.*write.*password': {
                'severity': 'high',
                'title': 'Credentials in File',
                'description': 'Credentials appear to be written to internal storage without encryption.',
            }
        }
        
        code_files = list(code_path.rglob("*.java")) + list(code_path.rglob("*.kt"))
        
        for file_path in code_files:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                for pattern, info in storage_issues.items():
                    if re.search(pattern, content, re.IGNORECASE):
                        self.findings.append(AndroidVulnerability(
                            id=self._generate_id(),
                            category="storage",
                            severity=info['severity'],
                            title=info['title'],
                            description=info['description'],
                            affected_component=file_path.name,
                            attack_vector="Access data via ADB or malicious app",
                            remediation="Use EncryptedSharedPreferences or Android Keystore for sensitive data",
                            cwe_id="CWE-312",
                            owasp_mobile="M2"
                        ))
                        
            except Exception as e:
                logger.debug(f"Could not read {file_path}: {e}")
    
    def get_findings(self) -> List[AndroidVulnerability]:
        """Get all findings"""
        return self.findings
    
    def get_summary(self) -> dict:
        """Get findings summary"""
        summary = {
            'total': len(self.findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_category': {}
        }
        
        for finding in self.findings:
            summary[finding.severity] = summary.get(finding.severity, 0) + 1
            cat = finding.category
            summary['by_category'][cat] = summary['by_category'].get(cat, 0) + 1
        
        return summary
