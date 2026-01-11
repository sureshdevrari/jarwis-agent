"""
Jarwis AGI Pen Test - Mobile Attack Engine
Runs ALL attacks on captured mobile app traffic.

Mobile scanning flow:
1. Extract APK/IPA → Static analysis (manifest, permissions, hardcoded secrets)
2. Install app on emulator/device
3. Start MITM proxy with certificate pinning bypass
4. Capture all API requests from mobile app
5. Run ALL web attacks on captured API requests
6. Run mobile-specific attacks (deeplinks, intent spoofing, etc.)
"""

import asyncio
import logging
import re
import json
import os
import subprocess
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path

# Reuse web attack modules
from .attack_engine import (
    AttackEngine, AttackResult, BaseAttack,
    SQLInjectionAttack, XSSAttack, NoSQLInjectionAttack,
    CommandInjectionAttack, SSTIAttack, XXEAttack,
    LDAPInjectionAttack, XPathInjectionAttack,
    IDORAttack, BOLAAttack, BFLAAttack,
    AuthBypassAttack, JWTAttack, SessionAttack,
    SSRFAttack, CSRFAttack, CORSAttack,
    PathTraversalAttack, OpenRedirectAttack
)
from .request_store import RequestStore, CapturedRequest

logger = logging.getLogger(__name__)


@dataclass
class MobileAppInfo:
    """Extracted mobile app information"""
    package_name: str = ""
    version: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    deeplinks: List[str] = field(default_factory=list)
    exported_components: List[str] = field(default_factory=list)
    hardcoded_secrets: List[Dict[str, str]] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    is_debuggable: bool = False
    allows_backup: bool = True
    has_certificate_pinning: bool = False


@dataclass
class MobileVulnerability:
    """Mobile-specific vulnerability finding"""
    id: str
    category: str
    severity: str
    title: str
    description: str
    
    # Mobile specific
    component: str = ""  # Activity, Service, etc.
    permission: str = ""
    file_path: str = ""
    
    # Evidence
    evidence: str = ""
    poc: str = ""
    remediation: str = ""
    cwe_id: str = ""


class MobileAttackEngine:
    """
    Mobile Attack Engine - runs all attacks on mobile app traffic.
    
    Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    STATIC ANALYSIS                          │
    │  - APK/IPA extraction                                       │
    │  - Manifest analysis (permissions, components)              │
    │  - Code analysis (hardcoded secrets, API endpoints)         │
    │  - Configuration analysis (debuggable, backup, etc.)        │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │                    DYNAMIC ANALYSIS                         │
    │  - Install on emulator/device                               │
    │  - MITM proxy with SSL bypass (Frida/objection)             │
    │  - Capture API traffic                                      │
    │  - Monitor runtime behavior                                 │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │              RUN ALL WEB ATTACKS ON API TRAFFIC             │
    │  - SQLi, XSS, NoSQLi, CMDi, SSTI, XXE                      │
    │  - IDOR, BOLA, BFLA, Path Traversal                        │
    │  - JWT, Auth Bypass, Session                               │
    │  - SSRF, CORS, Open Redirect                               │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │               MOBILE-SPECIFIC ATTACKS                       │
    │  - Deeplink hijacking                                       │
    │  - Intent spoofing                                          │
    │  - Insecure data storage                                    │
    │  - Root/Jailbreak detection bypass                          │
    │  - Certificate pinning bypass                               │
    │  - Clipboard data leakage                                   │
    └─────────────────────────────────────────────────────────────┘
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.app_info: Optional[MobileAppInfo] = None
        self.request_store = RequestStore("mobile_scan")
        
        # Initialize web attack engine for API testing
        self.web_attack_engine = AttackEngine(
            config=config,
            request_store=self.request_store
        )
        
        # Results
        self.static_findings: List[MobileVulnerability] = []
        self.dynamic_findings: List[AttackResult] = []
        
        logger.info("MobileAttackEngine initialized")
    
    async def analyze_app(self, app_path: str) -> Dict[str, Any]:
        """
        Full mobile app analysis pipeline.
        
        Args:
            app_path: Path to APK or IPA file
        """
        
        results = {
            'static_findings': [],
            'dynamic_findings': [],
            'api_findings': [],
            'app_info': None
        }
        
        try:
            # Step 1: Static Analysis
            logger.info("=" * 60)
            logger.info("STEP 1: Static Analysis")
            logger.info("=" * 60)
            
            self.app_info = await self._extract_app_info(app_path)
            results['app_info'] = self.app_info.__dict__
            
            static_vulns = await self._run_static_analysis()
            self.static_findings.extend(static_vulns)
            results['static_findings'] = [v.__dict__ for v in static_vulns]
            
            # Step 2: Dynamic Analysis (if enabled)
            if self.config.get('mobile', {}).get('dynamic_analysis', True):
                logger.info("=" * 60)
                logger.info("STEP 2: Dynamic Analysis")
                logger.info("=" * 60)
                
                await self._setup_dynamic_analysis(app_path)
                await self._capture_traffic()
            
            # Step 3: Run ALL web attacks on captured API traffic
            logger.info("=" * 60)
            logger.info("STEP 3: Running Web Attacks on API Traffic")
            logger.info("=" * 60)
            
            api_results = await self.web_attack_engine.run_all_attacks(post_login=False)
            results['api_findings'] = [r.__dict__ for r in api_results]
            
            # Step 4: Mobile-specific attacks
            logger.info("=" * 60)
            logger.info("STEP 4: Mobile-Specific Attacks")
            logger.info("=" * 60)
            
            mobile_vulns = await self._run_mobile_specific_attacks()
            self.dynamic_findings.extend(mobile_vulns)
            results['dynamic_findings'] = [v.__dict__ for v in mobile_vulns]
            
            return results
            
        except Exception as e:
            logger.error(f"Mobile analysis failed: {e}")
            return {'error': str(e)}
    
    async def _extract_app_info(self, app_path: str) -> MobileAppInfo:
        """Extract app information from APK/IPA"""
        
        app_info = MobileAppInfo()
        
        if app_path.endswith('.apk'):
            app_info = await self._analyze_apk(app_path)
        elif app_path.endswith('.ipa'):
            app_info = await self._analyze_ipa(app_path)
        
        return app_info
    
    async def _analyze_apk(self, apk_path: str) -> MobileAppInfo:
        """Analyze Android APK file"""
        
        app_info = MobileAppInfo()
        
        try:
            # Use apktool or androguard if available
            # Fallback to aapt
            result = subprocess.run(
                ['aapt', 'dump', 'badging', apk_path],
                capture_output=True,
                text=True
            )
            
            output = result.stdout
            
            # Extract package name
            match = re.search(r"package: name='([^']+)'", output)
            if match:
                app_info.package_name = match.group(1)
            
            # Extract version
            match = re.search(r"versionName='([^']+)'", output)
            if match:
                app_info.version = match.group(1)
            
            # Extract SDK versions
            match = re.search(r"sdkVersion:'(\d+)'", output)
            if match:
                app_info.min_sdk = int(match.group(1))
            
            match = re.search(r"targetSdkVersion:'(\d+)'", output)
            if match:
                app_info.target_sdk = int(match.group(1))
            
            # Extract permissions
            permissions = re.findall(r"uses-permission: name='([^']+)'", output)
            app_info.permissions = permissions
            
            # Check for dangerous configurations
            if 'android:debuggable' in output:
                app_info.is_debuggable = True
            
            if 'android:allowBackup' in output:
                app_info.allows_backup = True
            
            # Extract activities with deeplinks
            deeplinks = re.findall(r'android:scheme="([^"]+)"', output)
            app_info.deeplinks = list(set(deeplinks))
            
            # Scan for hardcoded secrets in decompiled code
            app_info.hardcoded_secrets = await self._scan_for_secrets(apk_path)
            
            # Extract API endpoints
            app_info.api_endpoints = await self._extract_api_endpoints(apk_path)
            
        except FileNotFoundError:
            logger.warning("aapt not found, using basic analysis")
        except Exception as e:
            logger.error(f"APK analysis error: {e}")
        
        return app_info
    
    async def _analyze_ipa(self, ipa_path: str) -> MobileAppInfo:
        """Analyze iOS IPA file"""
        
        app_info = MobileAppInfo()
        
        try:
            import zipfile
            import plistlib
            
            with zipfile.ZipFile(ipa_path, 'r') as zf:
                # Find Info.plist
                for name in zf.namelist():
                    if name.endswith('Info.plist'):
                        with zf.open(name) as plist_file:
                            plist_data = plistlib.load(plist_file)
                            
                            app_info.package_name = plist_data.get('CFBundleIdentifier', '')
                            app_info.version = plist_data.get('CFBundleShortVersionString', '')
                            
                            # Check for URL schemes (deeplinks)
                            url_types = plist_data.get('CFBundleURLTypes', [])
                            for url_type in url_types:
                                schemes = url_type.get('CFBundleURLSchemes', [])
                                app_info.deeplinks.extend(schemes)
                        break
            
            # Scan for secrets
            app_info.hardcoded_secrets = await self._scan_for_secrets(ipa_path)
            app_info.api_endpoints = await self._extract_api_endpoints(ipa_path)
            
        except Exception as e:
            logger.error(f"IPA analysis error: {e}")
        
        return app_info
    
    async def _scan_for_secrets(self, app_path: str) -> List[Dict[str, str]]:
        """Scan decompiled app for hardcoded secrets"""
        
        secrets = []
        
        patterns = {
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret': r'[A-Za-z0-9/+=]{40}',
            'API Key': r'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9]{20,})["\']?',
            'Private Key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            'Google API': r'AIza[0-9A-Za-z_-]{35}',
            'Firebase': r'firebase[a-z0-9-]+\.firebaseio\.com',
            'JWT': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            'Basic Auth': r'[Bb]asic [A-Za-z0-9+/=]{20,}',
            'Bearer Token': r'[Bb]earer [a-zA-Z0-9_-]{20,}',
            'Password': r'password["\s:=]+["\']([^"\']{6,})["\']',
        }
        
        try:
            # For APK, decompile first
            if app_path.endswith('.apk'):
                # Use jadx or apktool to decompile
                pass
            
            # Scan strings file or decompiled source
            # This is simplified - real implementation would decompile and scan
            
        except Exception as e:
            logger.debug(f"Secret scanning error: {e}")
        
        return secrets
    
    async def _extract_api_endpoints(self, app_path: str) -> List[str]:
        """Extract API endpoints from app"""
        
        endpoints = []
        
        url_patterns = [
            r'https?://[a-zA-Z0-9._-]+(?:\.[a-zA-Z]{2,})+[/\w.-]*',
            r'/api/v\d+/\w+',
            r'/graphql',
        ]
        
        # Would scan decompiled source for URLs
        return endpoints
    
    async def _run_static_analysis(self) -> List[MobileVulnerability]:
        """Run static analysis checks"""
        
        vulnerabilities = []
        
        if not self.app_info:
            return vulnerabilities
        
        # Check dangerous permissions
        dangerous_permissions = {
            'android.permission.READ_SMS': 'high',
            'android.permission.SEND_SMS': 'high',
            'android.permission.READ_CONTACTS': 'medium',
            'android.permission.ACCESS_FINE_LOCATION': 'medium',
            'android.permission.CAMERA': 'medium',
            'android.permission.RECORD_AUDIO': 'high',
            'android.permission.READ_CALL_LOG': 'high',
            'android.permission.WRITE_EXTERNAL_STORAGE': 'medium',
        }
        
        for perm in self.app_info.permissions:
            if perm in dangerous_permissions:
                vuln = MobileVulnerability(
                    id=f"PERM-{len(vulnerabilities)+1}",
                    category="M1 - Improper Platform Usage",
                    severity=dangerous_permissions[perm],
                    title=f"Dangerous Permission: {perm.split('.')[-1]}",
                    description=f"App requests dangerous permission: {perm}",
                    permission=perm,
                    remediation="Review if permission is necessary. Apply principle of least privilege.",
                    cwe_id="CWE-250"
                )
                vulnerabilities.append(vuln)
        
        # Check debuggable flag
        if self.app_info.is_debuggable:
            vuln = MobileVulnerability(
                id=f"DEBUG-{len(vulnerabilities)+1}",
                category="M7 - Client Code Quality",
                severity="high",
                title="Application is Debuggable",
                description="android:debuggable is set to true in production",
                component="AndroidManifest.xml",
                remediation="Set android:debuggable=false for production builds.",
                cwe_id="CWE-489"
            )
            vulnerabilities.append(vuln)
        
        # Check backup flag
        if self.app_info.allows_backup:
            vuln = MobileVulnerability(
                id=f"BACKUP-{len(vulnerabilities)+1}",
                category="M2 - Insecure Data Storage",
                severity="medium",
                title="Application Allows Backup",
                description="android:allowBackup is true, data can be extracted via ADB",
                component="AndroidManifest.xml",
                remediation="Set android:allowBackup=false or implement BackupAgent.",
                cwe_id="CWE-530"
            )
            vulnerabilities.append(vuln)
        
        # Check hardcoded secrets
        for secret in self.app_info.hardcoded_secrets:
            vuln = MobileVulnerability(
                id=f"SECRET-{len(vulnerabilities)+1}",
                category="M9 - Reverse Engineering",
                severity="critical",
                title=f"Hardcoded Secret: {secret.get('type', 'Unknown')}",
                description="Sensitive data hardcoded in application",
                file_path=secret.get('file', ''),
                evidence=secret.get('value', '')[:20] + "...",
                remediation="Never hardcode secrets. Use secure storage or fetch at runtime.",
                cwe_id="CWE-798"
            )
            vulnerabilities.append(vuln)
        
        # Check exported components without permissions
        for component in self.app_info.exported_components:
            vuln = MobileVulnerability(
                id=f"EXPORT-{len(vulnerabilities)+1}",
                category="M1 - Improper Platform Usage",
                severity="high",
                title=f"Exported Component: {component}",
                description="Component exported without permission protection",
                component=component,
                remediation="Add permission requirements or set exported=false.",
                cwe_id="CWE-926"
            )
            vulnerabilities.append(vuln)
        
        # Check deeplinks for hijacking potential
        for deeplink in self.app_info.deeplinks:
            vuln = MobileVulnerability(
                id=f"DEEPLINK-{len(vulnerabilities)+1}",
                category="M1 - Improper Platform Usage",
                severity="medium",
                title=f"Deeplink Scheme: {deeplink}",
                description=f"Custom URL scheme '{deeplink}' may be hijackable",
                component="URL Scheme",
                evidence=f"Scheme: {deeplink}://",
                remediation="Use App Links (Android) or Universal Links (iOS) for security.",
                cwe_id="CWE-939"
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _setup_dynamic_analysis(self, app_path: str):
        """Setup dynamic analysis environment"""
        
        # This would:
        # 1. Start emulator or connect to device
        # 2. Install app
        # 3. Install Frida/objection for SSL bypass
        # 4. Start MITM proxy
        
        logger.info("Setting up dynamic analysis environment...")
        
        # Placeholder for emulator/device setup
        pass
    
    async def _capture_traffic(self):
        """Capture API traffic from mobile app"""
        
        # This would:
        # 1. Launch app
        # 2. Capture traffic through MITM proxy
        # 3. Store requests in RequestStore
        
        logger.info("Capturing mobile app traffic...")
        
        # Placeholder - real implementation would interact with proxy
        pass
    
    async def _run_mobile_specific_attacks(self) -> List[AttackResult]:
        """Run mobile-specific attacks"""
        
        results = []
        
        # Deeplink attacks
        for deeplink in self.app_info.deeplinks if self.app_info else []:
            result = await self._test_deeplink_hijacking(deeplink)
            if result:
                results.append(result)
        
        # Intent spoofing (Android)
        if self.app_info and self.app_info.package_name:
            intent_results = await self._test_intent_spoofing()
            results.extend(intent_results)
        
        return results
    
    async def _test_deeplink_hijacking(self, scheme: str) -> Optional[AttackResult]:
        """Test for deeplink hijacking vulnerability"""
        
        # Custom schemes can be hijacked by malicious apps
        if scheme not in ['http', 'https']:
            return AttackResult(
                id=f"DEEPLINK-HIJACK-{scheme}",
                category="M1 - Improper Platform Usage",
                severity="medium",
                title=f"Deeplink Hijacking: {scheme}://",
                description="Custom URL scheme can be intercepted by malicious apps",
                original_request_id="static",
                url=f"{scheme}://",
                method="DEEPLINK",
                evidence="Custom scheme without signature verification",
                remediation="Use App Links/Universal Links. Verify intent caller.",
                cwe_id="CWE-939",
                reasoning="Custom scheme without proper validation"
            )
        
        return None
    
    async def _test_intent_spoofing(self) -> List[AttackResult]:
        """Test for intent spoofing vulnerabilities"""
        
        results = []
        
        # Would test exported activities for intent injection
        # Using ADB to send crafted intents
        
        return results


class MobileScanRunner:
    """
    Main orchestrator for mobile security scanning.
    Combines static analysis, dynamic analysis, and API testing.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.engine = MobileAttackEngine(config)
    
    async def scan(self, app_path: str) -> Dict[str, Any]:
        """
        Full mobile security scan.
        
        Args:
            app_path: Path to APK or IPA file
        """
        
        logger.info(f"Starting mobile scan: {app_path}")
        
        results = await self.engine.analyze_app(app_path)
        
        # Generate summary
        total_vulns = (
            len(results.get('static_findings', [])) +
            len(results.get('dynamic_findings', [])) +
            len(results.get('api_findings', []))
        )
        
        results['summary'] = {
            'total_vulnerabilities': total_vulns,
            'static_count': len(results.get('static_findings', [])),
            'dynamic_count': len(results.get('dynamic_findings', [])),
            'api_count': len(results.get('api_findings', []))
        }
        
        return results
