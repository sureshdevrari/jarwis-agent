"""
Jarwis AGI - iOS-Specific Security Attacks
Trending and common iOS vulnerability scanners

Covers:
- Keychain Security Analysis
- URL Scheme Hijacking
- Universal Links Abuse
- WebView Vulnerabilities (WKWebView, UIWebView)
- Pasteboard Data Leakage
- Jailbreak Detection Bypass
- Binary Protection Analysis
- Sensitive Data in Backups
- App Transport Security Issues
- Third-party Library Vulnerabilities
"""

import re
import json
import asyncio
import logging
import plistlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class IOSVulnerability:
    """Represents an iOS-specific vulnerability with comprehensive metadata"""
    id: str
    category: str  # keychain, url_scheme, webview, etc.
    severity: str
    title: str
    description: str
    affected_component: str
    attack_vector: str
    poc: str = ""  # Proof of concept
    remediation: str = ""
    cwe_id: str = ""
    cwe_name: str = ""
    owasp_mobile: str = ""  # M1-M10
    
    # Extended metadata fields
    impact: str = ""
    cvss_score: float = 0.0
    disclosure_days: int = 45
    compliance: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    # PoC Evidence
    poc_request: str = ""
    poc_response: str = ""
    poc_request_headers: Dict[str, str] = field(default_factory=dict)
    poc_response_headers: Dict[str, str] = field(default_factory=dict)
    
    # Attack details
    privileges_required: str = "none"
    user_interaction: str = "none"
    
    # Confidence
    confidence: str = "high"
    scanner_module: str = ""
    false_positive_hints: List[str] = field(default_factory=list)
    
    def enrich_from_registry(self) -> 'IOSVulnerability':
        """
        Enrich this vulnerability with metadata from the vulnerability registry.
        """
        from attacks.vulnerability_metadata import get_vuln_meta
        
        # Map category to registry attack type
        category_mapping = {
            "keychain": "insecure_data_storage",
            "url_scheme": "url_scheme_hijacking",
            "universal_link": "url_scheme_hijacking",
            "webview": "webview_vulnerability",
            "pasteboard": "clipboard_data_exposure",
            "jailbreak": "root_jailbreak_detection_bypass",
            "binary": "binary_protection",
            "backup": "backup_data_exposure",
            "ats": "ios_ats_bypass",
            "network": "insecure_network_communication",
            "storage": "insecure_data_storage",
            "crypto": "weak_cryptography",
            "logging": "logging_sensitive_data",
            "permission": "hardcoded_secret",
            "entitlement": "debuggable_application",
        }
        
        attack_type = category_mapping.get(self.category)
        if not attack_type:
            return self
            
        meta = get_vuln_meta(attack_type)
        if not meta:
            return self
        
        # Enrich with registry metadata (don't override existing values)
        if not self.cwe_id:
            self.cwe_id = meta.cwe_id
        if not self.cwe_name:
            self.cwe_name = meta.cwe_name
        if not self.impact:
            self.impact = meta.impact
        if not self.remediation:
            self.remediation = meta.remediation
        if self.cvss_score == 0.0:
            self.cvss_score = meta.cvss_base
        if self.disclosure_days == 45:
            self.disclosure_days = meta.disclosure_days
        if not self.compliance:
            self.compliance = meta.compliance.copy()
        if not self.references:
            self.references = meta.references.copy()
        if self.privileges_required == "none":
            self.privileges_required = meta.privileges_required
        if self.user_interaction == "none":
            self.user_interaction = meta.user_interaction
            
        return self
    
    def to_dict(self) -> Dict:
        """Convert vulnerability to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "affected_component": self.affected_component,
            "attack_vector": self.attack_vector,
            "poc": self.poc,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "owasp_mobile": self.owasp_mobile,
            "impact": self.impact,
            "cvss_score": self.cvss_score,
            "disclosure_days": self.disclosure_days,
            "compliance": self.compliance,
            "references": self.references,
            "poc_request": self.poc_request,
            "poc_response": self.poc_response,
            "poc_request_headers": self.poc_request_headers,
            "poc_response_headers": self.poc_response_headers,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
            "confidence": self.confidence,
            "scanner_module": self.scanner_module,
            "false_positive_hints": self.false_positive_hints,
        }


class IOSAttackScanner:
    """
    Scanner for iOS-specific vulnerabilities
    """
    
    # Scanner registry metadata
    CATEGORY = "M1"  # OWASP Mobile: Improper Platform Usage
    DESCRIPTION = "iOS-specific vulnerability scanner (Keychain, URL schemes, etc.)"
    ENABLED_BY_DEFAULT = True
    REQUIRES_AUTH = False
    
    # Dangerous Info.plist settings
    DANGEROUS_PLIST_KEYS = {
        'NSAllowsArbitraryLoads': ('high', 'App Transport Security disabled for all connections'),
        'NSExceptionAllowsInsecureHTTPLoads': ('medium', 'HTTP allowed for specific domains'),
        'NSTemporaryExceptionAllowsInsecureHTTPLoads': ('medium', 'Temporary HTTP exception'),
        'NSThirdPartyExceptionAllowsInsecureHTTPLoads': ('medium', 'Third-party HTTP exception'),
        'NSExceptionMinimumTLSVersion': ('medium', 'Custom TLS version - check if using TLS 1.0/1.1'),
        'UIFileSharingEnabled': ('medium', 'iTunes file sharing enabled - files visible via USB'),
        'LSSupportsOpeningDocumentsInPlace': ('low', 'Documents accessible in place'),
    }
    
    # Dangerous API patterns in iOS code
    DANGEROUS_APIS = {
        r'UIPasteboard.*general': {
            'severity': 'medium',
            'title': 'General Pasteboard Usage',
            'description': 'Using general pasteboard exposes data to all apps. Sensitive data could be leaked.',
            'cwe': 'CWE-200'
        },
        r'UIWebView': {
            'severity': 'high',
            'title': 'Deprecated UIWebView Usage',
            'description': 'UIWebView is deprecated and has known security issues. Should migrate to WKWebView.',
            'cwe': 'CWE-749'
        },
        r'allowsInlineMediaPlayback.*true.*javascript': {
            'severity': 'medium',
            'title': 'JavaScript Enabled in WebView',
            'description': 'JavaScript is enabled which could allow XSS if loading untrusted content.',
            'cwe': 'CWE-79'
        },
        r'kSecAttrAccessible.*kSecAttrAccessibleAlways': {
            'severity': 'high',
            'title': 'Keychain Item Always Accessible',
            'description': 'Keychain item accessible even when device is locked. Should use kSecAttrAccessibleWhenUnlocked.',
            'cwe': 'CWE-312'
        },
        r'kSecAttrAccessible.*AfterFirstUnlock': {
            'severity': 'medium',
            'title': 'Keychain Item Accessible After First Unlock',
            'description': 'Keychain item accessible after first unlock. Consider using WhenUnlocked for sensitive data.',
            'cwe': 'CWE-312'
        },
        r'UserDefaults.*password|UserDefaults.*token|UserDefaults.*secret': {
            'severity': 'high',
            'title': 'Secrets in UserDefaults',
            'description': 'Sensitive data stored in UserDefaults which is not encrypted.',
            'cwe': 'CWE-312'
        },
        r'NSLog.*password|NSLog.*token|NSLog.*key|print.*password|print.*token': {
            'severity': 'medium',
            'title': 'Sensitive Data in Logs',
            'description': 'Potentially sensitive data being logged. Device logs can be accessed via Xcode or jailbroken device.',
            'cwe': 'CWE-532'
        },
        r'canOpenURL|openURL': {
            'severity': 'low',
            'title': 'URL Scheme Handler',
            'description': 'App handles URL schemes. Validate input to prevent URL scheme hijacking.',
            'cwe': 'CWE-601'
        },
        r'MD5|CC_MD5|SHA1|CC_SHA1': {
            'severity': 'medium',
            'title': 'Weak Cryptographic Hash',
            'description': 'Using deprecated MD5 or SHA1 hash functions which are cryptographically broken.',
            'cwe': 'CWE-328'
        },
        r'kCCAlgorithmDES|kCCAlgorithm3DES': {
            'severity': 'high',
            'title': 'Weak Encryption Algorithm',
            'description': 'Using deprecated DES/3DES encryption. Should use AES-256.',
            'cwe': 'CWE-327'
        },
        r'SecTrustEvaluate.*always.*true|kSecTrustResultProceed': {
            'severity': 'critical',
            'title': 'Certificate Validation Bypass',
            'description': 'SSL certificate validation appears to be bypassed, enabling MITM attacks.',
            'cwe': 'CWE-295'
        },
        r'URLSession.*delegate.*nil': {
            'severity': 'medium',
            'title': 'URLSession Without SSL Pinning',
            'description': 'URLSession created without custom delegate. Consider implementing SSL pinning.',
            'cwe': 'CWE-295'
        },
        r'fileManager.*createFile.*attributes.*nil': {
            'severity': 'medium',
            'title': 'File Created Without Protection',
            'description': 'File created without data protection attributes. Use NSFileProtectionComplete.',
            'cwe': 'CWE-312'
        },
        r'isJailbroken|jailbreak|/Applications/Cydia|/private/var/lib/apt': {
            'severity': 'low',
            'title': 'Jailbreak Detection Present',
            'description': 'App has jailbreak detection which can be bypassed. Should implement additional protections.',
            'cwe': 'CWE-693'
        },
    }
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.findings: List[IOSVulnerability] = []
        self._finding_counter = 0
    
    def _generate_id(self) -> str:
        """Generate unique finding ID"""
        self._finding_counter += 1
        return f"IOS-{self._finding_counter:04d}"
    
    async def scan(
        self, 
        plist_info: dict = None,
        extracted_path: str = None,
        app_bundle_path: str = None
    ) -> List[IOSVulnerability]:
        """
        Scan for iOS-specific vulnerabilities
        
        Args:
            plist_info: Parsed Info.plist data
            extracted_path: Path to extracted IPA contents
            app_bundle_path: Path to .app bundle
        """
        self.findings = []
        
        # Scan Info.plist for issues
        if plist_info:
            await self._scan_plist(plist_info)
        
        # If we have extracted contents, do deeper analysis
        if extracted_path:
            extract_path = Path(extracted_path)
            if extract_path.exists():
                await self._scan_code_vulnerabilities(extract_path)
                await self._scan_url_schemes(extract_path, plist_info)
                await self._scan_binary_protections(extract_path)
                await self._scan_embedded_resources(extract_path)
                await self._scan_third_party_libraries(extract_path)
        
        return self.findings
    
    async def _scan_plist(self, plist_info: dict):
        """Scan Info.plist for security issues"""
        logger.info("Scanning Info.plist...")
        
        # Check App Transport Security settings
        ats = plist_info.get('NSAppTransportSecurity', {})
        
        if isinstance(ats, dict):
            for key, (severity, description) in self.DANGEROUS_PLIST_KEYS.items():
                if ats.get(key, False) == True:
                    self.findings.append(IOSVulnerability(
                        id=self._generate_id(),
                        category="ats",
                        severity=severity,
                        title=f"ATS Exception: {key}",
                        description=description,
                        affected_component="Info.plist",
                        attack_vector="MITM attack on unencrypted connections",
                        remediation="Remove ATS exception or specify minimum TLS 1.2",
                        cwe_id="CWE-319",
                        owasp_mobile="M3"
                    ))
            
            # Check exception domains
            exception_domains = ats.get('NSExceptionDomains', {})
            if exception_domains:
                for domain, settings in exception_domains.items():
                    if isinstance(settings, dict):
                        if settings.get('NSExceptionAllowsInsecureHTTPLoads', False):
                            self.findings.append(IOSVulnerability(
                                id=self._generate_id(),
                                category="ats",
                                severity="medium",
                                title=f"HTTP Allowed for {domain}",
                                description=f"App allows insecure HTTP connections to {domain}",
                                affected_component="Info.plist",
                                attack_vector="MITM to intercept traffic to this domain",
                                remediation="Enable HTTPS for this domain",
                                cwe_id="CWE-319",
                                owasp_mobile="M3"
                            ))
        
        # Check top-level dangerous settings
        for key in ['UIFileSharingEnabled', 'LSSupportsOpeningDocumentsInPlace']:
            if plist_info.get(key, False) == True:
                severity, description = self.DANGEROUS_PLIST_KEYS.get(key, ('low', 'Check setting'))
                self.findings.append(IOSVulnerability(
                    id=self._generate_id(),
                    category="configuration",
                    severity=severity,
                    title=f"Risky Setting: {key}",
                    description=description,
                    affected_component="Info.plist",
                    attack_vector="Access files via iTunes/Finder",
                    remediation=f"Disable {key} if not required",
                    cwe_id="CWE-200",
                    owasp_mobile="M2"
                ))
        
        # Check for background modes that could be abused
        bg_modes = plist_info.get('UIBackgroundModes', [])
        if 'location' in bg_modes:
            self.findings.append(IOSVulnerability(
                id=self._generate_id(),
                category="privacy",
                severity="low",
                title="Background Location Access",
                description="App can access location in background. Ensure this is necessary.",
                affected_component="Info.plist",
                attack_vector="Continuous location tracking",
                remediation="Use 'when in use' location if background not needed",
                cwe_id="CWE-200",
                owasp_mobile="M1"
            ))
        
        # Check minimum iOS version
        min_version = plist_info.get('MinimumOSVersion', '0')
        try:
            major = int(min_version.split('.')[0])
            if major < 13:
                self.findings.append(IOSVulnerability(
                    id=self._generate_id(),
                    category="configuration",
                    severity="low",
                    title=f"Supports Old iOS Versions ({min_version})",
                    description="App supports iOS versions that may have security vulnerabilities.",
                    affected_component="Info.plist",
                    attack_vector="Exploit old iOS vulnerabilities",
                    remediation="Consider raising minimum iOS version to 13 or higher",
                    owasp_mobile="M1"
                ))
        except:
            pass
    
    async def _scan_url_schemes(self, extract_path: Path, plist_info: dict = None):
        """Scan for URL scheme vulnerabilities"""
        logger.info("Scanning URL schemes...")
        
        # Get URL schemes from plist
        url_schemes = []
        if plist_info:
            url_types = plist_info.get('CFBundleURLTypes', [])
            for url_type in url_types:
                schemes = url_type.get('CFBundleURLSchemes', [])
                url_schemes.extend(schemes)
        
        if url_schemes:
            # Check for potentially hijackable schemes
            for scheme in url_schemes:
                # Generic schemes are more likely to be hijacked
                if scheme.lower() in ['http', 'https', 'mailto', 'tel', 'sms']:
                    continue  # Skip standard schemes
                
                self.findings.append(IOSVulnerability(
                    id=self._generate_id(),
                    category="url_scheme",
                    severity="medium",
                    title=f"Custom URL Scheme: {scheme}://",
                    description=f"App registers custom URL scheme '{scheme}'. Malicious apps could register the same scheme to hijack URLs.",
                    affected_component="Info.plist",
                    attack_vector="Register same scheme in malicious app to intercept links",
                    poc=f"Create app with same CFBundleURLSchemes: {scheme}",
                    remediation="Implement Universal Links instead of custom URL schemes",
                    cwe_id="CWE-601",
                    owasp_mobile="M1"
                ))
        
        # Check Universal Links configuration
        if plist_info:
            associated_domains = plist_info.get('com.apple.developer.associated-domains', [])
            if not associated_domains:
                self.findings.append(IOSVulnerability(
                    id=self._generate_id(),
                    category="url_scheme",
                    severity="low",
                    title="No Universal Links Configured",
                    description="App doesn't use Universal Links. Custom URL schemes are less secure.",
                    affected_component="Entitlements",
                    attack_vector="URL scheme hijacking",
                    remediation="Implement Universal Links for deep linking",
                    owasp_mobile="M1"
                ))
    
    async def _scan_code_vulnerabilities(self, extract_path: Path):
        """Scan source code for vulnerabilities"""
        logger.info("Scanning for code vulnerabilities...")
        
        # Find all Swift and Objective-C files
        code_files = (
            list(extract_path.rglob("*.swift")) + 
            list(extract_path.rglob("*.m")) +
            list(extract_path.rglob("*.h"))
        )
        
        for file_path in code_files:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                for pattern, info in self.DANGEROUS_APIS.items():
                    if re.search(pattern, content, re.IGNORECASE):
                        self.findings.append(IOSVulnerability(
                            id=self._generate_id(),
                            category="code",
                            severity=info['severity'],
                            title=info['title'],
                            description=info['description'],
                            affected_component=file_path.name,
                            attack_vector="Exploit vulnerable API usage",
                            remediation="Follow iOS secure coding guidelines",
                            cwe_id=info.get('cwe', ''),
                            owasp_mobile="M7"
                        ))
                        
            except Exception as e:
                logger.debug(f"Could not read {file_path}: {e}")
    
    async def _scan_binary_protections(self, extract_path: Path):
        """Check binary for security protections"""
        logger.info("Checking binary protections...")
        
        # Find the main binary
        payload_path = extract_path / "Payload"
        if not payload_path.exists():
            return
        
        for app_bundle in payload_path.glob("*.app"):
            # The main binary usually has the same name as the app
            app_name = app_bundle.stem
            binary_path = app_bundle / app_name
            
            if not binary_path.exists():
                continue
            
            try:
                # Read binary to check for protections
                # Note: Full analysis would require otool which may not be available
                with open(binary_path, 'rb') as f:
                    binary_data = f.read(4096)  # Read first 4KB for headers
                
                # Check for PIE (Position Independent Executable)
                # This is a simplified check - real analysis needs otool
                if b'__PAGEZERO' not in binary_data:
                    self.findings.append(IOSVulnerability(
                        id=self._generate_id(),
                        category="binary",
                        severity="medium",
                        title="PIE Not Detected",
                        description="Binary may not have PIE enabled. ASLR protection could be weakened.",
                        affected_component=binary_path.name,
                        attack_vector="Exploit memory corruption with predictable addresses",
                        remediation="Ensure PIE is enabled in Xcode build settings",
                        cwe_id="CWE-119",
                        owasp_mobile="M8"
                    ))
                
                # Check for stack canaries
                if b'__stack_chk_guard' not in binary_data and b'__stack_chk_fail' not in binary_data:
                    self.findings.append(IOSVulnerability(
                        id=self._generate_id(),
                        category="binary",
                        severity="medium",
                        title="Stack Canaries Not Detected",
                        description="Stack protection may not be enabled. Buffer overflows could be easier to exploit.",
                        affected_component=binary_path.name,
                        attack_vector="Stack-based buffer overflow",
                        remediation="Enable stack protection in Xcode build settings",
                        cwe_id="CWE-121",
                        owasp_mobile="M8"
                    ))
                
                # Check for ARC (Automatic Reference Counting)
                if b'objc_release' in binary_data and b'_objc_autoreleasePoolPush' not in binary_data:
                    self.findings.append(IOSVulnerability(
                        id=self._generate_id(),
                        category="binary",
                        severity="low",
                        title="Mixed Memory Management",
                        description="Binary may use manual memory management in some parts. Use-after-free risks.",
                        affected_component=binary_path.name,
                        attack_vector="Memory corruption via use-after-free",
                        remediation="Use ARC throughout the codebase",
                        cwe_id="CWE-416",
                        owasp_mobile="M8"
                    ))
                    
            except Exception as e:
                logger.debug(f"Could not analyze binary: {e}")
    
    async def _scan_embedded_resources(self, extract_path: Path):
        """Scan for sensitive data in embedded resources"""
        logger.info("Scanning embedded resources...")
        
        # Find potentially sensitive resource files
        sensitive_patterns = [
            ('*.pem', 'PEM Certificate/Key'),
            ('*.p12', 'PKCS12 Certificate'),
            ('*.mobileprovision', 'Provisioning Profile'),
            ('*.sqlite', 'SQLite Database'),
            ('*.db', 'Database File'),
            ('*.realm', 'Realm Database'),
            ('GoogleService-Info.plist', 'Firebase Config'),
            ('amplifyconfiguration.json', 'AWS Amplify Config'),
            ('awsconfiguration.json', 'AWS Config'),
        ]
        
        payload_path = extract_path / "Payload"
        if not payload_path.exists():
            return
        
        for pattern, description in sensitive_patterns:
            for file_path in payload_path.rglob(pattern):
                severity = 'high' if 'pem' in pattern or 'p12' in pattern else 'medium'
                
                self.findings.append(IOSVulnerability(
                    id=self._generate_id(),
                    category="resources",
                    severity=severity,
                    title=f"Embedded {description}",
                    description=f"Found {file_path.name} in app bundle. May contain sensitive configuration or credentials.",
                    affected_component=str(file_path.relative_to(extract_path)),
                    attack_vector="Extract and analyze embedded file",
                    remediation="Remove sensitive files from bundle or encrypt them",
                    cwe_id="CWE-312",
                    owasp_mobile="M2"
                ))
    
    async def _scan_third_party_libraries(self, extract_path: Path):
        """Check for vulnerable third-party libraries"""
        logger.info("Scanning third-party libraries...")
        
        # Known vulnerable library patterns
        vulnerable_libs = {
            'AFNetworking': {
                'severity': 'medium',
                'description': 'AFNetworking - check for versions < 2.6.0 which had SSL validation issues',
                'cve': 'CVE-2015-3996'
            },
            'SSZipArchive': {
                'severity': 'high',
                'description': 'SSZipArchive - check for path traversal vulnerabilities in older versions',
                'cve': 'CVE-2018-1000544'
            },
            'Alamofire': {
                'severity': 'low',
                'description': 'Alamofire - verify SSL pinning is properly implemented'
            },
            'Realm': {
                'severity': 'low',
                'description': 'Realm Database - ensure encryption is enabled for sensitive data'
            },
            'Firebase': {
                'severity': 'low',
                'description': 'Firebase - verify security rules are properly configured'
            }
        }
        
        payload_path = extract_path / "Payload"
        if not payload_path.exists():
            return
        
        for app_bundle in payload_path.glob("*.app"):
            frameworks_path = app_bundle / "Frameworks"
            
            if frameworks_path.exists():
                for framework in frameworks_path.glob("*.framework"):
                    framework_name = framework.stem
                    
                    if framework_name in vulnerable_libs:
                        info = vulnerable_libs[framework_name]
                        self.findings.append(IOSVulnerability(
                            id=self._generate_id(),
                            category="libraries",
                            severity=info['severity'],
                            title=f"Third-Party Library: {framework_name}",
                            description=info['description'],
                            affected_component=f"Frameworks/{framework_name}.framework",
                            attack_vector="Exploit known vulnerabilities in library",
                            poc=info.get('cve', ''),
                            remediation="Update to latest version and review security configuration",
                            owasp_mobile="M7"
                        ))
    
    def get_findings(self) -> List[IOSVulnerability]:
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
