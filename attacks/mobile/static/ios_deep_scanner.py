"""
Jarwis AGI Pen Test - iOS Deep Code Scanner

Advanced static analysis for iOS IPA files.
Extracts and analyzes Mach-O binaries and resources.

Detection Capabilities:
- Hardcoded API keys and secrets in binaries/plists
- Insecure Keychain usage patterns
- Weak cryptography (CommonCrypto misuse)
- ATS (App Transport Security) bypass
- URL scheme vulnerabilities
- Sensitive data in NSUserDefaults
- Insecure data storage patterns

Tools Used:
- unzip: IPA extraction
- plutil/plistlib: Plist parsing
- strings: Binary string extraction
- class-dump/dsdump: Objective-C class extraction
- otool: Mach-O analysis

OWASP Mobile Top 10 2024:
- M1: Improper Credential Usage
- M5: Insecure Communication (ATS bypass)
- M9: Insecure Data Storage (Keychain/UserDefaults)
- M10: Insufficient Cryptography

Usage:
    scanner = IOSDeepCodeScanner()
    findings = await scanner.scan_ipa("app.ipa")
"""

import os
import re
import json
import asyncio
import logging
import shutil
import tempfile
import subprocess
import plistlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Pattern, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(Enum):
    HARDCODED_SECRET = "hardcoded_secret"
    INSECURE_STORAGE = "insecure_storage"
    WEAK_CRYPTO = "weak_crypto"
    INSECURE_NETWORK = "insecure_network"
    URL_SCHEME = "url_scheme"
    BINARY_PROTECTION = "binary_protection"
    LOGGING = "logging"
    PRIVACY = "privacy"


@dataclass
class IOSCodeFinding:
    """A finding from iOS deep code analysis with comprehensive vulnerability metadata"""
    id: str
    title: str
    description: str
    severity: FindingSeverity
    category: FindingCategory
    
    # Location
    file_path: str
    line_number: int = 0
    code_snippet: str = ""
    
    # Context
    binary_name: str = ""
    class_name: str = ""
    method_name: str = ""
    matched_pattern: str = ""
    
    # OWASP/CWE
    owasp_category: str = ""
    cwe_id: str = ""
    cwe_name: str = ""
    
    # Impact and Remediation
    impact: str = ""
    remediation: str = ""
    
    # Compliance and Reporting
    cvss_base: float = 0.0
    disclosure_days: int = 45
    compliance: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    # Attack Vector Information
    attack_vector: str = "local"
    privileges_required: str = "none"
    user_interaction: str = "none"
    
    # Confidence
    confidence: str = "high"
    
    # PoC Evidence
    poc_request: str = ""
    poc_response: str = ""
    affected_component: str = ""
    
    def enrich_from_registry(self) -> 'IOSCodeFinding':
        """
        Enrich this finding with metadata from the vulnerability registry.
        Maps FindingCategory to registry attack_type for metadata lookup.
        """
        from attacks.vulnerability_metadata import get_vuln_meta
        
        # Map FindingCategory to registry attack type
        category_mapping = {
            FindingCategory.HARDCODED_SECRET: "hardcoded_secret",
            FindingCategory.INSECURE_STORAGE: "insecure_data_storage",
            FindingCategory.WEAK_CRYPTO: "weak_cryptography",
            FindingCategory.INSECURE_NETWORK: "ios_ats_bypass",
            FindingCategory.URL_SCHEME: "url_scheme_hijacking",
            FindingCategory.BINARY_PROTECTION: "binary_protection",
            FindingCategory.LOGGING: "logging_sensitive_data",
            FindingCategory.PRIVACY: "clipboard_data_exposure",
        }
        
        attack_type = category_mapping.get(self.category)
        if not attack_type:
            return self
            
        meta = get_vuln_meta(attack_type)
        if not meta:
            return self
        
        # Enrich with registry metadata (don't override existing values)
        if not self.owasp_category:
            self.owasp_category = meta.owasp_category
        if not self.cwe_id:
            self.cwe_id = meta.cwe_id
        if not self.cwe_name:
            self.cwe_name = meta.cwe_name
        if not self.impact:
            self.impact = meta.impact
        if not self.remediation:
            self.remediation = meta.remediation
        if self.cvss_base == 0.0:
            self.cvss_base = meta.cvss_base
        if self.disclosure_days == 45:
            self.disclosure_days = meta.disclosure_days
        if not self.compliance:
            self.compliance = meta.compliance.copy()
        if not self.references:
            self.references = meta.references.copy()
        if self.attack_vector == "local":
            self.attack_vector = meta.attack_vector
        if self.privileges_required == "none":
            self.privileges_required = meta.privileges_required
        if self.user_interaction == "none":
            self.user_interaction = meta.user_interaction
            
        return self
    
    def to_dict(self) -> Dict:
        """Convert finding to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value if isinstance(self.severity, FindingSeverity) else self.severity,
            "category": self.category.value if isinstance(self.category, FindingCategory) else self.category,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "binary_name": self.binary_name,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "matched_pattern": self.matched_pattern,
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "impact": self.impact,
            "remediation": self.remediation,
            "cvss_base": self.cvss_base,
            "disclosure_days": self.disclosure_days,
            "compliance": self.compliance,
            "references": self.references,
            "attack_vector": self.attack_vector,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
            "confidence": self.confidence,
            "poc_request": self.poc_request,
            "poc_response": self.poc_response,
            "affected_component": self.affected_component,
        }


@dataclass
class IOSAppMetadata:
    """Metadata extracted from iOS app"""
    bundle_id: str = ""
    bundle_name: str = ""
    version: str = ""
    build: str = ""
    min_ios_version: str = ""
    
    # Binary info
    architectures: List[str] = field(default_factory=list)
    is_encrypted: bool = False
    has_pie: bool = False
    has_arc: bool = False
    has_stack_canary: bool = False
    
    # Entitlements
    entitlements: Dict = field(default_factory=dict)
    
    # URL schemes
    url_schemes: List[str] = field(default_factory=list)
    
    # ATS config
    ats_config: Dict = field(default_factory=dict)
    allows_arbitrary_loads: bool = False
    
    # Frameworks
    frameworks: List[str] = field(default_factory=list)
    
    # Permissions
    permissions: Dict[str, str] = field(default_factory=dict)


@dataclass
class IOSScanConfig:
    """Configuration for iOS deep scanning"""
    extract_strings: bool = True
    analyze_binary: bool = True
    scan_resources: bool = True
    check_entitlements: bool = True
    max_string_length: int = 500
    timeout_minutes: int = 30
    keep_extracted: bool = False
    output_dir: str = ""


class IOSDeepCodeScanner:
    """
    Deep code analysis scanner for iOS IPA files.
    
    Extracts and analyzes app contents including:
    - Mach-O binaries for hardcoded secrets
    - Info.plist for misconfigurations
    - Embedded resources and plists
    - Entitlements for dangerous capabilities
    """
    
    # ==================== API Key Patterns ====================
    API_KEY_PATTERNS = [
        # Google
        (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "Google API Key", FindingSeverity.HIGH),
        (re.compile(r'[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com'), "Google OAuth Client", FindingSeverity.MEDIUM),
        
        # Firebase
        (re.compile(r'[a-zA-Z0-9_-]+\.firebaseio\.com'), "Firebase Database URL", FindingSeverity.MEDIUM),
        (re.compile(r'[a-zA-Z0-9_-]+\.firebaseapp\.com'), "Firebase App URL", FindingSeverity.LOW),
        
        # AWS
        (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID", FindingSeverity.CRITICAL),
        (re.compile(r's3\.amazonaws\.com/[a-zA-Z0-9_\-\.]+'), "AWS S3 Bucket", FindingSeverity.MEDIUM),
        
        # Apple
        (re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'), "UUID (potential key)", FindingSeverity.LOW),
        
        # Stripe
        (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), "Stripe Live Secret Key", FindingSeverity.CRITICAL),
        (re.compile(r'pk_live_[0-9a-zA-Z]{24,}'), "Stripe Live Publishable Key", FindingSeverity.MEDIUM),
        
        # Twilio
        (re.compile(r'SK[0-9a-fA-F]{32}'), "Twilio API Key", FindingSeverity.HIGH),
        
        # Generic
        (re.compile(r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']'), "Generic API Key", FindingSeverity.MEDIUM),
        (re.compile(r'(?i)(secret|password|passwd)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']'), "Hardcoded Secret", FindingSeverity.HIGH),
        
        # Private keys
        (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), "Embedded Private Key", FindingSeverity.CRITICAL),
        
        # JWT
        (re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'), "JWT Token", FindingSeverity.MEDIUM),
    ]
    
    # ==================== Insecure Storage Patterns ====================
    STORAGE_PATTERNS = [
        # NSUserDefaults for sensitive data
        (
            re.compile(r'NSUserDefaults.*(?:password|token|secret|key|auth)', re.IGNORECASE),
            "Sensitive data in NSUserDefaults",
            "NSUserDefaults stores data unencrypted. Use Keychain for sensitive data.",
            FindingSeverity.HIGH,
            "CWE-312"
        ),
        
        # Keychain without accessibility
        (
            re.compile(r'kSecAttrAccessible(?:Always|AfterFirstUnlock)(?!WhenPasscode)'),
            "Insecure Keychain accessibility",
            "Keychain items accessible when device locked. Use stricter accessibility.",
            FindingSeverity.MEDIUM,
            "CWE-311"
        ),
        
        # File writing
        (
            re.compile(r'writeToFile.*(?:password|token|secret|key)', re.IGNORECASE),
            "Sensitive data written to file",
            "Sensitive data may be stored in unprotected files.",
            FindingSeverity.HIGH,
            "CWE-312"
        ),
        
        # Core Data unencrypted
        (
            re.compile(r'NSPersistentStoreCoordinator.*(?!Encrypted)'),
            "Unencrypted Core Data store",
            "Core Data stores may contain sensitive data without encryption.",
            FindingSeverity.MEDIUM,
            "CWE-311"
        ),
        
        # Clipboard
        (
            re.compile(r'UIPasteboard.*(?:password|token|secret)', re.IGNORECASE),
            "Sensitive data in clipboard",
            "Clipboard data can be accessed by other apps.",
            FindingSeverity.HIGH,
            "CWE-200"
        ),
    ]
    
    # ==================== Weak Crypto Patterns ====================
    CRYPTO_PATTERNS = [
        # Weak algorithms
        (
            re.compile(r'kCCAlgorithmDES|kCCAlgorithm3DES|kCCAlgorithmRC4'),
            "Weak encryption algorithm",
            "DES, 3DES, and RC4 are considered weak. Use AES-256.",
            FindingSeverity.HIGH,
            "CWE-327"
        ),
        
        # ECB mode
        (
            re.compile(r'kCCModeECB|kCCOptionECBMode'),
            "ECB mode encryption",
            "ECB mode does not provide semantic security.",
            FindingSeverity.HIGH,
            "CWE-327"
        ),
        
        # MD5/SHA1 for passwords
        (
            re.compile(r'CC_MD5|CC_SHA1.*(?:password|passwd|pwd)', re.IGNORECASE),
            "Weak hash for passwords",
            "MD5 and SHA1 are too fast for password hashing. Use PBKDF2.",
            FindingSeverity.HIGH,
            "CWE-328"
        ),
        
        # Static IV
        (
            re.compile(r'(?:iv|IV|initVector)\s*=\s*(?:\[|@"|"|\{)'),
            "Hardcoded initialization vector",
            "IVs should be randomly generated for each encryption.",
            FindingSeverity.HIGH,
            "CWE-329"
        ),
        
        # arc4random insecure
        (
            re.compile(r'arc4random\s*\(\s*\)\s*%'),
            "Biased random number generation",
            "Use arc4random_uniform to avoid modulo bias.",
            FindingSeverity.LOW,
            "CWE-330"
        ),
    ]
    
    # ==================== Network Security Patterns ====================
    NETWORK_PATTERNS = [
        # HTTP URLs
        (
            re.compile(r'http://(?!localhost|127\.0\.0\.1)[a-zA-Z0-9\.\-]+'),
            "Cleartext HTTP URL",
            "Use HTTPS for all network communication.",
            FindingSeverity.MEDIUM,
            "CWE-319"
        ),
        
        # Certificate validation bypass
        (
            re.compile(r'allowsInvalidSSLCertificate|validatesDomainName\s*=\s*(?:NO|false|0)'),
            "SSL certificate validation disabled",
            "Certificate validation is critical for preventing MITM attacks.",
            FindingSeverity.CRITICAL,
            "CWE-295"
        ),
        
        # URLSession delegate bypass
        (
            re.compile(r'didReceiveChallenge.*completionHandler\s*\(\s*\.useCredential'),
            "Potential certificate pinning bypass",
            "Review authentication challenge handling for proper validation.",
            FindingSeverity.MEDIUM,
            "CWE-295"
        ),
    ]
    
    # ==================== Dangerous Entitlements ====================
    DANGEROUS_ENTITLEMENTS = {
        "get-task-allow": (FindingSeverity.HIGH, "Debug entitlement enabled - allows debugger attachment"),
        "com.apple.developer.team-identifier": (FindingSeverity.INFO, "Team identifier exposed"),
        "keychain-access-groups": (FindingSeverity.LOW, "Keychain sharing enabled"),
        "com.apple.security.application-groups": (FindingSeverity.LOW, "App groups enabled"),
        "com.apple.developer.associated-domains": (FindingSeverity.INFO, "Universal links configured"),
    }
    
    def __init__(self, config: Optional[IOSScanConfig] = None):
        self.config = config or IOSScanConfig()
        self._findings: List[IOSCodeFinding] = []
        self._metadata: Optional[IOSAppMetadata] = None
        self._temp_dir: Optional[Path] = None
        self._strings_cache: Set[str] = set()
    
    async def scan_ipa(self, ipa_path: str) -> List[IOSCodeFinding]:
        """
        Scan an IPA file for security vulnerabilities.
        
        Performs extraction and comprehensive analysis.
        """
        self._findings = []
        self._metadata = IOSAppMetadata()
        
        ipa_path = Path(ipa_path)
        if not ipa_path.exists():
            logger.error(f"IPA not found: {ipa_path}")
            return []
        
        logger.info(f"Starting iOS deep scan of {ipa_path.name}")
        
        # Create temp directory
        self._temp_dir = Path(tempfile.mkdtemp(prefix="jarwis_ios_"))
        
        try:
            # Extract IPA
            app_dir = await self._extract_ipa(ipa_path)
            
            if not app_dir:
                logger.error("Failed to extract IPA")
                return []
            
            # Parse Info.plist
            await self._parse_info_plist(app_dir)
            
            # Check entitlements
            if self.config.check_entitlements:
                await self._check_entitlements(app_dir)
            
            # Extract and scan strings from binary
            if self.config.extract_strings:
                await self._scan_binary_strings(app_dir)
            
            # Analyze binary security
            if self.config.analyze_binary:
                await self._analyze_binary_security(app_dir)
            
            # Scan resources
            if self.config.scan_resources:
                await self._scan_resources(app_dir)
            
            # Check ATS configuration
            await self._check_ats_config()
            
            # Check URL schemes
            await self._check_url_schemes()
            
            logger.info(f"iOS deep scan complete: {len(self._findings)} findings")
            
        finally:
            if not self.config.keep_extracted and self._temp_dir:
                try:
                    shutil.rmtree(self._temp_dir)
                except:
                    pass
        
        return self._findings
    
    async def _extract_ipa(self, ipa_path: Path) -> Optional[Path]:
        """Extract IPA file"""
        logger.info("Extracting IPA...")
        
        try:
            import zipfile
            
            with zipfile.ZipFile(ipa_path, 'r') as zf:
                zf.extractall(self._temp_dir)
            
            # Find .app directory
            payload_dir = self._temp_dir / "Payload"
            if not payload_dir.exists():
                logger.error("No Payload directory in IPA")
                return None
            
            app_dirs = list(payload_dir.glob("*.app"))
            if not app_dirs:
                logger.error("No .app bundle found")
                return None
            
            return app_dirs[0]
            
        except Exception as e:
            logger.error(f"Failed to extract IPA: {e}")
            return None
    
    async def _parse_info_plist(self, app_dir: Path):
        """Parse Info.plist for app metadata"""
        info_plist = app_dir / "Info.plist"
        
        if not info_plist.exists():
            logger.warning("Info.plist not found")
            return
        
        try:
            with open(info_plist, 'rb') as f:
                plist = plistlib.load(f)
            
            self._metadata.bundle_id = plist.get("CFBundleIdentifier", "")
            self._metadata.bundle_name = plist.get("CFBundleName", "")
            self._metadata.version = plist.get("CFBundleShortVersionString", "")
            self._metadata.build = plist.get("CFBundleVersion", "")
            self._metadata.min_ios_version = plist.get("MinimumOSVersion", "")
            
            # URL schemes
            url_types = plist.get("CFBundleURLTypes", [])
            for url_type in url_types:
                schemes = url_type.get("CFBundleURLSchemes", [])
                self._metadata.url_schemes.extend(schemes)
            
            # ATS config
            ats = plist.get("NSAppTransportSecurity", {})
            self._metadata.ats_config = ats
            self._metadata.allows_arbitrary_loads = ats.get("NSAllowsArbitraryLoads", False)
            
            # Privacy permissions
            for key, value in plist.items():
                if key.startswith("NS") and key.endswith("UsageDescription"):
                    permission = key.replace("NS", "").replace("UsageDescription", "")
                    self._metadata.permissions[permission] = value
            
            logger.info(f"Parsed Info.plist: {self._metadata.bundle_id}")
            
        except Exception as e:
            logger.error(f"Failed to parse Info.plist: {e}")
    
    async def _check_entitlements(self, app_dir: Path):
        """Check embedded entitlements"""
        logger.info("Checking entitlements...")
        
        # Find main binary
        binary_path = app_dir / self._metadata.bundle_name
        if not binary_path.exists():
            # Try CFBundleExecutable from plist
            binary_path = app_dir / Path(self._metadata.bundle_id).stem
        
        if not binary_path.exists():
            # Find any Mach-O binary
            for f in app_dir.iterdir():
                if f.is_file() and not f.suffix:
                    binary_path = f
                    break
        
        if not binary_path or not binary_path.exists():
            logger.warning("Could not find main binary")
            return
        
        # Extract entitlements using codesign (macOS) or manual extraction
        try:
            proc = await asyncio.create_subprocess_exec(
                "codesign", "-d", "--entitlements", ":-", str(binary_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if stdout:
                entitlements = plistlib.loads(stdout)
                self._metadata.entitlements = entitlements
                
                # Check for dangerous entitlements
                for key, value in entitlements.items():
                    if key in self.DANGEROUS_ENTITLEMENTS:
                        severity, desc = self.DANGEROUS_ENTITLEMENTS[key]
                        
                        self._findings.append(IOSCodeFinding(
                            id=f"ENT-{len(self._findings)+1}",
                            title=f"Entitlement: {key}",
                            description=desc,
                            severity=severity,
                            category=FindingCategory.BINARY_PROTECTION,
                            file_path="embedded.mobileprovision",
                            code_snippet=f"{key}: {value}",
                            owasp_category="M1",
                            cwe_id="CWE-250",
                            remediation="Review entitlements and remove unnecessary capabilities."
                        ))
                        
        except FileNotFoundError:
            logger.debug("codesign not available (not on macOS)")
        except Exception as e:
            logger.debug(f"Failed to extract entitlements: {e}")
    
    async def _scan_binary_strings(self, app_dir: Path):
        """Extract and scan strings from binary"""
        logger.info("Scanning binary strings...")
        
        # Find all binaries
        binaries = []
        
        for root, dirs, files in os.walk(app_dir):
            for file in files:
                file_path = Path(root) / file
                
                # Check if Mach-O binary
                if await self._is_macho_binary(file_path):
                    binaries.append(file_path)
        
        for binary in binaries:
            await self._extract_and_scan_strings(binary)
    
    async def _is_macho_binary(self, file_path: Path) -> bool:
        """Check if file is a Mach-O binary"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                
                # Mach-O magic numbers
                macho_magics = [
                    b'\xfe\xed\xfa\xce',  # MH_MAGIC (32-bit)
                    b'\xfe\xed\xfa\xcf',  # MH_MAGIC_64
                    b'\xce\xfa\xed\xfe',  # MH_CIGAM (32-bit, reverse)
                    b'\xcf\xfa\xed\xfe',  # MH_CIGAM_64 (reverse)
                    b'\xca\xfe\xba\xbe',  # FAT binary
                    b'\xbe\xba\xfe\xca',  # FAT binary (reverse)
                ]
                
                return magic in macho_magics
        except:
            return False
    
    async def _extract_and_scan_strings(self, binary_path: Path):
        """Extract strings from binary and scan for secrets"""
        try:
            # Use strings command
            proc = await asyncio.create_subprocess_exec(
                "strings", "-a", str(binary_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            strings_output = stdout.decode('utf-8', errors='ignore')
            binary_name = binary_path.name
            
            for line_num, line in enumerate(strings_output.split('\n'), 1):
                line = line.strip()
                
                if not line or len(line) > self.config.max_string_length:
                    continue
                
                # Skip if already scanned
                if line in self._strings_cache:
                    continue
                self._strings_cache.add(line)
                
                # Check API key patterns
                for pattern, name, severity in self.API_KEY_PATTERNS:
                    if pattern.search(line):
                        # Filter false positives
                        if self._is_likely_false_positive(line, name):
                            continue
                        
                        self._findings.append(IOSCodeFinding(
                            id=f"SECRET-{len(self._findings)+1}",
                            title=name,
                            description=f"{name} found in binary. May provide unauthorized access.",
                            severity=severity,
                            category=FindingCategory.HARDCODED_SECRET,
                            file_path=str(binary_path.relative_to(self._temp_dir)),
                            binary_name=binary_name,
                            code_snippet=line[:100],
                            matched_pattern=pattern.pattern[:50],
                            owasp_category="M1",
                            cwe_id="CWE-798",
                            remediation="Remove hardcoded secrets. Use iOS Keychain or secure configuration."
                        ))
                
                # Check storage patterns
                for pattern, title, desc, severity, cwe in self.STORAGE_PATTERNS:
                    if pattern.search(line):
                        self._findings.append(IOSCodeFinding(
                            id=f"STORAGE-{len(self._findings)+1}",
                            title=title,
                            description=desc,
                            severity=severity,
                            category=FindingCategory.INSECURE_STORAGE,
                            file_path=str(binary_path.relative_to(self._temp_dir)),
                            binary_name=binary_name,
                            code_snippet=line[:100],
                            owasp_category="M9",
                            cwe_id=cwe,
                            remediation="Use iOS Keychain for sensitive data storage."
                        ))
                
                # Check crypto patterns
                for pattern, title, desc, severity, cwe in self.CRYPTO_PATTERNS:
                    if pattern.search(line):
                        self._findings.append(IOSCodeFinding(
                            id=f"CRYPTO-{len(self._findings)+1}",
                            title=title,
                            description=desc,
                            severity=severity,
                            category=FindingCategory.WEAK_CRYPTO,
                            file_path=str(binary_path.relative_to(self._temp_dir)),
                            binary_name=binary_name,
                            code_snippet=line[:100],
                            owasp_category="M10",
                            cwe_id=cwe,
                            remediation="Use AES-256-GCM for encryption, PBKDF2 for password hashing."
                        ))
                
                # Check network patterns
                for pattern, title, desc, severity, cwe in self.NETWORK_PATTERNS:
                    if pattern.search(line):
                        self._findings.append(IOSCodeFinding(
                            id=f"NET-{len(self._findings)+1}",
                            title=title,
                            description=desc,
                            severity=severity,
                            category=FindingCategory.INSECURE_NETWORK,
                            file_path=str(binary_path.relative_to(self._temp_dir)),
                            binary_name=binary_name,
                            code_snippet=line[:100],
                            owasp_category="M5",
                            cwe_id=cwe,
                            remediation="Use HTTPS with proper certificate validation."
                        ))
                        
        except FileNotFoundError:
            logger.debug("strings command not available")
        except Exception as e:
            logger.debug(f"Error scanning binary: {e}")
    
    def _is_likely_false_positive(self, line: str, pattern_name: str) -> bool:
        """Check if a match is likely a false positive"""
        false_positive_indicators = [
            "example", "sample", "test", "demo", "placeholder",
            "YOUR_", "INSERT_", "REPLACE_", "xxx", "000000"
        ]
        
        line_lower = line.lower()
        return any(fp in line_lower for fp in false_positive_indicators)
    
    async def _analyze_binary_security(self, app_dir: Path):
        """Analyze binary for security features"""
        logger.info("Analyzing binary security...")
        
        # Find main binary
        for f in app_dir.iterdir():
            if await self._is_macho_binary(f):
                await self._check_binary_protections(f)
                break
    
    async def _check_binary_protections(self, binary_path: Path):
        """Check binary for security protections"""
        try:
            # Use otool to check protections
            proc = await asyncio.create_subprocess_exec(
                "otool", "-hv", str(binary_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            output = stdout.decode()
            
            # Check PIE
            has_pie = "PIE" in output
            self._metadata.has_pie = has_pie
            
            if not has_pie:
                self._findings.append(IOSCodeFinding(
                    id=f"BIN-{len(self._findings)+1}",
                    title="Missing PIE protection",
                    description="Binary not compiled with Position Independent Executable. ASLR less effective.",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.BINARY_PROTECTION,
                    file_path=binary_path.name,
                    owasp_category="M8",
                    cwe_id="CWE-119",
                    remediation="Enable PIE in build settings (-pie flag)."
                ))
            
            # Check for encryption
            proc = await asyncio.create_subprocess_exec(
                "otool", "-l", str(binary_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            output = stdout.decode()
            
            # Look for LC_ENCRYPTION_INFO
            if "cryptid 1" in output:
                self._metadata.is_encrypted = True
            elif "cryptid 0" in output:
                self._metadata.is_encrypted = False
                
                self._findings.append(IOSCodeFinding(
                    id=f"BIN-{len(self._findings)+1}",
                    title="Binary not encrypted",
                    description="App Store encryption (FairPlay) not present. Binary may be decrypted dump.",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.BINARY_PROTECTION,
                    file_path=binary_path.name,
                    owasp_category="M9",
                    cwe_id="CWE-311",
                    remediation="Ensure app is downloaded from App Store for encryption."
                ))
                
        except FileNotFoundError:
            logger.debug("otool not available (not on macOS)")
        except Exception as e:
            logger.debug(f"Binary analysis failed: {e}")
    
    async def _scan_resources(self, app_dir: Path):
        """Scan resource files for secrets"""
        logger.info("Scanning resources...")
        
        # Scan all plist files
        for plist_file in app_dir.rglob("*.plist"):
            await self._scan_plist_file(plist_file)
        
        # Scan JSON files
        for json_file in app_dir.rglob("*.json"):
            await self._scan_json_file(json_file)
        
        # Scan other config files
        for config_file in app_dir.rglob("*.config"):
            await self._scan_text_file(config_file)
    
    async def _scan_plist_file(self, plist_path: Path):
        """Scan a plist file for secrets"""
        try:
            with open(plist_path, 'rb') as f:
                try:
                    plist = plistlib.load(f)
                except:
                    return
            
            # Recursively scan for secrets
            self._scan_dict_for_secrets(plist, str(plist_path.relative_to(self._temp_dir)))
            
        except Exception as e:
            logger.debug(f"Error scanning plist {plist_path}: {e}")
    
    def _scan_dict_for_secrets(self, data: dict, file_path: str, prefix: str = ""):
        """Recursively scan dictionary for secrets"""
        sensitive_keys = ["key", "secret", "password", "token", "api", "auth", "credential"]
        
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                self._scan_dict_for_secrets(value, file_path, full_key)
            elif isinstance(value, str):
                key_lower = key.lower()
                
                # Check if key name suggests sensitive data
                if any(s in key_lower for s in sensitive_keys):
                    if len(value) > 8 and not value.startswith("$("):  # Exclude build variables
                        self._findings.append(IOSCodeFinding(
                            id=f"PLIST-{len(self._findings)+1}",
                            title=f"Potential secret in plist: {key}",
                            description=f"Sensitive value found for key '{key}' in plist.",
                            severity=FindingSeverity.MEDIUM,
                            category=FindingCategory.HARDCODED_SECRET,
                            file_path=file_path,
                            code_snippet=f"{key}: {value[:50]}...",
                            owasp_category="M1",
                            cwe_id="CWE-798",
                            remediation="Remove sensitive data from plist files."
                        ))
    
    async def _scan_json_file(self, json_path: Path):
        """Scan a JSON file for secrets"""
        try:
            with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            if isinstance(data, dict):
                self._scan_dict_for_secrets(data, str(json_path.relative_to(self._temp_dir)))
                
        except Exception as e:
            logger.debug(f"Error scanning JSON {json_path}: {e}")
    
    async def _scan_text_file(self, file_path: Path):
        """Scan a text file for secrets"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            for pattern, name, severity in self.API_KEY_PATTERNS:
                for match in pattern.finditer(content):
                    line_num = content[:match.start()].count('\n') + 1
                    
                    self._findings.append(IOSCodeFinding(
                        id=f"CONFIG-{len(self._findings)+1}",
                        title=f"{name} in config file",
                        description=f"{name} found in configuration file.",
                        severity=severity,
                        category=FindingCategory.HARDCODED_SECRET,
                        file_path=str(file_path.relative_to(self._temp_dir)),
                        line_number=line_num,
                        code_snippet=match.group(0)[:100],
                        owasp_category="M1",
                        cwe_id="CWE-798",
                        remediation="Remove secrets from configuration files."
                    ))
                    
        except Exception as e:
            logger.debug(f"Error scanning config file: {e}")
    
    async def _check_ats_config(self):
        """Check App Transport Security configuration"""
        if self._metadata.allows_arbitrary_loads:
            self._findings.append(IOSCodeFinding(
                id=f"ATS-{len(self._findings)+1}",
                title="ATS disabled (NSAllowsArbitraryLoads)",
                description="App Transport Security is disabled. All HTTP traffic is allowed.",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.INSECURE_NETWORK,
                file_path="Info.plist",
                code_snippet="NSAllowsArbitraryLoads: true",
                owasp_category="M5",
                cwe_id="CWE-319",
                remediation="Remove NSAllowsArbitraryLoads and configure specific exceptions if needed."
            ))
        
        # Check for domain exceptions
        ats = self._metadata.ats_config
        exception_domains = ats.get("NSExceptionDomains", {})
        
        for domain, config in exception_domains.items():
            if config.get("NSExceptionAllowsInsecureHTTPLoads", False):
                self._findings.append(IOSCodeFinding(
                    id=f"ATS-{len(self._findings)+1}",
                    title=f"ATS exception for {domain}",
                    description=f"Insecure HTTP allowed for domain: {domain}",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.INSECURE_NETWORK,
                    file_path="Info.plist",
                    code_snippet=f"{domain}: NSExceptionAllowsInsecureHTTPLoads = true",
                    owasp_category="M5",
                    cwe_id="CWE-319",
                    remediation=f"Ensure {domain} supports HTTPS and remove exception."
                ))
    
    async def _check_url_schemes(self):
        """Check URL scheme security"""
        for scheme in self._metadata.url_schemes:
            # Check for overly permissive schemes
            if scheme in ["http", "https", "file"]:
                self._findings.append(IOSCodeFinding(
                    id=f"URL-{len(self._findings)+1}",
                    title=f"Dangerous URL scheme: {scheme}",
                    description=f"App registers handler for {scheme}:// URLs. May be exploited.",
                    severity=FindingSeverity.HIGH,
                    category=FindingCategory.URL_SCHEME,
                    file_path="Info.plist",
                    code_snippet=f"CFBundleURLSchemes: [{scheme}]",
                    owasp_category="M1",
                    cwe_id="CWE-939",
                    remediation="Review URL scheme handler for input validation."
                ))
            else:
                # Info about custom schemes
                self._findings.append(IOSCodeFinding(
                    id=f"URL-{len(self._findings)+1}",
                    title=f"Custom URL scheme: {scheme}",
                    description=f"App handles custom URL scheme. Verify input validation.",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.URL_SCHEME,
                    file_path="Info.plist",
                    code_snippet=f"CFBundleURLSchemes: [{scheme}]",
                    owasp_category="M1",
                    cwe_id="CWE-20",
                    remediation="Validate all input from URL scheme handlers."
                ))
    
    def get_metadata(self) -> IOSAppMetadata:
        """Get parsed app metadata"""
        return self._metadata
    
    def get_findings_by_severity(self, severity: FindingSeverity) -> List[IOSCodeFinding]:
        """Filter findings by severity"""
        return [f for f in self._findings if f.severity == severity]
    
    def get_findings_by_category(self, category: FindingCategory) -> List[IOSCodeFinding]:
        """Filter findings by category"""
        return [f for f in self._findings if f.category == category]
    
    def get_summary(self) -> Dict:
        """Get scan summary"""
        severity_counts = {}
        for severity in FindingSeverity:
            severity_counts[severity.value] = len(self.get_findings_by_severity(severity))
        
        category_counts = {}
        for category in FindingCategory:
            count = len(self.get_findings_by_category(category))
            if count > 0:
                category_counts[category.value] = count
        
        return {
            "app_info": {
                "bundle_id": self._metadata.bundle_id,
                "version": self._metadata.version,
                "min_ios": self._metadata.min_ios_version
            },
            "total_findings": len(self._findings),
            "by_severity": severity_counts,
            "by_category": category_counts,
            "security_features": {
                "pie_enabled": self._metadata.has_pie,
                "encrypted": self._metadata.is_encrypted,
                "ats_enabled": not self._metadata.allows_arbitrary_loads
            },
            "critical_issues": [
                {
                    "title": f.title,
                    "file": f.file_path
                }
                for f in self._findings
                if f.severity == FindingSeverity.CRITICAL
            ][:10]
        }


# Convenience function
async def scan_ipa_deep(ipa_path: str) -> List[IOSCodeFinding]:
    """Convenience function to scan an IPA file"""
    scanner = IOSDeepCodeScanner()
    return await scanner.scan_ipa(ipa_path)
