"""
Jarwis AGI Pen Test - Deep Code Scanner

Advanced static analysis using Jadx/APKTool for Android apps.
Goes beyond basic manifest analysis to find:
- Hardcoded API keys and secrets in Java/Kotlin code
- Insecure SharedPreferences usage
- Weak cryptography implementations
- SQL injection vulnerabilities
- Hardcoded credentials
- Insecure network configurations

Decompilation Tools:
- Jadx: Java/Kotlin decompilation (preferred)
- APKTool: Resource extraction and smali
- dex2jar: DEX to JAR conversion (fallback)

OWASP Mobile Top 10 2024:
- M9: Insecure Data Storage (SharedPreferences)
- M10: Insufficient Cryptography
- M1: Improper Credential Usage (hardcoded keys)

Usage:
    scanner = DeepCodeScanner()
    findings = await scanner.scan_apk("app.apk")
    
    for finding in findings:
        print(f"{finding.severity}: {finding.title}")
        print(f"  File: {finding.file_path}:{finding.line_number}")
        print(f"  Code: {finding.code_snippet}")
"""

import os
import re
import json
import asyncio
import logging
import shutil
import tempfile
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set, Pattern
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
    SQL_INJECTION = "sql_injection"
    LOGGING = "logging"
    WEBVIEW = "webview"
    INTENT = "intent"


@dataclass
class CodeFinding:
    """A finding from deep code analysis with comprehensive vulnerability metadata"""
    id: str
    title: str
    description: str
    severity: FindingSeverity
    category: FindingCategory
    
    # Location
    file_path: str
    line_number: int
    code_snippet: str
    
    # Context
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
    confidence: str = "high"  # high, medium, low
    false_positive_hints: List[str] = field(default_factory=list)
    
    # PoC Evidence
    poc_request: str = ""
    poc_response: str = ""
    affected_component: str = ""
    
    def enrich_from_registry(self) -> 'CodeFinding':
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
            FindingCategory.INSECURE_NETWORK: "insecure_network_communication",
            FindingCategory.SQL_INJECTION: "sqli",
            FindingCategory.LOGGING: "logging_sensitive_data",
            FindingCategory.WEBVIEW: "webview_vulnerability",
            FindingCategory.INTENT: "intent_injection",
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
            "false_positive_hints": self.false_positive_hints,
            "poc_request": self.poc_request,
            "poc_response": self.poc_response,
            "affected_component": self.affected_component,
        }


@dataclass
class SecretPattern:
    """Pattern for detecting hardcoded secrets"""
    name: str
    pattern: Pattern
    severity: FindingSeverity
    description: str
    cwe_id: str = "CWE-798"
    false_positive_patterns: List[str] = field(default_factory=list)


@dataclass
class DeepScanConfig:
    """Configuration for deep code scanning"""
    # Tools
    jadx_path: str = "jadx"
    apktool_path: str = "apktool"
    
    # Scan options
    scan_resources: bool = True
    scan_smali: bool = False  # Slower but more complete
    max_file_size_mb: int = 10
    timeout_minutes: int = 30
    
    # Output
    keep_decompiled: bool = False
    output_dir: str = ""
    
    # Patterns
    custom_secret_patterns: List[Dict] = field(default_factory=list)


class DeepCodeScanner:
    """
    Deep code analysis scanner using Jadx/APKTool.
    
    Performs comprehensive static analysis on Android apps
    to find security vulnerabilities in decompiled code.
    """
    
    # ==================== API Key Patterns ====================
    API_KEY_PATTERNS = [
        # Google
        SecretPattern(
            name="Google API Key",
            pattern=re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            severity=FindingSeverity.HIGH,
            description="Google API key found. May provide access to Google Cloud services.",
            cwe_id="CWE-798"
        ),
        SecretPattern(
            name="Google OAuth Client ID",
            pattern=re.compile(r'[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com'),
            severity=FindingSeverity.MEDIUM,
            description="Google OAuth client ID found.",
            cwe_id="CWE-798"
        ),
        
        # Firebase
        SecretPattern(
            name="Firebase API Key",
            pattern=re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
            severity=FindingSeverity.HIGH,
            description="Firebase Cloud Messaging server key found.",
            cwe_id="CWE-798"
        ),
        
        # AWS
        SecretPattern(
            name="AWS Access Key ID",
            pattern=re.compile(r'AKIA[0-9A-Z]{16}'),
            severity=FindingSeverity.CRITICAL,
            description="AWS Access Key ID found. May provide access to AWS resources.",
            cwe_id="CWE-798"
        ),
        SecretPattern(
            name="AWS Secret Access Key",
            pattern=re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
            severity=FindingSeverity.CRITICAL,
            description="Potential AWS Secret Access Key found.",
            cwe_id="CWE-798",
            false_positive_patterns=["test", "example", "sample", "dummy"]
        ),
        
        # Stripe
        SecretPattern(
            name="Stripe API Key",
            pattern=re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
            severity=FindingSeverity.CRITICAL,
            description="Stripe live secret key found. Financial data at risk.",
            cwe_id="CWE-798"
        ),
        SecretPattern(
            name="Stripe Publishable Key",
            pattern=re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),
            severity=FindingSeverity.MEDIUM,
            description="Stripe live publishable key found.",
            cwe_id="CWE-798"
        ),
        
        # Twilio
        SecretPattern(
            name="Twilio API Key",
            pattern=re.compile(r'SK[0-9a-fA-F]{32}'),
            severity=FindingSeverity.HIGH,
            description="Twilio API key found.",
            cwe_id="CWE-798"
        ),
        
        # SendGrid
        SecretPattern(
            name="SendGrid API Key",
            pattern=re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
            severity=FindingSeverity.HIGH,
            description="SendGrid API key found. Email sending access.",
            cwe_id="CWE-798"
        ),
        
        # Slack
        SecretPattern(
            name="Slack Token",
            pattern=re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'),
            severity=FindingSeverity.HIGH,
            description="Slack token found. Workspace access possible.",
            cwe_id="CWE-798"
        ),
        SecretPattern(
            name="Slack Webhook",
            pattern=re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'),
            severity=FindingSeverity.MEDIUM,
            description="Slack webhook URL found.",
            cwe_id="CWE-798"
        ),
        
        # GitHub
        SecretPattern(
            name="GitHub Token",
            pattern=re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
            severity=FindingSeverity.HIGH,
            description="GitHub personal access token found.",
            cwe_id="CWE-798"
        ),
        
        # Generic secrets
        SecretPattern(
            name="Generic API Key",
            pattern=re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']'),
            severity=FindingSeverity.MEDIUM,
            description="Potential API key found in code.",
            cwe_id="CWE-798",
            false_positive_patterns=["YOUR_API_KEY", "API_KEY_HERE", "REPLACE_ME"]
        ),
        SecretPattern(
            name="Generic Secret",
            pattern=re.compile(r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']'),
            severity=FindingSeverity.HIGH,
            description="Hardcoded secret/password found.",
            cwe_id="CWE-798",
            false_positive_patterns=["password", "secret", "changeme", "example"]
        ),
        
        # Private keys
        SecretPattern(
            name="RSA Private Key",
            pattern=re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
            severity=FindingSeverity.CRITICAL,
            description="RSA private key embedded in code.",
            cwe_id="CWE-321"
        ),
        SecretPattern(
            name="Generic Private Key",
            pattern=re.compile(r'-----BEGIN (?:EC |DSA )?PRIVATE KEY-----'),
            severity=FindingSeverity.CRITICAL,
            description="Private key embedded in code.",
            cwe_id="CWE-321"
        ),
        
        # JWT
        SecretPattern(
            name="JWT Token",
            pattern=re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
            severity=FindingSeverity.MEDIUM,
            description="JWT token found in code. May contain sensitive claims.",
            cwe_id="CWE-798"
        ),
    ]
    
    # ==================== SharedPreferences Patterns ====================
    SHARED_PREFS_PATTERNS = [
        # Insecure mode
        (
            re.compile(r'getSharedPreferences\s*\([^,]+,\s*(?:Context\.)?MODE_WORLD_READABLE'),
            FindingSeverity.CRITICAL,
            "SharedPreferences with MODE_WORLD_READABLE",
            "Data can be read by any app on device.",
            "CWE-276"
        ),
        (
            re.compile(r'getSharedPreferences\s*\([^,]+,\s*(?:Context\.)?MODE_WORLD_WRITEABLE'),
            FindingSeverity.CRITICAL,
            "SharedPreferences with MODE_WORLD_WRITEABLE",
            "Data can be modified by any app on device.",
            "CWE-276"
        ),
        
        # Sensitive data in SharedPreferences
        (
            re.compile(r'(?:putString|edit\(\)\.putString)\s*\([^,]*(?:password|passwd|pwd|secret|token|key|api_key|apikey|auth)[^,]*,'),
            FindingSeverity.HIGH,
            "Sensitive data stored in SharedPreferences",
            "Passwords/tokens stored in SharedPreferences are easily accessible on rooted devices.",
            "CWE-312"
        ),
        
        # Unencrypted SharedPreferences
        (
            re.compile(r'getSharedPreferences\s*\(\s*["\'][^"\']+["\']\s*,'),
            FindingSeverity.LOW,
            "Standard SharedPreferences usage",
            "Consider using EncryptedSharedPreferences for sensitive data.",
            "CWE-311"
        ),
    ]
    
    # ==================== Weak Crypto Patterns ====================
    WEAK_CRYPTO_PATTERNS = [
        # Weak algorithms
        (
            re.compile(r'(?:Cipher|MessageDigest|Mac)\.getInstance\s*\(\s*["\'](?:DES|DESede|RC2|RC4|MD5|SHA-1|SHA1)["\']'),
            FindingSeverity.HIGH,
            "Weak cryptographic algorithm",
            "DES, 3DES, RC2, RC4, MD5, and SHA-1 are considered weak.",
            "CWE-327"
        ),
        
        # ECB mode
        (
            re.compile(r'Cipher\.getInstance\s*\(\s*["\'][^"\']*\/ECB\/'),
            FindingSeverity.HIGH,
            "ECB mode encryption",
            "ECB mode does not provide semantic security.",
            "CWE-327"
        ),
        
        # No padding
        (
            re.compile(r'Cipher\.getInstance\s*\(\s*["\'][^"\']*\/NoPadding["\']'),
            FindingSeverity.MEDIUM,
            "Encryption without padding",
            "NoPadding can leak information about plaintext length.",
            "CWE-327"
        ),
        
        # Hardcoded IV
        (
            re.compile(r'IvParameterSpec\s*\(\s*(?:new\s+byte\s*\[\s*\]\s*\{|["\'])'),
            FindingSeverity.HIGH,
            "Hardcoded initialization vector",
            "IVs should be randomly generated for each encryption.",
            "CWE-329"
        ),
        
        # Hardcoded key
        (
            re.compile(r'SecretKeySpec\s*\(\s*(?:new\s+byte\s*\[\s*\]\s*\{|["\'])'),
            FindingSeverity.CRITICAL,
            "Hardcoded encryption key",
            "Encryption keys should not be hardcoded in source code.",
            "CWE-321"
        ),
        
        # Weak key generation
        (
            re.compile(r'KeyGenerator\.getInstance\s*\(\s*["\']DES["\']'),
            FindingSeverity.HIGH,
            "DES key generation",
            "DES has an effective key length of only 56 bits.",
            "CWE-326"
        ),
        
        # Insecure random
        (
            re.compile(r'(?:new\s+Random\s*\(|java\.util\.Random)'),
            FindingSeverity.MEDIUM,
            "Insecure random number generator",
            "Use SecureRandom for cryptographic operations.",
            "CWE-330"
        ),
        
        # Static seed
        (
            re.compile(r'(?:SecureRandom|Random)\s*\(\s*\d+\s*\)|\.setSeed\s*\(\s*\d+\s*\)'),
            FindingSeverity.HIGH,
            "Static seed for random generator",
            "Seeds should not be hardcoded.",
            "CWE-330"
        ),
    ]
    
    # ==================== Other Security Patterns ====================
    OTHER_PATTERNS = [
        # SQL Injection
        (
            re.compile(r'(?:rawQuery|execSQL)\s*\([^,]*\+[^,]*(?:getString|getIntent|getExtra)'),
            FindingSeverity.HIGH,
            "Potential SQL Injection",
            "User input concatenated into SQL query.",
            "CWE-89",
            FindingCategory.SQL_INJECTION
        ),
        
        # Logging sensitive data
        (
            re.compile(r'Log\.(?:d|v|i|w|e)\s*\([^,]+,\s*[^)]*(?:password|token|secret|key|auth)'),
            FindingSeverity.MEDIUM,
            "Sensitive data in logs",
            "Sensitive information may be exposed in system logs.",
            "CWE-532",
            FindingCategory.LOGGING
        ),
        
        # WebView JavaScript enabled
        (
            re.compile(r'setJavaScriptEnabled\s*\(\s*true\s*\)'),
            FindingSeverity.MEDIUM,
            "JavaScript enabled in WebView",
            "May be vulnerable to XSS if loading untrusted content.",
            "CWE-79",
            FindingCategory.WEBVIEW
        ),
        
        # WebView file access
        (
            re.compile(r'setAllowFileAccess\s*\(\s*true\s*\)'),
            FindingSeverity.HIGH,
            "File access enabled in WebView",
            "May allow reading local files via file:// URLs.",
            "CWE-200",
            FindingCategory.WEBVIEW
        ),
        
        # Insecure intent
        (
            re.compile(r'setFlags\s*\([^)]*FLAG_GRANT_(?:READ|WRITE)_URI_PERMISSION'),
            FindingSeverity.MEDIUM,
            "URI permission flags in Intent",
            "Verify intent is only sent to trusted components.",
            "CWE-926",
            FindingCategory.INTENT
        ),
        
        # Cleartext traffic
        (
            re.compile(r'(?:http://|usesCleartextTraffic\s*=\s*["\']?true)'),
            FindingSeverity.MEDIUM,
            "Cleartext HTTP traffic",
            "Data transmitted without encryption.",
            "CWE-319",
            FindingCategory.INSECURE_NETWORK
        ),
        
        # Certificate pinning bypass
        (
            re.compile(r'TrustManager|X509TrustManager|checkClientTrusted|checkServerTrusted'),
            FindingSeverity.INFO,
            "Custom TrustManager implementation",
            "Review for proper certificate validation.",
            "CWE-295",
            FindingCategory.INSECURE_NETWORK
        ),
    ]
    
    def __init__(self, config: Optional[DeepScanConfig] = None):
        self.config = config or DeepScanConfig()
        self._findings: List[CodeFinding] = []
        self._scanned_files: Set[str] = set()
        self._temp_dir: Optional[Path] = None
        
        # Find tools
        self._jadx_path = self._find_tool("jadx")
        self._apktool_path = self._find_tool("apktool")
    
    def _find_tool(self, tool_name: str) -> Optional[str]:
        """Find tool in PATH or common locations"""
        # Check config
        if tool_name == "jadx" and self.config.jadx_path:
            if Path(self.config.jadx_path).exists():
                return self.config.jadx_path
        if tool_name == "apktool" and self.config.apktool_path:
            if Path(self.config.apktool_path).exists():
                return self.config.apktool_path
        
        # Check PATH
        try:
            result = subprocess.run(
                ["which" if os.name != "nt" else "where", tool_name],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip().split('\n')[0]
        except:
            pass
        
        # Check common locations - prioritize user/agent configured paths
        common_paths = [
            # Agent-configured tool path (highest priority)
            Path(os.environ.get("JARWIS_TOOLS_PATH", "")) / tool_name,
            # User home paths
            Path.home() / ".jarwis" / "tools" / tool_name,
            Path.home() / ".jarwis" / "tools" / f"{tool_name}.bat",
            # System paths (platform-specific)
            Path(f"/usr/local/bin/{tool_name}") if os.name != "nt" else Path(f"C:/Tools/{tool_name}/{tool_name}.exe"),
            Path(f"/opt/{tool_name}/bin/{tool_name}") if os.name != "nt" else Path(f"C:/Program Files/{tool_name}/{tool_name}.exe"),
            # Homebrew on macOS
            Path("/opt/homebrew/bin") / tool_name,
        ]
        
        for path in common_paths:
            if path.exists():
                return str(path)
        
        return None
    
    async def scan_apk(self, apk_path: str) -> List[CodeFinding]:
        """
        Scan an APK file for security vulnerabilities.
        
        This performs full decompilation and code analysis.
        """
        self._findings = []
        self._scanned_files = set()
        
        apk_path = Path(apk_path)
        if not apk_path.exists():
            logger.error(f"APK not found: {apk_path}")
            return []
        
        logger.info(f"Starting deep code scan of {apk_path.name}")
        
        # Create temp directory
        self._temp_dir = Path(tempfile.mkdtemp(prefix="jarwis_decompile_"))
        
        try:
            # Decompile with Jadx (preferred)
            if self._jadx_path:
                await self._decompile_with_jadx(apk_path)
            elif self._apktool_path:
                await self._decompile_with_apktool(apk_path)
            else:
                logger.error("No decompilation tool available. Install jadx or apktool.")
                return []
            
            # Scan decompiled code
            await self._scan_decompiled_code()
            
            # Scan resources
            if self.config.scan_resources:
                await self._scan_resources()
            
            logger.info(f"Deep scan complete: {len(self._findings)} findings")
            
        finally:
            # Cleanup
            if not self.config.keep_decompiled and self._temp_dir:
                try:
                    shutil.rmtree(self._temp_dir)
                except:
                    pass
        
        return self._findings
    
    async def _decompile_with_jadx(self, apk_path: Path) -> bool:
        """Decompile APK using Jadx"""
        logger.info("Decompiling with Jadx...")
        
        output_dir = self._temp_dir / "jadx_output"
        
        cmd = [
            self._jadx_path,
            "--output-dir", str(output_dir),
            "--deobf",  # Deobfuscate
            "--show-bad-code",  # Show even if decompilation fails
            str(apk_path)
        ]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config.timeout_minutes * 60
            )
            
            if proc.returncode != 0:
                logger.warning(f"Jadx returned {proc.returncode}: {stderr.decode()}")
            
            return output_dir.exists()
            
        except asyncio.TimeoutError:
            logger.error("Jadx decompilation timed out")
            return False
        except Exception as e:
            logger.error(f"Jadx decompilation failed: {e}")
            return False
    
    async def _decompile_with_apktool(self, apk_path: Path) -> bool:
        """Decompile APK using APKTool"""
        logger.info("Decompiling with APKTool...")
        
        output_dir = self._temp_dir / "apktool_output"
        
        cmd = [
            self._apktool_path,
            "d",  # decode
            "-f",  # force
            "-o", str(output_dir),
            str(apk_path)
        ]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config.timeout_minutes * 60
            )
            
            return output_dir.exists()
            
        except Exception as e:
            logger.error(f"APKTool decompilation failed: {e}")
            return False
    
    async def _scan_decompiled_code(self):
        """Scan all decompiled Java/Kotlin files"""
        logger.info("Scanning decompiled code...")
        
        # Find all source files
        source_extensions = ['.java', '.kt', '.smali'] if self.config.scan_smali else ['.java', '.kt']
        
        for ext in source_extensions:
            for file_path in self._temp_dir.rglob(f"*{ext}"):
                if file_path.stat().st_size > self.config.max_file_size_mb * 1024 * 1024:
                    continue
                
                await self._scan_file(file_path)
    
    async def _scan_file(self, file_path: Path):
        """Scan a single source file"""
        if str(file_path) in self._scanned_files:
            return
        
        self._scanned_files.add(str(file_path))
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            relative_path = str(file_path.relative_to(self._temp_dir))
            
            # Extract class/method context
            class_name = self._extract_class_name(content)
            
            # Scan for API keys and secrets
            for pattern in self.API_KEY_PATTERNS:
                await self._check_pattern(
                    pattern, content, lines, relative_path, class_name
                )
            
            # Scan for SharedPreferences issues
            for pattern_tuple in self.SHARED_PREFS_PATTERNS:
                await self._check_simple_pattern(
                    pattern_tuple, content, lines, relative_path, class_name,
                    FindingCategory.INSECURE_STORAGE
                )
            
            # Scan for weak crypto
            for pattern_tuple in self.WEAK_CRYPTO_PATTERNS:
                await self._check_simple_pattern(
                    pattern_tuple, content, lines, relative_path, class_name,
                    FindingCategory.WEAK_CRYPTO
                )
            
            # Scan for other issues
            for pattern_tuple in self.OTHER_PATTERNS:
                category = pattern_tuple[5] if len(pattern_tuple) > 5 else FindingCategory.HARDCODED_SECRET
                await self._check_simple_pattern(
                    pattern_tuple[:5], content, lines, relative_path, class_name,
                    category
                )
            
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
    
    async def _check_pattern(
        self,
        pattern: SecretPattern,
        content: str,
        lines: List[str],
        file_path: str,
        class_name: str
    ):
        """Check content for secret pattern"""
        for match in pattern.pattern.finditer(content):
            matched_text = match.group(0)
            
            # Check for false positives
            is_false_positive = False
            for fp_pattern in pattern.false_positive_patterns:
                if fp_pattern.lower() in matched_text.lower():
                    is_false_positive = True
                    break
            
            if is_false_positive:
                continue
            
            # Find line number
            line_number = content[:match.start()].count('\n') + 1
            
            # Get code snippet
            snippet_start = max(0, line_number - 2)
            snippet_end = min(len(lines), line_number + 2)
            code_snippet = '\n'.join(lines[snippet_start:snippet_end])
            
            finding = CodeFinding(
                id=f"SECRET-{len(self._findings)+1}",
                title=pattern.name,
                description=pattern.description,
                severity=pattern.severity,
                category=FindingCategory.HARDCODED_SECRET,
                file_path=file_path,
                line_number=line_number,
                code_snippet=code_snippet,
                class_name=class_name,
                matched_pattern=matched_text[:100],
                owasp_category="M1",  # Improper Credential Usage
                cwe_id=pattern.cwe_id,
                remediation="Remove hardcoded secrets. Use secure storage like Android Keystore or environment variables."
            )
            
            self._findings.append(finding)
    
    async def _check_simple_pattern(
        self,
        pattern_tuple: tuple,
        content: str,
        lines: List[str],
        file_path: str,
        class_name: str,
        category: FindingCategory
    ):
        """Check content for simple pattern tuple"""
        pattern, severity, title, description, cwe_id = pattern_tuple
        
        for match in pattern.finditer(content):
            line_number = content[:match.start()].count('\n') + 1
            
            snippet_start = max(0, line_number - 2)
            snippet_end = min(len(lines), line_number + 2)
            code_snippet = '\n'.join(lines[snippet_start:snippet_end])
            
            finding = CodeFinding(
                id=f"{category.value.upper()}-{len(self._findings)+1}",
                title=title,
                description=description,
                severity=severity,
                category=category,
                file_path=file_path,
                line_number=line_number,
                code_snippet=code_snippet,
                class_name=class_name,
                matched_pattern=match.group(0)[:100],
                owasp_category=self._get_owasp_category(category),
                cwe_id=cwe_id,
                remediation=self._get_remediation(category)
            )
            
            self._findings.append(finding)
    
    async def _scan_resources(self):
        """Scan resource files (strings.xml, etc.)"""
        logger.info("Scanning resources...")
        
        resource_patterns = [
            ('*.xml', self._scan_xml_resource),
            ('*.json', self._scan_json_resource),
            ('*.properties', self._scan_properties_resource),
        ]
        
        for pattern, scanner in resource_patterns:
            for file_path in self._temp_dir.rglob(pattern):
                if file_path.stat().st_size > self.config.max_file_size_mb * 1024 * 1024:
                    continue
                await scanner(file_path)
    
    async def _scan_xml_resource(self, file_path: Path):
        """Scan XML resource files"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Check for secrets in string resources
            string_pattern = re.compile(r'<string[^>]*name="([^"]*(?:key|secret|token|password|api)[^"]*)"[^>]*>([^<]+)</string>', re.IGNORECASE)
            
            for match in string_pattern.finditer(content):
                name = match.group(1)
                value = match.group(2)
                
                # Skip placeholders
                if value in ['', 'YOUR_KEY', 'TODO', 'REPLACE']:
                    continue
                
                line_number = content[:match.start()].count('\n') + 1
                
                finding = CodeFinding(
                    id=f"RESOURCE-{len(self._findings)+1}",
                    title=f"Potential secret in resources: {name}",
                    description="Sensitive value found in string resources.",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.HARDCODED_SECRET,
                    file_path=str(file_path.relative_to(self._temp_dir)),
                    line_number=line_number,
                    code_snippet=match.group(0),
                    matched_pattern=value[:50],
                    owasp_category="M1",
                    cwe_id="CWE-798",
                    remediation="Move secrets to secure storage or environment variables."
                )
                
                self._findings.append(finding)
                
        except Exception as e:
            logger.debug(f"Error scanning XML {file_path}: {e}")
    
    async def _scan_json_resource(self, file_path: Path):
        """Scan JSON resource files (like google-services.json)"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Check for google-services.json
            if 'google-services' in file_path.name:
                finding = CodeFinding(
                    id=f"RESOURCE-{len(self._findings)+1}",
                    title="Firebase configuration file found",
                    description="google-services.json contains Firebase project details.",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.HARDCODED_SECRET,
                    file_path=str(file_path.relative_to(self._temp_dir)),
                    line_number=1,
                    code_snippet=content[:200] + "...",
                    owasp_category="M1",
                    cwe_id="CWE-200",
                    remediation="Ensure Firebase security rules are properly configured."
                )
                self._findings.append(finding)
            
            # Check for API keys in JSON
            for pattern in self.API_KEY_PATTERNS[:5]:  # Check major patterns
                for match in pattern.pattern.finditer(content):
                    line_number = content[:match.start()].count('\n') + 1
                    
                    finding = CodeFinding(
                        id=f"RESOURCE-{len(self._findings)+1}",
                        title=f"{pattern.name} in JSON config",
                        description=pattern.description,
                        severity=pattern.severity,
                        category=FindingCategory.HARDCODED_SECRET,
                        file_path=str(file_path.relative_to(self._temp_dir)),
                        line_number=line_number,
                        code_snippet=match.group(0)[:100],
                        owasp_category="M1",
                        cwe_id=pattern.cwe_id,
                        remediation="Remove secrets from configuration files."
                    )
                    self._findings.append(finding)
                    
        except Exception as e:
            logger.debug(f"Error scanning JSON {file_path}: {e}")
    
    async def _scan_properties_resource(self, file_path: Path):
        """Scan .properties files"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Look for key=value with sensitive names
            prop_pattern = re.compile(r'^([^#=\n]*(?:key|secret|password|token|api)[^=\n]*)=(.+)$', re.MULTILINE | re.IGNORECASE)
            
            for match in prop_pattern.finditer(content):
                line_number = content[:match.start()].count('\n') + 1
                
                finding = CodeFinding(
                    id=f"RESOURCE-{len(self._findings)+1}",
                    title=f"Potential secret in properties: {match.group(1)}",
                    description="Sensitive value found in properties file.",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.HARDCODED_SECRET,
                    file_path=str(file_path.relative_to(self._temp_dir)),
                    line_number=line_number,
                    code_snippet=match.group(0),
                    owasp_category="M1",
                    cwe_id="CWE-798",
                    remediation="Move secrets to secure storage."
                )
                self._findings.append(finding)
                
        except Exception as e:
            logger.debug(f"Error scanning properties {file_path}: {e}")
    
    def _extract_class_name(self, content: str) -> str:
        """Extract class name from source code"""
        match = re.search(r'(?:class|interface|enum)\s+(\w+)', content)
        return match.group(1) if match else ""
    
    def _get_owasp_category(self, category: FindingCategory) -> str:
        """Map finding category to OWASP Mobile Top 10"""
        mapping = {
            FindingCategory.HARDCODED_SECRET: "M1",  # Improper Credential Usage
            FindingCategory.INSECURE_STORAGE: "M9",  # Insecure Data Storage
            FindingCategory.WEAK_CRYPTO: "M10",      # Insufficient Cryptography
            FindingCategory.INSECURE_NETWORK: "M5",  # Insecure Communication
            FindingCategory.SQL_INJECTION: "M4",     # Insufficient Input/Output Validation
            FindingCategory.LOGGING: "M9",           # Insecure Data Storage
            FindingCategory.WEBVIEW: "M4",           # Insufficient Input/Output Validation
            FindingCategory.INTENT: "M3",            # Insecure Authentication/Authorization
        }
        return mapping.get(category, "M1")
    
    def _get_remediation(self, category: FindingCategory) -> str:
        """Get remediation guidance for category"""
        remediations = {
            FindingCategory.HARDCODED_SECRET: 
                "Remove hardcoded secrets. Use Android Keystore, EncryptedSharedPreferences, or environment variables.",
            FindingCategory.INSECURE_STORAGE:
                "Use EncryptedSharedPreferences for sensitive data. Never use MODE_WORLD_READABLE/WRITEABLE.",
            FindingCategory.WEAK_CRYPTO:
                "Use AES-256-GCM for encryption. Use SHA-256 or SHA-3 for hashing. Generate random IVs and use secure key storage.",
            FindingCategory.INSECURE_NETWORK:
                "Use HTTPS for all network communication. Implement certificate pinning for sensitive endpoints.",
            FindingCategory.SQL_INJECTION:
                "Use parameterized queries or ContentValues. Never concatenate user input into SQL.",
            FindingCategory.LOGGING:
                "Remove sensitive data from log statements. Use ProGuard to strip logs in release builds.",
            FindingCategory.WEBVIEW:
                "Disable JavaScript if not needed. Validate URLs before loading. Don't enable file access.",
            FindingCategory.INTENT:
                "Verify intent recipients. Use explicit intents when possible. Validate received intent data.",
        }
        return remediations.get(category, "Review and fix the security issue.")
    
    def get_findings_by_severity(self, severity: FindingSeverity) -> List[CodeFinding]:
        """Filter findings by severity"""
        return [f for f in self._findings if f.severity == severity]
    
    def get_findings_by_category(self, category: FindingCategory) -> List[CodeFinding]:
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
            "total_findings": len(self._findings),
            "files_scanned": len(self._scanned_files),
            "by_severity": severity_counts,
            "by_category": category_counts,
            "critical_issues": [
                {
                    "title": f.title,
                    "file": f.file_path,
                    "line": f.line_number
                }
                for f in self._findings
                if f.severity == FindingSeverity.CRITICAL
            ][:10]
        }


# Convenience function
async def scan_apk_deep(apk_path: str) -> List[CodeFinding]:
    """Convenience function to scan an APK"""
    scanner = DeepCodeScanner()
    return await scanner.scan_apk(apk_path)
