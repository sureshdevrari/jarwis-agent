"""
Jarwis AGI - Mobile Static Analysis Engine
Analyzes APK/IPA files without execution

Supports:
- Android: APK analysis using apktool, jadx, androguard
- iOS: IPA analysis using unzip, class-dump
"""

import os
import re
import json
import asyncio
import logging
import zipfile
import tempfile
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class StaticAnalysisResult:
    """Results from static analysis"""
    id: str
    category: str  # OWASP Mobile category: M1-M10
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    file_path: str
    line_number: int = 0
    code_snippet: str = ""
    evidence: str = ""
    recommendation: str = ""


@dataclass
class AppMetadata:
    """Mobile app metadata extracted from static analysis"""
    platform: str  # android or ios
    package_name: str
    version_name: str
    version_code: str
    min_sdk: str = ""
    target_sdk: str = ""
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    exported_components: List[str] = field(default_factory=list)
    url_schemes: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    hardcoded_secrets: List[Dict] = field(default_factory=list)
    network_security_config: Dict = field(default_factory=dict)
    is_debuggable: bool = False
    allows_backup: bool = False
    uses_cleartext: bool = False


class StaticAnalyzer:
    """
    Static Analysis Engine for Mobile Applications
    Extracts and analyzes APK/IPA files without execution
    """
    
    # Scanner registry metadata
    CATEGORY = "M2"  # OWASP Mobile: Inadequate Supply Chain Security
    DESCRIPTION = "Static analysis for mobile app binaries (APK/IPA)"
    ENABLED_BY_DEFAULT = True
    REQUIRES_AUTH = False
    
    # Dangerous Android permissions
    DANGEROUS_PERMISSIONS = [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.PROCESS_OUTGOING_CALLS",
    ]
    
    # Secret patterns to detect
    SECRET_PATTERNS = [
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'API Key'),
        (r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', 'Password/Secret'),
        (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key'),
        (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'AWS Secret Key'),
        (r'(?i)(firebase[_-]?api[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{39})["\']', 'Firebase API Key'),
        (r'(?i)(google[_-]?api[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{39})["\']', 'Google API Key'),
        (r'(?i)(private[_-]?key)\s*[=:]\s*["\']([^"\']+)["\']', 'Private Key'),
        (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', 'Private Key File'),
        (r'(?i)(bearer|authorization)\s*[=:]\s*["\']([a-zA-Z0-9._\-]+)["\']', 'Auth Token'),
        (r'(?i)eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', 'JWT Token'),
    ]
    
    # API endpoint patterns
    API_PATTERNS = [
        r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
        r'(?i)/api/v\d+/[a-zA-Z0-9/_-]+',
        r'(?i)/graphql',
        r'(?i)/rest/[a-zA-Z0-9/_-]+',
    ]
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.temp_dir = None
        self._tools_available = {}
        self._check_tools()
    
    def _check_tools(self):
        """Check which analysis tools are available on the system"""
        import platform as sys_platform
        is_windows = sys_platform.system() == 'Windows'
        
        # Tools to check - on Windows we look for .exe or .bat versions
        tools = {
            'apktool': ['apktool', 'apktool.bat', 'apktool.exe'],
            'jadx': ['jadx', 'jadx.bat', 'jadx.exe'],
            'aapt': ['aapt', 'aapt.exe', 'aapt2.exe'],
            'unzip': ['unzip', 'unzip.exe'],  # Windows has built-in Expand-Archive
            'strings': ['strings', 'strings.exe'],
        }
        
        for tool_name, variants in tools.items():
            found = False
            for variant in variants:
                try:
                    # Use 'where' on Windows, 'which' on Unix
                    check_cmd = ['where', variant] if is_windows else ['which', variant]
                    result = subprocess.run(
                        check_cmd,
                        capture_output=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        found = True
                        break
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue
            
            self._tools_available[tool_name] = found
        
        # On Windows, we always have Python's zipfile which can replace unzip
        self._tools_available['python_zip'] = True
        
        logger.info(f"Static analysis tools available: {self._tools_available}")
    
    async def analyze(self, file_path: str) -> tuple[AppMetadata, List[StaticAnalysisResult]]:
        """
        Analyze a mobile app file (APK or IPA)
        
        Returns:
            tuple of (AppMetadata, List[StaticAnalysisResult])
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Determine platform based on file extension
        ext = file_path.suffix.lower()
        
        if ext == '.apk':
            return await self._analyze_apk(file_path)
        elif ext == '.xapk':
            # XAPK is a split APK format - extract base APK first
            return await self._analyze_xapk(file_path)
        elif ext == '.ipa':
            return await self._analyze_ipa(file_path)
        else:
            raise ValueError(f"Unsupported file type: {ext}. Supported: .apk, .xapk, .ipa")
    
    async def _analyze_xapk(self, xapk_path: Path) -> tuple[AppMetadata, List[StaticAnalysisResult]]:
        """
        Analyze XAPK file (split APK bundle format).
        
        XAPK contains:
        - manifest.json with app metadata
        - base APK file
        - Split APKs for different architectures/configurations
        """
        logger.info(f"Analyzing XAPK: {xapk_path}")
        
        # Create temp directory for extraction
        xapk_temp_dir = tempfile.mkdtemp(prefix="jarwis_xapk_")
        base_apk_path = None
        xapk_manifest = {}
        
        try:
            # Extract XAPK (it's a zip file)
            with zipfile.ZipFile(xapk_path, 'r') as zip_ref:
                zip_ref.extractall(xapk_temp_dir)
            
            xapk_extract = Path(xapk_temp_dir)
            
            # Find base APK - check for manifest.json first
            manifest_json = xapk_extract / "manifest.json"
            if manifest_json.exists():
                try:
                    with open(manifest_json, 'r', encoding='utf-8') as f:
                        xapk_manifest = json.load(f)
                    logger.info(f"XAPK manifest: package={xapk_manifest.get('package_name')}, version={xapk_manifest.get('version_name')}")
                except Exception as e:
                    logger.warning(f"Failed to parse XAPK manifest: {e}")
            
            # Look for base APK (usually named base.apk or {package}.apk)
            apk_files = list(xapk_extract.glob("*.apk"))
            
            # Prioritize base.apk or the largest APK
            for apk in apk_files:
                if apk.name.lower() in ['base.apk', 'base-master.apk']:
                    base_apk_path = apk
                    break
            
            if not base_apk_path and apk_files:
                # Use the largest APK as base
                base_apk_path = max(apk_files, key=lambda p: p.stat().st_size)
            
            if not base_apk_path:
                raise ValueError("No APK file found in XAPK bundle")
            
            logger.info(f"Using base APK: {base_apk_path.name}")
            
            # Analyze the base APK
            metadata, findings = await self._analyze_apk(base_apk_path)
            
            # Override with XAPK manifest data (more accurate)
            if xapk_manifest:
                if xapk_manifest.get('package_name'):
                    metadata.package_name = xapk_manifest.get('package_name')
                if xapk_manifest.get('version_name'):
                    metadata.version_name = xapk_manifest.get('version_name')
                if xapk_manifest.get('version_code'):
                    metadata.version_code = str(xapk_manifest.get('version_code'))
                if xapk_manifest.get('min_sdk_version'):
                    metadata.min_sdk = str(xapk_manifest.get('min_sdk_version'))
                if xapk_manifest.get('target_sdk_version'):
                    metadata.target_sdk = str(xapk_manifest.get('target_sdk_version'))
                # Extract permissions from XAPK manifest
                if xapk_manifest.get('permissions'):
                    for perm in xapk_manifest.get('permissions', []):
                        if perm not in metadata.permissions:
                            metadata.permissions.append(perm)
            
            # Add XAPK-specific info
            findings.append(StaticAnalysisResult(
                id=f"xapk_bundle_{xapk_path.stem}",
                category="info",
                severity="info",
                title="Split APK Bundle Detected",
                description=f"Application is distributed as XAPK (split APK bundle) with {len(apk_files)} APK components.",
                file_path=str(xapk_path),
                evidence=f"APK components: {', '.join(a.name for a in apk_files)}"
            ))
            
            return metadata, findings
            
        finally:
            # Cleanup temp directory
            import shutil
            shutil.rmtree(xapk_temp_dir, ignore_errors=True)
    
    async def _analyze_apk(self, apk_path: Path) -> tuple[AppMetadata, List[StaticAnalysisResult]]:
        """Analyze Android APK file"""
        logger.info(f"Analyzing APK: {apk_path}")
        
        metadata = AppMetadata(platform="android", package_name="", version_name="", version_code="")
        findings: List[StaticAnalysisResult] = []
        
        # Create temp directory for extraction
        self.temp_dir = tempfile.mkdtemp(prefix="jarwis_apk_")
        
        try:
            # Extract APK
            extract_dir = Path(self.temp_dir) / "extracted"
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Parse AndroidManifest.xml (binary format, need aapt or apktool)
            manifest_findings = await self._parse_android_manifest(apk_path, metadata)
            findings.extend(manifest_findings)
            
            # Scan for hardcoded secrets
            secret_findings = await self._scan_for_secrets(extract_dir, "android")
            findings.extend(secret_findings)
            
            # Scan for API endpoints
            api_findings = await self._scan_for_api_endpoints(extract_dir)
            metadata.api_endpoints = [f.evidence for f in api_findings if f.category == "info"]
            
            # Analyze network security config
            nsc_findings = await self._analyze_network_security_config(extract_dir, metadata)
            findings.extend(nsc_findings)
            
            # Check for insecure configurations
            config_findings = self._check_android_security_config(metadata)
            findings.extend(config_findings)
            
            # Decompile and analyze code if jadx available
            if self._tools_available.get('jadx'):
                code_findings = await self._analyze_decompiled_code(apk_path)
                findings.extend(code_findings)
            
        finally:
            # Cleanup temp directory
            if self.temp_dir:
                import shutil
                shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        return metadata, findings
    
    async def _analyze_ipa(self, ipa_path: Path) -> tuple[AppMetadata, List[StaticAnalysisResult]]:
        """Analyze iOS IPA file"""
        logger.info(f"Analyzing IPA: {ipa_path}")
        
        metadata = AppMetadata(platform="ios", package_name="", version_name="", version_code="")
        findings: List[StaticAnalysisResult] = []
        
        # Create temp directory for extraction
        self.temp_dir = tempfile.mkdtemp(prefix="jarwis_ipa_")
        
        try:
            # Extract IPA (it's just a zip file)
            extract_dir = Path(self.temp_dir) / "extracted"
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Find .app directory
            payload_dir = extract_dir / "Payload"
            app_dir = None
            if payload_dir.exists():
                for item in payload_dir.iterdir():
                    if item.suffix == '.app':
                        app_dir = item
                        break
            
            if app_dir:
                # Parse Info.plist
                plist_findings = await self._parse_info_plist(app_dir, metadata)
                findings.extend(plist_findings)
                
                # Scan for hardcoded secrets
                secret_findings = await self._scan_for_secrets(app_dir, "ios")
                findings.extend(secret_findings)
                
                # Check ATS configuration
                ats_findings = self._check_ios_ats(metadata)
                findings.extend(ats_findings)
            
        finally:
            # Cleanup temp directory
            if self.temp_dir:
                import shutil
                shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        return metadata, findings
    
    async def _parse_android_manifest(self, apk_path: Path, metadata: AppMetadata) -> List[StaticAnalysisResult]:
        """Parse AndroidManifest.xml using aapt"""
        findings = []
        
        try:
            # Use aapt to dump manifest info
            if self._tools_available.get('aapt'):
                result = subprocess.run(
                    ['aapt', 'dump', 'badging', str(apk_path)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                output = result.stdout
                
                # Extract package info
                pkg_match = re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", output)
                if pkg_match:
                    metadata.package_name = pkg_match.group(1)
                    metadata.version_code = pkg_match.group(2)
                    metadata.version_name = pkg_match.group(3)
                
                # Extract SDK versions
                sdk_match = re.search(r"sdkVersion:'(\d+)'", output)
                if sdk_match:
                    metadata.min_sdk = sdk_match.group(1)
                
                target_match = re.search(r"targetSdkVersion:'(\d+)'", output)
                if target_match:
                    metadata.target_sdk = target_match.group(1)
                
                # Extract permissions
                for perm_match in re.finditer(r"uses-permission: name='([^']+)'", output):
                    metadata.permissions.append(perm_match.group(1))
                
                # Check for debuggable
                if "application-debuggable" in output:
                    metadata.is_debuggable = True
                    findings.append(StaticAnalysisResult(
                        id="M7-DEBUG-001",
                        category="M7",
                        severity="high",
                        title="Application is Debuggable",
                        description="The android:debuggable flag is set to true in the manifest.",
                        file_path="AndroidManifest.xml",
                        evidence="android:debuggable=true",
                        recommendation="Set android:debuggable to false in production builds."
                    ))
            
            # Fallback: extract and parse binary manifest using pure Python
            else:
                logger.info("aapt not available, using pure Python manifest parsing")
                manifest_data = await self._parse_binary_manifest(apk_path, metadata)
                if manifest_data:
                    # Check for debuggable
                    if manifest_data.get('debuggable'):
                        metadata.is_debuggable = True
                        findings.append(StaticAnalysisResult(
                            id="M7-DEBUG-001",
                            category="M7",
                            severity="high",
                            title="Application is Debuggable",
                            description="The android:debuggable flag is set to true.",
                            file_path="AndroidManifest.xml",
                            evidence="android:debuggable=true",
                            recommendation="Set android:debuggable to false in production builds."
                        ))
                        
        except Exception as e:
            logger.error(f"Error parsing Android manifest: {e}")
        
        # Check for dangerous permissions
        for perm in metadata.permissions:
            if perm in self.DANGEROUS_PERMISSIONS:
                findings.append(StaticAnalysisResult(
                    id=f"M1-PERM-{len(findings)+1:03d}",
                    category="M1",
                    severity="medium",
                    title=f"Dangerous Permission: {perm.split('.')[-1]}",
                    description=f"Application requests dangerous permission: {perm}",
                    file_path="AndroidManifest.xml",
                    evidence=perm,
                    recommendation="Ensure this permission is necessary and properly justified."
                ))
        
        return findings
    
    async def _parse_binary_manifest(self, apk_path: Path, metadata: AppMetadata) -> dict:
        """
        Parse binary AndroidManifest.xml without external tools.
        Uses basic string scanning since full binary XML parsing requires androguard.
        """
        result = {}
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # Try to extract strings from classes.dex for package info
                if 'classes.dex' in zf.namelist():
                    dex_data = zf.read('classes.dex')
                    # Simple string extraction from DEX
                    # Look for package name patterns
                    dex_str = dex_data.decode('latin-1', errors='ignore')
                    
                    # Find package name (usually follows pattern Lcom/example/app;)
                    pkg_matches = re.findall(r'L([a-z][a-z0-9_]*(?:/[a-z][a-z0-9_]*)+);', dex_str)
                    if pkg_matches:
                        # Get most common package prefix
                        pkg_counts = {}
                        for m in pkg_matches:
                            parts = m.split('/')
                            if len(parts) >= 2:
                                pkg = '.'.join(parts[:3]) if len(parts) >= 3 else '.'.join(parts[:2])
                                pkg_counts[pkg] = pkg_counts.get(pkg, 0) + 1
                        
                        if pkg_counts:
                            best_pkg = max(pkg_counts, key=pkg_counts.get)
                            metadata.package_name = best_pkg
                            logger.info(f"Inferred package name: {best_pkg}")
                
                # Try to find version info from resources.arsc
                if 'resources.arsc' in zf.namelist():
                    res_data = zf.read('resources.arsc')
                    res_str = res_data.decode('latin-1', errors='ignore')
                    
                    # Look for version patterns
                    version_match = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', res_str)
                    if version_match:
                        metadata.version_name = version_match.group(1)
                
                # Check AndroidManifest.xml for permissions (binary but strings are readable)
                if 'AndroidManifest.xml' in zf.namelist():
                    manifest_data = zf.read('AndroidManifest.xml')
                    manifest_str = manifest_data.decode('latin-1', errors='ignore')
                    
                    # Find permissions
                    perm_matches = re.findall(r'(android\.permission\.[A-Z_]+)', manifest_str)
                    for perm in set(perm_matches):
                        if perm not in metadata.permissions:
                            metadata.permissions.append(perm)
                    
                    # Check for debuggable
                    if b'debuggable' in manifest_data:
                        # This is a rough check - binary encoding varies
                        result['debuggable'] = True
                    
                    # Check for backup allowed  
                    if b'allowBackup' in manifest_data:
                        result['allowBackup'] = True
                        metadata.allows_backup = True
                        
            logger.info(f"Binary manifest parse: pkg={metadata.package_name}, perms={len(metadata.permissions)}")
            
        except Exception as e:
            logger.warning(f"Error in binary manifest parsing: {e}")
        
        return result

    async def _parse_info_plist(self, app_dir: Path, metadata: AppMetadata) -> List[StaticAnalysisResult]:
        """Parse iOS Info.plist"""
        findings = []
        plist_path = app_dir / "Info.plist"
        
        if not plist_path.exists():
            return findings
        
        try:
            import plistlib
            with open(plist_path, 'rb') as f:
                plist = plistlib.load(f)
            
            metadata.package_name = plist.get('CFBundleIdentifier', '')
            metadata.version_name = plist.get('CFBundleShortVersionString', '')
            metadata.version_code = plist.get('CFBundleVersion', '')
            
            # Check URL schemes
            url_types = plist.get('CFBundleURLTypes', [])
            for url_type in url_types:
                schemes = url_type.get('CFBundleURLSchemes', [])
                metadata.url_schemes.extend(schemes)
            
            # Check ATS configuration
            ats = plist.get('NSAppTransportSecurity', {})
            if ats.get('NSAllowsArbitraryLoads', False):
                metadata.uses_cleartext = True
                findings.append(StaticAnalysisResult(
                    id="M3-ATS-001",
                    category="M3",
                    severity="high",
                    title="App Transport Security Disabled",
                    description="NSAllowsArbitraryLoads is set to YES, allowing insecure HTTP connections.",
                    file_path="Info.plist",
                    evidence="NSAllowsArbitraryLoads = YES",
                    recommendation="Enable ATS and use HTTPS for all connections."
                ))
            
        except Exception as e:
            logger.error(f"Error parsing Info.plist: {e}")
        
        return findings
    
    async def _scan_for_secrets(self, directory: Path, platform: str) -> List[StaticAnalysisResult]:
        """Scan files for hardcoded secrets"""
        findings = []
        
        # File extensions to scan
        scan_extensions = {'.java', '.kt', '.swift', '.m', '.h', '.xml', '.json', '.plist', '.js', '.ts'}
        
        for root, dirs, files in os.walk(directory):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {'__MACOSX', '.git', 'node_modules'}]
            
            for file in files:
                file_path = Path(root) / file
                
                # Check file extension
                if file_path.suffix.lower() not in scan_extensions:
                    continue
                
                try:
                    content = file_path.read_text(errors='ignore')
                    
                    for pattern, secret_type in self.SECRET_PATTERNS:
                        for match in re.finditer(pattern, content):
                            # Get line number
                            line_num = content[:match.start()].count('\n') + 1
                            
                            findings.append(StaticAnalysisResult(
                                id=f"M9-SECRET-{len(findings)+1:03d}",
                                category="M9",
                                severity="critical" if "private" in secret_type.lower() else "high",
                                title=f"Hardcoded {secret_type} Detected",
                                description=f"Found hardcoded {secret_type.lower()} in source code.",
                                file_path=str(file_path.relative_to(directory)),
                                line_number=line_num,
                                code_snippet=match.group(0)[:100] + "...",
                                evidence=f"Pattern matched: {secret_type}",
                                recommendation=f"Remove hardcoded {secret_type.lower()} and use secure storage."
                            ))
                            
                except Exception as e:
                    logger.debug(f"Error scanning file {file_path}: {e}")
        
        return findings
    
    async def _scan_for_api_endpoints(self, directory: Path) -> List[StaticAnalysisResult]:
        """Scan for API endpoints in code"""
        findings = []
        endpoints = set()
        
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in {'__MACOSX', '.git', 'node_modules'}]
            
            for file in files:
                file_path = Path(root) / file
                
                try:
                    content = file_path.read_text(errors='ignore')
                    
                    for pattern in self.API_PATTERNS:
                        for match in re.finditer(pattern, content):
                            endpoint = match.group(0)
                            if endpoint not in endpoints:
                                endpoints.add(endpoint)
                                findings.append(StaticAnalysisResult(
                                    id=f"INFO-API-{len(findings)+1:03d}",
                                    category="info",
                                    severity="info",
                                    title="API Endpoint Discovered",
                                    description=f"Found API endpoint in source code.",
                                    file_path=str(file_path.relative_to(directory)),
                                    evidence=endpoint,
                                    recommendation="Test this endpoint for security vulnerabilities."
                                ))
                                
                except Exception:
                    pass
        
        return findings
    
    async def _analyze_network_security_config(self, extract_dir: Path, metadata: AppMetadata) -> List[StaticAnalysisResult]:
        """Analyze Android network security configuration"""
        findings = []
        
        nsc_path = extract_dir / "res" / "xml" / "network_security_config.xml"
        
        if nsc_path.exists():
            try:
                tree = ET.parse(nsc_path)
                root = tree.getroot()
                
                # Check for cleartext traffic
                base_config = root.find('.//base-config')
                if base_config is not None:
                    if base_config.get('cleartextTrafficPermitted', 'false').lower() == 'true':
                        metadata.uses_cleartext = True
                        findings.append(StaticAnalysisResult(
                            id="M3-NSC-001",
                            category="M3",
                            severity="high",
                            title="Cleartext Traffic Allowed",
                            description="Network security config allows cleartext (HTTP) traffic.",
                            file_path="res/xml/network_security_config.xml",
                            evidence="cleartextTrafficPermitted=true",
                            recommendation="Disable cleartext traffic and use HTTPS only."
                        ))
                
                # Check for trust anchors
                trust_anchors = root.findall('.//trust-anchors/certificates')
                for anchor in trust_anchors:
                    if anchor.get('src') == 'user':
                        findings.append(StaticAnalysisResult(
                            id="M3-NSC-002",
                            category="M3",
                            severity="medium",
                            title="User Certificates Trusted",
                            description="App trusts user-installed certificates, making it vulnerable to MITM.",
                            file_path="res/xml/network_security_config.xml",
                            evidence="src=user in trust-anchors",
                            recommendation="Remove user certificate trust in production."
                        ))
                        
            except Exception as e:
                logger.error(f"Error parsing network security config: {e}")
        
        return findings
    
    def _check_android_security_config(self, metadata: AppMetadata) -> List[StaticAnalysisResult]:
        """Check Android security configuration issues"""
        findings = []
        
        if metadata.allows_backup:
            findings.append(StaticAnalysisResult(
                id="M2-BACKUP-001",
                category="M2",
                severity="medium",
                title="Backup Allowed",
                description="Application allows backup, which may expose sensitive data.",
                file_path="AndroidManifest.xml",
                evidence="android:allowBackup=true",
                recommendation="Set android:allowBackup to false or implement BackupAgent."
            ))
        
        if int(metadata.target_sdk or "0") < 28:
            findings.append(StaticAnalysisResult(
                id="M1-SDK-001",
                category="M1",
                severity="medium",
                title="Outdated Target SDK",
                description=f"Target SDK {metadata.target_sdk} is outdated and may lack security features.",
                file_path="AndroidManifest.xml",
                evidence=f"targetSdkVersion={metadata.target_sdk}",
                recommendation="Update targetSdkVersion to 33 or higher."
            ))
        
        return findings
    
    def _check_ios_ats(self, metadata: AppMetadata) -> List[StaticAnalysisResult]:
        """Check iOS ATS configuration"""
        findings = []
        
        if metadata.uses_cleartext:
            findings.append(StaticAnalysisResult(
                id="M3-ATS-002",
                category="M3",
                severity="high",
                title="Insecure Transport Allowed",
                description="App allows insecure HTTP connections.",
                file_path="Info.plist",
                evidence="NSAllowsArbitraryLoads or NSExceptionAllowsInsecureHTTPLoads",
                recommendation="Use HTTPS for all network connections."
            ))
        
        return findings
    
    async def _analyze_decompiled_code(self, apk_path: Path) -> List[StaticAnalysisResult]:
        """Analyze decompiled Java/Kotlin code"""
        findings = []
        
        # This would use jadx to decompile and analyze
        # For now, return empty - full implementation would include:
        # - Crypto misuse detection
        # - Insecure random number generation
        # - SQL injection vulnerabilities
        # - WebView vulnerabilities
        
        return findings
