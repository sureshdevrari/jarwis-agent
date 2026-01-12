"""
Jarwis AGI - Mobile App Unpacker & Secrets Extractor
Decompiles APK/IPA files to find hardcoded secrets, API keys, and sensitive data

Features:
- APK/IPA extraction and decompilation
- Hardcoded secrets detection (API keys, passwords, tokens)
- Certificate and keystore analysis
- Firebase/Cloud config extraction
- Sensitive file detection
"""

import os
import re
import json
import shutil
import zipfile
import tempfile
import subprocess
import logging
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class SecretFinding:
    """Represents a found secret or sensitive data"""
    id: str
    category: str  # api_key, password, token, firebase, aws, etc.
    severity: str  # critical, high, medium, low
    title: str
    description: str
    file_path: str
    line_number: int = 0
    secret_type: str = ""
    secret_value: str = ""  # Partially masked
    full_match: str = ""
    confidence: str = "high"  # high, medium, low
    owasp_category: str = "M9"  # Reverse Engineering


@dataclass
class UnpackResult:
    """Result of unpacking and analyzing an app"""
    app_name: str
    package_name: str
    version: str
    platform: str  # android, ios
    extraction_path: str
    
    # Extracted components
    manifest_info: Dict = field(default_factory=dict)
    certificates: List[Dict] = field(default_factory=list)
    native_libs: List[str] = field(default_factory=list)
    
    # Security findings
    secrets: List[SecretFinding] = field(default_factory=list)
    sensitive_files: List[Dict] = field(default_factory=list)
    config_files: List[Dict] = field(default_factory=list)
    
    # Statistics
    total_files: int = 0
    analyzed_files: int = 0
    extraction_time: float = 0


class AppUnpacker:
    """
    Unpacks and analyzes mobile applications for secrets and sensitive data
    """
    
    # Regex patterns for finding secrets
    SECRET_PATTERNS = {
        'aws_access_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'severity': 'critical',
            'title': 'AWS Access Key ID',
            'description': 'Hardcoded AWS access key found. This could allow unauthorized access to AWS resources.'
        },
        'aws_secret_key': {
            'pattern': r'(?i)(aws_secret_access_key|aws_secret_key)[\'"\s:=]+([A-Za-z0-9+/]{40})',
            'severity': 'critical',
            'title': 'AWS Secret Access Key',
            'description': 'AWS secret key found in code. This is a critical security vulnerability.'
        },
        'google_api_key': {
            'pattern': r'AIza[0-9A-Za-z\-_]{35}',
            'severity': 'high',
            'title': 'Google API Key',
            'description': 'Google API key exposed. May allow unauthorized API usage and incur charges.'
        },
        'google_oauth': {
            'pattern': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'severity': 'medium',
            'title': 'Google OAuth Client ID',
            'description': 'Google OAuth client ID found. Review if this should be public.'
        },
        'firebase_url': {
            'pattern': r'https://[a-z0-9-]+\.firebaseio\.com',
            'severity': 'high',
            'title': 'Firebase Database URL',
            'description': 'Firebase database URL found. Check if database rules are properly configured.'
        },
        'firebase_api_key': {
            'pattern': r'(?i)(firebase[_-]?api[_-]?key)[\'"\s:=]+([A-Za-z0-9_-]{39})',
            'severity': 'high',
            'title': 'Firebase API Key',
            'description': 'Firebase API key found in code.'
        },
        'stripe_key': {
            'pattern': r'(sk_live_[0-9a-zA-Z]{24}|pk_live_[0-9a-zA-Z]{24})',
            'severity': 'critical',
            'title': 'Stripe API Key',
            'description': 'Stripe payment key found. This could allow unauthorized payment operations.'
        },
        'stripe_test_key': {
            'pattern': r'(sk_test_[0-9a-zA-Z]{24}|pk_test_[0-9a-zA-Z]{24})',
            'severity': 'medium',
            'title': 'Stripe Test Key',
            'description': 'Stripe test key found. While not production, indicates key management issues.'
        },
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'severity': 'high',
            'title': 'JWT Token',
            'description': 'JWT token hardcoded. Tokens should not be embedded in code.'
        },
        'private_key': {
            'pattern': r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            'severity': 'critical',
            'title': 'Private Key',
            'description': 'Private cryptographic key found. This is a severe security issue.'
        },
        'github_token': {
            'pattern': r'ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}',
            'severity': 'critical',
            'title': 'GitHub Token',
            'description': 'GitHub personal access token found. Could allow repository access.'
        },
        'slack_token': {
            'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
            'severity': 'high',
            'title': 'Slack Token',
            'description': 'Slack API token found. Could allow access to Slack workspace.'
        },
        'twilio_key': {
            'pattern': r'SK[0-9a-fA-F]{32}',
            'severity': 'high',
            'title': 'Twilio API Key',
            'description': 'Twilio API key found. Could allow SMS/call operations.'
        },
        'sendgrid_key': {
            'pattern': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
            'severity': 'high',
            'title': 'SendGrid API Key',
            'description': 'SendGrid API key found. Could allow email sending operations.'
        },
        'mailchimp_key': {
            'pattern': r'[0-9a-f]{32}-us[0-9]{1,2}',
            'severity': 'medium',
            'title': 'Mailchimp API Key',
            'description': 'Mailchimp API key found in code.'
        },
        'password_in_code': {
            'pattern': r'(?i)(password|passwd|pwd|secret|api_?key|auth_?token)[\'"\s:=]+[\'"]([^\'"]{8,})[\'"]',
            'severity': 'high',
            'title': 'Hardcoded Password/Secret',
            'description': 'Possible hardcoded password or secret found in code.'
        },
        'basic_auth': {
            'pattern': r'(?i)basic\s+[a-zA-Z0-9+/=]{20,}',
            'severity': 'high',
            'title': 'Basic Auth Credentials',
            'description': 'Base64 encoded Basic Authentication credentials found.'
        },
        'bearer_token': {
            'pattern': r'(?i)bearer\s+[a-zA-Z0-9_\-\.=]{20,}',
            'severity': 'high',
            'title': 'Bearer Token',
            'description': 'Bearer authentication token found hardcoded.'
        },
        'mongodb_uri': {
            'pattern': r'mongodb(\+srv)?://[^\s<>\"\']+',
            'severity': 'critical',
            'title': 'MongoDB Connection String',
            'description': 'MongoDB connection string found. May contain credentials.'
        },
        'mysql_connection': {
            'pattern': r'(?i)mysql://[^\s<>\"\']+',
            'severity': 'critical',
            'title': 'MySQL Connection String',
            'description': 'MySQL connection string found. May contain credentials.'
        },
        'postgres_connection': {
            'pattern': r'(?i)postgres(ql)?://[^\s<>\"\']+',
            'severity': 'critical',
            'title': 'PostgreSQL Connection String',
            'description': 'PostgreSQL connection string found. May contain credentials.'
        },
        'ip_address': {
            'pattern': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'severity': 'low',
            'title': 'IP Address',
            'description': 'Hardcoded IP address found. May indicate infrastructure details.',
            'filter': lambda ip: not ip.startswith(('10.', '192.168.', '127.', '0.'))
        },
        'azure_storage': {
            'pattern': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
            'severity': 'critical',
            'title': 'Azure Storage Connection String',
            'description': 'Azure Storage connection string with key found.'
        },
        'razorpay_key': {
            'pattern': r'rzp_(live|test)_[0-9a-zA-Z]{14}',
            'severity': 'high',
            'title': 'Razorpay API Key',
            'description': 'Razorpay payment gateway key found.'
        },
        'paytm_key': {
            'pattern': r'(?i)(paytm[_-]?merchant[_-]?key|paytm[_-]?secret)[\'"\s:=]+([A-Za-z0-9_-]{16,})',
            'severity': 'high',
            'title': 'Paytm Merchant Key',
            'description': 'Paytm payment gateway key found.'
        }
    }
    
    # Sensitive file patterns
    SENSITIVE_FILES = [
        ('*.pem', 'PEM Certificate/Key'),
        ('*.key', 'Private Key File'),
        ('*.p12', 'PKCS#12 Certificate'),
        ('*.pfx', 'PKCS#12 Certificate'),
        ('*.keystore', 'Java Keystore'),
        ('*.jks', 'Java Keystore'),
        ('*.bks', 'Bouncy Castle Keystore'),
        ('google-services.json', 'Firebase Configuration'),
        ('GoogleService-Info.plist', 'Firebase iOS Configuration'),
        ('*.sqlite', 'SQLite Database'),
        ('*.db', 'Database File'),
        ('*.realm', 'Realm Database'),
        ('secrets.xml', 'Secrets File'),
        ('credentials.xml', 'Credentials File'),
        ('config.xml', 'Configuration File'),
        ('aws-exports.js', 'AWS Amplify Config'),
        ('amplifyconfiguration.json', 'AWS Amplify Config'),
    ]
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.temp_dir = None
        self._tools_checked = False
        self._apktool_available = False
        self._jadx_available = False
    
    def _check_tools(self):
        """Check for available decompilation tools"""
        if self._tools_checked:
            return
        
        # Check for apktool
        try:
            result = subprocess.run(['apktool', '--version'], capture_output=True, text=True)
            self._apktool_available = result.returncode == 0
            logger.info(f"apktool available: {self._apktool_available}")
        except FileNotFoundError:
            self._apktool_available = False
            logger.warning("apktool not found - basic extraction only")
        
        # Check for jadx
        try:
            result = subprocess.run(['jadx', '--version'], capture_output=True, text=True)
            self._jadx_available = result.returncode == 0
            logger.info(f"jadx available: {self._jadx_available}")
        except FileNotFoundError:
            self._jadx_available = False
            logger.warning("jadx not found - no Java decompilation")
        
        self._tools_checked = True
    
    def _mask_secret(self, secret: str, visible_chars: int = 4) -> str:
        """Mask a secret value, showing only first and last few characters"""
        if len(secret) <= visible_chars * 2:
            return '*' * len(secret)
        return secret[:visible_chars] + '*' * (len(secret) - visible_chars * 2) + secret[-visible_chars:]
    
    def _generate_finding_id(self, file_path: str, secret_type: str, line: int) -> str:
        """Generate unique ID for a finding"""
        hash_input = f"{file_path}:{secret_type}:{line}"
        return f"SEC-{hashlib.md5(hash_input.encode()).hexdigest()[:8].upper()}"
    
    async def unpack(self, file_path: str, output_dir: str = None) -> UnpackResult:
        """
        Unpack and analyze a mobile application
        
        Args:
            file_path: Path to APK or IPA file
            output_dir: Directory to extract files to (optional)
            
        Returns:
            UnpackResult with all findings
        """
        import time
        start_time = time.time()
        
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Determine platform
        platform = "android" if file_path.suffix.lower() == ".apk" else "ios"
        
        # Create extraction directory
        if output_dir:
            extract_path = Path(output_dir)
        else:
            self.temp_dir = tempfile.mkdtemp(prefix="jarwis_unpack_")
            extract_path = Path(self.temp_dir)
        
        extract_path.mkdir(parents=True, exist_ok=True)
        
        result = UnpackResult(
            app_name=file_path.stem,
            package_name="",
            version="",
            platform=platform,
            extraction_path=str(extract_path)
        )
        
        logger.info(f"Unpacking {platform} app: {file_path.name}")
        
        try:
            if platform == "android":
                await self._unpack_apk(file_path, extract_path, result)
            else:
                await self._unpack_ipa(file_path, extract_path, result)
            
            # Scan for secrets
            await self._scan_for_secrets(extract_path, result)
            
            # Find sensitive files
            await self._find_sensitive_files(extract_path, result)
            
            result.extraction_time = time.time() - start_time
            logger.info(f"Unpacking complete: {result.total_files} files, {len(result.secrets)} secrets found")
            
        except Exception as e:
            logger.error(f"Unpacking failed: {e}")
            raise
        
        return result
    
    async def _unpack_apk(self, apk_path: Path, extract_path: Path, result: UnpackResult):
        """Unpack Android APK file"""
        self._check_tools()
        
        # Basic ZIP extraction first
        logger.info("Extracting APK contents...")
        with zipfile.ZipFile(apk_path, 'r') as zf:
            zf.extractall(extract_path)
            result.total_files = len(zf.namelist())
        
        # Parse AndroidManifest.xml if apktool is available
        if self._apktool_available:
            logger.info("Running apktool for manifest decoding...")
            apktool_output = extract_path / "apktool_output"
            try:
                subprocess.run(
                    ['apktool', 'd', '-f', '-o', str(apktool_output), str(apk_path)],
                    capture_output=True,
                    timeout=120
                )
                
                # Parse decoded manifest
                manifest_file = apktool_output / "AndroidManifest.xml"
                if manifest_file.exists():
                    result.manifest_info = self._parse_android_manifest(manifest_file)
                    result.package_name = result.manifest_info.get('package', '')
                    result.version = result.manifest_info.get('version_name', '')
                    
            except subprocess.TimeoutExpired:
                logger.warning("apktool timed out")
            except Exception as e:
                logger.warning(f"apktool failed: {e}")
        
        # Use jadx for Java decompilation if available
        if self._jadx_available:
            logger.info("Running jadx for Java decompilation...")
            jadx_output = extract_path / "jadx_output"
            try:
                subprocess.run(
                    ['jadx', '-d', str(jadx_output), str(apk_path)],
                    capture_output=True,
                    timeout=300
                )
            except subprocess.TimeoutExpired:
                logger.warning("jadx timed out")
            except Exception as e:
                logger.warning(f"jadx failed: {e}")
        
        # Find native libraries
        lib_path = extract_path / "lib"
        if lib_path.exists():
            for so_file in lib_path.rglob("*.so"):
                result.native_libs.append(str(so_file.relative_to(extract_path)))
        
        # Extract certificates
        meta_inf = extract_path / "META-INF"
        if meta_inf.exists():
            for cert_file in meta_inf.glob("*.RSA"):
                result.certificates.append({
                    'file': cert_file.name,
                    'type': 'RSA'
                })
            for cert_file in meta_inf.glob("*.DSA"):
                result.certificates.append({
                    'file': cert_file.name,
                    'type': 'DSA'
                })
    
    async def _unpack_ipa(self, ipa_path: Path, extract_path: Path, result: UnpackResult):
        """Unpack iOS IPA file"""
        logger.info("Extracting IPA contents...")
        
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            zf.extractall(extract_path)
            result.total_files = len(zf.namelist())
        
        # Find the .app bundle
        payload_path = extract_path / "Payload"
        if payload_path.exists():
            for app_bundle in payload_path.glob("*.app"):
                # Parse Info.plist
                info_plist = app_bundle / "Info.plist"
                if info_plist.exists():
                    result.manifest_info = self._parse_ios_plist(info_plist)
                    result.package_name = result.manifest_info.get('CFBundleIdentifier', '')
                    result.version = result.manifest_info.get('CFBundleShortVersionString', '')
                    result.app_name = result.manifest_info.get('CFBundleDisplayName', result.app_name)
                
                # Find embedded provisioning profile
                embedded_provision = app_bundle / "embedded.mobileprovision"
                if embedded_provision.exists():
                    result.certificates.append({
                        'file': 'embedded.mobileprovision',
                        'type': 'Provisioning Profile'
                    })
    
    def _parse_android_manifest(self, manifest_path: Path) -> dict:
        """Parse decoded AndroidManifest.xml"""
        import xml.etree.ElementTree as ET
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract namespace
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            
            manifest_info = {
                'package': root.get('package', ''),
                'version_code': root.get('{http://schemas.android.com/apk/res/android}versionCode', ''),
                'version_name': root.get('{http://schemas.android.com/apk/res/android}versionName', ''),
                'permissions': [],
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': [],
                'exported_components': [],
                'debuggable': False,
                'allowBackup': True,
                'usesCleartextTraffic': True
            }
            
            # Get application attributes
            app_elem = root.find('application')
            if app_elem is not None:
                manifest_info['debuggable'] = app_elem.get(
                    '{http://schemas.android.com/apk/res/android}debuggable', 'false') == 'true'
                manifest_info['allowBackup'] = app_elem.get(
                    '{http://schemas.android.com/apk/res/android}allowBackup', 'true') == 'true'
                manifest_info['usesCleartextTraffic'] = app_elem.get(
                    '{http://schemas.android.com/apk/res/android}usesCleartextTraffic', 'true') == 'true'
            
            # Get permissions
            for perm in root.findall('uses-permission'):
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
                if perm_name:
                    manifest_info['permissions'].append(perm_name)
            
            # Get components
            if app_elem is not None:
                for activity in app_elem.findall('activity'):
                    name = activity.get('{http://schemas.android.com/apk/res/android}name', '')
                    exported = activity.get('{http://schemas.android.com/apk/res/android}exported', '')
                    manifest_info['activities'].append(name)
                    if exported == 'true' or activity.find('intent-filter') is not None:
                        manifest_info['exported_components'].append(('activity', name))
                
                for service in app_elem.findall('service'):
                    name = service.get('{http://schemas.android.com/apk/res/android}name', '')
                    exported = service.get('{http://schemas.android.com/apk/res/android}exported', '')
                    manifest_info['services'].append(name)
                    if exported == 'true' or service.find('intent-filter') is not None:
                        manifest_info['exported_components'].append(('service', name))
                
                for receiver in app_elem.findall('receiver'):
                    name = receiver.get('{http://schemas.android.com/apk/res/android}name', '')
                    exported = receiver.get('{http://schemas.android.com/apk/res/android}exported', '')
                    manifest_info['receivers'].append(name)
                    if exported == 'true' or receiver.find('intent-filter') is not None:
                        manifest_info['exported_components'].append(('receiver', name))
                
                for provider in app_elem.findall('provider'):
                    name = provider.get('{http://schemas.android.com/apk/res/android}name', '')
                    exported = provider.get('{http://schemas.android.com/apk/res/android}exported', '')
                    manifest_info['providers'].append(name)
                    if exported == 'true':
                        manifest_info['exported_components'].append(('provider', name))
            
            return manifest_info
            
        except Exception as e:
            logger.error(f"Failed to parse manifest: {e}")
            return {}
    
    def _parse_ios_plist(self, plist_path: Path) -> dict:
        """Parse iOS Info.plist file"""
        import plistlib
        
        try:
            with open(plist_path, 'rb') as f:
                plist_data = plistlib.load(f)
            return dict(plist_data)
        except Exception as e:
            logger.warning(f"Failed to parse plist: {e}")
            return {}
    
    async def _scan_for_secrets(self, extract_path: Path, result: UnpackResult):
        """Scan extracted files for secrets"""
        logger.info("Scanning for hardcoded secrets...")
        
        # Extensions to scan
        scan_extensions = {
            '.java', '.kt', '.xml', '.json', '.yaml', '.yml', '.properties',
            '.gradle', '.plist', '.strings', '.swift', '.m', '.h', '.js',
            '.ts', '.html', '.txt', '.cfg', '.conf', '.ini', '.smali'
        }
        
        for file_path in extract_path.rglob('*'):
            if not file_path.is_file():
                continue
            
            # Skip binary files
            if file_path.suffix.lower() not in scan_extensions:
                # Check if it might be text
                if file_path.suffix.lower() in {'.so', '.dex', '.oat', '.png', '.jpg', '.gif', '.mp3', '.mp4'}:
                    continue
            
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                result.analyzed_files += 1
                
                # Search for each secret pattern
                for secret_type, pattern_info in self.SECRET_PATTERNS.items():
                    pattern = pattern_info['pattern']
                    matches = list(re.finditer(pattern, content))
                    
                    for match in matches:
                        # Apply filter if present
                        if 'filter' in pattern_info:
                            if not pattern_info['filter'](match.group()):
                                continue
                        
                        # Find line number
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Get the secret value (might be in a capture group)
                        secret_value = match.group()
                        if match.groups():
                            # Use last non-empty group as the secret
                            for g in reversed(match.groups()):
                                if g:
                                    secret_value = g
                                    break
                        
                        finding = SecretFinding(
                            id=self._generate_finding_id(str(file_path), secret_type, line_num),
                            category=secret_type,
                            severity=pattern_info['severity'],
                            title=pattern_info['title'],
                            description=pattern_info['description'],
                            file_path=str(file_path.relative_to(extract_path)),
                            line_number=line_num,
                            secret_type=secret_type,
                            secret_value=self._mask_secret(secret_value),
                            full_match=match.group()[:100] + ('...' if len(match.group()) > 100 else ''),
                            owasp_category="M9"
                        )
                        result.secrets.append(finding)
                        
            except Exception as e:
                logger.debug(f"Could not read file {file_path}: {e}")
    
    async def _find_sensitive_files(self, extract_path: Path, result: UnpackResult):
        """Find sensitive files in extracted contents"""
        logger.info("Scanning for sensitive files...")
        
        for pattern, description in self.SENSITIVE_FILES:
            for file_path in extract_path.rglob(pattern):
                file_info = {
                    'path': str(file_path.relative_to(extract_path)),
                    'name': file_path.name,
                    'description': description,
                    'size': file_path.stat().st_size
                }
                
                # Extract config file contents for analysis
                if file_path.suffix.lower() in {'.json', '.xml', '.plist'}:
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        file_info['preview'] = content[:500] + ('...' if len(content) > 500 else '')
                        result.config_files.append(file_info)
                    except:
                        pass
                else:
                    result.sensitive_files.append(file_info)
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            self.temp_dir = None


# Singleton for quick access
_unpacker = None

def get_unpacker(config: dict = None) -> AppUnpacker:
    """Get or create unpacker instance"""
    global _unpacker
    if _unpacker is None:
        _unpacker = AppUnpacker(config)
    return _unpacker
