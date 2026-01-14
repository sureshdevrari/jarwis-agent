"""
Jarwis AGI - SSL Pinning Detection Module
Detects if an app implements SSL/TLS certificate pinning BEFORE attempting bypass

This module probes the app's network behavior to determine:
1. Whether the app uses SSL pinning
2. What libraries implement the pinning
3. Whether Frida bypass is necessary

This follows the OWASP MASVS best practice:
"First detect if SSL pinning is implemented, then decide on bypass strategy"
"""

import os
import re
import json
import asyncio
import logging
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from enum import Enum
from zipfile import ZipFile

logger = logging.getLogger(__name__)


class PinningType(Enum):
    """Type of SSL pinning detected"""
    NONE = "none"
    CERTIFICATE_PINNING = "certificate_pinning"
    PUBLIC_KEY_PINNING = "public_key_pinning"
    NETWORK_SECURITY_CONFIG = "network_security_config"
    CUSTOM_TRUSTMANAGER = "custom_trustmanager"
    OKHTTP_PINNER = "okhttp_pinner"
    TRUSTKIT = "trustkit"
    FLUTTER_PINNING = "flutter_pinning"
    REACT_NATIVE_PINNING = "react_native_pinning"
    IOS_ATS = "ios_ats"
    IOS_CUSTOM = "ios_custom"
    UNKNOWN = "unknown"


class DetectionMethod(Enum):
    """How pinning was detected"""
    STATIC_ANALYSIS = "static_analysis"
    RUNTIME_PROBE = "runtime_probe"
    TRAFFIC_ANALYSIS = "traffic_analysis"
    MANIFEST_CHECK = "manifest_check"


@dataclass
class PinningEvidence:
    """Evidence of SSL pinning implementation"""
    pinning_type: PinningType
    detection_method: DetectionMethod
    library: str
    evidence: str
    confidence: float  # 0.0 to 1.0
    file_path: str = ""
    code_snippet: str = ""


@dataclass
class SSLPinningDetectionResult:
    """Result of SSL pinning detection"""
    has_pinning: bool
    pinning_types: List[PinningType] = field(default_factory=list)
    evidence: List[PinningEvidence] = field(default_factory=list)
    bypass_required: bool = False
    bypass_recommendation: str = ""
    detection_methods_used: List[DetectionMethod] = field(default_factory=list)
    detection_time_ms: int = 0
    confidence_score: float = 0.0
    pinned_domains: List[str] = field(default_factory=list)


class SSLPinningDetector:
    """
    Detects SSL pinning in mobile apps before running Frida bypass.
    
    Detection approaches:
    1. Static Analysis: Analyze APK/IPA for pinning code patterns
    2. Runtime Probe: Test app's behavior with proxy
    3. Manifest/Config Check: Check Network Security Config (Android) or ATS (iOS)
    """
    
    # Android pinning patterns
    ANDROID_PINNING_PATTERNS = {
        'okhttp_pinner': [
            r'CertificatePinner\.Builder',
            r'\.add\s*\(\s*"[^"]+"\s*,\s*"sha256/',
            r'certificatePinner\s*\(',
        ],
        'trustkit': [
            r'com\.datatheorem\.android\.trustkit',
            r'TrustKit\.initializeWithNetworkSecurityConfiguration',
            r'trustkit_config\.xml',
        ],
        'custom_trustmanager': [
            r'implements\s+X509TrustManager',
            r'checkServerTrusted\s*\([^)]+\)\s*\{',
            r'X509TrustManager.*getAcceptedIssuers',
        ],
        'network_security_config': [
            r'<pin-set[^>]*>',
            r'<pin\s+digest="SHA-256"',
            r'networkSecurityConfig',
        ],
        'flutter': [
            r'SecurityContext\.defaultContext',
            r'badCertificateCallback',
            r'HttpClient\(\)\.findProxy',
        ],
        'react_native': [
            r'react-native-ssl-pinning',
            r'RNSSLPinning',
            r'SSLPinningVerifyPeerCertificates',
        ],
    }
    
    # iOS pinning patterns
    IOS_PINNING_PATTERNS = {
        'alamofire': [
            r'ServerTrustPolicy',
            r'PinnedCertificatesTrustEvaluator',
            r'PublicKeysTrustEvaluator',
        ],
        'afnetworking': [
            r'AFSecurityPolicy',
            r'AFSSLPinningModeCertificate',
            r'AFSSLPinningModePublicKey',
        ],
        'trustkit': [
            r'TSKPinningValidator',
            r'TrustKitConfig',
            r'kTSKEnforcePinning',
        ],
        'custom': [
            r'didReceiveChallenge.*URLAuthenticationChallenge',
            r'evaluateServerTrust',
            r'SecTrustEvaluate',
        ],
        'ats': [
            r'NSAppTransportSecurity',
            r'NSAllowsArbitraryLoads.*false',
            r'NSPinnedDomains',
        ],
    }
    
    # Common pinned domain patterns
    DOMAIN_PIN_PATTERNS = [
        r'"([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}"\s*,\s*"sha256/',
        r'add\s*\(\s*"([^"]+)"',
        r'pinnedDomains.*"([^"]+)"',
    ]

    def __init__(
        self,
        platform: str = "android",
        timeout_seconds: int = 30,
        proxy_port: int = 8080
    ):
        self.platform = platform.lower()
        self.timeout = timeout_seconds
        self.proxy_port = proxy_port
        self._log_callback = None
        self._extracted_path: Optional[Path] = None
    
    def set_log_callback(self, callback):
        """Set callback for logging"""
        self._log_callback = callback
    
    def _log(self, level: str, message: str):
        """Log message via callback or standard logger"""
        if self._log_callback:
            self._log_callback(level, message)
        else:
            getattr(logger, level, logger.info)(message)
    
    async def detect(
        self,
        app_path: str,
        package_name: Optional[str] = None,
        device_id: Optional[str] = None
    ) -> SSLPinningDetectionResult:
        """
        Detect SSL pinning in the app.
        
        Args:
            app_path: Path to APK or IPA file
            package_name: Package name (for runtime probe)
            device_id: Device ID (for runtime probe)
        
        Returns:
            SSLPinningDetectionResult with detection findings
        """
        start_time = datetime.now()
        result = SSLPinningDetectionResult(has_pinning=False)
        
        try:
            # 1. Static analysis of the app binary
            static_evidence = await self._static_analysis(app_path)
            result.evidence.extend(static_evidence)
            result.detection_methods_used.append(DetectionMethod.STATIC_ANALYSIS)
            
            # 2. Check manifest/config for pinning declarations
            config_evidence = await self._check_config(app_path)
            result.evidence.extend(config_evidence)
            result.detection_methods_used.append(DetectionMethod.MANIFEST_CHECK)
            
            # 3. Runtime probe (if device available)
            if device_id and package_name:
                runtime_evidence = await self._runtime_probe(
                    package_name, device_id
                )
                result.evidence.extend(runtime_evidence)
                result.detection_methods_used.append(DetectionMethod.RUNTIME_PROBE)
            
            # Aggregate results
            if result.evidence:
                result.has_pinning = True
                result.pinning_types = list(set(
                    e.pinning_type for e in result.evidence
                ))
                result.confidence_score = max(
                    e.confidence for e in result.evidence
                )
                result.pinned_domains = self._extract_pinned_domains(result.evidence)
                result.bypass_required = True
                result.bypass_recommendation = self._generate_bypass_recommendation(
                    result.pinning_types
                )
            else:
                result.has_pinning = False
                result.bypass_required = False
                result.confidence_score = 0.8  # 80% confident no pinning
                result.bypass_recommendation = (
                    "No SSL pinning detected. MITM proxy should work without Frida bypass."
                )
            
        except Exception as e:
            self._log('error', f'SSL pinning detection failed: {e}')
            logger.exception('SSL pinning detection error')
            # Default to requiring bypass for safety
            result.has_pinning = True
            result.bypass_required = True
            result.bypass_recommendation = (
                "Detection failed. Enabling Frida bypass as precaution."
            )
        finally:
            result.detection_time_ms = int(
                (datetime.now() - start_time).total_seconds() * 1000
            )
            # Cleanup extracted files
            if self._extracted_path and self._extracted_path.exists():
                import shutil
                try:
                    shutil.rmtree(self._extracted_path)
                except:
                    pass
        
        return result
    
    async def _static_analysis(self, app_path: str) -> List[PinningEvidence]:
        """Analyze app binary for SSL pinning patterns"""
        evidence = []
        
        if self.platform == "android":
            evidence.extend(await self._analyze_apk(app_path))
        else:
            evidence.extend(await self._analyze_ipa(app_path))
        
        return evidence
    
    async def _analyze_apk(self, apk_path: str) -> List[PinningEvidence]:
        """Analyze Android APK for SSL pinning"""
        evidence = []
        
        try:
            # Extract APK
            extract_dir = Path(tempfile.mkdtemp(prefix="jarwis_ssl_"))
            self._extracted_path = extract_dir
            
            with ZipFile(apk_path, 'r') as zf:
                zf.extractall(extract_dir)
            
            self._log('info', 'Analyzing APK for SSL pinning patterns...')
            
            # Check Network Security Config
            nsc_path = extract_dir / "res" / "xml" / "network_security_config.xml"
            if nsc_path.exists():
                nsc_evidence = self._analyze_network_security_config(nsc_path)
                evidence.extend(nsc_evidence)
            
            # Check for alternative NSC locations
            for xml_file in (extract_dir / "res" / "xml").glob("*.xml") if (extract_dir / "res" / "xml").exists() else []:
                content = xml_file.read_text(errors='ignore')
                if '<pin-set' in content or '<pin ' in content:
                    evidence.append(PinningEvidence(
                        pinning_type=PinningType.NETWORK_SECURITY_CONFIG,
                        detection_method=DetectionMethod.STATIC_ANALYSIS,
                        library="NetworkSecurityConfig",
                        evidence=f"Pin configuration found in {xml_file.name}",
                        confidence=0.95,
                        file_path=str(xml_file),
                        code_snippet=content[:500]
                    ))
            
            # Analyze DEX files for pinning patterns
            for dex_file in extract_dir.glob("*.dex"):
                dex_evidence = await self._analyze_dex(dex_file)
                evidence.extend(dex_evidence)
            
            # Check for native libraries with pinning
            lib_dirs = [
                extract_dir / "lib",
                extract_dir / "lib" / "arm64-v8a",
                extract_dir / "lib" / "armeabi-v7a",
                extract_dir / "lib" / "x86_64",
            ]
            
            for lib_dir in lib_dirs:
                if lib_dir.exists():
                    for so_file in lib_dir.glob("*.so"):
                        native_evidence = await self._analyze_native_lib(so_file)
                        evidence.extend(native_evidence)
            
            # Check for Flutter/React Native specific patterns
            framework_evidence = await self._detect_framework_pinning(extract_dir)
            evidence.extend(framework_evidence)
            
        except Exception as e:
            self._log('warning', f'APK static analysis error: {e}')
        
        return evidence
    
    async def _analyze_dex(self, dex_path: Path) -> List[PinningEvidence]:
        """Analyze DEX file for SSL pinning patterns"""
        evidence = []
        
        try:
            # Read DEX as binary and search for string patterns
            content = dex_path.read_bytes()
            content_str = content.decode('utf-8', errors='ignore')
            
            for lib_name, patterns in self.ANDROID_PINNING_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content_str, re.IGNORECASE):
                        pinning_type = self._map_lib_to_pinning_type(lib_name)
                        evidence.append(PinningEvidence(
                            pinning_type=pinning_type,
                            detection_method=DetectionMethod.STATIC_ANALYSIS,
                            library=lib_name,
                            evidence=f"Pattern '{pattern}' found in {dex_path.name}",
                            confidence=0.85,
                            file_path=str(dex_path)
                        ))
                        break
            
            # Check for specific class names
            pinning_classes = [
                b'CertificatePinner',
                b'TrustKit',
                b'X509TrustManager',
                b'SSLPinningVerify',
                b'PinningTrustManager',
            ]
            
            for class_name in pinning_classes:
                if class_name in content:
                    evidence.append(PinningEvidence(
                        pinning_type=PinningType.UNKNOWN,
                        detection_method=DetectionMethod.STATIC_ANALYSIS,
                        library=class_name.decode(),
                        evidence=f"Class '{class_name.decode()}' found in DEX",
                        confidence=0.80,
                        file_path=str(dex_path)
                    ))
            
        except Exception as e:
            self._log('debug', f'DEX analysis error: {e}')
        
        return evidence
    
    async def _analyze_native_lib(self, lib_path: Path) -> List[PinningEvidence]:
        """Analyze native library for SSL pinning"""
        evidence = []
        
        try:
            content = lib_path.read_bytes()
            
            # Check for common SSL pinning indicators in native code
            indicators = [
                b'SSL_CTX_set_verify',
                b'X509_verify_cert',
                b'ssl_verify_cert_chain',
                b'PeerCertificateChainVerifier',
                b'sha256/',  # Pin format
            ]
            
            for indicator in indicators:
                if indicator in content:
                    evidence.append(PinningEvidence(
                        pinning_type=PinningType.CUSTOM_TRUSTMANAGER,
                        detection_method=DetectionMethod.STATIC_ANALYSIS,
                        library=f"Native ({lib_path.name})",
                        evidence=f"SSL verification indicator '{indicator.decode(errors='ignore')}' in native lib",
                        confidence=0.70,
                        file_path=str(lib_path)
                    ))
                    break
            
        except Exception as e:
            self._log('debug', f'Native lib analysis error: {e}')
        
        return evidence
    
    async def _detect_framework_pinning(self, extract_dir: Path) -> List[PinningEvidence]:
        """Detect framework-specific SSL pinning (Flutter, React Native)"""
        evidence = []
        
        # Check for Flutter
        flutter_lib = extract_dir / "lib" / "arm64-v8a" / "libflutter.so"
        if flutter_lib.exists() or (extract_dir / "assets" / "flutter_assets").exists():
            self._log('info', 'Flutter app detected, checking for pinning...')
            
            # Flutter apps often use dart:io HttpClient with custom pinning
            assets_dir = extract_dir / "assets" / "flutter_assets"
            if assets_dir.exists():
                for asset in assets_dir.rglob("*"):
                    if asset.is_file() and asset.suffix in ['.json', '.yaml', '.pem', '.crt']:
                        try:
                            content = asset.read_text(errors='ignore')
                            if 'sha256' in content.lower() or 'certificate' in content.lower():
                                evidence.append(PinningEvidence(
                                    pinning_type=PinningType.FLUTTER_PINNING,
                                    detection_method=DetectionMethod.STATIC_ANALYSIS,
                                    library="Flutter",
                                    evidence=f"Certificate/pin config in {asset.name}",
                                    confidence=0.75,
                                    file_path=str(asset)
                                ))
                        except:
                            pass
        
        # Check for React Native
        rn_bundle = extract_dir / "assets" / "index.android.bundle"
        if rn_bundle.exists():
            self._log('info', 'React Native app detected, checking for pinning...')
            
            try:
                content = rn_bundle.read_text(errors='ignore')
                for pattern in self.ANDROID_PINNING_PATTERNS.get('react_native', []):
                    if re.search(pattern, content, re.IGNORECASE):
                        evidence.append(PinningEvidence(
                            pinning_type=PinningType.REACT_NATIVE_PINNING,
                            detection_method=DetectionMethod.STATIC_ANALYSIS,
                            library="React Native",
                            evidence=f"SSL pinning pattern in JS bundle",
                            confidence=0.85,
                            file_path=str(rn_bundle)
                        ))
                        break
            except:
                pass
        
        return evidence
    
    def _analyze_network_security_config(self, nsc_path: Path) -> List[PinningEvidence]:
        """Analyze Android Network Security Config for pin-set declarations"""
        evidence = []
        
        try:
            content = nsc_path.read_text()
            
            # Check for pin-set
            if '<pin-set' in content:
                evidence.append(PinningEvidence(
                    pinning_type=PinningType.NETWORK_SECURITY_CONFIG,
                    detection_method=DetectionMethod.MANIFEST_CHECK,
                    library="NetworkSecurityConfig",
                    evidence="Certificate pinning via pin-set in network_security_config.xml",
                    confidence=0.95,
                    file_path=str(nsc_path),
                    code_snippet=content[:1000]
                ))
            
            # Extract pinned domains
            domain_matches = re.findall(r'<domain[^>]*>([^<]+)</domain>', content)
            pin_matches = re.findall(r'<pin\s+digest="([^"]+)"[^>]*>([^<]+)</pin>', content)
            
            if domain_matches and pin_matches:
                evidence[-1].evidence += f"\nPinned domains: {', '.join(domain_matches[:5])}"
                evidence[-1].evidence += f"\nPins: {len(pin_matches)} SHA-256 pins configured"
            
        except Exception as e:
            self._log('debug', f'NSC analysis error: {e}')
        
        return evidence
    
    async def _analyze_ipa(self, ipa_path: str) -> List[PinningEvidence]:
        """Analyze iOS IPA for SSL pinning"""
        evidence = []
        
        try:
            extract_dir = Path(tempfile.mkdtemp(prefix="jarwis_ssl_ios_"))
            self._extracted_path = extract_dir
            
            with ZipFile(ipa_path, 'r') as zf:
                zf.extractall(extract_dir)
            
            self._log('info', 'Analyzing IPA for SSL pinning patterns...')
            
            # Find app bundle
            payload_dir = extract_dir / "Payload"
            if payload_dir.exists():
                app_bundles = list(payload_dir.glob("*.app"))
                
                for app_bundle in app_bundles:
                    # Check Info.plist for ATS settings
                    info_plist = app_bundle / "Info.plist"
                    if info_plist.exists():
                        ats_evidence = await self._analyze_info_plist(info_plist)
                        evidence.extend(ats_evidence)
                    
                    # Check embedded TrustKit config
                    trustkit_plist = app_bundle / "TrustKit.plist"
                    if trustkit_plist.exists():
                        evidence.append(PinningEvidence(
                            pinning_type=PinningType.TRUSTKIT,
                            detection_method=DetectionMethod.STATIC_ANALYSIS,
                            library="TrustKit",
                            evidence="TrustKit configuration plist found",
                            confidence=0.95,
                            file_path=str(trustkit_plist)
                        ))
                    
                    # Analyze binary for pinning patterns
                    binary_name = app_bundle.stem
                    binary_path = app_bundle / binary_name
                    if binary_path.exists():
                        binary_evidence = await self._analyze_ios_binary(binary_path)
                        evidence.extend(binary_evidence)
            
        except Exception as e:
            self._log('warning', f'IPA analysis error: {e}')
        
        return evidence
    
    async def _analyze_info_plist(self, plist_path: Path) -> List[PinningEvidence]:
        """Analyze Info.plist for App Transport Security settings"""
        evidence = []
        
        try:
            # Read plist content
            content = plist_path.read_text(errors='ignore')
            
            # Check for strict ATS (no arbitrary loads)
            if 'NSAppTransportSecurity' in content:
                if 'NSAllowsArbitraryLoads' in content and '<false/>' in content:
                    evidence.append(PinningEvidence(
                        pinning_type=PinningType.IOS_ATS,
                        detection_method=DetectionMethod.MANIFEST_CHECK,
                        library="App Transport Security",
                        evidence="Strict ATS enabled (NSAllowsArbitraryLoads = false)",
                        confidence=0.70,
                        file_path=str(plist_path)
                    ))
                
                # Check for pinned domains
                if 'NSPinnedDomains' in content:
                    evidence.append(PinningEvidence(
                        pinning_type=PinningType.IOS_ATS,
                        detection_method=DetectionMethod.MANIFEST_CHECK,
                        library="ATS Pinned Domains",
                        evidence="NSPinnedDomains configured in Info.plist",
                        confidence=0.95,
                        file_path=str(plist_path)
                    ))
            
        except Exception as e:
            self._log('debug', f'Info.plist analysis error: {e}')
        
        return evidence
    
    async def _analyze_ios_binary(self, binary_path: Path) -> List[PinningEvidence]:
        """Analyze iOS binary for SSL pinning patterns"""
        evidence = []
        
        try:
            content = binary_path.read_bytes()
            
            # Check for common iOS pinning patterns
            for lib_name, patterns in self.IOS_PINNING_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern.encode(), content, re.IGNORECASE):
                        pinning_type = self._map_ios_lib_to_type(lib_name)
                        evidence.append(PinningEvidence(
                            pinning_type=pinning_type,
                            detection_method=DetectionMethod.STATIC_ANALYSIS,
                            library=lib_name,
                            evidence=f"Pattern '{pattern}' found in binary",
                            confidence=0.80,
                            file_path=str(binary_path)
                        ))
                        break
            
        except Exception as e:
            self._log('debug', f'iOS binary analysis error: {e}')
        
        return evidence
    
    async def _check_config(self, app_path: str) -> List[PinningEvidence]:
        """Check manifest/config files for pinning declarations"""
        evidence = []
        
        if self.platform == "android":
            # AndroidManifest.xml check for networkSecurityConfig attribute
            try:
                with ZipFile(app_path, 'r') as zf:
                    if 'AndroidManifest.xml' in zf.namelist():
                        # Binary XML - check for networkSecurityConfig string
                        manifest = zf.read('AndroidManifest.xml')
                        if b'networkSecurityConfig' in manifest:
                            evidence.append(PinningEvidence(
                                pinning_type=PinningType.NETWORK_SECURITY_CONFIG,
                                detection_method=DetectionMethod.MANIFEST_CHECK,
                                library="AndroidManifest",
                                evidence="networkSecurityConfig attribute found in manifest",
                                confidence=0.90,
                                file_path="AndroidManifest.xml"
                            ))
            except Exception as e:
                self._log('debug', f'Manifest check error: {e}')
        
        return evidence
    
    async def _runtime_probe(
        self,
        package_name: str,
        device_id: str
    ) -> List[PinningEvidence]:
        """
        Runtime probe to detect SSL pinning behavior.
        Starts app with proxy and checks if connections fail.
        """
        evidence = []
        
        self._log('info', 'Running SSL pinning runtime probe...')
        
        try:
            # Set up proxy
            proxy_enabled = await self._configure_device_proxy(device_id, True)
            
            if not proxy_enabled:
                self._log('warning', 'Could not configure device proxy for runtime probe')
                return evidence
            
            # Start app and monitor for SSL errors
            ssl_errors_detected = await self._monitor_app_ssl_errors(
                package_name, device_id
            )
            
            if ssl_errors_detected:
                evidence.append(PinningEvidence(
                    pinning_type=PinningType.UNKNOWN,
                    detection_method=DetectionMethod.RUNTIME_PROBE,
                    library="Runtime Detection",
                    evidence="App rejected proxy certificate - SSL pinning active",
                    confidence=0.95
                ))
            
        except Exception as e:
            self._log('debug', f'Runtime probe error: {e}')
        finally:
            # Disable proxy
            await self._configure_device_proxy(device_id, False)
        
        return evidence
    
    async def _configure_device_proxy(self, device_id: str, enable: bool) -> bool:
        """Configure proxy on Android device"""
        try:
            if enable:
                # Set global proxy
                cmd = [
                    'adb', '-s', device_id, 'shell',
                    'settings', 'put', 'global', 'http_proxy',
                    f'127.0.0.1:{self.proxy_port}'
                ]
            else:
                # Remove proxy
                cmd = [
                    'adb', '-s', device_id, 'shell',
                    'settings', 'put', 'global', 'http_proxy', ':0'
                ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            return result.returncode == 0
            
        except Exception as e:
            self._log('debug', f'Proxy config error: {e}')
            return False
    
    async def _monitor_app_ssl_errors(
        self,
        package_name: str,
        device_id: str
    ) -> bool:
        """Monitor app for SSL handshake errors"""
        try:
            # Clear logcat and start app
            subprocess.run(
                ['adb', '-s', device_id, 'logcat', '-c'],
                capture_output=True, timeout=5
            )
            
            # Start app
            subprocess.run(
                ['adb', '-s', device_id, 'shell', 'am', 'start',
                 '-n', f'{package_name}/.MainActivity'],
                capture_output=True, timeout=10
            )
            
            # Wait for network activity
            await asyncio.sleep(5)
            
            # Check logcat for SSL errors
            result = subprocess.run(
                ['adb', '-s', device_id, 'logcat', '-d', '-s',
                 'System.err:W', 'SSLHandshake:E', 'OkHttp:E'],
                capture_output=True, text=True, timeout=10
            )
            
            ssl_error_patterns = [
                'SSLHandshakeException',
                'CertPathValidatorException',
                'Trust anchor for certification path not found',
                'SSL handshake aborted',
                'Chain validation failed',
                'Certificate pinning failure',
            ]
            
            for pattern in ssl_error_patterns:
                if pattern in result.stdout:
                    return True
            
            return False
            
        except Exception as e:
            self._log('debug', f'SSL error monitor failed: {e}')
            return False
    
    def _map_lib_to_pinning_type(self, lib_name: str) -> PinningType:
        """Map library name to pinning type"""
        mapping = {
            'okhttp_pinner': PinningType.OKHTTP_PINNER,
            'trustkit': PinningType.TRUSTKIT,
            'custom_trustmanager': PinningType.CUSTOM_TRUSTMANAGER,
            'network_security_config': PinningType.NETWORK_SECURITY_CONFIG,
            'flutter': PinningType.FLUTTER_PINNING,
            'react_native': PinningType.REACT_NATIVE_PINNING,
        }
        return mapping.get(lib_name, PinningType.UNKNOWN)
    
    def _map_ios_lib_to_type(self, lib_name: str) -> PinningType:
        """Map iOS library to pinning type"""
        mapping = {
            'alamofire': PinningType.IOS_CUSTOM,
            'afnetworking': PinningType.IOS_CUSTOM,
            'trustkit': PinningType.TRUSTKIT,
            'custom': PinningType.IOS_CUSTOM,
            'ats': PinningType.IOS_ATS,
        }
        return mapping.get(lib_name, PinningType.UNKNOWN)
    
    def _extract_pinned_domains(self, evidence: List[PinningEvidence]) -> List[str]:
        """Extract pinned domain names from evidence"""
        domains = set()
        
        for e in evidence:
            # Try to extract domains from evidence text
            domain_matches = re.findall(
                r'(?:domain[s]?:\s*)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)',
                e.evidence
            )
            domains.update(domain_matches)
            
            # Extract from code snippets
            if e.code_snippet:
                snippet_matches = re.findall(
                    r'"([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)"',
                    e.code_snippet
                )
                domains.update(snippet_matches)
        
        # Filter out common false positives
        filtered = [
            d for d in domains
            if not d.startswith('www.')
            and not d.endswith('.xml')
            and not d.endswith('.java')
            and len(d) > 5
        ]
        
        return list(filtered)[:10]  # Return top 10
    
    def _generate_bypass_recommendation(
        self,
        pinning_types: List[PinningType]
    ) -> str:
        """Generate bypass recommendation based on pinning types detected"""
        recommendations = []
        
        if PinningType.OKHTTP_PINNER in pinning_types:
            recommendations.append("OkHttp CertificatePinner detected - Frida universal bypass will hook check() methods")
        
        if PinningType.TRUSTKIT in pinning_types:
            recommendations.append("TrustKit detected - Frida bypass will disable TSKPinningValidator")
        
        if PinningType.NETWORK_SECURITY_CONFIG in pinning_types:
            recommendations.append("Network Security Config pins detected - Frida will bypass TrustManager")
        
        if PinningType.CUSTOM_TRUSTMANAGER in pinning_types:
            recommendations.append("Custom TrustManager detected - Frida will hook X509TrustManager methods")
        
        if PinningType.FLUTTER_PINNING in pinning_types:
            recommendations.append("Flutter pinning detected - Frida will hook SecurityContext.setTrustedCertificates")
        
        if PinningType.REACT_NATIVE_PINNING in pinning_types:
            recommendations.append("React Native SSL pinning module detected - Frida will hook native verification")
        
        if PinningType.IOS_ATS in pinning_types:
            recommendations.append("iOS ATS pinning detected - Frida will hook SecTrustEvaluate")
        
        if PinningType.IOS_CUSTOM in pinning_types:
            recommendations.append("iOS custom pinning detected - Frida will bypass URLSession delegate")
        
        if not recommendations:
            recommendations.append("Unknown pinning type - Frida universal bypass will be attempted")
        
        return "\n".join(recommendations)


async def detect_ssl_pinning(
    app_path: str,
    platform: str = "android",
    package_name: Optional[str] = None,
    device_id: Optional[str] = None
) -> SSLPinningDetectionResult:
    """
    Convenience function to detect SSL pinning in an app.
    
    Args:
        app_path: Path to APK or IPA
        platform: 'android' or 'ios'
        package_name: Optional package name for runtime probe
        device_id: Optional device ID for runtime probe
    
    Returns:
        SSLPinningDetectionResult
    """
    detector = SSLPinningDetector(platform=platform)
    return await detector.detect(app_path, package_name, device_id)
