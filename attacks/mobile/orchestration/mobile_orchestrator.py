"""
Jarwis AGI - Mobile Pentest Orchestrator
Unified orchestrator for full Android and iOS application penetration testing

This module coordinates all phases of mobile app testing:
1. Device/Emulator Setup
2. SSL Pinning Bypass via Frida
3. App Installation and Launching
4. Traffic Interception (Burp-style)
5. App Crawling (like web crawling)
6. Attack Module Execution
7. Report Generation

Works like web app testing but for mobile apps.
"""

import os
import re
import json
import asyncio
import logging
import threading
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable, Any, Set
from queue import Queue

logger = logging.getLogger(__name__)


@dataclass
class MobileEndpoint:
    """Discovered API endpoint from mobile app"""
    id: str
    url: str
    method: str
    path: str
    host: str
    params: Dict = field(default_factory=dict)
    headers: Dict = field(default_factory=dict)
    body: str = ""
    response_code: int = 0
    response_body: str = ""
    content_type: str = ""
    requires_auth: bool = False
    auth_type: str = ""
    discovered_at: str = ""
    source: str = ""  # frida, mitm, static


@dataclass
class MobileVulnerability:
    """Vulnerability finding from mobile testing with comprehensive metadata"""
    id: str
    category: str  # OWASP Mobile category
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    affected_endpoint: str = ""
    method: str = ""
    parameter: str = ""
    evidence: str = ""
    request: str = ""  # Burp-style request
    response: str = ""  # Burp-style response
    poc: str = ""  # Proof of concept
    remediation: str = ""
    cwe_id: str = ""
    cwe_name: str = ""
    cvss_score: float = 0.0
    
    # Extended metadata fields
    owasp_category: str = ""
    impact: str = ""
    disclosure_days: int = 45
    compliance: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    # Attack vector information
    attack_vector: str = "local"
    privileges_required: str = "none"
    user_interaction: str = "none"
    
    # Additional PoC details
    poc_request_headers: Dict[str, str] = field(default_factory=dict)
    poc_response_headers: Dict[str, str] = field(default_factory=dict)
    affected_component: str = ""
    
    # Source tracking
    scanner_module: str = ""
    confidence: str = "high"
    false_positive_hints: List[str] = field(default_factory=list)
    
    def enrich_from_registry(self) -> 'MobileVulnerability':
        """
        Enrich this vulnerability with metadata from the vulnerability registry.
        Uses category to map to appropriate registry attack_type.
        """
        from attacks.vulnerability_metadata import get_vuln_meta
        
        # Map OWASP Mobile categories to registry attack types
        category_mapping = {
            "M1": "hardcoded_secret",  # Improper Credential Usage
            "M2": "insecure_data_storage",  # Inadequate Supply Chain Security (map to storage)
            "M3": "insecure_network_communication",  # Insecure Authentication (map to network)
            "M4": "webview_vulnerability",  # Insufficient Input/Output Validation
            "M5": "insecure_network_communication",  # Insecure Communication
            "M6": "binary_protection",  # Inadequate Privacy Controls
            "M7": "binary_protection",  # Insufficient Binary Protections
            "M8": "debuggable_application",  # Security Misconfiguration
            "M9": "insecure_data_storage",  # Insecure Data Storage
            "M10": "weak_cryptography",  # Insufficient Cryptography
            "hardcoded_secret": "hardcoded_secret",
            "insecure_storage": "insecure_data_storage",
            "weak_crypto": "weak_cryptography",
            "insecure_network": "insecure_network_communication",
            "webview": "webview_vulnerability",
            "intent": "intent_injection",
            "url_scheme": "url_scheme_hijacking",
            "ats_bypass": "ios_ats_bypass",
            "debuggable": "debuggable_application",
            "binary": "binary_protection",
            "logging": "logging_sensitive_data",
            "clipboard": "clipboard_data_exposure",
            "backup": "backup_data_exposure",
            "root_jailbreak": "root_jailbreak_detection_bypass",
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
        if self.cvss_score == 0.0:
            self.cvss_score = meta.cvss_base
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
        """Convert vulnerability to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "affected_endpoint": self.affected_endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "poc": self.poc,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "cvss_score": self.cvss_score,
            "owasp_category": self.owasp_category,
            "impact": self.impact,
            "disclosure_days": self.disclosure_days,
            "compliance": self.compliance,
            "references": self.references,
            "attack_vector": self.attack_vector,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
            "poc_request_headers": self.poc_request_headers,
            "poc_response_headers": self.poc_response_headers,
            "affected_component": self.affected_component,
            "scanner_module": self.scanner_module,
            "confidence": self.confidence,
            "false_positive_hints": self.false_positive_hints,
        }


@dataclass
class MobileScanContext:
    """Context maintained throughout the mobile scan"""
    app_path: str
    package_name: str = ""
    bundle_id: str = ""  # For iOS
    platform: str = ""  # android, ios
    
    # Discovered endpoints (like web crawling)
    endpoints: List[MobileEndpoint] = field(default_factory=list)
    
    # Authentication state
    authenticated: bool = False
    auth_tokens: Dict = field(default_factory=dict)
    cookies: Dict = field(default_factory=dict)
    
    # Findings
    vulnerabilities: List[MobileVulnerability] = field(default_factory=list)
    
    # Traffic log
    traffic_log: List[Dict] = field(default_factory=list)
    
    # Base URLs discovered
    base_urls: Set[str] = field(default_factory=set)
    
    # SSL Pinning Detection (populated by _phase_ssl_bypass)
    ssl_pinning_detected: bool = False
    ssl_pinning_types: List[str] = field(default_factory=list)
    
    # Authentication/2FA status (for dashboard integration)
    auth_status: str = "not_started"  # not_started, waiting_for_otp, waiting_for_manual_auth, authenticated, failed
    otp_request_id: str = ""  # ID for OTP request if waiting


@dataclass
class MobileScanConfig:
    """Configuration for mobile penetration test"""
    # App path
    app_path: str = ""
    
    # Platform auto-detection
    platform: str = "auto"  # auto, android, ios
    
    # SSL Pinning
    ssl_pinned: bool = True
    frida_bypass_enabled: bool = True
    
    # Emulator/Simulator
    use_emulator: bool = True
    headless: bool = False
    device_id: str = ""
    keep_emulator_on_failure: bool = True  # Keep emulator running if scan fails
    keep_emulator_on_complete: bool = True  # Keep emulator running after scan completes
    
    # Proxy/Traffic
    mitm_enabled: bool = True
    mitm_port: int = 8080
    capture_traffic: bool = True
    
    # Crawling (like web app)
    crawl_enabled: bool = True
    crawl_duration: int = 120  # seconds
    max_depth: int = 10
    
    # Authentication
    auth_enabled: bool = False
    auth_type: str = ""  # email_password, phone_otp, social
    username: str = ""
    password: str = ""
    phone: str = ""
    login_api_url: str = ""  # User-provided login URL (optional, auto-discovered if empty)
    continue_on_auth_failure: bool = True  # Continue with unauthenticated scan if auth fails
    
    # 2FA / OTP
    two_factor_enabled: bool = False
    two_factor_type: str = "sms"  # sms, email, authenticator
    
    # Attack modules
    attacks_enabled: bool = True
    attack_categories: List[str] = field(default_factory=lambda: [
        "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"
    ])
    
    # AI Analysis
    ai_analysis: bool = True
    
    # Output
    output_dir: str = "reports/mobile"
    generate_report: bool = True


class MobilePenTestOrchestrator:
    """
    Main orchestrator for mobile application penetration testing
    Similar to PenTestRunner but for mobile apps
    
    Phases:
    1. Setup - Emulator/device preparation
    2. SSL Bypass - Frida injection
    3. App Launch - Install and start app
    4. Crawling - Discover all endpoints (like web crawler)
    5. Pre-Auth Attacks - Test unauthenticated surface
    6. Authentication - Login if enabled
    7. Post-Auth Attacks - Test authenticated features
    8. AI Planning - LLM recommendations
    9. Reporting - Generate final report
    """
    
    OWASP_MOBILE_TOP_10 = {
        "M1": "Improper Platform Usage",
        "M2": "Insecure Data Storage", 
        "M3": "Insecure Communication",
        "M4": "Insecure Authentication",
        "M5": "Insufficient Cryptography",
        "M6": "Insecure Authorization",
        "M7": "Client Code Quality",
        "M8": "Code Tampering",
        "M9": "Reverse Engineering",
        "M10": "Extraneous Functionality"
    }
    
    def __init__(self, config: MobileScanConfig):
        self.config = config
        self.context = MobileScanContext(app_path=config.app_path)
        
        # Detect platform
        if config.platform == "auto":
            self.context.platform = self._detect_platform(config.app_path)
        else:
            self.context.platform = config.platform
        
        # Components
        self.emulator = None
        self.simulator = None
        self.frida_bypass = None
        self.mitm_proxy = None
        self.crawler = None
        
        # MITM-first infrastructure (NEW)
        self.request_store = None      # MobileRequestStoreDB
        self.http_client = None        # MobileHTTPClient
        self.frida_bridge = None       # FridaRequestBridge
        self._scanners = []            # Mobile attack scanners
        
        # Callbacks
        self._log_callback: Optional[Callable] = None
        self._progress_callback: Optional[Callable] = None
        self._traffic_callback: Optional[Callable] = None
        
        # State
        self._running = False
        self._phase = "init"
        self._progress = 0
        
    def _detect_platform(self, app_path: str) -> str:
        """Auto-detect platform from file extension"""
        ext = Path(app_path).suffix.lower()
        if ext == ".apk":
            return "android"
        elif ext in [".ipa", ".app"]:
            return "ios"
        return "unknown"
    
    def set_log_callback(self, callback: Callable):
        """Set callback for logging"""
        self._log_callback = callback
    
    def set_progress_callback(self, callback: Callable):
        """Set callback for progress updates"""
        self._progress_callback = callback
    
    def set_traffic_callback(self, callback: Callable):
        """Set callback for real-time traffic"""
        self._traffic_callback = callback
    
    def _log(self, log_type: str, message: str, details: str = None):
        """Log message via callback"""
        if self._log_callback:
            try:
                self._log_callback(log_type, message, details)
            except:
                pass
        logger.info(f"[{log_type}] {message}")
    
    def _update_progress(self, phase: str, progress: int, message: str):
        """Update progress via callback"""
        self._phase = phase
        self._progress = progress
        
        if self._progress_callback:
            try:
                self._progress_callback(phase, progress, message)
            except:
                pass
    
    async def run(self) -> Dict:
        """
        Run the full mobile penetration test
        
        Returns:
            Dict with scan results
        """
        self._running = True
        scan_id = f"MOB-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        
        result = {
            "scan_id": scan_id,
            "app_path": self.config.app_path,
            "platform": self.context.platform,
            "started_at": start_time.isoformat(),
            "status": "running",
            "phases_completed": [],
            "endpoints_discovered": 0,
            "vulnerabilities": [],
            "traffic_log": [],
            "summary": {}
        }
        
        scan_succeeded = False  # Track success for cleanup decision
        
        try:
            self._log('start', f'[*]    Starting Mobile Pentest: {Path(self.config.app_path).name}')
            self._log('info', f'Platform: {self.context.platform.upper()}')
            
            # Phase 1: Device/Emulator Setup
            phase_result = await self._phase_setup()
            result["phases_completed"].append({"phase": "setup", "success": phase_result})
            
            if not phase_result:
                raise Exception("Device setup failed")
            
            # Phase 2: SSL Pinning Bypass
            if self.config.frida_bypass_enabled:
                phase_result = await self._phase_ssl_bypass()
                result["phases_completed"].append({"phase": "ssl_bypass", "success": phase_result})
            
            # Phase 3: App Installation & Launch
            phase_result = await self._phase_app_launch()
            result["phases_completed"].append({"phase": "app_launch", "success": phase_result})
            
            if not phase_result:
                raise Exception("App launch failed")
            
            # Phase 4: Crawling & Endpoint Discovery
            if self.config.crawl_enabled:
                phase_result = await self._phase_crawling()
                result["phases_completed"].append({"phase": "crawling", "success": phase_result})
                result["endpoints_discovered"] = len(self.context.endpoints)
            
            # Phase 5: Pre-Auth Attack Scanning
            if self.config.attacks_enabled:
                phase_result = await self._phase_pre_auth_attacks()
                result["phases_completed"].append({"phase": "pre_auth_attacks", "success": phase_result})
            
            # Phase 6: Authentication (if enabled)
            if self.config.auth_enabled:
                phase_result = await self._phase_authentication()
                result["phases_completed"].append({"phase": "authentication", "success": phase_result})
                
                # Phase 7: Post-Auth Attack Scanning
                if phase_result and self.config.attacks_enabled:
                    phase_result = await self._phase_post_auth_attacks()
                    result["phases_completed"].append({"phase": "post_auth_attacks", "success": phase_result})
            
            # Phase 8: AI Planning & Additional Tests
            if self.config.ai_analysis:
                phase_result = await self._phase_ai_analysis()
                result["phases_completed"].append({"phase": "ai_analysis", "success": phase_result})
            
            # Phase 9: Report Generation
            if self.config.generate_report:
                report_path = await self._phase_reporting(result)
                result["report_path"] = report_path
            
            result["status"] = "completed"
            scan_succeeded = True
            
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            self._log('error', f'Scan failed: {e}')
            logger.exception(f"Mobile scan failed: {e}")
            scan_succeeded = False
        
        finally:
            # Determine whether to keep emulator based on config and scan result
            if scan_succeeded:
                keep_emulator = self.config.keep_emulator_on_complete
            else:
                keep_emulator = self.config.keep_emulator_on_failure
            
            self._log('debug', f'Cleanup: keep_emulator={keep_emulator} (succeeded={scan_succeeded})')
            await self._cleanup(keep_emulator=keep_emulator)
        
        # Final summary
        result["ended_at"] = datetime.now().isoformat()
        result["duration_seconds"] = (datetime.now() - start_time).total_seconds()
        result["vulnerabilities"] = [asdict(v) for v in self.context.vulnerabilities]
        result["traffic_log"] = self.context.traffic_log
        result["endpoints"] = [asdict(e) for e in self.context.endpoints]
        
        result["summary"] = {
            "total_endpoints": len(self.context.endpoints),
            "total_vulnerabilities": len(self.context.vulnerabilities),
            "critical": len([v for v in self.context.vulnerabilities if v.severity == "critical"]),
            "high": len([v for v in self.context.vulnerabilities if v.severity == "high"]),
            "medium": len([v for v in self.context.vulnerabilities if v.severity == "medium"]),
            "low": len([v for v in self.context.vulnerabilities if v.severity == "low"]),
            "base_urls": list(self.context.base_urls)
        }
        
        self._log('complete', f'[!]   Scan complete: {result["summary"]["total_vulnerabilities"]} vulnerabilities found')
        self._update_progress("complete", 100, "Scan complete!")
        
        return result
    
    async def _phase_setup(self) -> bool:
        """Phase 1: Setup emulator/simulator/device"""
        self._log('phase', '[*]    Phase 1: Device Setup')
        self._update_progress("setup", 5, "Setting up device...")
        
        # Ensure Android SDK environment variables are set
        self._ensure_android_env()
        
        try:
            if self.context.platform == "android":
                return await self._setup_android()
            elif self.context.platform == "ios":
                return await self._setup_ios()
            else:
                self._log('error', f'Unknown platform: {self.context.platform}')
                return False
                
        except Exception as e:
            self._log('error', f'Setup failed: {e}')
            logger.exception(f"Device setup exception: {e}")
            return False
    
    def _ensure_android_env(self):
        """Ensure Android SDK environment variables are properly set"""
        import os
        
        # Common SDK locations on Windows
        sdk_paths = [
            os.environ.get("ANDROID_SDK_ROOT"),
            os.environ.get("ANDROID_HOME"),
            "C:/Android/Sdk",
            "C:/Android/sdk",
            os.path.expanduser("~/.jarwis/android-sdk"),
            os.path.expanduser("~/AppData/Local/Android/Sdk"),
        ]
        
        # Find valid SDK path
        sdk_root = None
        for path in sdk_paths:
            if path and os.path.exists(path):
                sdk_root = path
                break
        
        if sdk_root:
            os.environ["ANDROID_SDK_ROOT"] = sdk_root
            os.environ["ANDROID_HOME"] = sdk_root
            self._log('info', f'Android SDK: {sdk_root}')
            
            # Add platform-tools to PATH if not already there
            platform_tools = os.path.join(sdk_root, "platform-tools")
            emulator_path = os.path.join(sdk_root, "emulator")
            
            current_path = os.environ.get("PATH", "")
            paths_to_add = []
            
            if platform_tools not in current_path:
                paths_to_add.append(platform_tools)
            if emulator_path not in current_path:
                paths_to_add.append(emulator_path)
            
            if paths_to_add:
                os.environ["PATH"] = os.pathsep.join(paths_to_add) + os.pathsep + current_path
            
            # Set AVD home if not set
            if not os.environ.get("ANDROID_AVD_HOME"):
                avd_paths = [
                    "C:/Android/avd",
                    os.path.expanduser("~/.android/avd"),
                    os.path.expanduser("~/.jarwis/avd"),
                ]
                for avd_path in avd_paths:
                    if os.path.exists(avd_path):
                        os.environ["ANDROID_AVD_HOME"] = avd_path
                        break
        else:
            self._log('warning', 'Android SDK not found in standard locations')
    
    async def _setup_android(self) -> bool:
        """Setup Android emulator or device with enhanced detection"""
        from attacks.mobile.platform.android.emulator_manager import EmulatorManager, EmulatorConfig
        from attacks.mobile.platform.android.adb_device_manager import ADBDeviceManager, DeviceType
        import subprocess
        import os
        
        self.emulator = EmulatorManager()
        status = self.emulator.get_status()
        
        # Log SDK status for debugging
        self._log('info', f'SDK Root: {status.get("sdk_root", "Not set")}')
        self._log('info', f'Platform Tools: {"OK" if status.get("platform_tools_installed") else "Missing"}')
        self._log('info', f'Emulator: {"Installed" if status.get("emulator_installed") else "Not installed"}')
        
        # Verify ADB is accessible
        adb_available = False
        try:
            result = subprocess.run(['adb', 'version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                adb_available = True
                self._log('info', 'ADB: Available')
            else:
                self._log('warning', f'ADB command failed: {result.stderr}')
        except FileNotFoundError:
            self._log('error', 'ADB not found in PATH. Please install Android SDK platform-tools.')
        except Exception as e:
            self._log('warning', f'ADB check error: {e}')
        
        if not adb_available:
            self._log('error', 'Cannot proceed without ADB. Run SETUP_ANDROID_EMULATOR.bat first.')
            return False
        
        # Use enhanced ADB device manager for better device detection
        from attacks.mobile.platform.android.adb_device_manager import ADBConfig
        adb_config = ADBConfig(prefer_real_device=True)
        self.device_manager = ADBDeviceManager(config=adb_config)
        
        # Check for connected device first (real device preferred)
        if self.config.device_id:
            self._log('info', f'Using specified device: {self.config.device_id}')
            return True
        
        # Use enhanced device discovery
        try:
            devices = await self.device_manager.discover_devices()
            
            if devices:
                # Select best device (prefers real devices)
                selected = await self.device_manager.select_device()
                
                if selected:
                    self.config.device_id = selected.device_id
                    
                    # Log device details
                    device_type = "Real Device" if selected.device_type == DeviceType.REAL_DEVICE else "Emulator"
                    self._log('info', f'Using {device_type}: {selected.display_name}')
                    self._log('info', f'  Android {selected.android_version} (API {selected.sdk_version})')
                    self._log('info', f'  Root: {selected.root_status.value}, Frida: {"Yes" if selected.frida_server_running else "No"}')
                    
                    # Prepare device for testing if needed
                    try:
                        security_summary = await self.device_manager.get_device_security_summary(selected.device_id)
                        self._log('info', f'  Security: Verified Boot={security_summary.get("verified_boot_state", "N/A")}')
                    except Exception as sec_err:
                        self._log('warning', f'Could not get security summary: {sec_err}')
                    
                    return True
        except Exception as e:
            self._log('warning', f'Enhanced device detection failed: {e}, falling back to basic ADB')
        
        # Fallback: Check ADB for devices directly
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=5)
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            devices = []
            unauthorized = []
            
            for line in lines:
                if '\tdevice' in line:
                    devices.append(line.split('\t')[0])
                elif '\tunauthorized' in line:
                    unauthorized.append(line.split('\t')[0])
            
            if unauthorized:
                self._log('warning', f'Unauthorized devices detected: {unauthorized}. Accept USB debugging prompt on device.')
            
            if devices:
                self._log('info', f'Using connected device: {devices[0]}')
                self.config.device_id = devices[0]
                return True
        except Exception as e:
            self._log('warning', f'ADB device check failed: {e}')
        
        # No device connected - try to start emulator
        self._log('info', 'No connected devices found. Attempting to start emulator...')
        
        if self.config.use_emulator:
            if not status.get('emulator_installed'):
                self._log('error', 'Android emulator not installed. Run SETUP_ANDROID_EMULATOR.bat first.')
                return False
            
            # Check if AVD exists
            try:
                emulator_exe = os.path.join(status.get('sdk_root', ''), 'emulator', 'emulator.exe')
                if os.path.exists(emulator_exe):
                    result = subprocess.run([emulator_exe, '-list-avds'], capture_output=True, text=True, timeout=10)
                    avds = [a.strip() for a in result.stdout.strip().split('\n') if a.strip()]
                    if not avds:
                        self._log('error', 'No AVDs found. Run SETUP_ANDROID_EMULATOR.bat to create one.')
                        return False
                    self._log('info', f'Available AVDs: {avds}')
            except Exception as e:
                self._log('warning', f'Could not list AVDs: {e}')
            
            if not status.get('running'):
                self._log('info', 'Starting Android emulator (this may take 1-2 minutes)...')
                self._update_progress("setup", 8, "Starting emulator...")
                
                try:
                    started = await self.emulator.start_emulator(headless=self.config.headless, wait=True)
                    
                    if started:
                        # Refresh status after starting
                        status = self.emulator.get_status()
                        self.config.device_id = status.get('device_id', '')
                        self._log('success', f'Emulator started: {self.config.device_id}')
                        return True
                    else:
                        self._log('error', 'Failed to start emulator. Check if virtualization is enabled.')
                        return False
                except Exception as e:
                    self._log('error', f'Emulator start error: {e}')
                    return False
            else:
                self.config.device_id = status.get('device_id', '')
                self._log('success', f'Emulator already running: {self.config.device_id}')
                return True
        
        self._log('error', 'No device available and emulator not enabled. Enable use_emulator or connect a device.')
        return False
    
    async def _setup_ios(self) -> bool:
        """Setup iOS simulator or device with enhanced detection"""
        from attacks.mobile.platform.ios.ios_simulator_manager import IOSSimulatorManager, SimulatorConfig
        from attacks.mobile.platform.ios.ios_device_manager import IOSDeviceManager, IOSDeviceType
        
        self.simulator = IOSSimulatorManager()
        status = self.simulator.get_status()
        
        # Use enhanced iOS device manager for better detection
        self.ios_device_manager = IOSDeviceManager(prefer_real_device=True)
        
        # Check for real iOS devices first
        try:
            devices = await self.ios_device_manager.discover_devices()
            
            # Filter for real devices
            real_devices = [d for d in devices if d.device_type == IOSDeviceType.REAL_DEVICE]
            
            if real_devices:
                # Prefer jailbroken for full testing capabilities
                jailbroken = [d for d in real_devices if d.is_jailbroken]
                selected = jailbroken[0] if jailbroken else real_devices[0]
                
                self.config.device_id = selected.udid
                device_type = "Jailbroken" if selected.is_jailbroken else "Real Device"
                self._log('info', f'Using {device_type}: {selected.display_name}')
                self._log('info', f'  iOS {selected.ios_version}')
                self._log('info', f'  Jailbreak: {selected.jailbreak_status.value}, Frida: {"Yes" if selected.frida_server_running else "No"}')
                
                # Get security summary
                security = self.ios_device_manager.get_device_security_summary(selected.udid)
                self._log('info', f'  Capabilities: {", ".join(security.get("testing_capabilities", [])[:3])}...')
                
                return True
        except Exception as e:
            self._log('warning', f'Enhanced iOS device detection failed: {e}, falling back to simulator')
        
        # Fall back to simulator on macOS
        if not status.get('is_macos', False):
            self._log('warning', 'iOS testing requires macOS with Xcode or a connected iOS device')
            return False
        
        if self.config.use_emulator:
            if not status.get('running', False):
                self._log('info', 'Starting iOS Simulator...')
                await self.simulator.full_setup()
            
            self._log('success', f'iOS Simulator ready')
            return True
        
        return False
    
    async def _phase_ssl_bypass(self) -> bool:
        """Phase 2: Detect SSL Pinning & Bypass if needed + Initialize MITM infrastructure"""
        self._log('phase', '[*]    Phase 2: SSL Pinning Detection & Bypass')
        self._update_progress("ssl_bypass", 15, "Detecting SSL pinning...")
        
        # Step 1: Detect if SSL pinning is present BEFORE attempting bypass
        ssl_pinning_detected = False
        try:
            from attacks.mobile.dynamic.ssl_pinning_detector import SSLPinningDetector
            
            detector = SSLPinningDetector(
                platform=self.context.platform,
                proxy_port=self.config.mitm_port
            )
            detector.set_log_callback(self._log)
            
            # Get package name first
            if not self.context.package_name:
                self.context.package_name = await self._get_package_name()
            
            # Run SSL pinning detection
            detection_result = await detector.detect(
                app_path=self.config.app_path,
                package_name=self.context.package_name,
                device_id=self.config.device_id
            )
            
            ssl_pinning_detected = detection_result.has_pinning
            
            if detection_result.has_pinning:
                self._log('warning', f'[!]   SSL Pinning DETECTED (confidence: {detection_result.confidence_score:.0%})')
                pinning_types = [pt.value for pt in detection_result.pinning_types]
                self._log('info', f'      Pinning types: {", ".join(pinning_types)}')
                
                if detection_result.pinned_domains:
                    self._log('info', f'      Pinned domains: {", ".join(detection_result.pinned_domains[:3])}...')
                
                self._log('info', f'      Recommendation: {detection_result.bypass_recommendation.split(chr(10))[0]}')
                
                # Store detection result in context for reporting
                self.context.ssl_pinning_detected = True
                self.context.ssl_pinning_types = pinning_types
            else:
                self._log('success', '[!]   No SSL Pinning detected - MITM proxy will work without Frida')
                self.context.ssl_pinning_detected = False
                
        except ImportError as e:
            self._log('warning', f'SSL pinning detector not available: {e}')
            # Default to assuming pinning exists for safety
            ssl_pinning_detected = True
        except Exception as e:
            self._log('warning', f'SSL pinning detection failed: {e}. Assuming pinning present.')
            ssl_pinning_detected = True
        
        # Step 2: Initialize MITM infrastructure (always needed)
        self._update_progress("ssl_bypass", 17, "Initializing MITM infrastructure...")
        await self._initialize_mitm_infrastructure()
        
        # Step 3: Only run Frida bypass if pinning was detected (or detection failed)
        if ssl_pinning_detected and self.config.frida_bypass_enabled:
            self._update_progress("ssl_bypass", 20, "Bypassing SSL pinning with Frida...")
            
            try:
                from attacks.mobile.dynamic.frida_ssl_bypass import FridaSSLBypass
                
                self.frida_bypass = FridaSSLBypass()
                self.frida_bypass.set_log_callback(self._log)
                self.frida_bypass.set_request_callback(self._on_traffic_intercepted)
                
                # Connect to device
                await self.frida_bypass.connect_device(self.config.device_id)
                
                if not self.context.package_name:
                    self._log('warning', 'Could not determine package name, SSL bypass will attach after app launch')
                    return True
                
                # Register Frida bridge as message handler
                if self.frida_bridge and hasattr(self.frida_bypass, 'set_message_callback'):
                    self.frida_bypass.set_message_callback(self.frida_bridge.on_frida_message)
                    self._log('info', 'Frida request bridge connected')
                
                # Attach and bypass
                result = await self.frida_bypass.attach_and_bypass(
                    self.context.package_name,
                    platform=self.context.platform,
                    spawn=True
                )
                
                if result.success:
                    self._log('success', f'[!]   SSL bypass active: {len(result.libraries_bypassed)} libraries bypassed')
                    
                    # Start Frida bridge message processing
                    if self.frida_bridge:
                        asyncio.create_task(self.frida_bridge.start_listening())
                        
                    return True
                else:
                    self._log('warning', f'SSL bypass partial: {result.error}')
                    return True  # Continue even if partial
                    
            except ImportError:
                self._log('warning', 'Frida not available. SSL bypass disabled.')
                return True
            except Exception as e:
                self._log('warning', f'SSL bypass failed: {e}')
                return True  # Continue scan
        else:
            if not ssl_pinning_detected:
                self._log('info', 'Skipping Frida bypass - no SSL pinning detected')
            return True
    
    async def _phase_app_launch(self) -> bool:
        """Phase 3: Install and launch the app"""
        self._log('phase', '[*]    Phase 3: App Launch')
        self._update_progress("app_launch", 25, "Launching application...")
        
        try:
            if self.context.platform == "android":
                return await self._launch_android_app()
            else:
                return await self._launch_ios_app()
                
        except Exception as e:
            self._log('error', f'App launch failed: {e}')
            return False
    
    async def _launch_android_app(self) -> bool:
        """Launch Android app"""
        if not self.emulator:
            from attacks.mobile.platform.android.emulator_manager import EmulatorManager
            self.emulator = EmulatorManager()
        
        # Install APK
        self._log('info', f'Installing APK: {Path(self.config.app_path).name}')
        await self.emulator.install_apk(self.config.app_path)
        
        # Get package name if not known
        if not self.context.package_name:
            self.context.package_name = await self._get_package_name()
        
        # Launch app
        self._log('info', f'Launching: {self.context.package_name}')
        await self.emulator.launch_app(self.context.package_name)
        
        await asyncio.sleep(3)  # Wait for app to start
        
        # Now attach Frida if SSL bypass is enabled and wasn't attached before
        if self.config.frida_bypass_enabled and self.frida_bypass and not self.frida_bypass.is_connected:
            await self.frida_bypass.connect_device()
            await self.frida_bypass.attach_and_bypass(
                self.context.package_name,
                platform="android",
                spawn=False  # Already running
            )
        
        self._log('success', 'App launched successfully')
        return True
    
    async def _launch_ios_app(self) -> bool:
        """Launch iOS app"""
        if not self.simulator:
            from attacks.mobile.platform.ios.ios_simulator_manager import IOSSimulatorManager
            self.simulator = IOSSimulatorManager()
        
        # Install app
        self._log('info', f'Installing IPA: {Path(self.config.app_path).name}')
        await self.simulator.install_app(self.config.app_path)
        
        # Get bundle ID
        if not self.context.bundle_id:
            self.context.bundle_id = await self._get_bundle_id()
        
        # Launch app
        self._log('info', f'Launching: {self.context.bundle_id}')
        await self.simulator.launch_app(self.context.bundle_id)
        
        await asyncio.sleep(3)
        
        self._log('success', 'App launched successfully')
        return True
    
    async def _phase_crawling(self) -> bool:
        """Phase 4: Crawl the app and discover endpoints (like web crawling)"""
        self._log('phase', '[>]     Phase 4: App Crawling & API Discovery')
        self._update_progress("crawling", 35, "Crawling application...")
        
        try:
            from attacks.mobile.dynamic.dynamic_crawler import DynamicAppCrawler
            
            self.crawler = DynamicAppCrawler(
                callback=self._log
            )
            
            # Run dynamic crawl
            crawl_result = await self.crawler.crawl(
                apk_path=self.config.app_path,
                package_name=self.context.package_name or self.context.bundle_id,
                duration=self.config.crawl_duration,
                use_emulator=False  # Already running
            )
            
            # Convert to MobileEndpoint format
            for api in crawl_result.apis:
                endpoint = MobileEndpoint(
                    id=api.id,
                    url=api.url,
                    method=api.method,
                    path=api.path,
                    host=api.base_url,
                    headers=api.request_headers,
                    body=api.request_body,
                    response_code=api.response_status,
                    content_type=api.response_content_type,
                    requires_auth=api.requires_auth,
                    discovered_at=api.discovered_at,
                    source="frida_dynamic"
                )
                self.context.endpoints.append(endpoint)
                self.context.base_urls.add(api.base_url)
            
            self._log('success', f'[!]   Discovered {len(self.context.endpoints)} API endpoints')
            self._log('info', f'   Base URLs: {len(self.context.base_urls)}')
            
            return True
            
        except Exception as e:
            self._log('warning', f'Dynamic crawling failed: {e}')
            
            # Fallback to static crawling
            return await self._static_crawl()
    
    async def _static_crawl(self) -> bool:
        """Fallback: Static analysis for endpoint discovery"""
        try:
            from attacks.mobile.dynamic.app_crawler import MobileAppCrawler
            
            crawler = MobileAppCrawler(callback=self._log)
            
            result = await crawler.crawl(
                app_path=self.config.app_path,
                platform=self.context.platform
            )
            
            for endpoint in result.endpoints:
                self.context.endpoints.append(MobileEndpoint(
                    id=endpoint.id,
                    url=endpoint.url,
                    method=endpoint.method,
                    path=endpoint.path,
                    host=endpoint.base_url,
                    source="static"
                ))
                self.context.base_urls.add(endpoint.base_url)
            
            return True
            
        except Exception as e:
            self._log('warning', f'Static crawling failed: {e}')
            return False
    
    async def _phase_pre_auth_attacks(self) -> bool:
        """Phase 5: Run attacks on unauthenticated endpoints"""
        self._log('phase', '[>]     Phase 5: Pre-Auth Attack Scanning')
        self._update_progress("pre_auth_attacks", 50, "Running pre-auth attacks...")
        
        try:
            # Static analysis attacks
            await self._run_static_attacks()
            
            # API-based attacks on discovered endpoints
            await self._run_api_attacks(authenticated=False)
            
            self._log('success', f'Pre-auth scan: {len(self.context.vulnerabilities)} vulnerabilities')
            return True
            
        except Exception as e:
            self._log('warning', f'Pre-auth attacks failed: {e}')
            return False
    
    async def _run_static_attacks(self):
        """Run static analysis attack modules with error handling"""
        try:
            if self.context.platform == "android":
                from attacks.mobile.platform.android.android_attacks import AndroidAttackScanner
                scanner = AndroidAttackScanner()
            else:
                from attacks.mobile.platform.ios.ios_attacks import IOSAttackScanner
                scanner = IOSAttackScanner()
            
            # Run scanner
            self._log('info', f'Running {self.context.platform}-specific security checks...')
            findings = await scanner.scan({}, self.config.app_path)
            
            for finding in findings:
                try:
                    self.context.vulnerabilities.append(MobileVulnerability(
                        id=finding.id,
                        category=finding.category,
                        severity=finding.severity,
                        title=finding.title,
                        description=finding.description,
                        poc=finding.poc if hasattr(finding, 'poc') else "",
                        remediation=finding.remediation if hasattr(finding, 'remediation') else "",
                        cwe_id=finding.cwe_id if hasattr(finding, 'cwe_id') else ""
                    ))
                except Exception as e:
                    self._log('debug', f'Error processing finding: {e}')
                    continue
            
            self._log('success', f'{self.context.platform.upper()} checks completed')
            
        except ImportError as e:
            self._log('warning', f'Platform scanner not available: {e}')
        except Exception as e:
            self._log('error', f'Platform scanner error: {e}')
            logger.exception('Platform scanner error')
        
        # Run deep code scanner based on platform
        if self.context.platform == "android":
            await self._run_deep_code_scan_android()
        elif self.context.platform == "ios":
            await self._run_deep_code_scan_ios()
    
    async def _run_deep_code_scan_android(self):
        """
        Run deep code analysis using Jadx/APKTool for Android.
        
        This goes beyond basic manifest analysis to find:
        - Hardcoded API keys in Java/Kotlin code
        - Insecure SharedPreferences usage
        - Weak cryptography implementations
        - SQL injection patterns
        - Sensitive data logging
        """
        try:
            from attacks.mobile.static.deep_code_scanner import (
                DeepCodeScanner, DeepScanConfig, FindingSeverity
            )
            
            self._log('info', 'Running Android deep code analysis (Jadx/APKTool)...')
            
            # Configure scanner
            config = DeepScanConfig(
                scan_resources=True,
                scan_smali=False,  # Faster without smali
                keep_decompiled=False,
                output_dir=self.config.output_dir
            )
            
            scanner = DeepCodeScanner(config)
            findings = await scanner.scan_apk(self.config.app_path)
            
            # Get summary
            summary = scanner.get_summary()
            
            if summary['total_findings'] > 0:
                self._log('info', f'Deep scan: {summary["total_findings"]} findings')
                self._log('info', f'  Critical: {summary["by_severity"].get("critical", 0)}, High: {summary["by_severity"].get("high", 0)}')
                
                # Convert to MobileVulnerability format
                for finding in findings:
                    try:
                        # Map severity
                        severity_map = {
                            FindingSeverity.CRITICAL: "critical",
                            FindingSeverity.HIGH: "high",
                            FindingSeverity.MEDIUM: "medium",
                            FindingSeverity.LOW: "low",
                            FindingSeverity.INFO: "info"
                        }
                        
                        self.context.vulnerabilities.append(MobileVulnerability(
                            id=finding.id,
                            category=finding.owasp_category,
                            severity=severity_map.get(finding.severity, "medium"),
                            title=finding.title,
                            description=finding.description,
                            affected_endpoint=finding.file_path,
                            poc=finding.code_snippet,
                            remediation=finding.remediation,
                            cwe_id=finding.cwe_id
                        ))
                    except Exception as e:
                        self._log('debug', f'Error processing deep finding: {e}')
                        continue
                
                self._log('success', 'Android deep code analysis completed')
            else:
                self._log('info', 'Android deep scan: No issues found (or Jadx/APKTool not available)')
                
        except ImportError as e:
            self._log('warning', f'Android deep code scanner not available: {e}')
        except Exception as e:
            self._log('warning', f'Android deep code scan failed: {e}')
            logger.exception('Android deep code scan error')
    
    async def _run_deep_code_scan_ios(self):
        """
        Run deep code analysis for iOS IPA files.
        
        This analyzes:
        - Binary strings for hardcoded secrets
        - Insecure Keychain/NSUserDefaults patterns
        - ATS (App Transport Security) configuration
        - URL scheme vulnerabilities
        - Binary protection (PIE, encryption)
        - Entitlements for dangerous capabilities
        """
        try:
            from attacks.mobile.static.ios_deep_scanner import (
                IOSDeepCodeScanner, IOSScanConfig, FindingSeverity
            )
            
            self._log('info', 'Running iOS deep code analysis...')
            
            # Configure scanner
            config = IOSScanConfig(
                extract_strings=True,
                analyze_binary=True,
                scan_resources=True,
                check_entitlements=True,
                keep_extracted=False
            )
            
            scanner = IOSDeepCodeScanner(config)
            findings = await scanner.scan_ipa(self.config.app_path)
            
            # Get summary and metadata
            summary = scanner.get_summary()
            metadata = scanner.get_metadata()
            
            if metadata.bundle_id:
                self.context.bundle_id = metadata.bundle_id
                self._log('info', f'App: {metadata.bundle_id} v{metadata.version}')
            
            if summary['total_findings'] > 0:
                self._log('info', f'iOS deep scan: {summary["total_findings"]} findings')
                self._log('info', f'  Critical: {summary["by_severity"].get("critical", 0)}, High: {summary["by_severity"].get("high", 0)}')
                
                # Log security features
                sec_features = summary.get('security_features', {})
                self._log('info', f'  PIE: {sec_features.get("pie_enabled", "N/A")}, ATS: {sec_features.get("ats_enabled", "N/A")}')
                
                # Convert to MobileVulnerability format
                for finding in findings:
                    try:
                        severity_map = {
                            FindingSeverity.CRITICAL: "critical",
                            FindingSeverity.HIGH: "high",
                            FindingSeverity.MEDIUM: "medium",
                            FindingSeverity.LOW: "low",
                            FindingSeverity.INFO: "info"
                        }
                        
                        self.context.vulnerabilities.append(MobileVulnerability(
                            id=finding.id,
                            category=finding.owasp_category,
                            severity=severity_map.get(finding.severity, "medium"),
                            title=finding.title,
                            description=finding.description,
                            affected_endpoint=finding.file_path,
                            poc=finding.code_snippet,
                            remediation=finding.remediation,
                            cwe_id=finding.cwe_id
                        ))
                    except Exception as e:
                        self._log('debug', f'Error processing iOS finding: {e}')
                        continue
                
                self._log('success', 'iOS deep code analysis completed')
            else:
                self._log('info', 'iOS deep scan: No issues found')
                
        except ImportError as e:
            self._log('warning', f'iOS deep code scanner not available: {e}')
        except Exception as e:
            self._log('warning', f'iOS deep code scan failed: {e}')
            logger.exception('iOS deep code scan error')
    
    async def _initialize_mitm_infrastructure(self):
        """Initialize MITM-first attack infrastructure (NEW)"""
        try:
            from core.mobile_request_store import MobileRequestStoreDB
            from core.mobile_http_client import MobileHTTPClient
            from attacks.mobile.dynamic.frida_request_bridge import FridaRequestBridge
            from attacks.mobile.api import MobileSQLiScanner, MobileIDORScanner, MobileXSSScanner
            
            # Initialize request store (SQLite-backed)
            db_path = Path(self.config.output_dir) / f"mobile_requests_{self.context.package_name or 'app'}.db"
            self.request_store = MobileRequestStoreDB(str(db_path))
            await self.request_store.initialize()
            
            # Initialize HTTP client (routes through MITM)
            self.http_client = MobileHTTPClient(
                request_store=self.request_store,
                proxy_host="127.0.0.1",
                proxy_port=self.config.mitm_port,
                app_package=self.context.package_name or self.context.bundle_id,
                platform=self.context.platform
            )
            await self.http_client.initialize()
            
            # Initialize Frida bridge (captures traffic to request store)
            self.frida_bridge = FridaRequestBridge(
                request_store=self.request_store,
                app_package=self.context.package_name or self.context.bundle_id,
                platform=self.context.platform,
                on_request_captured=self._on_frida_request,
                on_auth_captured=self._on_frida_auth
            )
            
            # Initialize scanners
            self._scanners = [
                MobileSQLiScanner(
                    http_client=self.http_client,
                    request_store=self.request_store,
                    max_payloads_per_param=10
                ),
                MobileIDORScanner(
                    http_client=self.http_client,
                    request_store=self.request_store,
                    test_user_token=self.context.auth_tokens.get('alt_user')
                ),
                MobileXSSScanner(
                    http_client=self.http_client,
                    request_store=self.request_store,
                    test_mobile_specific=True
                )
            ]
            
            self._log('success', 'MITM-first infrastructure initialized')
            return True
            
        except ImportError as e:
            self._log('warning', f'MITM infrastructure not available: {e}')
            return False
        except Exception as e:
            self._log('error', f'MITM infrastructure init failed: {e}')
            return False
    
    def _on_frida_request(self, request_id: str, url: str, method: str):
        """Callback when Frida captures a request"""
        self._log('traffic', f'{method} {url[:60]}...')
        if self._traffic_callback:
            self._traffic_callback('request', method, url)
    
    def _on_frida_auth(self, token_type: str, token_value: str):
        """Callback when Frida captures an auth token"""
        self._log('auth', f'Captured {token_type} token')
        self.context.auth_tokens[token_type] = token_value
    
    async def _run_api_attacks(self, authenticated: bool = False):
        """Run attacks on discovered API endpoints using MITM-first pipeline"""
        
        # Try new MITM-first approach first
        if self.request_store and self.http_client and self._scanners:
            await self._run_mitm_attacks(authenticated)
            return
        
        # Fallback to legacy web-style attacks
        await self._run_legacy_api_attacks(authenticated)
    
    async def _run_mitm_attacks(self, authenticated: bool = False):
        """Run mobile attack scanners via MITM pipeline (NEW)"""
        self._log('info', 'Running MITM-first mobile attacks...')
        
        try:
            # Get requests from store
            request_count = await self.request_store.get_request_count()
            self._log('info', f'Scanning {request_count} captured requests')
            
            for scanner in self._scanners:
                if not self._running:
                    break
                
                self._log('info', f'Running {scanner.scanner_name}...')
                
                try:
                    findings = await scanner.run(post_login=authenticated)
                    
                    for finding in findings:
                        self.context.vulnerabilities.append(MobileVulnerability(
                            id=finding.id,
                            category=finding.owasp_category,
                            severity=finding.severity,
                            title=finding.title,
                            description=finding.description,
                            affected_endpoint=finding.url,
                            method=finding.method,
                            parameter=finding.parameter,
                            evidence=finding.evidence,
                            request=finding.request,
                            response=finding.response,
                            poc=finding.payload,
                            cwe_id=finding.cwe_id
                        ))
                    
                    self._log('success', f'{scanner.scanner_name}: {len(findings)} findings')
                    
                except Exception as e:
                    self._log('warning', f'{scanner.scanner_name} failed: {e}')
            
        except Exception as e:
            self._log('error', f'MITM attacks failed: {e}')
            # Fallback to legacy
            await self._run_legacy_api_attacks(authenticated)
    
    async def _run_legacy_api_attacks(self, authenticated: bool = False):
        """Legacy: Run web-style attacks (fallback) + NEW sub-category scanners"""
        from attacks.web.pre_login import PreLoginAttacks
        
        # Convert mobile endpoints to web-style endpoints for attack modules
        web_endpoints = [
            {
                "url": ep.url,
                "method": ep.method,
                "params": ep.params,
                "headers": ep.headers
            }
            for ep in self.context.endpoints
            if not ep.requires_auth or authenticated
        ]
        
        if not web_endpoints:
            self._log('info', 'No endpoints to test')
            return
        
        # Create minimal context for web attack modules
        attack_config = {
            'target': {'url': list(self.context.base_urls)[0] if self.context.base_urls else ""},
            'rate_limit': 5,
            'attacks': {
                'owasp': {
                    'injection': True,
                    'auth': True,
                    'idor': authenticated,
                    'ssrf': True
                }
            }
        }
        
        # Run web-style attacks on mobile API endpoints
        pre_login = PreLoginAttacks(attack_config, {"endpoints": web_endpoints})
        
        try:
            results = await pre_login.run_all_scans()
            
            for result in results:
                self.context.vulnerabilities.append(MobileVulnerability(
                    id=result.id if hasattr(result, 'id') else "",
                    category=result.category if hasattr(result, 'category') else "",
                    severity=result.severity if hasattr(result, 'severity') else "medium",
                    title=result.title if hasattr(result, 'title') else "",
                    description=result.description if hasattr(result, 'description') else "",
                    affected_endpoint=result.url if hasattr(result, 'url') else "",
                    method=result.method if hasattr(result, 'method') else "",
                    parameter=result.parameter if hasattr(result, 'parameter') else "",
                    evidence=result.evidence if hasattr(result, 'evidence') else "",
                    poc=result.poc if hasattr(result, 'poc') else ""
                ))
        except Exception as e:
            self._log('warning', f'Legacy API attacks failed: {e}')
        
        # NEW: Run sub-category scanners (XSS reflected/stored/dom, SQLi variants, SSRF)
        await self._run_subcategory_attacks(web_endpoints, attack_config, authenticated)
    
    async def _run_subcategory_attacks(self, endpoints: list, config: dict, authenticated: bool):
        """Run NEW sub-category scanners for enhanced detection"""
        try:
            from attacks.scanner_adapter import SubCategoryScannerAdapter
            
            # Create a minimal context object for the scanners
            class MobileAPIContext:
                def __init__(self, target_url, endpoints):
                    self.target_url = target_url
                    self.crawl_results = [{'url': ep['url'], 'method': ep.get('method', 'GET')} for ep in endpoints]
            
            target = config.get('target', {}).get('url', '')
            context = MobileAPIContext(target, endpoints)
            
            adapter = SubCategoryScannerAdapter(config, context)
            findings = await adapter.run_all()
            
            for f in findings:
                self.context.vulnerabilities.append(MobileVulnerability(
                    id=f.id,
                    category=f.category,
                    severity=f.severity,
                    title=f.title,
                    description=f.description,
                    affected_endpoint=f.url,
                    method=f.method,
                    parameter=f.parameter,
                    evidence=f.evidence,
                    poc=f.poc,
                    cwe_id=f.cwe_id,
                    scanner_module=f"SubCategory-{f.sub_type}"
                ))
            
            if findings:
                self._log('success', f'Sub-category scanners: {len(findings)} findings')
                
        except ImportError as e:
            self._log('debug', f'Sub-category scanners not available: {e}')
        except Exception as e:
            self._log('warning', f'Sub-category attacks failed: {e}')
    
    
    async def _phase_authentication(self) -> bool:
        """Phase 6: Authenticate to the app with Dashboard 2FA/OTP integration"""
        self._log('phase', '[*]    Phase 6: Authentication')
        self._update_progress("authentication", 60, "Authenticating...")
        
        if not self.config.auth_enabled:
            self.context.auth_status = "not_required"
            return True
        
        try:
            from attacks.mobile.utils.otp_handler import (
                UsernamePasswordHandler, 
                SecureOTPHandler,
                OTPStatus,
                AuthSessionStatus
            )
            
            auth_type = self.config.auth_type
            
            if auth_type in ["email_password", "username_password"]:
                # Standard password authentication
                self.context.auth_status = "authenticating"
                
                # Create handler with config
                handler_config = {
                    'app_package': getattr(self.config, 'app_package', ''),
                    'device_id': self.config.device_id,
                }
                handler = UsernamePasswordHandler(handler_config)
                
                # Use user-provided login URL if available, otherwise auto-discover
                login_url = self.config.login_api_url if self.config.login_api_url else None
                
                if login_url:
                    self._log('info', f'Using user-provided login URL: {login_url}')
                else:
                    # Try to discover login API URL from captured traffic
                    login_url = await self._discover_login_endpoint()
                
                if not login_url:
                    self._log('warning', 'Login API endpoint not discovered from traffic')
                    self._log('info', 'Continuing with UI-based authentication instead')
                    # Fall back to manual/UI-based auth
                    self.context.auth_status = "manual_required"
                    return await self._handle_manual_auth()
                
                self._log('info', f'Attempting login via: {login_url}')
                
                session = await handler.login(
                    self.config.username,
                    self.config.password,
                    login_api_url=login_url
                )
                
                # Close the handler's HTTP session
                await handler.close()
                
                if session and session.status == AuthSessionStatus.AUTHENTICATED:
                    self.context.authenticated = True
                    # Use access_token (correct attribute name)
                    self.context.auth_tokens['session'] = session.access_token
                    self.context.auth_tokens['refresh'] = session.refresh_token
                    self.context.auth_status = "authenticated"
                    self._log('success', '[!]   Password authentication successful')
                    
                    # Check if 2FA/OTP is also required
                    if self.config.two_factor_enabled:
                        self._log('info', f'2FA enabled ({self.config.two_factor_type}), waiting for OTP...')
                        return await self._handle_otp_auth()
                    
                    return True
                else:
                    self._log('warning', 'API authentication failed, trying UI-based auth...')
                    return await self._handle_manual_auth()
                    
            elif auth_type == "phone_otp":
                # OTP flow - requires dashboard interaction
                return await self._handle_otp_auth()
                
            elif auth_type in ["google", "facebook", "apple"]:
                # Social login - requires manual auth via dashboard
                return await self._handle_social_auth(auth_type)
            
            elif auth_type == "manual":
                # User will authenticate manually via dashboard
                return await self._handle_manual_auth()
                
            else:
                self._log('warning', f'Unknown auth type: {auth_type}')
                if self.config.continue_on_auth_failure:
                    self._log('info', 'Continuing scan without authentication (continue_on_auth_failure=True)')
                    return True
                return False
                
        except ImportError as e:
            self._log('error', f'Auth handler not available: {e}')
            if self.config.continue_on_auth_failure:
                self._log('info', 'Continuing scan without authentication')
                return True
            return False
        except Exception as e:
            self._log('error', f'Authentication error: {e}')
            self.context.auth_status = "failed"
            if self.config.continue_on_auth_failure:
                self._log('warning', 'Continuing scan without authentication (continue_on_auth_failure=True)')
                return True
            self._log('error', 'Stopping scan due to authentication failure (continue_on_auth_failure=False)')
            return False
    
    async def _handle_otp_auth(self) -> bool:
        """Handle OTP-based authentication with dashboard polling"""
        from attacks.mobile.utils.otp_handler import SecureOTPHandler, OTPStatus
        import uuid
        
        otp_type = self.config.two_factor_type if self.config.two_factor_enabled else "sms"
        otp_type_labels = {"sms": "SMS", "email": "Email", "authenticator": "Authenticator App"}
        otp_label = otp_type_labels.get(otp_type, "OTP")
        
        self._log('info', f'OTP authentication ({otp_label}) - waiting for user input from dashboard...')
        
        # Generate OTP request ID
        otp_request_id = f"otp_{uuid.uuid4().hex[:16]}"
        self.context.otp_request_id = otp_request_id
        
        # Update status to notify dashboard
        self.context.auth_status = "waiting_for_otp"
        self._update_progress("authentication", 62, f"Waiting for {otp_label} code from dashboard...")
        
        # Notify via callback that OTP is needed
        if self._log_callback:
            message = f"Please enter the OTP code from your {otp_label}"
            if otp_type == "sms":
                message = f"Please enter the OTP sent to {self.config.phone or 'your phone'}"
            elif otp_type == "email":
                message = f"Please enter the OTP sent to your email"
            elif otp_type == "authenticator":
                message = "Please enter the code from your authenticator app"
                
            self._log('auth_required', json.dumps({
                "type": "otp",
                "otp_type": otp_type,
                "request_id": otp_request_id,
                "phone": self.config.phone or "",
                "message": message,
                "timeout": 180  # 3 minutes as promised in UI
            }))
        
        # Initialize OTP handler
        otp_handler = SecureOTPHandler(self.config.__dict__)
        
        # Poll for OTP from dashboard (via scan status endpoint)
        max_wait = 180  # 3 minutes timeout (as promised in UI)
        poll_interval = 2  # seconds
        elapsed = 0
        
        while elapsed < max_wait and self._running:
            # Check if OTP was provided via API
            otp_value = await self._check_for_otp_input(otp_request_id)
            
            if otp_value:
                self._log('info', 'OTP received, verifying...')
                self.context.auth_status = "verifying_otp"
                
                # Verify OTP with customer's backend
                verify_url = self.config.__dict__.get('otp_verify_url', '')
                if not verify_url:
                    # Try to discover verify endpoint from captured traffic
                    verify_url = self._find_otp_verify_endpoint()
                
                if verify_url:
                    session = await otp_handler.verify_otp(
                        request_id=otp_request_id,
                        otp_value=otp_value,  # Used once then discarded
                        phone_number=self.config.phone,
                        verify_api_url=verify_url
                    )
                    
                    if session.status.value == 'authenticated':
                        self.context.authenticated = True
                        self.context.auth_tokens['session'] = session.access_token
                        self.context.auth_status = "authenticated"
                        self._log('success', '[!]   OTP authentication successful')
                        await otp_handler.close()
                        return True
                    else:
                        self._log('warning', 'OTP verification failed')
                        # Allow retry
                        self.context.auth_status = "waiting_for_otp"
                        elapsed = 0  # Reset timer for retry
                else:
                    self._log('warning', 'OTP verify endpoint not configured')
            
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
            
            # Update progress
            remaining = max_wait - elapsed
            self._update_progress("authentication", 62, f"Waiting for OTP ({remaining}s remaining)...")
        
        # Timeout
        self._log('warning', 'OTP authentication timed out')
        self.context.auth_status = "timeout"
        await otp_handler.close()
        return False
    
    async def _handle_social_auth(self, provider: str) -> bool:
        """Handle social login (Google/Facebook/Apple) via dashboard"""
        import uuid
        
        self._log('info', f'{provider.title()} login - waiting for manual authentication...')
        
        # Generate auth request ID
        auth_request_id = f"social_{uuid.uuid4().hex[:16]}"
        self.context.otp_request_id = auth_request_id
        
        # Update status to notify dashboard
        self.context.auth_status = "waiting_for_manual_auth"
        self._update_progress("authentication", 62, f"Waiting for {provider} login from dashboard...")
        
        # Notify via callback that manual auth is needed
        if self._log_callback:
            self._log('auth_required', json.dumps({
                "type": "social",
                "provider": provider,
                "request_id": auth_request_id,
                "message": f"Please complete {provider.title()} login on the device/emulator",
                "timeout": 180
            }))
        
        # Poll for auth completion
        max_wait = 180  # 3 minutes for social login
        poll_interval = 3
        elapsed = 0
        
        while elapsed < max_wait and self._running:
            # Check if auth was completed (tokens captured by Frida)
            if self.context.auth_tokens.get('bearer') or self.context.auth_tokens.get('session'):
                self.context.authenticated = True
                self.context.auth_status = "authenticated"
                self._log('success', f'[!]   {provider.title()} authentication successful')
                return True
            
            # Also check for dashboard confirmation
            auth_confirmed = await self._check_for_auth_confirmation(auth_request_id)
            if auth_confirmed:
                self.context.authenticated = True
                self.context.auth_status = "authenticated"
                self._log('success', f'[!]   {provider.title()} authentication confirmed')
                return True
            
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
            
            remaining = max_wait - elapsed
            self._update_progress("authentication", 62, f"Waiting for {provider} login ({remaining}s)...")
        
        self._log('warning', f'{provider.title()} authentication timed out')
        self.context.auth_status = "timeout"
        return False
    
    async def _discover_login_endpoint(self) -> Optional[str]:
        """
        Try to discover the login API endpoint from captured traffic.
        Looks for common login patterns in intercepted requests.
        """
        try:
            # Common login endpoint patterns
            login_patterns = [
                '/login', '/signin', '/auth', '/authenticate',
                '/api/login', '/api/auth', '/api/signin',
                '/api/v1/login', '/api/v1/auth', '/api/v2/login',
                '/oauth/token', '/token', '/session',
                '/user/login', '/users/login', '/account/login'
            ]
            
            # Check captured requests from MITM proxy
            if self.request_store:
                requests = await self.request_store.get_all_requests()
                
                for req in requests:
                    url = req.get('url', '')
                    method = req.get('method', '').upper()
                    
                    # Only consider POST requests for login
                    if method != 'POST':
                        continue
                    
                    # Check if URL matches login patterns
                    url_lower = url.lower()
                    for pattern in login_patterns:
                        if pattern in url_lower:
                            self._log('info', f'Found potential login endpoint: {url}')
                            return url
            
            # Check Frida bridge captured requests
            if self.frida_bridge:
                captured = self.frida_bridge.get_captured_requests()
                for req in captured:
                    url = req.get('url', '')
                    method = req.get('method', '').upper()
                    
                    if method != 'POST':
                        continue
                    
                    url_lower = url.lower()
                    for pattern in login_patterns:
                        if pattern in url_lower:
                            self._log('info', f'Found potential login endpoint from Frida: {url}')
                            return url
            
            # If we have app_base_url from config, construct common login URLs
            base_url = getattr(self.config, 'app_base_url', None)
            if base_url:
                # Return a best-guess login URL
                return f"{base_url.rstrip('/')}/api/login"
            
            return None
            
        except Exception as e:
            self._log('warning', f'Error discovering login endpoint: {e}')
            return None
    
    async def _handle_manual_auth(self) -> bool:
        """Handle fully manual authentication via dashboard"""
        import uuid
        
        self._log('info', 'Manual authentication mode - waiting for user to login via dashboard...')
        
        auth_request_id = f"manual_{uuid.uuid4().hex[:16]}"
        self.context.otp_request_id = auth_request_id
        
        self.context.auth_status = "waiting_for_manual_auth"
        self._update_progress("authentication", 62, "Waiting for manual login from dashboard...")
        
        if self._log_callback:
            self._log('auth_required', json.dumps({
                "type": "manual",
                "request_id": auth_request_id,
                "message": "Please complete login on the device and click 'Continue' when done",
                "timeout": 300
            }))
        
        max_wait = 300  # 5 minutes for manual auth
        poll_interval = 3
        elapsed = 0
        
        while elapsed < max_wait and self._running:
            # Check for captured auth tokens from traffic
            if self.context.auth_tokens.get('bearer') or self.context.auth_tokens.get('session'):
                self.context.authenticated = True
                self.context.auth_status = "authenticated"
                self._log('success', '[!]   Authentication tokens captured - session active')
                return True
            
            # Check for dashboard confirmation
            auth_confirmed = await self._check_for_auth_confirmation(auth_request_id)
            if auth_confirmed:
                self.context.authenticated = True
                self.context.auth_status = "authenticated"
                self._log('success', '[!]   Manual authentication confirmed')
                return True
            
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        
        self._log('warning', 'Manual authentication timed out')
        self.context.auth_status = "timeout"
        return False
    
    async def _check_for_otp_input(self, request_id: str) -> Optional[str]:
        """Check if OTP was provided via API endpoint"""
        # This would be implemented by checking a shared state or API
        # The frontend submits OTP to /api/mobile/auth/submit-otp
        # which stores it temporarily for this request_id
        try:
            from services.mobile_service import get_pending_otp
            otp = await get_pending_otp(request_id)
            return otp
        except:
            return None
    
    async def _check_for_auth_confirmation(self, request_id: str) -> bool:
        """Check if auth was confirmed via dashboard"""
        try:
            from services.mobile_service import get_auth_confirmation
            return await get_auth_confirmation(request_id)
        except:
            return False
    
    def _find_otp_verify_endpoint(self) -> Optional[str]:
        """Find OTP verify endpoint from captured traffic patterns"""
        # Search captured endpoints for common OTP verify patterns
        otp_patterns = ['/verify', '/otp', '/auth/verify', '/login/verify']
        
        for endpoint in self.context.endpoints:
            for pattern in otp_patterns:
                if pattern in endpoint.path.lower() and endpoint.method == 'POST':
                    return endpoint.url
        
        return None
    
    async def _phase_post_auth_attacks(self) -> bool:
        """Phase 7: Run attacks on authenticated endpoints"""
        self._log('phase', '[>]     Phase 7: Post-Auth Attack Scanning')
        self._update_progress("post_auth_attacks", 70, "Running post-auth attacks...")
        
        try:
            # Run API attacks with auth
            await self._run_api_attacks(authenticated=True)
            
            # IDOR tests
            await self._test_idor()
            
            # Authorization tests
            await self._test_authorization()
            
            self._log('success', f'Post-auth scan complete')
            return True
            
        except Exception as e:
            self._log('warning', f'Post-auth attacks failed: {e}')
            return False
    
    async def _test_idor(self):
        """Test for Insecure Direct Object References"""
        self._log('info', 'Testing for IDOR vulnerabilities...')
        
        # Find endpoints with IDs
        idor_findings = []
        for endpoint in self.context.endpoints:
            if re.search(r'/\d+', endpoint.path) or re.search(r'[?&]id=\d+', endpoint.url):
                try:
                    # Test horizontal IDOR (user A accessing user B's resources)
                    idor_result = await self._test_idor_endpoint(endpoint)
                    if idor_result:
                        idor_findings.append(idor_result)
                except Exception as e:
                    self._log('debug', f'IDOR test error for {endpoint.url}: {e}')
        
        if idor_findings:
            self._log('warning', f'Found {len(idor_findings)} potential IDOR vulnerabilities')
            self.context.vulnerabilities.extend(idor_findings)
    
    async def _test_idor_endpoint(self, endpoint) -> Optional[MobileVulnerability]:
        """Test a single endpoint for IDOR"""
        # Extract ID from endpoint
        id_match = re.search(r'/(\d+)', endpoint.path) or re.search(r'[?&]id=(\d+)', endpoint.url)
        if not id_match:
            return None
        
        original_id = id_match.group(1)
        test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), '1', '999999']
        
        for test_id in test_ids:
            test_url = endpoint.url.replace(original_id, test_id)
            # Check if response differs (basic IDOR check)
            # In real implementation, would make HTTP request and check response
            # For now, flag as potential issue
            pass
        
        # Report potential IDOR if endpoint has ID parameter
        return MobileVulnerability(
            id=f"idor-{endpoint.id}",
            category="M4",  # Insufficient Input/Output Validation
            severity="high",
            title=f"Potential IDOR in {endpoint.method} {endpoint.path}",
            description=f"Endpoint {endpoint.url} contains ID parameter that may allow unauthorized access to other users' data.",
            affected_endpoint=endpoint.url,
            method=endpoint.method,
            evidence=f"Endpoint pattern: {endpoint.path}\nID parameter found: {original_id}",
            poc=f"Test with modified IDs: {', '.join(test_ids)}",
            remediation="Implement authorization checks to verify user owns the requested resource."
        )
    
    async def _test_authorization(self):
        """Test for authorization bypass"""
        self._log('info', 'Testing authorization...')
        
        # Test authenticated endpoints without auth
        auth_findings = []
        for endpoint in self.context.endpoints:
            if endpoint.requires_auth:
                try:
                    # Test if endpoint responds without auth headers
                    auth_result = await self._test_auth_bypass(endpoint)
                    if auth_result:
                        auth_findings.append(auth_result)
                except Exception as e:
                    self._log('debug', f'Auth test error for {endpoint.url}: {e}')
        
        if auth_findings:
            self._log('warning', f'Found {len(auth_findings)} authorization issues')
            self.context.vulnerabilities.extend(auth_findings)
    
    async def _test_auth_bypass(self, endpoint) -> Optional[MobileVulnerability]:
        """Test if authenticated endpoint allows unauthenticated access"""
        # In real implementation, would make request without auth tokens
        # For now, report as potential issue for manual verification
        return MobileVulnerability(
            id=f"auth-bypass-{endpoint.id}",
            category="M3",  # Insecure Authentication/Authorization
            severity="high",
            title=f"Check Authorization for {endpoint.method} {endpoint.path}",
            description=f"Endpoint {endpoint.url} requires authentication. Verify it properly validates auth tokens.",
            affected_endpoint=endpoint.url,
            method=endpoint.method,
            evidence=f"Endpoint marked as requiring authentication: {endpoint.auth_type}",
            poc="Test by removing Authorization header and retrying request.",
            remediation="Ensure all authenticated endpoints validate tokens and user permissions."
        )
    
    async def _phase_ai_analysis(self) -> bool:
        """Phase 8: AI-powered security analysis"""
        self._log('phase', '[*]    Phase 8: AI Security Analysis')
        self._update_progress("ai_analysis", 80, "Running AI analysis...")
        
        try:
            from attacks.mobile.utils.llm_analyzer import MobileLLMAnalyzer
            
            analyzer = MobileLLMAnalyzer(self.config.__dict__)
            
            # Prepare context for AI
            app_info = {
                "app_path": self.config.app_path,
                "platform": self.context.platform,
                "package_name": self.context.package_name,
                "endpoints_count": len(self.context.endpoints),
                "vulnerabilities_found": len(self.context.vulnerabilities),
                "base_urls": list(self.context.base_urls)
            }
            
            vulnerabilities = [asdict(v) for v in self.context.vulnerabilities[:20]]
            
            # Get AI recommendations
            recommendations = await analyzer.analyze_findings(app_info, vulnerabilities)
            
            if recommendations:
                self._log('success', f'AI generated {len(recommendations)} recommendations')
            
            return True
            
        except Exception as e:
            self._log('warning', f'AI analysis failed: {e}')
            return True
    
    async def _phase_reporting(self, result: Dict) -> str:
        """Phase 9: Generate final report"""
        self._log('phase', '[*]    Phase 9: Report Generation')
        self._update_progress("reporting", 90, "Generating report...")
        
        try:
            os.makedirs(self.config.output_dir, exist_ok=True)
            
            # Generate JSON report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            app_name = Path(self.config.app_path).stem
            
            json_path = Path(self.config.output_dir) / f"report_{app_name}_{timestamp}.json"
            html_path = Path(self.config.output_dir) / f"report_{app_name}_{timestamp}.html"
            
            with open(json_path, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            
            # Generate HTML report
            html_content = self._generate_html_report(result)
            with open(html_path, 'w') as f:
                f.write(html_content)
            
            self._log('success', f'Reports saved: {html_path}')
            
            return str(html_path)
            
        except Exception as e:
            self._log('error', f'Report generation failed: {e}')
            return ""
    
    def _generate_html_report(self, result: Dict) -> str:
        """Generate HTML report"""
        summary = result.get("summary", {})
        vulnerabilities = result.get("vulnerabilities", [])
        endpoints = result.get("endpoints", [])
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jarwis Mobile Security Report - {Path(self.config.app_path).stem}</title>
    <style>
        :root {{
            --bg-dark: #0f0f1a;
            --bg-card: #1a1a2e;
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --accent: #667eea;
            --critical: #ff4757;
            --high: #ff6b35;
            --medium: #ffd32a;
            --low: #3498db;
            --info: #2ecc71;
        }}
        
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        
        .container {{ max-width: 1400px; margin: 0 auto; }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
        }}
        
        .header h1 {{ margin: 0 0 10px 0; font-size: 2.5em; }}
        .header p {{ margin: 5px 0; opacity: 0.9; }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: var(--bg-card);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
        }}
        
        .summary-card h2 {{ font-size: 2.5em; margin: 0; }}
        .summary-card.critical {{ border-left: 4px solid var(--critical); }}
        .summary-card.high {{ border-left: 4px solid var(--high); }}
        .summary-card.medium {{ border-left: 4px solid var(--medium); }}
        .summary-card.low {{ border-left: 4px solid var(--low); }}
        .summary-card.info {{ border-left: 4px solid var(--info); }}
        
        .section {{
            background: var(--bg-card);
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 20px;
        }}
        
        .section h3 {{ margin-top: 0; color: var(--accent); }}
        
        .finding {{
            background: rgba(255,255,255,0.05);
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 4px solid var(--accent);
        }}
        
        .finding.critical {{ border-left-color: var(--critical); }}
        .finding.high {{ border-left-color: var(--high); }}
        .finding.medium {{ border-left-color: var(--medium); }}
        .finding.low {{ border-left-color: var(--low); }}
        
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-badge.critical {{ background: var(--critical); }}
        .severity-badge.high {{ background: var(--high); }}
        .severity-badge.medium {{ background: var(--medium); color: #333; }}
        .severity-badge.low {{ background: var(--low); }}
        .severity-badge.info {{ background: var(--info); }}
        
        .endpoint {{
            background: rgba(255,255,255,0.03);
            padding: 10px 15px;
            margin: 5px 0;
            border-radius: 6px;
            font-family: monospace;
        }}
        
        .method {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: bold;
            margin-right: 10px;
        }}
        
        .method.GET {{ background: #3498db; }}
        .method.POST {{ background: #2ecc71; }}
        .method.PUT {{ background: #f39c12; }}
        .method.DELETE {{ background: #e74c3c; }}
        
        pre {{
            background: #0a0a15;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
        }}
        
        code {{ font-family: 'Consolas', monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>[>]     Jarwis Mobile Security Report</h1>
            <p><strong>App:</strong> {Path(self.config.app_path).name}</p>
            <p><strong>Platform:</strong> {self.context.platform.upper()}</p>
            <p><strong>Package:</strong> {self.context.package_name or self.context.bundle_id}</p>
            <p><strong>Scan ID:</strong> {result.get("scan_id")} | <strong>Duration:</strong> {result.get("duration_seconds", 0):.1f}s</p>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card critical">
                <h2>{summary.get("critical", 0)}</h2>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h2>{summary.get("high", 0)}</h2>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h2>{summary.get("medium", 0)}</h2>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h2>{summary.get("low", 0)}</h2>
                <p>Low</p>
            </div>
            <div class="summary-card">
                <h2>{summary.get("total_endpoints", 0)}</h2>
                <p>Endpoints</p>
            </div>
        </div>
        
        <div class="section">
            <h3>[*]    Vulnerabilities ({summary.get("total_vulnerabilities", 0)})</h3>
'''
        
        # Add vulnerabilities
        for vuln in sorted(vulnerabilities, key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x.get('severity', 'info').lower()) if x.get('severity', 'info').lower() in ['critical', 'high', 'medium', 'low', 'info'] else 4):
            severity = vuln.get('severity', 'info').lower()
            html += f'''
            <div class="finding {severity}">
                <span class="severity-badge {severity}">{severity.upper()}</span>
                <strong style="font-size: 1.1em; margin-left: 10px;">{vuln.get('title', 'Unknown')}</strong>
                <p>{vuln.get('description', '')}</p>
                <p><strong>Category:</strong> {vuln.get('category', 'N/A')}</p>
                {f"<p><strong>Endpoint:</strong> {vuln.get('affected_endpoint', '')}</p>" if vuln.get('affected_endpoint') else ""}
                {f"<p><strong>PoC:</strong> <code>{vuln.get('poc', '')}</code></p>" if vuln.get('poc') else ""}
                {f"<p><strong>Remediation:</strong> {vuln.get('remediation', '')}</p>" if vuln.get('remediation') else ""}
            </div>
'''
        
        html += '''
        </div>
        
        <div class="section">
            <h3>[*]    Discovered API Endpoints</h3>
'''
        
        # Add endpoints
        for ep in endpoints[:50]:  # Limit to 50
            method = ep.get('method', 'GET')
            html += f'''
            <div class="endpoint">
                <span class="method {method}">{method}</span>
                <span>{ep.get('url', '')}</span>
            </div>
'''
        
        if len(endpoints) > 50:
            html += f'<p style="color: var(--text-secondary);">... and {len(endpoints) - 50} more endpoints</p>'
        
        html += '''
        </div>
        
        <div class="section">
            <h3>[*]    Base URLs Discovered</h3>
'''
        
        for url in summary.get('base_urls', []):
            html += f'<div class="endpoint">{url}</div>'
        
        html += f'''
        </div>
        
        <footer style="text-align: center; padding: 20px; color: var(--text-secondary);">
            <p>Generated by Jarwis AGI Pentest - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>
'''
        
        return html
    
    async def _cleanup(self, keep_emulator: bool = False):
        """
        Cleanup ALL resources properly.
        Called in finally block of run() or when scan is stopped.
        
        Args:
            keep_emulator: If True, don't stop the emulator (allows reuse)
        """
        self._log('info', 'Cleaning up mobile scan resources...')
        self._running = False
        
        # 1. Cleanup Frida bypass
        if self.frida_bypass:
            try:
                self.frida_bypass.cleanup()
                self._log('debug', 'Frida bypass cleaned up')
            except Exception as e:
                logger.error(f"Frida cleanup error: {e}")
        
        # 2. Kill Frida server on device
        if self.config.device_id or (self.emulator and self.emulator.status.device_id):
            device_id = self.config.device_id or self.emulator.status.device_id
            try:
                import subprocess
                subprocess.run(
                    ['adb', '-s', device_id, 'shell', 'pkill', '-f', 'frida-server'],
                    capture_output=True,
                    timeout=10
                )
                self._log('debug', f'Frida server killed on {device_id}')
            except Exception as e:
                logger.error(f"Failed to kill frida-server: {e}")
        
        # 3. Stop MITM proxy
        if self.mitm_proxy:
            try:
                if hasattr(self.mitm_proxy, 'shutdown'):
                    await self.mitm_proxy.shutdown()
                elif hasattr(self.mitm_proxy, 'stop'):
                    if asyncio.iscoroutinefunction(self.mitm_proxy.stop):
                        await self.mitm_proxy.stop()
                    else:
                        self.mitm_proxy.stop()
                self._log('debug', 'MITM proxy stopped')
            except Exception as e:
                logger.error(f"MITM proxy cleanup error: {e}")
        
        # 4. Stop crawler
        if self.crawler:
            try:
                if hasattr(self.crawler, 'stop'):
                    if asyncio.iscoroutinefunction(self.crawler.stop):
                        await self.crawler.stop()
                    else:
                        self.crawler.stop()
                self._log('debug', 'Mobile crawler stopped')
            except Exception as e:
                logger.error(f"Crawler cleanup error: {e}")
        
        # 5. Stop Frida bridge (NEW)
        if self.frida_bridge:
            try:
                self.frida_bridge.stop_listening()
                self._log('debug', 'Frida request bridge stopped')
            except Exception as e:
                logger.error(f"Frida bridge cleanup error: {e}")
        
        # 6. Close HTTP client (NEW)
        if self.http_client:
            try:
                await self.http_client.close()
                self._log('debug', 'Mobile HTTP client closed')
            except Exception as e:
                logger.error(f"HTTP client cleanup error: {e}")
        
        # 7. Close request store (NEW)
        if self.request_store:
            try:
                await self.request_store.close()
                self._log('debug', 'Mobile request store closed')
            except Exception as e:
                logger.error(f"Request store cleanup error: {e}")
        
        # 8. Stop Android emulator (unless keep_emulator is True)
        if self.emulator and not keep_emulator:
            try:
                await self.emulator.stop_emulator()
                self._log('debug', 'Android emulator stopped')
            except Exception as e:
                logger.error(f"Emulator stop error: {e}")
        elif self.emulator and keep_emulator:
            self._log('info', 'Keeping emulator running for potential reuse')
        
        # 9. Stop iOS simulator (unless keep_emulator is True)
        if self.simulator and not keep_emulator:
            try:
                if hasattr(self.simulator, 'stop'):
                    if asyncio.iscoroutinefunction(self.simulator.stop):
                        await self.simulator.stop()
                    else:
                        self.simulator.stop()
                self._log('debug', 'iOS simulator stopped')
            except Exception as e:
                logger.error(f"Simulator stop error: {e}")
        elif self.simulator and keep_emulator:
            self._log('info', 'Keeping iOS simulator running for potential reuse')
        
        # 7. Unregister from MobileProcessRegistry
        try:
            from core.mobile_process_registry import MobileProcessRegistry
            # Try to find and unregister this orchestrator's scan
            for scan_id in MobileProcessRegistry.get_active_scans():
                process = await MobileProcessRegistry.get(scan_id)
                if process and process.orchestrator is self:
                    await MobileProcessRegistry.unregister(scan_id)
                    self._log('debug', f'Unregistered from MobileProcessRegistry: {scan_id}')
                    break
        except Exception as e:
            logger.debug(f"MobileProcessRegistry unregister error (may be expected): {e}")
        
        self._log('info', 'Mobile scan cleanup completed')
    
    async def _get_package_name(self) -> str:
        """Get package name from APK"""
        try:
            import subprocess
            result = subprocess.run(
                ['aapt', 'dump', 'badging', self.config.app_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            match = re.search(r"package: name='([^']+)'", result.stdout)
            if match:
                return match.group(1)
        except:
            pass
        
        return ""
    
    async def _get_bundle_id(self) -> str:
        """Get bundle ID from IPA"""
        import zipfile
        import plistlib
        
        try:
            with zipfile.ZipFile(self.config.app_path, 'r') as zf:
                for name in zf.namelist():
                    if 'Info.plist' in name and 'Payload' in name:
                        with zf.open(name) as plist_file:
                            info = plistlib.load(plist_file)
                            return info.get('CFBundleIdentifier', '')
        except:
            pass
        
        return ""
    
    def _on_traffic_intercepted(self, request):
        """Handle intercepted traffic"""
        entry = {
            "timestamp": request.timestamp,
            "method": request.method,
            "url": request.url,
            "host": request.host,
            "request": self._format_burp_request(request),
            "response": self._format_burp_response(request)
        }
        
        self.context.traffic_log.append(entry)
        
        if self._traffic_callback:
            self._traffic_callback(entry)
    
    def _format_burp_request(self, request) -> str:
        """Format request in Burp style"""
        from urllib.parse import urlparse
        parsed = urlparse(request.url)
        
        lines = [
            f"{request.method} {parsed.path or '/'} HTTP/1.1",
            f"Host: {request.host}"
        ]
        
        for key, value in request.headers.items():
            lines.append(f"{key}: {value}")
        
        if request.body:
            lines.append("")
            lines.append(request.body)
        
        return "\n".join(lines)
    
    def _format_burp_response(self, request) -> str:
        """Format response in Burp style"""
        lines = [f"HTTP/1.1 {request.response_code} OK"]
        
        if request.response_body:
            lines.append("")
            lines.append(request.response_body)
        
        return "\n".join(lines)


# Convenience function
async def run_mobile_pentest(
    app_path: str,
    frida_bypass: bool = True,
    crawl: bool = True,
    auth_config: Dict = None,
    output_dir: str = "reports/mobile"
) -> Dict:
    """
    Run a complete mobile penetration test
    
    Args:
        app_path: Path to APK or IPA file
        frida_bypass: Enable SSL pinning bypass
        crawl: Enable app crawling
        auth_config: Authentication configuration
        output_dir: Output directory for reports
        
    Returns:
        Scan results dictionary
    """
    config = MobileScanConfig(
        app_path=app_path,
        frida_bypass_enabled=frida_bypass,
        crawl_enabled=crawl,
        output_dir=output_dir
    )
    
    if auth_config:
        config.auth_enabled = True
        config.auth_type = auth_config.get('type', '')
        config.username = auth_config.get('username', '')
        config.password = auth_config.get('password', '')
    
    orchestrator = MobilePenTestOrchestrator(config)
    return await orchestrator.run()


def create_mobile_orchestrator(config: Dict) -> MobilePenTestOrchestrator:
    """Create mobile orchestrator from config dict"""
    scan_config = MobileScanConfig(**config)
    return MobilePenTestOrchestrator(scan_config)
