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
    """Vulnerability finding from mobile testing"""
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
    cvss_score: float = 0.0


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
            
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            self._log('error', f'Scan failed: {e}')
            logger.exception(f"Mobile scan failed: {e}")
        
        finally:
            await self._cleanup()
        
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
            return False
    
    async def _setup_android(self) -> bool:
        """Setup Android emulator or device"""
        from .emulator_manager import EmulatorManager, EmulatorConfig
        
        self.emulator = EmulatorManager()
        status = self.emulator.get_status()
        
        # Check for connected device first
        if self.config.device_id:
            self._log('info', f'Using specified device: {self.config.device_id}')
            return True
        
        # Check ADB for devices
        try:
            import subprocess
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=5)
            devices = [l.split('\t')[0] for l in result.stdout.split('\n')[1:] if '\tdevice' in l]
            
            if devices:
                self._log('info', f'Using connected device: {devices[0]}')
                self.config.device_id = devices[0]
                return True
        except:
            pass
        
        # Use emulator
        if self.config.use_emulator:
            if not status['running']:
                self._log('info', 'Starting Android emulator...')
                
                config = EmulatorConfig(headless=self.config.headless)
                
                if not status['emulator_installed']:
                    self._log('info', 'Emulator not found. Please run setup_emulator.py first')
                    return False
                
                await self.emulator.start_emulator(headless=self.config.headless)
            
            self._log('success', f'Emulator ready: {status.get("device_id", "emulator")}')
            return True
        
        self._log('warning', 'No device available')
        return False
    
    async def _setup_ios(self) -> bool:
        """Setup iOS simulator or device"""
        from .ios_simulator_manager import IOSSimulatorManager, SimulatorConfig
        
        self.simulator = IOSSimulatorManager()
        status = self.simulator.get_status()
        
        if not status['is_macos']:
            self._log('warning', 'iOS testing requires macOS with Xcode')
            return False
        
        if self.config.use_emulator:
            if not status['running']:
                self._log('info', 'Starting iOS Simulator...')
                await self.simulator.full_setup()
            
            self._log('success', f'iOS Simulator ready')
            return True
        
        return False
    
    async def _phase_ssl_bypass(self) -> bool:
        """Phase 2: Bypass SSL pinning using Frida"""
        self._log('phase', '[*]    Phase 2: SSL Pinning Bypass')
        self._update_progress("ssl_bypass", 15, "Bypassing SSL pinning...")
        
        try:
            from .frida_ssl_bypass import FridaSSLBypass
            
            self.frida_bypass = FridaSSLBypass()
            self.frida_bypass.set_log_callback(self._log)
            self.frida_bypass.set_request_callback(self._on_traffic_intercepted)
            
            # Connect to device
            await self.frida_bypass.connect_device(self.config.device_id)
            
            # Get package name
            if not self.context.package_name:
                self.context.package_name = await self._get_package_name()
            
            if not self.context.package_name:
                self._log('warning', 'Could not determine package name, SSL bypass will attach after app launch')
                return True
            
            # Attach and bypass
            result = await self.frida_bypass.attach_and_bypass(
                self.context.package_name,
                platform=self.context.platform,
                spawn=True
            )
            
            if result.success:
                self._log('success', f'[!]   SSL bypass active: {len(result.libraries_bypassed)} libraries bypassed')
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
            from .emulator_manager import EmulatorManager
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
            from .ios_simulator_manager import IOSSimulatorManager
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
            from .dynamic_crawler import DynamicAppCrawler
            
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
            from .app_crawler import MobileAppCrawler
            
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
        """Run static analysis attack modules"""
        if self.context.platform == "android":
            from .android_attacks import AndroidAttackScanner
            scanner = AndroidAttackScanner()
        else:
            from .ios_attacks import IOSAttackScanner
            scanner = IOSAttackScanner()
        
        # Run scanner
        findings = await scanner.scan({}, self.config.app_path)
        
        for finding in findings:
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
    
    async def _run_api_attacks(self, authenticated: bool = False):
        """Run attacks on discovered API endpoints"""
        from attacks.pre_login import PreLoginAttacks
        
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
            self._log('warning', f'API attacks failed: {e}')
        
        # Run Mobile POST Method Scanner for comprehensive POST testing
        try:
            from .mobile_post_scanner import MobilePostMethodScanner
            
            post_scanner = MobilePostMethodScanner(
                config={'platform': self.context.platform},
                context=self.context,
                callback=self._log
            )
            
            post_findings = await post_scanner.scan(web_endpoints)
            
            for finding in post_findings:
                self.context.vulnerabilities.append(MobileVulnerability(
                    id=finding.id,
                    category=finding.category,
                    severity=finding.severity,
                    title=finding.title,
                    description=finding.description,
                    affected_endpoint=finding.url,
                    method=finding.method,
                    parameter=finding.parameter,
                    evidence=finding.evidence,
                    poc=finding.poc,
                    remediation=finding.remediation,
                    cwe_id=finding.cwe_id
                ))
            
            # Store captured traffic for reporting
            if hasattr(self.context, 'traffic_log'):
                self.context.traffic_log.extend(post_scanner.get_captured_traffic())
            
            self._log('info', f'Mobile POST scan: {len(post_findings)} additional findings')
            
        except Exception as e:
            self._log('warning', f'Mobile POST scanner failed: {e}')
    
    async def _phase_authentication(self) -> bool:
        """Phase 6: Authenticate to the app"""
        self._log('phase', '[*]    Phase 6: Authentication')
        self._update_progress("authentication", 60, "Authenticating...")
        
        if not self.config.auth_enabled:
            return True
        
        try:
            from .otp_handler import UsernamePasswordHandler, SecureOTPHandler
            
            auth_type = self.config.auth_type
            
            if auth_type in ["email_password", "username_password"]:
                handler = UsernamePasswordHandler()
                
                session = await handler.login(
                    self.config.username,
                    self.config.password
                )
                
                if session and session.status.value == 'authenticated':
                    self.context.authenticated = True
                    self.context.auth_tokens['session'] = session.token
                    self._log('success', '[!]   Authentication successful')
                    return True
                else:
                    self._log('error', 'Authentication failed')
                    return False
                    
            elif auth_type == "phone_otp":
                # OTP flow requires user interaction
                self._log('info', 'OTP authentication requires manual input')
                return True
                
            else:
                self._log('warning', f'Unknown auth type: {auth_type}')
                return False
                
        except Exception as e:
            self._log('error', f'Authentication failed: {e}')
            return False
    
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
        for endpoint in self.context.endpoints:
            if re.search(r'/\d+', endpoint.path) or re.search(r'[?&]id=\d+', endpoint.url):
                # TODO: Implement IDOR testing
                pass
    
    async def _test_authorization(self):
        """Test for authorization bypass"""
        self._log('info', 'Testing authorization...')
        # TODO: Implement authorization testing
    
    async def _phase_ai_analysis(self) -> bool:
        """Phase 8: AI-powered security analysis"""
        self._log('phase', '[*]    Phase 8: AI Security Analysis')
        self._update_progress("ai_analysis", 80, "Running AI analysis...")
        
        try:
            from .llm_analyzer import MobileLLMAnalyzer
            
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
    
    async def _cleanup(self):
        """Cleanup resources"""
        if self.frida_bypass:
            self.frida_bypass.cleanup()
        
        self._running = False
    
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
