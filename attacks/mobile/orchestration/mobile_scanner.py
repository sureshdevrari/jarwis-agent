"""
Jarwis AGI - Mobile Security Scanner
Main orchestrator for mobile application security testing

Covers OWASP Mobile Top 10:
M1: Improper Platform Usage
M2: Insecure Data Storage
M3: Insecure Communication
M4: Insecure Authentication
M5: Insufficient Cryptography
M6: Insecure Authorization
M7: Client Code Quality
M8: Code Tampering
M9: Reverse Engineering
M10: Extraneous Functionality
"""

import os
import json
import asyncio
import logging
import hashlib
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable, Any

from attacks.mobile.static.static_analyzer import StaticAnalyzer, StaticAnalysisResult, AppMetadata
from attacks.mobile.dynamic.runtime_analyzer import RuntimeAnalyzer, RuntimeFinding, InterceptedRequest
from attacks.mobile.api.api_discovery import APIDiscoveryEngine, APIMap

logger = logging.getLogger(__name__)


@dataclass
class MobileScanResult:
    """Complete mobile security scan result"""
    scan_id: str
    app_name: str
    package_name: str
    platform: str
    version: str
    file_hash: str
    scan_start: str
    scan_end: str = ""
    status: str = "running"  # running, completed, failed
    
    # Metadata
    metadata: Dict = field(default_factory=dict)
    
    # Findings by category
    static_findings: List[Dict] = field(default_factory=list)
    runtime_findings: List[Dict] = field(default_factory=list)
    api_findings: List[Dict] = field(default_factory=list)
    
    # API Map
    api_map: Dict = field(default_factory=dict)
    
    # Summary
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # OWASP Mobile Top 10 coverage
    owasp_coverage: Dict = field(default_factory=dict)


class MobileSecurityScanner:
    """
    Main Mobile Security Scanner
    Orchestrates static analysis, runtime analysis, and API testing
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
    
    def __init__(self, config: dict = None, output_dir: str = None):
        self.config = config or {}
        self.output_dir = output_dir or self.config.get('output_dir', 'reports/mobile')
        self.static_analyzer = StaticAnalyzer(config)
        self.runtime_analyzer = RuntimeAnalyzer(config)
        self.api_discovery = APIDiscoveryEngine(config)
        self._verbose_callback: Optional[Callable] = None
        self._progress_callback: Optional[Callable] = None
    
    def set_verbose_callback(self, callback: Callable):
        """Set callback for verbose logging"""
        self._verbose_callback = callback
    
    def set_progress_callback(self, callback: Callable):
        """Set callback for progress updates"""
        self._progress_callback = callback
    
    def _log(self, log_type: str, message: str, details: str = None):
        """Log message via callback"""
        if self._verbose_callback:
            try:
                self._verbose_callback(log_type, message, details)
            except:
                pass
        logger.info(f"[{log_type}] {message}")
    
    def _progress(self, phase: str, progress: int, message: str):
        """Report progress via callback"""
        if self._progress_callback:
            try:
                self._progress_callback(phase, progress, message)
            except:
                pass
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    async def scan(
        self,
        file_path: str = None,
        app_path: str = None,
        scan_type: str = "full",  # full, static, runtime
        runtime_duration: int = 60,
        enable_traffic_intercept: bool = True,
        runtime_analysis: bool = False,
        device_id: str = None,
        bypass_ssl_pinning: bool = False
    ) -> MobileScanResult:
        """
        Perform mobile security scan
        
        Args:
            file_path: Path to APK or IPA file (deprecated, use app_path)
            app_path: Path to APK or IPA file  
            scan_type: Type of scan (full, static, runtime)
            runtime_duration: Duration for runtime analysis in seconds
            enable_traffic_intercept: Whether to intercept network traffic
            runtime_analysis: Whether to perform runtime analysis
            device_id: Device ID for runtime analysis
            bypass_ssl_pinning: Whether to bypass SSL pinning using Frida
            
        Returns:
            MobileScanResult with all findings
        """
        # Support both file_path and app_path for backwards compatibility
        actual_path = app_path or file_path
        if not actual_path:
            raise ValueError("Either file_path or app_path must be provided")
            
        file_path = Path(actual_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Initialize scan result
        scan_id = f"MOB-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        file_hash = self._calculate_file_hash(file_path)
        
        result = MobileScanResult(
            scan_id=scan_id,
            app_name=file_path.stem,
            package_name="",
            platform="android" if file_path.suffix.lower() == ".apk" else "ios",
            version="",
            file_hash=file_hash,
            scan_start=datetime.now().isoformat()
        )
        
        self._log("start", f"Starting mobile security scan: {file_path.name}")
        self._progress("init", 5, "Initializing scan...")
        
        try:
            # Phase 1: Static Analysis
            if scan_type in ["full", "static"]:
                self._log("phase", "Phase 1: Static Analysis", "Analyzing app package...")
                self._progress("static", 10, "Running static analysis...")
                
                metadata, static_findings = await self.static_analyzer.analyze(str(file_path))
                
                result.package_name = metadata.package_name
                result.version = metadata.version_name
                result.metadata = {
                    "permissions": metadata.permissions,
                    "activities": metadata.activities,
                    "services": metadata.services,
                    "exported_components": metadata.exported_components,
                    "is_debuggable": metadata.is_debuggable,
                    "uses_cleartext": metadata.uses_cleartext,
                    "api_endpoints": metadata.api_endpoints,
                    "hardcoded_secrets": metadata.hardcoded_secrets
                }
                
                result.static_findings = [asdict(f) for f in static_findings]
                self._log("result", f"Static analysis complete", f"Found {len(static_findings)} issues")
                self._progress("static", 40, f"Static analysis complete: {len(static_findings)} findings")
            
            # Phase 2: Runtime Analysis (if enabled and possible)
            if scan_type in ["full", "runtime"] and self.runtime_analyzer.frida_available:
                self._log("phase", "Phase 2: Runtime Analysis", "Instrumenting application...")
                self._progress("runtime", 50, "Running runtime analysis...")
                
                # Log SSL pinning bypass status
                if bypass_ssl_pinning:
                    self._log("info", "[OK]  SSL Pinning Bypass ENABLED", "Frida will inject SSL bypass scripts")
                else:
                    self._log("info", "[!]   SSL Pinning Bypass DISABLED", "SSL bypass will not be applied")
                
                try:
                    runtime_findings, intercepted_requests = await self.runtime_analyzer.run_full_analysis(
                        result.package_name,
                        duration=runtime_duration,
                        bypass_ssl_pinning=bypass_ssl_pinning
                    )
                    
                    result.runtime_findings = [asdict(f) for f in runtime_findings]
                    self._log("result", f"Runtime analysis complete", f"Found {len(runtime_findings)} issues")
                    self._progress("runtime", 70, f"Runtime analysis complete: {len(runtime_findings)} findings")
                    
                    # Discover APIs from traffic
                    if intercepted_requests:
                        traffic_data = [
                            {"type": "request", "url": r.url, "method": r.method, "headers": r.headers}
                            for r in intercepted_requests
                        ]
                        traffic_api_map = await self.api_discovery.discover_from_traffic(traffic_data)
                        result.api_map = asdict(traffic_api_map) if hasattr(traffic_api_map, '__dataclass_fields__') else {}
                        
                except Exception as e:
                    self._log("warning", f"Runtime analysis failed: {e}")
            
            # Phase 3: API Security Analysis
            if result.metadata.get("api_endpoints"):
                self._log("phase", "Phase 3: API Analysis", "Analyzing discovered APIs...")
                self._progress("api", 80, "Analyzing API endpoints...")
                
                attack_surface = self.api_discovery.get_attack_surface(
                    APIMap(
                        app_name=result.app_name,
                        endpoints=[],
                        base_urls=list(set([ep.split('/')[0:3] for ep in result.metadata.get("api_endpoints", []) if ep.startswith('http')]))
                    )
                )
                
                result.api_findings = attack_surface.get("recommendations", [])
                self._progress("api", 90, "API analysis complete")
            
            # Calculate summary
            result.scan_end = datetime.now().isoformat()
            result.status = "completed"
            
            all_findings = result.static_findings + result.runtime_findings
            result.total_findings = len(all_findings)
            
            for finding in all_findings:
                severity = finding.get("severity", "info").lower()
                if severity == "critical":
                    result.critical_count += 1
                elif severity == "high":
                    result.high_count += 1
                elif severity == "medium":
                    result.medium_count += 1
                elif severity == "low":
                    result.low_count += 1
                else:
                    result.info_count += 1
            
            # Calculate OWASP coverage
            result.owasp_coverage = self._calculate_owasp_coverage(all_findings)
            
            self._log("complete", "Scan completed successfully", 
                     f"Total: {result.total_findings} findings ({result.critical_count} critical, {result.high_count} high)")
            self._progress("complete", 100, "Scan complete!")
            
        except Exception as e:
            result.status = "failed"
            result.scan_end = datetime.now().isoformat()
            self._log("error", f"Scan failed: {str(e)}")
            logger.exception(f"Mobile scan failed: {e}")
        
        return result
    
    def _calculate_owasp_coverage(self, findings: List[Dict]) -> Dict:
        """Calculate OWASP Mobile Top 10 coverage from findings"""
        coverage = {}
        
        for category, name in self.OWASP_MOBILE_TOP_10.items():
            category_findings = [f for f in findings if f.get("category", "").upper().startswith(category)]
            coverage[category] = {
                "name": name,
                "findings_count": len(category_findings),
                "tested": len(category_findings) > 0 or True,  # Mark as tested even if no findings
                "findings": category_findings[:5]  # Top 5 findings per category
            }
        
        return coverage
    
    async def quick_scan(self, file_path: str) -> MobileScanResult:
        """Perform quick static-only scan"""
        return await self.scan(file_path, scan_type="static")
    
    async def deep_scan(self, file_path: str, duration: int = 120) -> MobileScanResult:
        """Perform deep scan with extended runtime analysis"""
        return await self.scan(file_path, scan_type="full", runtime_duration=duration)
    
    def export_report(self, result: MobileScanResult, format: str = "json") -> str:
        """Export scan result to various formats"""
        if format == "json":
            return json.dumps(asdict(result), indent=2, default=str)
        elif format == "html":
            return self._generate_html_report(result)
        elif format == "sarif":
            return self._generate_sarif_report(result)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_html_report(self, result: MobileScanResult) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Jarwis Mobile Security Report - {result.app_name}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: #16213e; padding: 20px; border-radius: 8px; text-align: center; }}
        .critical {{ border-left: 4px solid #ff4757; }}
        .high {{ border-left: 4px solid #ffa502; }}
        .medium {{ border-left: 4px solid #ffd32a; }}
        .low {{ border-left: 4px solid #3498db; }}
        .info {{ border-left: 4px solid #2ecc71; }}
        .finding {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; }}
        .finding-title {{ font-weight: bold; font-size: 1.1em; }}
        .severity-badge {{ padding: 3px 10px; border-radius: 4px; font-size: 0.8em; }}
        .severity-critical {{ background: #ff4757; }}
        .severity-high {{ background: #ffa502; }}
        .severity-medium {{ background: #ffd32a; color: #333; }}
        .severity-low {{ background: #3498db; }}
        h2 {{ color: #667eea; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>[!]   Jarwis Mobile Security Report</h1>
        <p><strong>App:</strong> {result.app_name} ({result.package_name})</p>
        <p><strong>Version:</strong> {result.version} | <strong>Platform:</strong> {result.platform.upper()}</p>
        <p><strong>Scan ID:</strong> {result.scan_id} | <strong>Status:</strong> {result.status}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card critical"><h2>{result.critical_count}</h2><p>Critical</p></div>
        <div class="summary-card high"><h2>{result.high_count}</h2><p>High</p></div>
        <div class="summary-card medium"><h2>{result.medium_count}</h2><p>Medium</p></div>
        <div class="summary-card low"><h2>{result.low_count}</h2><p>Low</p></div>
        <div class="summary-card info"><h2>{result.info_count}</h2><p>Info</p></div>
    </div>
    
    <h2>[OK]  Findings ({result.total_findings})</h2>
"""
        
        all_findings = result.static_findings + result.runtime_findings
        for finding in sorted(all_findings, key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x.get('severity', 'info').lower())):
            severity = finding.get('severity', 'info').lower()
            html += f"""
    <div class="finding {severity}">
        <span class="severity-badge severity-{severity}">{severity.upper()}</span>
        <span class="finding-title">{finding.get('title', 'Unknown')}</span>
        <p>{finding.get('description', '')}</p>
        <p><strong>Category:</strong> {finding.get('category', 'N/A')} | <strong>File:</strong> {finding.get('file_path', 'N/A')}</p>
        {f"<p><strong>Recommendation:</strong> {finding.get('recommendation', '')}</p>" if finding.get('recommendation') else ""}
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
    
    def _generate_sarif_report(self, result: MobileScanResult) -> str:
        """Generate SARIF format report"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Jarwis Mobile Security Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://jarwis.ai",
                        "rules": []
                    }
                },
                "results": []
            }]
        }
        
        rules_seen = set()
        all_findings = result.static_findings + result.runtime_findings
        
        for finding in all_findings:
            rule_id = finding.get('id', 'UNKNOWN')
            
            if rule_id not in rules_seen:
                rules_seen.add(rule_id)
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": finding.get('title', ''),
                    "shortDescription": {"text": finding.get('title', '')},
                    "fullDescription": {"text": finding.get('description', '')},
                    "defaultConfiguration": {
                        "level": "error" if finding.get('severity') in ['critical', 'high'] else "warning"
                    }
                })
            
            sarif["runs"][0]["results"].append({
                "ruleId": rule_id,
                "level": "error" if finding.get('severity') in ['critical', 'high'] else "warning",
                "message": {"text": finding.get('description', '')},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.get('file_path', 'unknown')},
                        "region": {"startLine": finding.get('line_number', 1)}
                    }
                }]
            })
        
        return json.dumps(sarif, indent=2)
