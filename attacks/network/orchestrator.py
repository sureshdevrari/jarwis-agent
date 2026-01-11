"""
Jarwis Network Security - Phase Orchestrator

Coordinates network security tools across scanning phases:
1. DISCOVERY - Find live hosts (Netdiscover, ARP-scan)
2. PORT_SCAN - Find open ports (Nmap, Masscan, RustScan)
3. SERVICE_ENUM - Identify services (Nmap -sV, SNMP, DNS)
4. VULN_SCAN - Find vulnerabilities (Nuclei, OpenVAS, Vulners)
5. SSL_AUDIT - TLS configuration (SSLScan, testssl, SSLyze)
6. CREDENTIAL - Authenticated testing (if creds provided)
7. EXPLOITATION - Verification (CME, Impacket, Metasploit)
8. TRAFFIC_ANALYSIS - Passive analysis (Zeek, Suricata)

The orchestrator intelligently selects tools based on:
- Target type (IP, subnet, domain)
- Scan profile (quick, standard, comprehensive, stealth)
- Available tools on system
- Previous phase results
"""

import asyncio
import logging
import shutil
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Any
from datetime import datetime

from .base import ScanPhase, ScanResult, Finding, Severity, ScannerRegistry as NetworkScannerRegistry
# Import scanners to trigger decorator registration
from .scanners import ALL_SCANNERS

logger = logging.getLogger(__name__)


class ScanProfile(str, Enum):
    """Predefined scan profiles"""
    QUICK = "quick"           # Fast discovery + top ports
    STANDARD = "standard"     # Full port scan + vulns
    COMPREHENSIVE = "comprehensive"  # Everything
    STEALTH = "stealth"       # Low and slow
    CREDENTIAL = "credential" # Authenticated only
    WEB = "web"              # Web-focused (ports 80, 443, 8080, etc.)
    INTERNAL = "internal"     # Internal network focus


@dataclass
class ScanState:
    """Tracks scan state across phases"""
    target: str
    profile: ScanProfile
    live_hosts: Set[str] = field(default_factory=set)
    open_ports: Dict[str, List[int]] = field(default_factory=dict)
    services: Dict[str, Dict[int, str]] = field(default_factory=dict)
    ssl_ports: Dict[str, List[int]] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    results: Dict[str, List[ScanResult]] = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.now)
    completed_phases: List[ScanPhase] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    # Credentials for authenticated scanning
    ssh_creds: Optional[Dict] = None
    windows_creds: Optional[Dict] = None
    snmp_creds: Optional[Dict] = None
    db_creds: Optional[Dict] = None


@dataclass
class PhaseConfig:
    """Configuration for a scan phase"""
    phase: ScanPhase
    scanners: List[str]  # Scanner names (not classes)
    enabled: bool = True
    timeout: int = 300
    parallel: bool = False
    depends_on: List[ScanPhase] = field(default_factory=list)


class NetworkOrchestrator:
    """
    Main orchestrator for network security scanning.
    
    Runs tools in organized phases, passing results forward
    and making intelligent decisions about what to scan next.
    """
    
    # Default phase configurations (using scanner names for registry lookup)
    PHASE_CONFIG = {
        ScanProfile.QUICK: [
            PhaseConfig(ScanPhase.DISCOVERY, ["ARPScanScanner", "NetdiscoverScanner"], timeout=60),
            PhaseConfig(ScanPhase.PORT_SCAN, ["MasscanScanner"], timeout=120),
            PhaseConfig(ScanPhase.SERVICE_ENUM, ["NmapScanner"], timeout=180),
        ],
        ScanProfile.STANDARD: [
            PhaseConfig(ScanPhase.DISCOVERY, ["ARPScanScanner", "NetdiscoverScanner"], timeout=120),
            PhaseConfig(ScanPhase.PORT_SCAN, ["NmapScanner"], timeout=300),
            PhaseConfig(ScanPhase.SERVICE_ENUM, ["NmapScanner", "DNSReconScanner"], timeout=300),
            PhaseConfig(ScanPhase.VULN_SCAN, ["NucleiScanner", "VulnersNmapScanner"], timeout=600),
            PhaseConfig(ScanPhase.SSL_AUDIT, ["SSLyzeScanner"], timeout=300),
        ],
        ScanProfile.COMPREHENSIVE: [
            PhaseConfig(ScanPhase.DISCOVERY, ["ARPScanScanner", "NetdiscoverScanner"], timeout=180),
            PhaseConfig(ScanPhase.PORT_SCAN, ["NmapScanner", "MasscanScanner"], parallel=True, timeout=600),
            PhaseConfig(ScanPhase.SERVICE_ENUM, ["NmapScanner", "SNMPScanner", "DNSReconScanner"], timeout=600),
            PhaseConfig(ScanPhase.VULN_SCAN, ["NucleiScanner", "OpenVASScanner", "VulnersNmapScanner"], timeout=1800),
            PhaseConfig(ScanPhase.SSL_AUDIT, ["SSLScanScanner", "TestSSLScanner", "SSLyzeScanner"], timeout=600),
            PhaseConfig(ScanPhase.EXPLOITATION, ["CrackMapExecScanner", "ImpacketScanner"], timeout=900),
        ],
        ScanProfile.STEALTH: [
            PhaseConfig(ScanPhase.PORT_SCAN, ["NmapScanner"], timeout=1800),  # -T1 profile
            PhaseConfig(ScanPhase.VULN_SCAN, ["NucleiScanner"], timeout=1200),
        ],
        ScanProfile.CREDENTIAL: [
            PhaseConfig(ScanPhase.DISCOVERY, ["NmapScanner"], timeout=60),
            PhaseConfig(ScanPhase.PORT_SCAN, ["NmapScanner"], timeout=300),
            PhaseConfig(ScanPhase.CREDENTIAL, ["CrackMapExecScanner", "ImpacketScanner", "SNMPScanner"], timeout=600),
            PhaseConfig(ScanPhase.EXPLOITATION, ["MetasploitScanner"], timeout=900),
        ],
        ScanProfile.WEB: [
            PhaseConfig(ScanPhase.PORT_SCAN, ["NmapScanner"], timeout=180),  # Web ports only
            PhaseConfig(ScanPhase.SSL_AUDIT, ["SSLyzeScanner", "TestSSLScanner"], timeout=300),
            PhaseConfig(ScanPhase.VULN_SCAN, ["NucleiScanner"], timeout=600),  # Web templates
        ],
        ScanProfile.INTERNAL: [
            PhaseConfig(ScanPhase.DISCOVERY, ["ARPScanScanner", "NetdiscoverScanner"], timeout=300),
            PhaseConfig(ScanPhase.PORT_SCAN, ["MasscanScanner", "NmapScanner"], timeout=600),
            PhaseConfig(ScanPhase.SERVICE_ENUM, ["NmapScanner", "SNMPScanner"], timeout=600),
            PhaseConfig(ScanPhase.CREDENTIAL, ["CrackMapExecScanner"], timeout=600),
            PhaseConfig(ScanPhase.VULN_SCAN, ["NucleiScanner", "VulnersNmapScanner"], timeout=1200),
        ],
    }
    
    def __init__(self, config: Dict = None):
        """
        Initialize orchestrator.
        
        Args:
            config: Global configuration dict
        """
        self.config = config or {}
        self.state: Optional[ScanState] = None
        self._available_tools: Set[str] = set()
        # Use the network-specific registry with decorator-registered scanners
        self._network_registry = NetworkScannerRegistry
        self._scanner_map = self._build_scanner_map()
        self._check_available_tools()
    
    def _build_scanner_map(self) -> Dict[str, type]:
        """Build a name→class map from the network scanner registry"""
        scanner_map = {}
        for phase, scanners in self._network_registry.get_all_scanners().items():
            for scanner_class in scanners:
                scanner_map[scanner_class.__name__] = scanner_class
        logger.info(f"🔍 Network scanner registry: {len(scanner_map)} scanners mapped")
        return scanner_map
    
    def _check_available_tools(self):
        """Check which tools are available on the system"""
        tools = [
            'nmap', 'masscan', 'rustscan',
            'nuclei', 'openvas',
            'netdiscover', 'arp-scan', 'snmpwalk', 'dnsrecon',
            'sslscan', 'testssl.sh', 'sslyze',
            'crackmapexec', 'netexec',
            'zeek', 'suricata', 'snort', 'tshark',
            'msfconsole',
        ]
        
        for tool in tools:
            if shutil.which(tool):
                self._available_tools.add(tool)
        
        # Also check Python libraries
        try:
            import sslyze
            self._available_tools.add('sslyze-lib')
        except ImportError:
            pass
        
        try:
            from gvm.connections import TLSConnection
            self._available_tools.add('gvm-tools')
        except ImportError:
            pass
        
        logger.info(f"Available tools: {self._available_tools}")
    
    async def run(self, target: str, profile: ScanProfile = ScanProfile.STANDARD,
                  credentials: Dict = None, phases: List[ScanPhase] = None,
                  callback: callable = None) -> ScanState:
        """
        Run network security scan.
        
        Args:
            target: Target IP, hostname, or CIDR range
            profile: Scan profile to use
            credentials: Dict with ssh_creds, windows_creds, snmp_creds, db_creds
            phases: Specific phases to run (overrides profile)
            callback: Progress callback function(phase, progress, message)
        
        Returns:
            ScanState with all findings and results
        """
        # Initialize state
        self.state = ScanState(
            target=target,
            profile=profile,
            ssh_creds=credentials.get('ssh') if credentials else None,
            windows_creds=credentials.get('windows') if credentials else None,
            snmp_creds=credentials.get('snmp') if credentials else None,
            db_creds=credentials.get('database') if credentials else None,
        )
        
        # Get phase configuration
        phase_configs = self.PHASE_CONFIG.get(profile, self.PHASE_CONFIG[ScanProfile.STANDARD])
        
        # Filter to specific phases if requested
        if phases:
            phase_configs = [p for p in phase_configs if p.phase in phases]
        
        # Execute phases sequentially
        total_phases = len(phase_configs)
        
        for i, phase_config in enumerate(phase_configs):
            if not phase_config.enabled:
                continue
            
            phase_name = phase_config.phase.value
            
            if callback:
                callback(phase_name, i / total_phases, f"Starting {phase_name}")
            
            logger.info(f"Starting phase: {phase_name}")
            
            try:
                await self._run_phase(phase_config)
                self.state.completed_phases.append(phase_config.phase)
            except Exception as e:
                error_msg = f"Phase {phase_name} failed: {str(e)}"
                logger.error(error_msg)
                self.state.errors.append(error_msg)
            
            if callback:
                callback(phase_name, (i + 1) / total_phases, f"Completed {phase_name}")
        
        # Generate summary
        self._generate_summary()
        
        return self.state
    
    async def _run_phase(self, phase_config: PhaseConfig):
        """Execute a single scan phase"""
        
        # Filter to available scanners using the scanner map
        available_scanners = []
        for scanner_name in phase_config.scanners:
            # Get scanner class from our pre-built map
            scanner_class = self._scanner_map.get(scanner_name)
            
            if not scanner_class:
                logger.warning(f"Scanner {scanner_name} not found in registry")
                continue
            
            tool_name = getattr(scanner_class, 'TOOL_NAME', scanner_name.lower().replace('scanner', ''))
            
            # Map tool names to executable names
            tool_map = {
                'testssl': 'testssl.sh',
                'crackmapexec': 'crackmapexec',  # or netexec
                'vulners': 'nmap',  # Uses nmap
            }
            
            check_tool = tool_map.get(tool_name, tool_name)
            
            # Special case: sslyze can use library
            if tool_name == 'sslyze' and 'sslyze-lib' in self._available_tools:
                available_scanners.append(scanner_class)
            elif check_tool in self._available_tools:
                available_scanners.append(scanner_class)
            elif tool_name == 'crackmapexec' and 'netexec' in self._available_tools:
                available_scanners.append(scanner_class)
        
        if not available_scanners:
            logger.warning(f"No tools available for phase {phase_config.phase.value}")
            return
        
        # Build scanner configs based on phase
        scanner_tasks = []
        
        for scanner_class in available_scanners:
            scanner = scanner_class(self.config)
            
            # Get targets based on phase and previous results
            targets = self._get_phase_targets(phase_config.phase, scanner_class)
            
            for target_info in targets:
                task = self._run_scanner(scanner, target_info, phase_config)
                scanner_tasks.append(task)
        
        # Run scanners SEQUENTIALLY (one at a time to reduce server load)
        # Never run tools in parallel to avoid overwhelming the system
        results = []
        for i, task in enumerate(scanner_tasks):
            try:
                logger.info(f"Running scanner {i+1}/{len(scanner_tasks)} in phase {phase_config.phase.value}")
                result = await task
                results.append(result)
                
                # Small delay between scanners to prevent overload
                if i < len(scanner_tasks) - 1:
                    await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Scanner task failed: {e}")
                results.append(e)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                self.state.errors.append(str(result))
            elif isinstance(result, ScanResult):
                # Store result
                if result.tool not in self.state.results:
                    self.state.results[result.tool] = []
                self.state.results[result.tool].append(result)
                
                # Collect findings
                self.state.findings.extend(result.findings)
                
                # Update state based on findings
                self._update_state_from_result(result, phase_config.phase)
    
    async def _run_scanner(self, scanner, target_info: Dict,
                           phase_config: PhaseConfig) -> ScanResult:
        """Run a single scanner with target info - ONE AT A TIME"""
        tool_name = scanner.TOOL_NAME
        target = target_info.get('target', 'unknown')
        
        logger.info(f"[{tool_name}] Starting scan on {target}")
        start_time = asyncio.get_event_loop().time()
        
        try:
            result = await asyncio.wait_for(
                scanner.run(**target_info),
                timeout=phase_config.timeout
            )
            
            elapsed = asyncio.get_event_loop().time() - start_time
            findings_count = len(result.findings) if result.findings else 0
            logger.info(f"[{tool_name}] Completed in {elapsed:.1f}s - {findings_count} findings")
            
            # Add delay after each tool to prevent server overload
            await asyncio.sleep(2)
            
            return result
            
        except asyncio.TimeoutError:
            logger.warning(f"[{tool_name}] Timeout after {phase_config.timeout}s on {target}")
            return ScanResult(
                tool=tool_name,
                target=target,
                phase=phase_config.phase.value,
                error=f"Timeout after {phase_config.timeout}s"
            )
        except Exception as e:
            logger.error(f"[{tool_name}] Error scanning {target}: {e}")
            return ScanResult(
                tool=tool_name,
                target=target,
                phase=phase_config.phase.value,
                error=str(e)
            )
    
    def _get_phase_targets(self, phase: ScanPhase, scanner_class) -> List[Dict]:
        """
        Get targets for a phase based on previous results.
        
        Returns list of dicts with target and phase-specific options.
        """
        targets = []
        base_target = self.state.target
        
        if phase == ScanPhase.DISCOVERY:
            # Discovery uses original target (IP/subnet)
            targets.append({'target': base_target})
        
        elif phase == ScanPhase.PORT_SCAN:
            # Scan discovered hosts or original target
            if self.state.live_hosts:
                for host in self.state.live_hosts:
                    targets.append({'target': host})
            else:
                targets.append({'target': base_target})
            
            # Add profile-specific options
            if self.state.profile == ScanProfile.QUICK:
                for t in targets:
                    t['profile'] = 'quick'
            elif self.state.profile == ScanProfile.STEALTH:
                for t in targets:
                    t['profile'] = 'stealth'
            elif self.state.profile == ScanProfile.WEB:
                for t in targets:
                    t['ports'] = '80,443,8080,8443,8000,3000,5000'
        
        elif phase == ScanPhase.SERVICE_ENUM:
            # Enumerate services on hosts with open ports
            if self.state.open_ports:
                for host, ports in self.state.open_ports.items():
                    port_str = ','.join(map(str, ports[:100]))  # Limit ports
                    targets.append({'target': host, 'ports': port_str})
            else:
                targets.append({'target': base_target})
            
            # SNMP scanner needs different params
            if scanner_class == SNMPScanner and self.state.snmp_creds:
                for t in targets:
                    t['community'] = self.state.snmp_creds.get('community', 'public')
                    t['version'] = self.state.snmp_creds.get('version', '2c')
        
        elif phase == ScanPhase.VULN_SCAN:
            # Scan hosts with identified services
            if self.state.services:
                for host in self.state.services.keys():
                    targets.append({'target': host})
            elif self.state.open_ports:
                for host in self.state.open_ports.keys():
                    targets.append({'target': host})
            else:
                targets.append({'target': base_target})
        
        elif phase == ScanPhase.SSL_AUDIT:
            # Scan SSL/TLS ports
            if self.state.ssl_ports:
                for host, ports in self.state.ssl_ports.items():
                    for port in ports:
                        targets.append({'target': host, 'port': port})
            elif self.state.open_ports:
                # Check common SSL ports
                ssl_common = {443, 8443, 993, 995, 636, 465, 3389}
                for host, ports in self.state.open_ports.items():
                    for port in ports:
                        if port in ssl_common:
                            targets.append({'target': host, 'port': port})
            else:
                targets.append({'target': base_target, 'port': 443})
        
        elif phase == ScanPhase.CREDENTIAL:
            # Authenticated testing - needs credentials
            for host in self.state.open_ports.keys() or [base_target]:
                target_info = {'target': host}
                
                if self.state.windows_creds:
                    target_info.update({
                        'username': self.state.windows_creds.get('username'),
                        'password': self.state.windows_creds.get('password'),
                        'domain': self.state.windows_creds.get('domain', ''),
                    })
                
                targets.append(target_info)
        
        elif phase == ScanPhase.EXPLOITATION:
            # Only exploit hosts with high-severity vulns
            vuln_hosts = set()
            for finding in self.state.findings:
                if finding.severity in [Severity.CRITICAL.value, Severity.HIGH.value]:
                    vuln_hosts.add(finding.target)
            
            for host in vuln_hosts or [base_target]:
                target_info = {'target': host}
                if self.state.windows_creds:
                    target_info.update(self.state.windows_creds)
                targets.append(target_info)
        
        return targets or [{'target': base_target}]
    
    def _update_state_from_result(self, result: ScanResult, phase: ScanPhase):
        """Update scan state based on results"""
        
        for finding in result.findings:
            # Update live hosts
            if finding.target and phase == ScanPhase.DISCOVERY:
                self.state.live_hosts.add(finding.target)
            
            # Update open ports
            if finding.port and finding.port > 0:
                target = finding.target or result.target
                if target not in self.state.open_ports:
                    self.state.open_ports[target] = []
                if finding.port not in self.state.open_ports[target]:
                    self.state.open_ports[target].append(finding.port)
            
            # Update services
            if finding.service:
                target = finding.target or result.target
                if target not in self.state.services:
                    self.state.services[target] = {}
                if finding.port:
                    self.state.services[target][finding.port] = finding.service
            
            # Track SSL ports
            if finding.service in ['https', 'ssl', 'tls'] or finding.port in [443, 8443, 993, 995]:
                target = finding.target or result.target
                if target not in self.state.ssl_ports:
                    self.state.ssl_ports[target] = []
                if finding.port and finding.port not in self.state.ssl_ports[target]:
                    self.state.ssl_ports[target].append(finding.port)
    
    def _generate_summary(self):
        """Generate scan summary"""
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }
        
        for finding in self.state.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1
        
        logger.info(f"""
=== Network Scan Complete ===
Target: {self.state.target}
Profile: {self.state.profile.value}
Duration: {(datetime.now() - self.state.start_time).total_seconds():.1f}s
Phases: {', '.join(p.value for p in self.state.completed_phases)}

Hosts Discovered: {len(self.state.live_hosts)}
Total Findings: {len(self.state.findings)}
  Critical: {severity_counts['critical']}
  High: {severity_counts['high']}
  Medium: {severity_counts['medium']}
  Low: {severity_counts['low']}
  Info: {severity_counts['info']}

Errors: {len(self.state.errors)}
        """)


# Export
__all__ = ['NetworkOrchestrator', 'ScanProfile', 'ScanState', 'PhaseConfig']
