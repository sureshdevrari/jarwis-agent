"""
Jarwis Network Security - Vulnerability Scanners

Tools:
- Nuclei: Template-based vulnerability scanning
- OpenVAS (GVM): Enterprise vulnerability scanning
- Vulners Nmap NSE: CVE mapping via Nmap
"""

import asyncio
import json
import re
import logging
from typing import Dict, List, Optional
from pathlib import Path

from .base import (
    BaseScanner, ScanResult, Finding, ScanPhase,
    ScannerRegistry, Severity
)

logger = logging.getLogger(__name__)


@ScannerRegistry.register
class NucleiScanner(BaseScanner):
    """
    Nuclei - Fast and customizable vulnerability scanner
    
    Uses YAML templates to detect:
    - CVEs
    - Misconfigurations
    - Exposed panels/services
    - Default credentials
    - Network service vulnerabilities
    
    Jarwis Advantage: LLM can generate custom templates
    """
    
    TOOL_NAME = "nuclei"
    PHASE = ScanPhase.VULN_SCAN
    REQUIRES_ROOT = False
    
    # Template categories for network scanning
    NETWORK_TEMPLATES = [
        'network',
        'cves',
        'vulnerabilities',
        'default-logins',
        'exposed-panels',
        'misconfigurations',
        'takeovers',
    ]
    
    async def run(self, target: str, templates: List[str] = None,
                  severity: List[str] = None, tags: List[str] = None,
                  **kwargs) -> ScanResult:
        """
        Run Nuclei scan against target.
        
        Args:
            target: IP/hostname/URL
            templates: Specific templates or template directories
            severity: Filter by severity (critical, high, medium, low, info)
            tags: Filter by tags (cve, network, etc.)
        """
        start_time = asyncio.get_event_loop().time()
        
        cmd = ['nuclei', '-target', target, '-jsonl']
        
        # Add template filters
        if templates:
            for t in templates:
                cmd.extend(['-t', t])
        else:
            # Default to network-related templates
            cmd.extend(['-tags', 'network,cve,default-login,exposure'])
        
        if severity:
            cmd.extend(['-severity', ','.join(severity)])
        
        if tags:
            cmd.extend(['-tags', ','.join(tags)])
        
        # Rate limiting
        cmd.extend(['-rate-limit', str(self.rate_limit)])
        
        # Timeout
        cmd.extend(['-timeout', '10'])
        
        stdout, stderr, returncode = await self._run_command(cmd)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
            raw_output=stdout,
            error=stderr if returncode != 0 and 'No results' not in stderr else "",
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        if stdout:
            result.findings = self.parse_output(stdout, target)
        
        return result
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse Nuclei JSONL output"""
        findings = []
        
        for line in raw_output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                entry = json.loads(line)
                
                info = entry.get('info', {})
                severity_str = info.get('severity', 'info').lower()
                
                # Map Nuclei severity
                severity_map = {
                    'critical': Severity.CRITICAL.value,
                    'high': Severity.HIGH.value,
                    'medium': Severity.MEDIUM.value,
                    'low': Severity.LOW.value,
                    'info': Severity.INFO.value,
                }
                
                # Extract CVE if present
                cve_id = ''
                classification = info.get('classification', {})
                if classification.get('cve-id'):
                    cve_ids = classification.get('cve-id', [])
                    cve_id = cve_ids[0] if cve_ids else ''
                
                findings.append(Finding(
                    id=self._generate_id(),
                    tool=self.TOOL_NAME,
                    category=info.get('tags', ['vulnerability'])[0] if info.get('tags') else 'vulnerability',
                    severity=severity_map.get(severity_str, 'info'),
                    title=info.get('name', 'Unknown Vulnerability'),
                    description=info.get('description', ''),
                    target=entry.get('host', target),
                    port=entry.get('port', 0) or self._extract_port(entry.get('matched-at', '')),
                    cve_id=cve_id,
                    cvss_score=float(classification.get('cvss-score', 0) or 0),
                    confidence=0.90,
                    evidence=entry.get('matched-at', ''),
                    remediation=info.get('remediation', ''),
                    references=info.get('reference', []),
                    raw_output=line
                ))
                
            except json.JSONDecodeError:
                continue
            except Exception as e:
                logger.warning(f"Error parsing Nuclei result: {e}")
        
        return findings
    
    def _extract_port(self, url: str) -> int:
        """Extract port from URL"""
        port_match = re.search(r':(\d+)', url)
        if port_match:
            return int(port_match.group(1))
        return 0


@ScannerRegistry.register
class OpenVASScanner(BaseScanner):
    """
    OpenVAS (Greenbone) - Enterprise Vulnerability Scanner
    
    Full-featured vulnerability scanner with:
    - 50,000+ vulnerability tests (NVTs)
    - Compliance checking
    - Detailed reporting
    
    Requires GVM (Greenbone Vulnerability Manager) installation.
    """
    
    TOOL_NAME = "openvas"
    PHASE = ScanPhase.VULN_SCAN
    REQUIRES_ROOT = True
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.gvm_host = config.get('gvm_host', '127.0.0.1')
        self.gvm_port = config.get('gvm_port', 9390)
        self.gvm_user = config.get('gvm_user', 'admin')
        self.gvm_password = config.get('gvm_password', '')
    
    async def run(self, target: str, scan_config: str = 'Full and fast',
                  **kwargs) -> ScanResult:
        """
        Run OpenVAS scan via GVM API.
        
        Args:
            target: IP/hostname/CIDR
            scan_config: Scan configuration name
        """
        start_time = asyncio.get_event_loop().time()
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
        )
        
        try:
            # Try to use gvm-tools Python library
            from gvm.connections import TLSConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = TLSConnection(hostname=self.gvm_host, port=self.gvm_port)
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                # Authenticate
                gmp.authenticate(self.gvm_user, self.gvm_password)
                
                # Create target
                target_id = self._create_target(gmp, target)
                
                # Get scan config ID
                config_id = self._get_scan_config_id(gmp, scan_config)
                
                # Create and start task
                task_id = self._create_task(gmp, target_id, config_id, f"Jarwis-{target}")
                gmp.start_task(task_id)
                
                # Wait for completion (with timeout)
                report_id = await self._wait_for_task(gmp, task_id)
                
                if report_id:
                    # Get results
                    report = gmp.get_report(report_id)
                    result.findings = self._parse_gvm_report(report, target)
                    result.raw_output = str(report)
                
        except ImportError:
            result.error = "gvm-tools not installed. Run: pip install gvm-tools"
        except Exception as e:
            result.error = str(e)
            logger.error(f"OpenVAS scan failed: {e}")
        
        result.scan_time = asyncio.get_event_loop().time() - start_time
        return result
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse OpenVAS XML output"""
        # Implemented in _parse_gvm_report
        return []
    
    def _create_target(self, gmp, target: str) -> str:
        """Create target in GVM"""
        response = gmp.create_target(
            name=f"Jarwis-{target}",
            hosts=[target]
        )
        return response.get('id')
    
    def _get_scan_config_id(self, gmp, config_name: str) -> str:
        """Get scan configuration ID"""
        configs = gmp.get_scan_configs()
        for config in configs.findall('.//config'):
            if config.find('name').text == config_name:
                return config.get('id')
        # Return default if not found
        return 'daba56c8-73ec-11df-a475-002264764cea'  # Full and fast
    
    def _create_task(self, gmp, target_id: str, config_id: str, name: str) -> str:
        """Create scan task"""
        response = gmp.create_task(
            name=name,
            config_id=config_id,
            target_id=target_id
        )
        return response.get('id')
    
    async def _wait_for_task(self, gmp, task_id: str, timeout: int = 3600) -> Optional[str]:
        """Wait for task completion"""
        import time
        start = time.time()
        
        while time.time() - start < timeout:
            task = gmp.get_task(task_id)
            status = task.find('.//status').text
            
            if status == 'Done':
                report = task.find('.//last_report/report')
                if report is not None:
                    return report.get('id')
                break
            
            await asyncio.sleep(30)
        
        return None
    
    def _parse_gvm_report(self, report, target: str) -> List[Finding]:
        """Parse GVM report into findings"""
        findings = []
        
        try:
            for result in report.findall('.//result'):
                nvt = result.find('nvt')
                if nvt is None:
                    continue
                
                threat = result.find('threat')
                severity_map = {
                    'High': Severity.HIGH.value,
                    'Medium': Severity.MEDIUM.value,
                    'Low': Severity.LOW.value,
                    'Log': Severity.INFO.value,
                }
                
                cve_refs = nvt.findall('.//ref[@type="cve"]')
                cve_id = cve_refs[0].get('id') if cve_refs else ''
                
                findings.append(Finding(
                    id=self._generate_id(),
                    tool=self.TOOL_NAME,
                    category="vulnerability",
                    severity=severity_map.get(threat.text if threat is not None else 'Log', 'info'),
                    title=nvt.find('name').text if nvt.find('name') is not None else 'Unknown',
                    description=result.find('description').text if result.find('description') is not None else '',
                    target=result.find('host').text if result.find('host') is not None else target,
                    port=self._extract_port_from_result(result),
                    cve_id=cve_id,
                    cvss_score=float(nvt.find('cvss_base').text or 0) if nvt.find('cvss_base') is not None else 0,
                    confidence=0.85,
                    remediation=nvt.find('solution').text if nvt.find('solution') is not None else '',
                ))
                
        except Exception as e:
            logger.error(f"Error parsing GVM report: {e}")
        
        return findings
    
    def _extract_port_from_result(self, result) -> int:
        """Extract port from result element"""
        port_elem = result.find('port')
        if port_elem is not None and port_elem.text:
            match = re.match(r'(\d+)', port_elem.text)
            if match:
                return int(match.group(1))
        return 0


@ScannerRegistry.register
class VulnersNmapScanner(BaseScanner):
    """
    Vulners Nmap NSE - CVE Detection via Nmap
    
    Uses the Vulners database to map detected service versions
    to known CVEs.
    """
    
    TOOL_NAME = "vulners"
    PHASE = ScanPhase.VULN_SCAN
    REQUIRES_ROOT = False
    
    async def run(self, target: str, ports: str = None, **kwargs) -> ScanResult:
        """
        Run Nmap with vulners script.
        """
        start_time = asyncio.get_event_loop().time()
        
        cmd = [
            'nmap', '-sV',
            '--script', 'vulners',
            '-oX', '-',
        ]
        
        if ports:
            cmd.extend(['-p', ports])
        else:
            cmd.extend(['--top-ports', '1000'])
        
        cmd.append(target)
        
        stdout, stderr, returncode = await self._run_command(cmd)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
            raw_output=stdout,
            error=stderr if returncode != 0 else "",
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        if stdout:
            result.findings = self.parse_output(stdout, target)
        
        return result
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse vulners Nmap output"""
        findings = []
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw_output)
            
            for host in root.findall('.//host'):
                ip = host.find('.//address[@addrtype="ipv4"]')
                ip_addr = ip.get('addr') if ip is not None else target
                
                for port in host.findall('.//port'):
                    port_id = int(port.get('portid', 0))
                    service = port.find('service')
                    
                    # Find vulners script output
                    for script in port.findall('.//script[@id="vulners"]'):
                        output = script.get('output', '')
                        
                        # Parse CVEs from output
                        cve_pattern = re.compile(r'(CVE-\d{4}-\d+)\s+(\d+\.?\d*)\s+')
                        
                        for match in cve_pattern.finditer(output):
                            cve_id = match.group(1)
                            cvss = float(match.group(2))
                            
                            findings.append(Finding(
                                id=self._generate_id(),
                                tool=self.TOOL_NAME,
                                category="vulnerability",
                                severity=self._severity_from_cvss(cvss),
                                title=f"{cve_id} - {service.get('product', 'Service')} {service.get('version', '')}".strip(),
                                description=f"Vulnerability {cve_id} detected on port {port_id}",
                                target=ip_addr,
                                port=port_id,
                                service=service.get('name', '') if service is not None else '',
                                version=service.get('version', '') if service is not None else '',
                                cve_id=cve_id,
                                cvss_score=cvss,
                                confidence=0.80,
                                references=[f'https://vulners.com/cve/{cve_id}'],
                            ))
                            
        except Exception as e:
            logger.error(f"Error parsing vulners output: {e}")
        
        return findings
