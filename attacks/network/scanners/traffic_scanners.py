"""
Jarwis Network Security - Traffic Analysis & IDS

Tools:
- Zeek: Network traffic analysis
- Suricata: IDS/IPS with rule matching
- Snort: Classic IDS
- Wireshark/tshark: Packet capture analysis
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
class ZeekScanner(BaseScanner):
    """
    Zeek (formerly Bro) - Network Analysis Framework
    
    Passive network traffic analysis:
    - Connection logging
    - Protocol analysis
    - File extraction
    - Anomaly detection
    - Custom script analysis
    
    Jarwis uses Zeek to analyze captured traffic or live feeds.
    """
    
    TOOL_NAME = "zeek"
    PHASE = ScanPhase.TRAFFIC_ANALYSIS
    REQUIRES_ROOT = True
    
    async def run(self, target: str = None, interface: str = None,
                  pcap_file: str = None, scripts: List[str] = None,
                  duration: int = 60, **kwargs) -> ScanResult:
        """
        Run Zeek traffic analysis.
        
        Args:
            target: Filter by target IP (BPF filter)
            interface: Network interface for live capture
            pcap_file: PCAP file to analyze
            scripts: Additional Zeek scripts
            duration: Capture duration in seconds (live only)
        """
        start_time = asyncio.get_event_loop().time()
        
        import tempfile
        output_dir = tempfile.mkdtemp(prefix='zeek_')
        
        cmd = ['zeek', '-C']  # -C: ignore checksum errors
        
        if pcap_file:
            cmd.extend(['-r', pcap_file])
        elif interface:
            cmd.extend(['-i', interface])
            if target:
                cmd.extend(['-f', f'host {target}'])
        else:
            result = ScanResult(
                tool=self.TOOL_NAME,
                target=target or "unknown",
                phase=self.PHASE.value,
                error="Specify either pcap_file or interface"
            )
            return result
        
        # Output directory
        cmd.extend(['Log::default_logdir=' + output_dir])
        
        # Add custom scripts
        if scripts:
            cmd.extend(scripts)
        
        # For live capture, use timeout
        timeout = duration + 30 if interface else 600
        
        stdout, stderr, returncode = await self._run_command(cmd, timeout=timeout)
        
        # Read log files
        all_findings = []
        log_content = []
        
        for log_file in Path(output_dir).glob('*.log'):
            try:
                content = log_file.read_text()
                log_content.append(f"=== {log_file.name} ===\n{content}")
                
                findings = self._parse_log_file(log_file.name, content, target)
                all_findings.extend(findings)
            except Exception as e:
                logger.error(f"Error reading {log_file}: {e}")
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target or interface or pcap_file,
            phase=self.PHASE.value,
            raw_output='\n'.join(log_content),
            error=stderr if returncode != 0 and not log_content else "",
            findings=all_findings,
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        # Cleanup
        import shutil
        shutil.rmtree(output_dir, ignore_errors=True)
        
        return result
    
    def _parse_log_file(self, filename: str, content: str, target: str) -> List[Finding]:
        """Parse Zeek log file"""
        findings = []
        
        if filename == 'notice.log':
            # Security notices
            for line in content.strip().split('\n'):
                if line.startswith('#'):
                    continue
                
                try:
                    fields = line.split('\t')
                    if len(fields) >= 10:
                        note_type = fields[6] if len(fields) > 6 else ''
                        msg = fields[7] if len(fields) > 7 else ''
                        
                        # Severity based on notice type
                        if 'Attack' in note_type or 'Scan' in note_type:
                            severity = Severity.HIGH.value
                        elif 'SSL' in note_type or 'Weird' in note_type:
                            severity = Severity.MEDIUM.value
                        else:
                            severity = Severity.LOW.value
                        
                        findings.append(Finding(
                            id=self._generate_id(),
                            tool=self.TOOL_NAME,
                            category="traffic_analysis",
                            severity=severity,
                            title=f"Zeek Notice: {note_type}",
                            description=msg,
                            target=target,
                            evidence=line,
                            confidence=0.85,
                        ))
                except Exception as e:
                    logger.debug(f"Error parsing notice line: {e}")
        
        elif filename == 'weird.log':
            # Anomalies
            for line in content.strip().split('\n'):
                if line.startswith('#'):
                    continue
                
                try:
                    fields = line.split('\t')
                    if len(fields) >= 4:
                        weird_name = fields[5] if len(fields) > 5 else 'Unknown'
                        
                        findings.append(Finding(
                            id=self._generate_id(),
                            tool=self.TOOL_NAME,
                            category="anomaly",
                            severity=Severity.LOW.value,
                            title=f"Network Anomaly: {weird_name}",
                            description="Unusual network behavior detected",
                            target=target,
                            evidence=line,
                            confidence=0.70,
                        ))
                except Exception as e:
                    logger.debug(f"Error parsing weird line: {e}")
        
        elif filename == 'ssl.log':
            # SSL/TLS issues
            for line in content.strip().split('\n'):
                if line.startswith('#'):
                    continue
                
                if 'SSLv2' in line or 'SSLv3' in line or 'TLSv1.0' in line:
                    findings.append(Finding(
                        id=self._generate_id(),
                        tool=self.TOOL_NAME,
                        category="cryptography",
                        severity=Severity.MEDIUM.value,
                        title="Deprecated TLS Version in Traffic",
                        description="Traffic using outdated SSL/TLS protocol",
                        target=target,
                        evidence=line,
                        confidence=0.90,
                    ))
        
        return findings
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Generic parser - uses log file parsing"""
        return []


@ScannerRegistry.register
class SuricataScanner(BaseScanner):
    """
    Suricata - High Performance IDS/IPS
    
    Multi-threaded IDS with:
    - Signature-based detection
    - Protocol analysis
    - File extraction
    - Flow analysis
    - Lua scripting
    
    Uses ET Open/Pro rulesets.
    """
    
    TOOL_NAME = "suricata"
    PHASE = ScanPhase.TRAFFIC_ANALYSIS
    REQUIRES_ROOT = True
    
    async def run(self, target: str = None, interface: str = None,
                  pcap_file: str = None, rules_file: str = None,
                  duration: int = 60, **kwargs) -> ScanResult:
        """
        Run Suricata IDS analysis.
        
        Args:
            target: Filter by IP
            interface: Network interface
            pcap_file: PCAP file to analyze
            rules_file: Custom rules file
            duration: Capture duration
        """
        start_time = asyncio.get_event_loop().time()
        
        import tempfile
        log_dir = tempfile.mkdtemp(prefix='suricata_')
        
        cmd = ['suricata', '-l', log_dir]
        
        if pcap_file:
            cmd.extend(['-r', pcap_file])
        elif interface:
            cmd.extend(['-i', interface])
        else:
            return ScanResult(
                tool=self.TOOL_NAME,
                target=target or "unknown",
                phase=self.PHASE.value,
                error="Specify either pcap_file or interface"
            )
        
        if rules_file:
            cmd.extend(['-S', rules_file])
        
        # Output as JSON
        cmd.extend(['-k', 'none'])  # Disable checksum checks
        
        timeout = duration + 60 if interface else 600
        
        stdout, stderr, returncode = await self._run_command(cmd, timeout=timeout)
        
        # Parse eve.json (unified log)
        all_findings = []
        eve_path = Path(log_dir) / 'eve.json'
        raw_output = ""
        
        if eve_path.exists():
            raw_output = eve_path.read_text()
            all_findings = self._parse_eve_json(raw_output, target)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target or interface or pcap_file,
            phase=self.PHASE.value,
            raw_output=raw_output,
            error=stderr if returncode != 0 and not all_findings else "",
            findings=all_findings,
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        # Cleanup
        import shutil
        shutil.rmtree(log_dir, ignore_errors=True)
        
        return result
    
    def _parse_eve_json(self, content: str, target: str) -> List[Finding]:
        """Parse Suricata EVE JSON log"""
        findings = []
        
        for line in content.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                event = json.loads(line)
                event_type = event.get('event_type', '')
                
                if event_type == 'alert':
                    alert = event.get('alert', {})
                    
                    severity_map = {
                        1: Severity.HIGH.value,
                        2: Severity.MEDIUM.value,
                        3: Severity.LOW.value,
                    }
                    
                    sig_severity = alert.get('severity', 3)
                    
                    findings.append(Finding(
                        id=self._generate_id(),
                        tool=self.TOOL_NAME,
                        category=alert.get('category', 'ids_alert'),
                        severity=severity_map.get(sig_severity, Severity.LOW.value),
                        title=alert.get('signature', 'Unknown Alert'),
                        description=f"Signature ID: {alert.get('signature_id', 'N/A')}",
                        target=event.get('dest_ip', target),
                        port=event.get('dest_port', 0),
                        evidence=json.dumps({
                            'src_ip': event.get('src_ip'),
                            'dest_ip': event.get('dest_ip'),
                            'proto': event.get('proto'),
                            'category': alert.get('category'),
                        }),
                        confidence=0.85,
                        metadata={
                            'signature_id': alert.get('signature_id'),
                            'rev': alert.get('rev'),
                            'category': alert.get('category'),
                        }
                    ))
                    
            except json.JSONDecodeError:
                continue
            except Exception as e:
                logger.debug(f"Error parsing Suricata event: {e}")
        
        return findings
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse raw output (EVE JSON format)"""
        return self._parse_eve_json(raw_output, target)


@ScannerRegistry.register
class SnortScanner(BaseScanner):
    """
    Snort - Classic Network IDS
    
    Original open-source IDS:
    - Signature-based detection
    - Real-time traffic analysis
    - Packet logging
    
    Still widely used with extensive rule community.
    """
    
    TOOL_NAME = "snort"
    PHASE = ScanPhase.TRAFFIC_ANALYSIS
    REQUIRES_ROOT = True
    
    async def run(self, target: str = None, interface: str = None,
                  pcap_file: str = None, rules_file: str = None,
                  **kwargs) -> ScanResult:
        """
        Run Snort IDS analysis.
        """
        start_time = asyncio.get_event_loop().time()
        
        import tempfile
        log_dir = tempfile.mkdtemp(prefix='snort_')
        
        cmd = ['snort', '-q', '-A', 'fast', '-l', log_dir]
        
        if pcap_file:
            cmd.extend(['-r', pcap_file])
        elif interface:
            cmd.extend(['-i', interface])
        else:
            return ScanResult(
                tool=self.TOOL_NAME,
                target=target or "unknown",
                phase=self.PHASE.value,
                error="Specify either pcap_file or interface"
            )
        
        if rules_file:
            cmd.extend(['-c', rules_file])
        
        stdout, stderr, returncode = await self._run_command(cmd, timeout=300)
        
        # Read alert file
        all_findings = []
        alert_path = Path(log_dir) / 'alert'
        raw_output = stdout
        
        if alert_path.exists():
            alert_content = alert_path.read_text()
            raw_output = alert_content
            all_findings = self.parse_output(alert_content, target)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target or interface or pcap_file,
            phase=self.PHASE.value,
            raw_output=raw_output,
            error=stderr if returncode != 0 and not all_findings else "",
            findings=all_findings,
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        import shutil
        shutil.rmtree(log_dir, ignore_errors=True)
        
        return result
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse Snort alert output (fast mode)"""
        findings = []
        
        # Fast alert format: timestamp  [**] [sid:rev] msg [**] {proto} src -> dest
        pattern = re.compile(
            r'\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.+?)\s+\[\*\*\]'
            r'.*?\{(\w+)\}\s+(\S+)\s+->\s+(\S+)'
        )
        
        for line in raw_output.strip().split('\n'):
            match = pattern.search(line)
            if match:
                gid, sid, rev, msg, proto, src, dest = match.groups()
                
                findings.append(Finding(
                    id=self._generate_id(),
                    tool=self.TOOL_NAME,
                    category="ids_alert",
                    severity=Severity.MEDIUM.value,
                    title=msg,
                    description=f"Snort rule {gid}:{sid}:{rev} triggered",
                    target=dest.split(':')[0] if ':' in dest else dest,
                    port=int(dest.split(':')[1]) if ':' in dest else 0,
                    evidence=line,
                    confidence=0.80,
                    metadata={
                        'gid': gid,
                        'sid': sid,
                        'rev': rev,
                        'protocol': proto,
                        'source': src,
                        'destination': dest,
                    }
                ))
        
        return findings


@ScannerRegistry.register
class TSharkScanner(BaseScanner):
    """
    TShark - Wireshark CLI
    
    Packet capture and analysis:
    - Protocol dissection
    - Statistics generation
    - Credential extraction
    - Traffic patterns
    
    Jarwis uses tshark for targeted packet analysis.
    """
    
    TOOL_NAME = "tshark"
    PHASE = ScanPhase.TRAFFIC_ANALYSIS
    REQUIRES_ROOT = True
    
    async def run(self, target: str = None, interface: str = None,
                  pcap_file: str = None, filter_expr: str = None,
                  extract_creds: bool = False, duration: int = 60,
                  **kwargs) -> ScanResult:
        """
        Run TShark packet analysis.
        
        Args:
            target: Target IP (for filtering)
            interface: Network interface
            pcap_file: PCAP file
            filter_expr: Display filter
            extract_creds: Attempt credential extraction
            duration: Capture duration
        """
        start_time = asyncio.get_event_loop().time()
        
        cmd = ['tshark', '-T', 'json']
        
        if pcap_file:
            cmd.extend(['-r', pcap_file])
        elif interface:
            cmd.extend(['-i', interface, '-a', f'duration:{duration}'])
        else:
            return ScanResult(
                tool=self.TOOL_NAME,
                target=target or "unknown",
                phase=self.PHASE.value,
                error="Specify either pcap_file or interface"
            )
        
        if target:
            cmd.extend(['-Y', f'ip.addr == {target}'])
        elif filter_expr:
            cmd.extend(['-Y', filter_expr])
        
        stdout, stderr, returncode = await self._run_command(cmd, timeout=duration + 60)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target or interface or pcap_file,
            phase=self.PHASE.value,
            raw_output=stdout[:10000] if stdout else "",  # Truncate for large captures
            error=stderr if returncode != 0 and not stdout else "",
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        if stdout:
            findings = self.parse_output(stdout, target, extract_creds)
            result.findings = findings
        
        return result
    
    def parse_output(self, raw_output: str, target: str,
                     extract_creds: bool = False) -> List[Finding]:
        """Parse TShark JSON output"""
        findings = []
        
        try:
            packets = json.loads(raw_output)
            
            # Analyze protocols
            protocols_seen = set()
            cleartext_creds = []
            
            for pkt in packets:
                layers = pkt.get('_source', {}).get('layers', {})
                
                # Track protocols
                for layer in layers.keys():
                    protocols_seen.add(layer.lower())
                
                # Look for cleartext credentials
                if extract_creds:
                    # HTTP Auth
                    http_layer = layers.get('http', {})
                    auth_header = http_layer.get('http.authorization')
                    if auth_header and 'Basic' in str(auth_header):
                        cleartext_creds.append(('http_basic', auth_header))
                    
                    # FTP
                    ftp_layer = layers.get('ftp', {})
                    ftp_cmd = ftp_layer.get('ftp.request.command', '')
                    ftp_arg = ftp_layer.get('ftp.request.arg', '')
                    if ftp_cmd in ['USER', 'PASS']:
                        cleartext_creds.append(('ftp', f'{ftp_cmd} {ftp_arg}'))
                    
                    # Telnet
                    if 'telnet' in layers:
                        telnet_data = layers.get('telnet', {})
                        if telnet_data:
                            cleartext_creds.append(('telnet', str(telnet_data)[:100]))
            
            # Report findings
            insecure_protocols = protocols_seen & {'ftp', 'telnet', 'http'}
            if insecure_protocols:
                findings.append(Finding(
                    id=self._generate_id(),
                    tool=self.TOOL_NAME,
                    category="traffic_analysis",
                    severity=Severity.MEDIUM.value,
                    title="Insecure Protocols Detected",
                    description=f"Traffic contains unencrypted protocols: {', '.join(insecure_protocols)}",
                    target=target,
                    evidence=f"Protocols: {', '.join(sorted(protocols_seen))}",
                    confidence=0.90,
                ))
            
            for cred_type, cred_data in cleartext_creds:
                findings.append(Finding(
                    id=self._generate_id(),
                    tool=self.TOOL_NAME,
                    category="credential",
                    severity=Severity.HIGH.value,
                    title=f"Cleartext Credentials in {cred_type.upper()}",
                    description=f"Credentials transmitted without encryption",
                    target=target,
                    evidence=cred_data[:100],
                    confidence=0.95,
                ))
                
        except json.JSONDecodeError:
            logger.warning("TShark output not valid JSON")
        except Exception as e:
            logger.error(f"Error parsing TShark output: {e}")
        
        return findings
