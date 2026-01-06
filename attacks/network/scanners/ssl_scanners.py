"""
Jarwis Network Security - SSL/TLS Scanners

Tools:
- SSLScan: SSL/TLS configuration analysis
- testssl.sh: Comprehensive TLS testing
- SSLyze: Python-native SSL analysis
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
class SSLScanScanner(BaseScanner):
    """
    SSLScan - SSL/TLS Configuration Scanner
    
    Fast scanner that identifies:
    - Supported SSL/TLS protocols
    - Cipher suites
    - Certificate details
    - Known vulnerabilities (Heartbleed, etc.)
    """
    
    TOOL_NAME = "sslscan"
    PHASE = ScanPhase.SSL_AUDIT
    REQUIRES_ROOT = False
    
    async def run(self, target: str, port: int = 443, **kwargs) -> ScanResult:
        """
        Run SSLScan against target.
        
        Args:
            target: IP/hostname
            port: TLS port (default 443)
        """
        start_time = asyncio.get_event_loop().time()
        
        cmd = [
            'sslscan',
            '--xml=-',  # XML to stdout
            '--no-colour',
            f'{target}:{port}'
        ]
        
        stdout, stderr, returncode = await self._run_command(cmd, timeout=120)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
            raw_output=stdout,
            error=stderr if returncode != 0 and not stdout else "",
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        if stdout:
            result.findings = self.parse_output(stdout, target, port)
        
        return result
    
    def parse_output(self, raw_output: str, target: str, port: int = 443) -> List[Finding]:
        """Parse SSLScan XML output"""
        findings = []
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw_output)
            
            ssltest = root.find('.//ssltest')
            if ssltest is None:
                return findings
            
            # Check for vulnerable protocols
            for protocol in ssltest.findall('.//protocol'):
                if protocol.get('enabled') == '1':
                    proto_type = protocol.get('type', '')
                    version = protocol.get('version', '')
                    
                    if proto_type == 'ssl' or version in ['1.0', '1.1']:
                        findings.append(Finding(
                            id=self._generate_id(),
                            tool=self.TOOL_NAME,
                            category="cryptography",
                            severity=Severity.HIGH.value if proto_type == 'ssl' else Severity.MEDIUM.value,
                            title=f"Weak Protocol Enabled: {proto_type.upper()}{version}",
                            description=f"Server supports deprecated {proto_type.upper()} {version} protocol",
                            target=target,
                            port=port,
                            service='tls',
                            evidence=f"Protocol: {proto_type} {version}",
                            confidence=0.99,
                            remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Enable only TLS 1.2+",
                        ))
            
            # Check for weak ciphers
            for cipher in ssltest.findall('.//cipher'):
                if cipher.get('status') == 'accepted':
                    cipher_name = cipher.get('cipher', '')
                    bits = int(cipher.get('bits', 256))
                    
                    # Check for weak ciphers
                    weak_patterns = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon']
                    is_weak = any(p in cipher_name for p in weak_patterns) or bits < 128
                    
                    if is_weak:
                        findings.append(Finding(
                            id=self._generate_id(),
                            tool=self.TOOL_NAME,
                            category="cryptography",
                            severity=Severity.MEDIUM.value,
                            title=f"Weak Cipher Supported: {cipher_name}",
                            description=f"Server accepts weak cipher with {bits}-bit key",
                            target=target,
                            port=port,
                            service='tls',
                            evidence=f"Cipher: {cipher_name} ({bits} bits)",
                            confidence=0.99,
                            remediation="Disable weak ciphers and enable only strong cipher suites",
                        ))
            
            # Check for Heartbleed
            heartbleed = ssltest.find('.//heartbleed')
            if heartbleed is not None and heartbleed.get('vulnerable') == '1':
                findings.append(Finding(
                    id=self._generate_id(),
                    tool=self.TOOL_NAME,
                    category="vulnerability",
                    severity=Severity.CRITICAL.value,
                    title="Heartbleed Vulnerability (CVE-2014-0160)",
                    description="Server is vulnerable to Heartbleed, allowing memory disclosure",
                    target=target,
                    port=port,
                    service='tls',
                    cve_id='CVE-2014-0160',
                    cvss_score=7.5,
                    confidence=0.99,
                    remediation="Update OpenSSL to a patched version",
                ))
            
            # Certificate analysis
            cert = ssltest.find('.//certificate')
            if cert is not None:
                # Check expiration
                not_after = cert.find('not-valid-after')
                if not_after is not None:
                    import datetime
                    try:
                        expiry = datetime.datetime.strptime(not_after.text, '%b %d %H:%M:%S %Y %Z')
                        if expiry < datetime.datetime.now():
                            findings.append(Finding(
                                id=self._generate_id(),
                                tool=self.TOOL_NAME,
                                category="certificate",
                                severity=Severity.HIGH.value,
                                title="Expired SSL/TLS Certificate",
                                description=f"Certificate expired on {not_after.text}",
                                target=target,
                                port=port,
                                service='tls',
                                evidence=f"Expiry: {not_after.text}",
                                confidence=0.99,
                                remediation="Renew the SSL/TLS certificate",
                            ))
                    except:
                        pass
                
                # Check signature algorithm
                sig_algo = cert.find('signature-algorithm')
                if sig_algo is not None and 'sha1' in sig_algo.text.lower():
                    findings.append(Finding(
                        id=self._generate_id(),
                        tool=self.TOOL_NAME,
                        category="cryptography",
                        severity=Severity.MEDIUM.value,
                        title="Weak Certificate Signature (SHA-1)",
                        description="Certificate uses deprecated SHA-1 signature algorithm",
                        target=target,
                        port=port,
                        service='tls',
                        evidence=f"Signature: {sig_algo.text}",
                        confidence=0.99,
                        remediation="Re-issue certificate with SHA-256 or stronger signature",
                    ))
                    
        except Exception as e:
            logger.error(f"Error parsing SSLScan output: {e}")
        
        return findings


@ScannerRegistry.register 
class TestSSLScanner(BaseScanner):
    """
    testssl.sh - Comprehensive TLS Testing
    
    The most thorough TLS testing tool, checking:
    - All protocol versions
    - Cipher suite analysis
    - Key exchange
    - Certificate chain
    - Known vulnerabilities (BEAST, BREACH, POODLE, DROWN, etc.)
    - Forward secrecy
    - HSTS, HPKP headers
    """
    
    TOOL_NAME = "testssl"
    PHASE = ScanPhase.SSL_AUDIT
    REQUIRES_ROOT = False
    
    async def run(self, target: str, port: int = 443,
                  quick: bool = False, **kwargs) -> ScanResult:
        """
        Run testssl.sh against target.
        
        Args:
            target: IP/hostname
            port: TLS port
            quick: Quick mode (less thorough)
        """
        start_time = asyncio.get_event_loop().time()
        
        cmd = ['testssl.sh', '--jsonfile=-', '--quiet']
        
        if quick:
            cmd.append('--fast')
        
        cmd.append(f'{target}:{port}')
        
        stdout, stderr, returncode = await self._run_command(cmd, timeout=600)
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
            raw_output=stdout,
            error=stderr if returncode != 0 and not stdout else "",
            scan_time=asyncio.get_event_loop().time() - start_time
        )
        
        if stdout:
            result.findings = self.parse_output(stdout, target, port)
        
        return result
    
    def parse_output(self, raw_output: str, target: str, port: int = 443) -> List[Finding]:
        """Parse testssl.sh JSON output"""
        findings = []
        
        try:
            data = json.loads(raw_output)
            
            for vuln in data.get('vulnerabilities', []):
                severity_map = {
                    'CRITICAL': Severity.CRITICAL.value,
                    'HIGH': Severity.HIGH.value,
                    'MEDIUM': Severity.MEDIUM.value,
                    'LOW': Severity.LOW.value,
                    'INFO': Severity.INFO.value,
                    'OK': Severity.INFO.value,
                }
                
                finding_text = vuln.get('finding', '')
                severity = vuln.get('severity', 'INFO')
                
                # Skip OK/not vulnerable
                if severity in ['OK', 'INFO'] and 'not vulnerable' in finding_text.lower():
                    continue
                
                # Extract CVE if present
                cve_match = re.search(r'CVE-\d{4}-\d+', vuln.get('id', '') + finding_text)
                cve_id = cve_match.group(0) if cve_match else ''
                
                findings.append(Finding(
                    id=self._generate_id(),
                    tool=self.TOOL_NAME,
                    category="ssl_vulnerability",
                    severity=severity_map.get(severity, Severity.INFO.value),
                    title=vuln.get('id', 'SSL/TLS Issue'),
                    description=finding_text,
                    target=target,
                    port=port,
                    service='tls',
                    cve_id=cve_id,
                    confidence=0.95,
                ))
            
            # Check protocols
            for proto in data.get('protocols', []):
                if proto.get('finding', '').lower() == 'offered':
                    proto_id = proto.get('id', '')
                    if 'ssl' in proto_id.lower() or 'tls1_0' in proto_id or 'tls1_1' in proto_id:
                        findings.append(Finding(
                            id=self._generate_id(),
                            tool=self.TOOL_NAME,
                            category="cryptography",
                            severity=Severity.HIGH.value if 'ssl' in proto_id.lower() else Severity.MEDIUM.value,
                            title=f"Weak Protocol: {proto_id}",
                            description=f"Server supports deprecated {proto_id} protocol",
                            target=target,
                            port=port,
                            service='tls',
                            confidence=0.99,
                            remediation="Disable deprecated protocols",
                        ))
            
            # Check ciphers
            for cipher in data.get('ciphers', []):
                severity = cipher.get('severity', 'OK')
                if severity not in ['OK', 'INFO']:
                    findings.append(Finding(
                        id=self._generate_id(),
                        tool=self.TOOL_NAME,
                        category="cryptography",
                        severity=Severity.MEDIUM.value,
                        title=f"Weak Cipher: {cipher.get('id', 'Unknown')}",
                        description=cipher.get('finding', ''),
                        target=target,
                        port=port,
                        service='tls',
                        confidence=0.95,
                    ))
                    
        except json.JSONDecodeError:
            logger.warning("testssl output not valid JSON, attempting text parse")
        except Exception as e:
            logger.error(f"Error parsing testssl output: {e}")
        
        return findings


@ScannerRegistry.register
class SSLyzeScanner(BaseScanner):
    """
    SSLyze - Python-native SSL/TLS Scanner
    
    Pure Python implementation for:
    - Protocol/cipher enumeration
    - Certificate validation
    - OCSP stapling
    - Session resumption
    - Known vulnerabilities
    
    Advantage: No external dependencies, works everywhere Python runs.
    """
    
    TOOL_NAME = "sslyze"
    PHASE = ScanPhase.SSL_AUDIT
    REQUIRES_ROOT = False
    
    async def run(self, target: str, port: int = 443, **kwargs) -> ScanResult:
        """
        Run SSLyze against target.
        """
        start_time = asyncio.get_event_loop().time()
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
        )
        
        try:
            # Try to use sslyze Python library directly
            from sslyze import (
                Scanner, 
                ServerScanRequest, 
                ScanCommand,
                ServerNetworkLocation
            )
            
            server_location = ServerNetworkLocation(target, port)
            
            # Create scan request
            scan_request = ServerScanRequest(
                server_location=server_location,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    ScanCommand.HEARTBLEED,
                    ScanCommand.ROBOT,
                    ScanCommand.OPENSSL_CCS_INJECTION,
                    ScanCommand.TLS_FALLBACK_SCSV,
                    ScanCommand.SESSION_RENEGOTIATION,
                }
            )
            
            scanner = Scanner()
            scanner.queue_scans([scan_request])
            
            all_findings = []
            
            for server_scan_result in scanner.get_results():
                # Process each scan command result
                all_findings.extend(
                    self._process_scan_results(server_scan_result, target, port)
                )
            
            result.findings = all_findings
            
        except ImportError:
            # Fall back to CLI
            cmd = [
                'sslyze',
                '--json_out=-',
                '--certinfo',
                '--compression',
                '--heartbleed',
                '--openssl_ccs',
                '--robot',
                '--sslv2',
                '--sslv3',
                '--tlsv1',
                '--tlsv1_1', 
                '--tlsv1_2',
                '--tlsv1_3',
                f'{target}:{port}'
            ]
            
            stdout, stderr, returncode = await self._run_command(cmd, timeout=180)
            result.raw_output = stdout
            result.error = stderr if returncode != 0 and not stdout else ""
            
            if stdout:
                result.findings = self.parse_output(stdout, target, port)
                
        except Exception as e:
            result.error = str(e)
            logger.error(f"SSLyze scan failed: {e}")
        
        result.scan_time = asyncio.get_event_loop().time() - start_time
        return result
    
    def _process_scan_results(self, scan_result, target: str, port: int) -> List[Finding]:
        """Process SSLyze library scan results"""
        findings = []
        
        try:
            # Heartbleed
            if hasattr(scan_result, 'scan_result'):
                result = scan_result.scan_result
                
                if hasattr(result, 'heartbleed'):
                    heartbleed = result.heartbleed
                    if heartbleed and heartbleed.result and heartbleed.result.is_vulnerable_to_heartbleed:
                        findings.append(Finding(
                            id=self._generate_id(),
                            tool=self.TOOL_NAME,
                            category="vulnerability",
                            severity=Severity.CRITICAL.value,
                            title="Heartbleed Vulnerability",
                            description="Server vulnerable to Heartbleed (CVE-2014-0160)",
                            target=target,
                            port=port,
                            service='tls',
                            cve_id='CVE-2014-0160',
                            cvss_score=7.5,
                            confidence=0.99,
                        ))
                
                # ROBOT
                if hasattr(result, 'robot'):
                    robot = result.robot
                    if robot and robot.result:
                        vuln_status = str(robot.result.robot_result)
                        if 'VULNERABLE' in vuln_status:
                            findings.append(Finding(
                                id=self._generate_id(),
                                tool=self.TOOL_NAME,
                                category="vulnerability",
                                severity=Severity.HIGH.value,
                                title="ROBOT Vulnerability",
                                description="Server vulnerable to ROBOT attack",
                                target=target,
                                port=port,
                                service='tls',
                                confidence=0.95,
                            ))
                
                # CCS Injection
                if hasattr(result, 'openssl_ccs_injection'):
                    ccs = result.openssl_ccs_injection
                    if ccs and ccs.result and ccs.result.is_vulnerable_to_ccs_injection:
                        findings.append(Finding(
                            id=self._generate_id(),
                            tool=self.TOOL_NAME,
                            category="vulnerability",
                            severity=Severity.HIGH.value,
                            title="OpenSSL CCS Injection",
                            description="Server vulnerable to CCS injection (CVE-2014-0224)",
                            target=target,
                            port=port,
                            service='tls',
                            cve_id='CVE-2014-0224',
                            confidence=0.99,
                        ))
                
                # Check deprecated protocols
                deprecated = [
                    ('ssl_2_0_cipher_suites', 'SSLv2', Severity.CRITICAL.value),
                    ('ssl_3_0_cipher_suites', 'SSLv3', Severity.HIGH.value),
                    ('tls_1_0_cipher_suites', 'TLS 1.0', Severity.MEDIUM.value),
                    ('tls_1_1_cipher_suites', 'TLS 1.1', Severity.MEDIUM.value),
                ]
                
                for attr, proto_name, severity in deprecated:
                    if hasattr(result, attr):
                        proto_result = getattr(result, attr)
                        if proto_result and proto_result.result:
                            ciphers = proto_result.result.accepted_cipher_suites
                            if ciphers:
                                findings.append(Finding(
                                    id=self._generate_id(),
                                    tool=self.TOOL_NAME,
                                    category="cryptography",
                                    severity=severity,
                                    title=f"Deprecated Protocol: {proto_name}",
                                    description=f"Server supports {proto_name} with {len(ciphers)} cipher(s)",
                                    target=target,
                                    port=port,
                                    service='tls',
                                    evidence=', '.join([c.cipher_suite.name for c in ciphers[:5]]),
                                    confidence=0.99,
                                    remediation=f"Disable {proto_name} protocol",
                                ))
                                
        except Exception as e:
            logger.error(f"Error processing SSLyze results: {e}")
        
        return findings
    
    def parse_output(self, raw_output: str, target: str, port: int = 443) -> List[Finding]:
        """Parse SSLyze JSON output"""
        findings = []
        
        try:
            data = json.loads(raw_output)
            
            for server_result in data.get('server_scan_results', []):
                commands = server_result.get('scan_result', {})
                
                # Heartbleed
                heartbleed = commands.get('heartbleed', {})
                if heartbleed.get('result', {}).get('is_vulnerable_to_heartbleed'):
                    findings.append(Finding(
                        id=self._generate_id(),
                        tool=self.TOOL_NAME,
                        category="vulnerability",
                        severity=Severity.CRITICAL.value,
                        title="Heartbleed Vulnerability",
                        description="Server vulnerable to Heartbleed",
                        target=target,
                        port=port,
                        service='tls',
                        cve_id='CVE-2014-0160',
                        confidence=0.99,
                    ))
                
                # Check for deprecated protocols in accepted ciphers
                deprecated_protocols = {
                    'ssl_2_0_cipher_suites': ('SSLv2', Severity.CRITICAL.value),
                    'ssl_3_0_cipher_suites': ('SSLv3', Severity.HIGH.value),
                    'tls_1_0_cipher_suites': ('TLS 1.0', Severity.MEDIUM.value),
                    'tls_1_1_cipher_suites': ('TLS 1.1', Severity.MEDIUM.value),
                }
                
                for key, (proto_name, severity) in deprecated_protocols.items():
                    proto_data = commands.get(key, {})
                    accepted = proto_data.get('result', {}).get('accepted_cipher_suites', [])
                    if accepted:
                        findings.append(Finding(
                            id=self._generate_id(),
                            tool=self.TOOL_NAME,
                            category="cryptography",
                            severity=severity,
                            title=f"Deprecated Protocol: {proto_name}",
                            description=f"Server supports {proto_name} with {len(accepted)} ciphers",
                            target=target,
                            port=port,
                            service='tls',
                            confidence=0.99,
                        ))
                        
        except json.JSONDecodeError:
            logger.warning("SSLyze output not valid JSON")
        except Exception as e:
            logger.error(f"Error parsing SSLyze output: {e}")
        
        return findings
