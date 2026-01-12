"""
Jarwis AGI Pen Test - Vulnerability Scanner Module
Checks detected services for known vulnerabilities
"""

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityInfo:
    """Information about a discovered vulnerability"""
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str = ""
    affected_product: str = ""
    affected_versions: str = ""
    remediation: str = ""
    references: List[str] = None
    exploit_available: bool = False
    
    def __post_init__(self):
        if self.references is None:
            self.references = []


class VulnerabilityScanner:
    """
    Scans for known vulnerabilities based on detected services/versions
    
    In production, this would integrate with:
    - NVD (National Vulnerability Database)
    - CVE databases
    - Exploit-DB
    - Vendor advisories
    """
    
    # Known vulnerabilities database (subset - would be much larger in production)
    VULN_DATABASE = {
        # OpenSSH vulnerabilities
        'openssh': {
            '7.2': [
                VulnerabilityInfo(
                    cve_id='CVE-2016-6210',
                    title='OpenSSH User Enumeration Timing Attack',
                    description='OpenSSH before 7.3 allows remote attackers to enumerate valid usernames through timing differences in authentication responses.',
                    severity='medium',
                    cvss_score=5.3,
                    cvss_vector='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                    affected_product='openssh',
                    affected_versions='< 7.3',
                    remediation='Upgrade OpenSSH to version 7.3 or later'
                ),
            ],
            '7.4': [
                VulnerabilityInfo(
                    cve_id='CVE-2017-15906',
                    title='OpenSSH sftp-server Write Issue',
                    description='The sftp-server component in OpenSSH before 7.6 does not properly prevent write operations in read-only mode.',
                    severity='medium',
                    cvss_score=5.3,
                    cvss_vector='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
                    affected_product='openssh',
                    affected_versions='< 7.6',
                    remediation='Upgrade OpenSSH to version 7.6 or later'
                ),
            ],
            '8.1': [
                VulnerabilityInfo(
                    cve_id='CVE-2021-28041',
                    title='OpenSSH ssh-agent Double Free',
                    description='ssh-agent in OpenSSH before 8.5 has a double free that may be relevant in a few less-common scenarios.',
                    severity='high',
                    cvss_score=7.1,
                    cvss_vector='CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H',
                    affected_product='openssh',
                    affected_versions='< 8.5',
                    remediation='Upgrade OpenSSH to version 8.5 or later'
                ),
            ],
        },
        # Apache vulnerabilities
        'apache': {
            '2.4.49': [
                VulnerabilityInfo(
                    cve_id='CVE-2021-41773',
                    title='Apache HTTP Server Path Traversal and RCE',
                    description='A path traversal vulnerability in Apache HTTP Server 2.4.49 allows remote attackers to map URLs to files outside the directories configured. When combined with mod_cgi, this can lead to RCE.',
                    severity='critical',
                    cvss_score=9.8,
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    affected_product='apache',
                    affected_versions='2.4.49',
                    remediation='Upgrade to Apache HTTP Server 2.4.51 or later immediately',
                    exploit_available=True
                ),
            ],
            '2.4.50': [
                VulnerabilityInfo(
                    cve_id='CVE-2021-42013',
                    title='Apache HTTP Server Path Traversal Bypass',
                    description='An incomplete fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 allows attackers to bypass path traversal protections.',
                    severity='critical',
                    cvss_score=9.8,
                    cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    affected_product='apache',
                    affected_versions='2.4.50',
                    remediation='Upgrade to Apache HTTP Server 2.4.51 or later immediately',
                    exploit_available=True
                ),
            ],
        },
        # vsftpd backdoor
        'vsftpd': {
            '2.3.4': [
                VulnerabilityInfo(
                    cve_id='CVE-2011-2523',
                    title='vsftpd Backdoor Command Execution',
                    description='vsftpd 2.3.4 downloaded between 2011-06-30 and 2011-07-01 contains a backdoor that opens a shell on port 6200 when triggered.',
                    severity='critical',
                    cvss_score=10.0,
                    cvss_vector='CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C',
                    affected_product='vsftpd',
                    affected_versions='2.3.4 (compromised version)',
                    remediation='Reinstall vsftpd from trusted source',
                    exploit_available=True
                ),
            ],
        },
        # MySQL
        'mysql': {
            '5.5': [
                VulnerabilityInfo(
                    cve_id='CVE-2012-2122',
                    title='MySQL Authentication Bypass',
                    description='MySQL and MariaDB allow remote attackers to bypass authentication on certain system configurations through repeated authentication attempts with an incorrect password.',
                    severity='high',
                    cvss_score=7.5,
                    cvss_vector='CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P',
                    affected_product='mysql',
                    affected_versions='5.1.x, 5.5.x before 5.5.24',
                    remediation='Upgrade MySQL to 5.5.24 or later',
                    exploit_available=True
                ),
            ],
        },
        # Redis
        'redis': {
            '2.': [
                VulnerabilityInfo(
                    cve_id='CVE-2015-4335',
                    title='Redis Lua Sandbox Escape',
                    description='Redis before 2.8.21 and 3.x before 3.0.2 allows remote attackers to execute arbitrary Lua code via the eval command.',
                    severity='critical',
                    cvss_score=9.8,
                    cvss_vector='CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    affected_product='redis',
                    affected_versions='< 2.8.21, 3.x < 3.0.2',
                    remediation='Upgrade Redis to 2.8.21/3.0.2 or later and enable authentication',
                    exploit_available=True
                ),
            ],
        },
        # nginx
        'nginx': {
            '1.4': [
                VulnerabilityInfo(
                    cve_id='CVE-2013-4547',
                    title='nginx Request Line Parsing Vulnerability',
                    description='nginx 0.8.41 through 1.4.3 and 1.5.x before 1.5.7 allows remote attackers to bypass security restrictions via an unescaped space character in a URI.',
                    severity='high',
                    cvss_score=7.5,
                    cvss_vector='CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P',
                    affected_product='nginx',
                    affected_versions='0.8.41 - 1.4.3, 1.5.x < 1.5.7',
                    remediation='Upgrade nginx to 1.4.4 or 1.5.7 or later'
                ),
            ],
        },
    }

    def __init__(self, config: dict):
        self.config = config
        self.check_exploits = config.get('check_exploits', True)
    
    async def scan(self, services: Dict[int, Dict]) -> List[Dict]:
        """
        Scan detected services for known vulnerabilities
        
        Args:
            services: Dict mapping port to service info
                     {port: {'service': str, 'version': str, 'product': str}}
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        for port, service_info in services.items():
            product = service_info.get('product', service_info.get('service', '')).lower()
            version = service_info.get('version', '')
            
            if not product or not version:
                continue
            
            # Check each product in our database
            for db_product, versions in self.VULN_DATABASE.items():
                if db_product in product or product in db_product:
                    # Check version matches
                    vulns = self._check_version(version, versions)
                    for vuln in vulns:
                        findings.append({
                            'port': port,
                            'service': product,
                            'version': version,
                            'vulnerability': vuln
                        })
        
        return findings
    
    def _check_version(self, detected_version: str, vuln_versions: Dict) -> List[VulnerabilityInfo]:
        """Check if detected version matches any vulnerable versions"""
        matches = []
        
        for vuln_version, vulns in vuln_versions.items():
            # Simple version prefix matching
            if detected_version.startswith(vuln_version):
                matches.extend(vulns)
            # Also check for partial matches
            elif vuln_version in detected_version:
                matches.extend(vulns)
        
        return matches
    
    def get_severity_from_cvss(self, cvss: float) -> str:
        """Convert CVSS score to severity string"""
        if cvss >= 9.0:
            return 'critical'
        elif cvss >= 7.0:
            return 'high'
        elif cvss >= 4.0:
            return 'medium'
        elif cvss > 0:
            return 'low'
        return 'info'
