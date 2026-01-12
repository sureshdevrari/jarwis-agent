"""
Jarwis Network Security - Scanners Package

Exports all scanner classes organized by phase.
"""

# Port Scanners
from .port_scanners import (
    NmapScanner,
    MasscanScanner,
    RustScanScanner,
)

# Vulnerability Scanners
from .vuln_scanners import (
    NucleiScanner,
    OpenVASScanner,
    VulnersNmapScanner,
)

# Enumeration Scanners
from .enum_scanners import (
    NetdiscoverScanner,
    SNMPScanner,
    DNSReconScanner,
    ARPScanScanner,
)

# SSL/TLS Scanners
from .ssl_scanners import (
    SSLScanScanner,
    TestSSLScanner,
    SSLyzeScanner,
)

# Exploitation Scanners
from .exploit_scanners import (
    CrackMapExecScanner,
    ImpacketScanner,
    MetasploitScanner,
)

# Traffic Analysis
from .traffic_scanners import (
    ZeekScanner,
    SuricataScanner,
    SnortScanner,
    TSharkScanner,
)

# All scanners by category
PORT_SCANNERS = [NmapScanner, MasscanScanner, RustScanScanner]
VULN_SCANNERS = [NucleiScanner, OpenVASScanner, VulnersNmapScanner]
ENUM_SCANNERS = [NetdiscoverScanner, SNMPScanner, DNSReconScanner, ARPScanScanner]
SSL_SCANNERS = [SSLScanScanner, TestSSLScanner, SSLyzeScanner]
EXPLOIT_SCANNERS = [CrackMapExecScanner, ImpacketScanner, MetasploitScanner]
TRAFFIC_SCANNERS = [ZeekScanner, SuricataScanner, SnortScanner, TSharkScanner]

# All scanners
ALL_SCANNERS = (
    PORT_SCANNERS + 
    VULN_SCANNERS + 
    ENUM_SCANNERS + 
    SSL_SCANNERS + 
    EXPLOIT_SCANNERS + 
    TRAFFIC_SCANNERS
)

__all__ = [
    # Port
    'NmapScanner',
    'MasscanScanner',
    'RustScanScanner',
    # Vuln
    'NucleiScanner',
    'OpenVASScanner',
    'VulnersNmapScanner',
    # Enum
    'NetdiscoverScanner',
    'SNMPScanner',
    'DNSReconScanner',
    'ARPScanScanner',
    # SSL
    'SSLScanScanner',
    'TestSSLScanner',
    'SSLyzeScanner',
    # Exploit
    'CrackMapExecScanner',
    'ImpacketScanner',
    'MetasploitScanner',
    # Traffic
    'ZeekScanner',
    'SuricataScanner',
    'SnortScanner',
    'TSharkScanner',
    # Categories
    'PORT_SCANNERS',
    'VULN_SCANNERS',
    'ENUM_SCANNERS',
    'SSL_SCANNERS',
    'EXPLOIT_SCANNERS',
    'TRAFFIC_SCANNERS',
    'ALL_SCANNERS',
]
