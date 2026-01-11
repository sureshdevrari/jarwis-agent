"""
Java Security Analyzer

FindSecBugs-style security analysis for Java code.
"""

import os
import re
import logging
from typing import List, Dict, Any, Pattern
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class JavaVulnPattern:
    id: str
    pattern: Pattern
    severity: str
    cwe: str
    title: str
    description: str


JAVA_PATTERNS = [
    JavaVulnPattern(
        id='java-sql-injection',
        pattern=re.compile(r'(?:executeQuery|executeUpdate|execute)\s*\([^)]*\+'),
        severity='critical',
        cwe='CWE-89',
        title='SQL Injection',
        description='SQL query built with string concatenation',
    ),
    JavaVulnPattern(
        id='java-command-injection',
        pattern=re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\('),
        severity='critical',
        cwe='CWE-78',
        title='Command Injection Risk',
        description='Runtime.exec() with untrusted input can lead to command injection',
    ),
    JavaVulnPattern(
        id='java-deserialization',
        pattern=re.compile(r'ObjectInputStream|readObject\s*\('),
        severity='critical',
        cwe='CWE-502',
        title='Insecure Deserialization',
        description='ObjectInputStream can deserialize malicious objects',
    ),
    JavaVulnPattern(
        id='java-xxe',
        pattern=re.compile(r'DocumentBuilderFactory\.newInstance\(\)(?!.*setFeature)'),
        severity='high',
        cwe='CWE-611',
        title='XXE Vulnerability',
        description='XML parser may be vulnerable to XXE if not properly configured',
    ),
    JavaVulnPattern(
        id='java-path-traversal',
        pattern=re.compile(r'new\s+File\s*\([^)]*\+'),
        severity='high',
        cwe='CWE-22',
        title='Path Traversal Risk',
        description='File path built with string concatenation',
    ),
    JavaVulnPattern(
        id='java-weak-crypto',
        pattern=re.compile(r'Cipher\.getInstance\s*\(["\'](?:DES|RC2|RC4|Blowfish)', re.IGNORECASE),
        severity='medium',
        cwe='CWE-327',
        title='Weak Cryptography',
        description='Using weak encryption algorithm',
    ),
    JavaVulnPattern(
        id='java-hardcoded-password',
        pattern=re.compile(r'(?:password|passwd|secret)\s*=\s*"[^"]{4,}"', re.IGNORECASE),
        severity='high',
        cwe='CWE-798',
        title='Hardcoded Credential',
        description='Hardcoded password or secret detected',
    ),
    JavaVulnPattern(
        id='java-trust-all-certs',
        pattern=re.compile(r'TrustManager|setHostnameVerifier.*ALLOW_ALL|checkServerTrusted.*return'),
        severity='high',
        cwe='CWE-295',
        title='Disabled Certificate Validation',
        description='SSL/TLS certificate validation may be disabled',
    ),
]


class JavaAnalyzer:
    """Java security analyzer"""
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
    
    async def scan(self) -> List[Dict[str, Any]]:
        """Scan Java files"""
        findings = []
        
        repo_path = getattr(self.context, 'repo_path', None)
        if not repo_path:
            return findings
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ['target', 'build', '.gradle', '.idea']]
            
            for file in files:
                if not file.endswith('.java'):
                    continue
                
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)
                
                file_findings = await self._analyze_file(file_path, relative_path)
                findings.extend(file_findings)
        
        return findings
    
    async def _analyze_file(self, file_path: str, relative_path: str) -> List[Dict[str, Any]]:
        """Analyze a Java file"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            for pattern in JAVA_PATTERNS:
                for line_num, line in enumerate(lines, 1):
                    if pattern.pattern.search(line):
                        findings.append({
                            'id': f'JAVA-{pattern.cwe}-{line_num}',
                            'category': 'A03:2021',
                            'severity': pattern.severity,
                            'title': pattern.title,
                            'description': pattern.description,
                            'file': relative_path,
                            'line': line_num,
                            'rule_id': pattern.id,
                            'cwe': pattern.cwe,
                            'language': 'java',
                            'evidence': line.strip()[:150],
                        })
        
        except Exception as e:
            logger.debug(f"Error analyzing {file_path}: {e}")
        
        return findings


__all__ = ['JavaAnalyzer']
