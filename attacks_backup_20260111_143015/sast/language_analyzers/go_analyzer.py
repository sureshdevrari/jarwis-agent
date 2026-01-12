"""
Go Security Analyzer

gosec-style security analysis for Go code.
"""

import os
import re
import logging
from typing import List, Dict, Any, Pattern
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class GoVulnPattern:
    id: str
    pattern: Pattern
    severity: str
    cwe: str
    title: str
    description: str


GO_PATTERNS = [
    GoVulnPattern(
        id='go-sql-injection',
        pattern=re.compile(r'(?:Query|Exec)\s*\([^)]*\+|fmt\.Sprintf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)', re.IGNORECASE),
        severity='critical',
        cwe='CWE-89',
        title='SQL Injection',
        description='SQL query built with string concatenation or fmt.Sprintf',
    ),
    GoVulnPattern(
        id='go-command-injection',
        pattern=re.compile(r'exec\.Command\s*\([^)]*\+'),
        severity='critical',
        cwe='CWE-78',
        title='Command Injection Risk',
        description='exec.Command with string concatenation',
    ),
    GoVulnPattern(
        id='go-path-traversal',
        pattern=re.compile(r'os\.Open\s*\([^)]*\+|ioutil\.ReadFile\s*\([^)]*\+'),
        severity='high',
        cwe='CWE-22',
        title='Path Traversal Risk',
        description='File operation with string concatenation',
    ),
    GoVulnPattern(
        id='go-weak-random',
        pattern=re.compile(r'math/rand|rand\.(?:Int|Intn|Float)'),
        severity='medium',
        cwe='CWE-330',
        title='Weak Random Number',
        description='math/rand is not cryptographically secure, use crypto/rand',
    ),
    GoVulnPattern(
        id='go-hardcoded-password',
        pattern=re.compile(r'(?:password|secret|apikey)\s*:?=\s*"[^"]{4,}"', re.IGNORECASE),
        severity='high',
        cwe='CWE-798',
        title='Hardcoded Credential',
        description='Hardcoded password or secret detected',
    ),
    GoVulnPattern(
        id='go-insecure-tls',
        pattern=re.compile(r'InsecureSkipVerify\s*:\s*true'),
        severity='high',
        cwe='CWE-295',
        title='Disabled TLS Verification',
        description='TLS certificate verification is disabled',
    ),
    GoVulnPattern(
        id='go-unhandled-error',
        pattern=re.compile(r'_\s*,\s*err\s*:?=|err\s*=\s*nil'),
        severity='low',
        cwe='CWE-755',
        title='Unhandled Error',
        description='Error value may be ignored',
    ),
]


class GoAnalyzer:
    """Go security analyzer"""
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
    
    async def scan(self) -> List[Dict[str, Any]]:
        """Scan Go files"""
        findings = []
        
        repo_path = getattr(self.context, 'repo_path', None)
        if not repo_path:
            return findings
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ['vendor', '.git']]
            
            for file in files:
                if not file.endswith('.go'):
                    continue
                
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)
                
                file_findings = await self._analyze_file(file_path, relative_path)
                findings.extend(file_findings)
        
        return findings
    
    async def _analyze_file(self, file_path: str, relative_path: str) -> List[Dict[str, Any]]:
        """Analyze a Go file"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            for pattern in GO_PATTERNS:
                for line_num, line in enumerate(lines, 1):
                    if pattern.pattern.search(line):
                        findings.append({
                            'id': f'GO-{pattern.cwe}-{line_num}',
                            'category': 'A03:2021',
                            'severity': pattern.severity,
                            'title': pattern.title,
                            'description': pattern.description,
                            'file': relative_path,
                            'line': line_num,
                            'rule_id': pattern.id,
                            'cwe': pattern.cwe,
                            'language': 'go',
                            'evidence': line.strip()[:150],
                        })
        
        except Exception as e:
            logger.debug(f"Error analyzing {file_path}: {e}")
        
        return findings


__all__ = ['GoAnalyzer']
