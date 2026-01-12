"""
JavaScript/TypeScript Security Analyzer

ESLint security rules and DOM-based vulnerability detection.
"""

import os
import re
import logging
from typing import List, Dict, Any, Pattern
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class JSVulnPattern:
    id: str
    pattern: Pattern
    severity: str
    cwe: str
    title: str
    description: str


JS_PATTERNS = [
    JSVulnPattern(
        id='js-eval',
        pattern=re.compile(r'\beval\s*\('),
        severity='critical',
        cwe='CWE-95',
        title='eval() Code Injection',
        description='eval() can execute arbitrary code and is vulnerable to injection',
    ),
    JSVulnPattern(
        id='js-innerhtml',
        pattern=re.compile(r'\.innerHTML\s*=(?!=)'),
        severity='high',
        cwe='CWE-79',
        title='DOM XSS via innerHTML',
        description='Setting innerHTML with untrusted data can lead to XSS',
    ),
    JSVulnPattern(
        id='js-document-write',
        pattern=re.compile(r'document\.write\s*\('),
        severity='high',
        cwe='CWE-79',
        title='DOM XSS via document.write',
        description='document.write with untrusted data can lead to XSS',
    ),
    JSVulnPattern(
        id='js-dangerously-set',
        pattern=re.compile(r'dangerouslySetInnerHTML'),
        severity='high',
        cwe='CWE-79',
        title='React XSS Risk',
        description='dangerouslySetInnerHTML can cause XSS if not properly sanitized',
    ),
    JSVulnPattern(
        id='js-child-process',
        pattern=re.compile(r'child_process\.exec\s*\(|exec\s*\([^)]*\$\{'),
        severity='critical',
        cwe='CWE-78',
        title='Command Injection Risk',
        description='child_process.exec with user input can lead to command injection',
    ),
    JSVulnPattern(
        id='js-sql-concat',
        pattern=re.compile(r'(?:query|execute)\s*\([^)]*\$\{|(?:query|execute)\s*\([^)]*\+'),
        severity='critical',
        cwe='CWE-89',
        title='SQL Injection',
        description='SQL query built with string concatenation',
    ),
    JSVulnPattern(
        id='js-weak-random',
        pattern=re.compile(r'Math\.random\s*\(\s*\)'),
        severity='low',
        cwe='CWE-330',
        title='Weak Random Number',
        description='Math.random() is not cryptographically secure',
    ),
    JSVulnPattern(
        id='js-postmessage',
        pattern=re.compile(r'postMessage\s*\([^)]+,\s*["\']?\*["\']?\s*\)'),
        severity='medium',
        cwe='CWE-346',
        title='Insecure postMessage',
        description='postMessage with "*" origin allows any domain to receive messages',
    ),
    JSVulnPattern(
        id='js-localstorage-sensitive',
        pattern=re.compile(r'localStorage\.setItem\s*\([^)]*(?:token|password|secret|key)', re.IGNORECASE),
        severity='medium',
        cwe='CWE-922',
        title='Sensitive Data in localStorage',
        description='Storing sensitive data in localStorage is insecure',
    ),
]


class JavaScriptAnalyzer:
    """JavaScript/TypeScript security analyzer"""
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
    
    async def scan(self) -> List[Dict[str, Any]]:
        """Scan JavaScript/TypeScript files"""
        findings = []
        
        repo_path = getattr(self.context, 'repo_path', None)
        if not repo_path:
            return findings
        
        extensions = {'.js', '.jsx', '.ts', '.tsx', '.mjs'}
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ['node_modules', 'dist', 'build', '.next']]
            
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext not in extensions:
                    continue
                
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)
                
                file_findings = await self._analyze_file(file_path, relative_path)
                findings.extend(file_findings)
        
        return findings
    
    async def _analyze_file(self, file_path: str, relative_path: str) -> List[Dict[str, Any]]:
        """Analyze a JavaScript file"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if len(content) > 500_000:
                return findings
            
            lines = content.split('\n')
            
            for pattern in JS_PATTERNS:
                for line_num, line in enumerate(lines, 1):
                    if pattern.pattern.search(line):
                        findings.append({
                            'id': f'JS-{pattern.cwe}-{line_num}',
                            'category': 'A03:2021' if 'inject' in pattern.title.lower() else 'A05:2021',
                            'severity': pattern.severity,
                            'title': pattern.title,
                            'description': pattern.description,
                            'file': relative_path,
                            'line': line_num,
                            'rule_id': pattern.id,
                            'cwe': pattern.cwe,
                            'language': 'javascript',
                            'evidence': line.strip()[:150],
                        })
        
        except Exception as e:
            logger.debug(f"Error analyzing {file_path}: {e}")
        
        return findings


__all__ = ['JavaScriptAnalyzer']
