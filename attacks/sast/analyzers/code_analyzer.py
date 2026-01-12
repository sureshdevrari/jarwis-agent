"""
Code Analyzer - Static Code Vulnerability Analysis

Detects security vulnerabilities in source code:
- SQL Injection patterns
- XSS vulnerabilities
- Command Injection
- Path Traversal
- Insecure Deserialization
- SSRF patterns
- Insecure Cryptography
- Hardcoded credentials (complements secret_scanner)

Uses language-specific analysis patterns.
"""

import os
import re
import logging
from typing import List, Dict, Any, Pattern, Optional
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class VulnPattern:
    """Vulnerability pattern definition"""
    id: str
    name: str
    pattern: Pattern
    severity: str
    category: str  # OWASP category
    cwe: str
    description: str
    languages: List[str] = field(default_factory=list)
    remediation: str = ""


# Language-specific vulnerability patterns
VULN_PATTERNS: List[VulnPattern] = [
    # SQL Injection
    VulnPattern(
        id='sql-injection-concat',
        name='SQL Injection (String Concatenation)',
        pattern=re.compile(r'(?:execute|query|cursor\.execute|raw)\s*\(\s*["\'][^"\']*["\'\s]*\+|\%\s*\(?[^)]+\)?|\.format\s*\(', re.IGNORECASE),
        severity='critical',
        category='A03:2021',
        cwe='CWE-89',
        description='SQL query built with string concatenation or format strings - vulnerable to SQL injection',
        languages=['python', 'java', 'php', 'ruby'],
        remediation='Use parameterized queries or prepared statements',
    ),
    VulnPattern(
        id='sql-injection-fstring',
        name='SQL Injection (f-string)',
        pattern=re.compile(r'(?:execute|query)\s*\(\s*f["\']'),
        severity='critical',
        category='A03:2021',
        cwe='CWE-89',
        description='SQL query built with Python f-strings - vulnerable to SQL injection',
        languages=['python'],
        remediation='Use parameterized queries with placeholders',
    ),
    
    # XSS
    VulnPattern(
        id='xss-inner-html',
        name='DOM-based XSS (innerHTML)',
        pattern=re.compile(r'\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\('),
        severity='high',
        category='A03:2021',
        cwe='CWE-79',
        description='Direct DOM manipulation with innerHTML - vulnerable to XSS',
        languages=['javascript', 'typescript'],
        remediation='Use textContent or sanitize input with DOMPurify',
    ),
    VulnPattern(
        id='xss-dangerously-set',
        name='React XSS (dangerouslySetInnerHTML)',
        pattern=re.compile(r'dangerouslySetInnerHTML'),
        severity='high',
        category='A03:2021',
        cwe='CWE-79',
        description='React dangerouslySetInnerHTML without sanitization',
        languages=['javascript', 'typescript', 'jsx', 'tsx'],
        remediation='Sanitize HTML content with DOMPurify before rendering',
    ),
    VulnPattern(
        id='xss-eval',
        name='Code Injection (eval)',
        pattern=re.compile(r'\beval\s*\(|\bexec\s*\(|\bsetTimeout\s*\([^,]*["\'][^"\']*\+'),
        severity='critical',
        category='A03:2021',
        cwe='CWE-95',
        description='Dynamic code execution with eval/exec - vulnerable to code injection',
        languages=['javascript', 'python', 'php'],
        remediation='Avoid eval(). Use safer alternatives like JSON.parse()',
    ),
    
    # Command Injection
    VulnPattern(
        id='command-injection-os',
        name='OS Command Injection',
        pattern=re.compile(r'os\.system\s*\(|os\.popen\s*\(|subprocess\.\w+\s*\([^)]*shell\s*=\s*True', re.IGNORECASE),
        severity='critical',
        category='A03:2021',
        cwe='CWE-78',
        description='OS command execution with shell=True or os.system() - vulnerable to command injection',
        languages=['python'],
        remediation='Use subprocess.run() with shell=False and pass arguments as list',
    ),
    VulnPattern(
        id='command-injection-runtime',
        name='Command Injection (Runtime.exec)',
        pattern=re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\('),
        severity='high',
        category='A03:2021',
        cwe='CWE-78',
        description='Java Runtime.exec() may be vulnerable to command injection',
        languages=['java'],
        remediation='Validate and sanitize all input used in command arguments',
    ),
    
    # Path Traversal
    VulnPattern(
        id='path-traversal',
        name='Path Traversal',
        pattern=re.compile(r'open\s*\([^)]*\+|readFile\s*\([^)]*\+|fs\.read|include\s*\$|require\s*\$'),
        severity='high',
        category='A01:2021',
        cwe='CWE-22',
        description='File operation with user-controlled path - vulnerable to path traversal',
        languages=['python', 'javascript', 'php'],
        remediation='Validate paths and use path.resolve() to prevent directory traversal',
    ),
    
    # Insecure Deserialization
    VulnPattern(
        id='insecure-deserialization-pickle',
        name='Insecure Deserialization (pickle)',
        pattern=re.compile(r'pickle\.loads?\s*\(|cPickle\.loads?\s*\('),
        severity='critical',
        category='A08:2021',
        cwe='CWE-502',
        description='Python pickle deserialization of untrusted data can lead to RCE',
        languages=['python'],
        remediation='Use JSON or other safe serialization formats for untrusted data',
    ),
    VulnPattern(
        id='insecure-deserialization-yaml',
        name='Insecure YAML Loading',
        pattern=re.compile(r'yaml\.load\s*\([^)]*(?!Loader|safe)'),
        severity='high',
        category='A08:2021',
        cwe='CWE-502',
        description='yaml.load() without safe_load can execute arbitrary code',
        languages=['python'],
        remediation='Use yaml.safe_load() instead of yaml.load()',
    ),
    VulnPattern(
        id='insecure-deserialization-java',
        name='Insecure Deserialization (Java)',
        pattern=re.compile(r'ObjectInputStream\s*\(|readObject\s*\('),
        severity='critical',
        category='A08:2021',
        cwe='CWE-502',
        description='Java ObjectInputStream deserialization may be vulnerable to RCE',
        languages=['java'],
        remediation='Implement ObjectInputFilter or use safer alternatives like JSON',
    ),
    
    # SSRF
    VulnPattern(
        id='ssrf-request',
        name='Server-Side Request Forgery',
        pattern=re.compile(r'requests\.(?:get|post|put|delete)\s*\([^)]*\+|urllib\.request\.urlopen|http\.get\s*\('),
        severity='high',
        category='A10:2021',
        cwe='CWE-918',
        description='HTTP request with potentially user-controlled URL',
        languages=['python', 'javascript'],
        remediation='Validate URLs against allowlist, block internal IPs',
    ),
    
    # Insecure Cryptography
    VulnPattern(
        id='weak-crypto-md5',
        name='Weak Cryptography (MD5)',
        pattern=re.compile(r'hashlib\.md5\s*\(|MD5\.Create|md5\s*\(|Digest::MD5'),
        severity='medium',
        category='A02:2021',
        cwe='CWE-328',
        description='MD5 is cryptographically weak - should not be used for security',
        languages=['python', 'java', 'php', 'ruby'],
        remediation='Use SHA-256 or stronger hash algorithms',
    ),
    VulnPattern(
        id='weak-crypto-sha1',
        name='Weak Cryptography (SHA1)',
        pattern=re.compile(r'hashlib\.sha1\s*\(|SHA1\.Create|sha1\s*\(|Digest::SHA1'),
        severity='medium',
        category='A02:2021',
        cwe='CWE-328',
        description='SHA1 is cryptographically weak for security purposes',
        languages=['python', 'java', 'php', 'ruby'],
        remediation='Use SHA-256 or stronger hash algorithms',
    ),
    VulnPattern(
        id='weak-random',
        name='Insecure Random Number Generator',
        pattern=re.compile(r'\brandom\.\w+\s*\(|Math\.random\s*\(|rand\s*\('),
        severity='medium',
        category='A02:2021',
        cwe='CWE-330',
        description='Weak random number generator used - not suitable for security',
        languages=['python', 'javascript', 'php'],
        remediation='Use secrets module (Python) or crypto.randomBytes() (Node.js)',
    ),
    
    # Hardcoded Secrets (backup to secret_scanner)
    VulnPattern(
        id='hardcoded-password-variable',
        name='Hardcoded Password in Variable',
        pattern=re.compile(r'(?:password|passwd|pwd|secret|api_key)\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        severity='high',
        category='A07:2021',
        cwe='CWE-798',
        description='Hardcoded password or secret in source code',
        languages=['python', 'javascript', 'java', 'ruby', 'php'],
        remediation='Use environment variables or secrets manager',
    ),
    
    # XXE
    VulnPattern(
        id='xxe-python',
        name='XML External Entity (XXE)',
        pattern=re.compile(r'etree\.parse\s*\(|minidom\.parse\s*\(|xml\.sax\.parse'),
        severity='high',
        category='A05:2021',
        cwe='CWE-611',
        description='XML parsing may be vulnerable to XXE attacks',
        languages=['python'],
        remediation='Use defusedxml library or disable external entities',
    ),
    VulnPattern(
        id='xxe-java',
        name='XML External Entity (XXE) - Java',
        pattern=re.compile(r'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory'),
        severity='high',
        category='A05:2021',
        cwe='CWE-611',
        description='Java XML parser may be vulnerable to XXE if not properly configured',
        languages=['java'],
        remediation='Disable DTDs and external entities in parser configuration',
    ),
    
    # Debug/Development Code
    VulnPattern(
        id='debug-enabled',
        name='Debug Mode Enabled',
        pattern=re.compile(r'DEBUG\s*=\s*True|app\.debug\s*=\s*True|\.run\s*\([^)]*debug\s*=\s*True'),
        severity='medium',
        category='A05:2021',
        cwe='CWE-489',
        description='Debug mode enabled in production code',
        languages=['python'],
        remediation='Disable debug mode in production deployments',
    ),
    VulnPattern(
        id='console-log-sensitive',
        name='Sensitive Data in Logs',
        pattern=re.compile(r'console\.log\s*\([^)]*(?:password|token|secret|key|credential)', re.IGNORECASE),
        severity='medium',
        category='A09:2021',
        cwe='CWE-532',
        description='Sensitive data may be exposed in console logs',
        languages=['javascript', 'typescript'],
        remediation='Remove sensitive data logging or use proper redaction',
    ),
    
    # CORS Misconfiguration
    VulnPattern(
        id='cors-wildcard',
        name='CORS Wildcard Origin',
        pattern=re.compile(r'Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']?\*|cors\s*\(\s*\)|origin\s*:\s*["\']?\*'),
        severity='medium',
        category='A05:2021',
        cwe='CWE-942',
        description='CORS configured with wildcard origin - may allow unauthorized access',
        languages=['javascript', 'python', 'java'],
        remediation='Configure specific allowed origins instead of wildcard',
    ),
    
    # JWT Issues
    VulnPattern(
        id='jwt-none-algorithm',
        name='JWT None Algorithm',
        pattern=re.compile(r'algorithm\s*[=:]\s*["\']?(?:none|None|NONE)["\']?'),
        severity='critical',
        category='A07:2021',
        cwe='CWE-327',
        description='JWT with "none" algorithm allows signature bypass',
        languages=['javascript', 'python', 'java'],
        remediation='Always specify a secure algorithm like RS256 or HS256',
    ),
]


class CodeAnalyzer:
    """
    Analyzes source code for security vulnerabilities.
    
    Uses pattern-based detection with language-aware filtering.
    Maps findings to OWASP categories and CWE identifiers.
    """
    
    # File extensions to language mapping
    EXTENSION_MAP = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'jsx',
        '.ts': 'typescript',
        '.tsx': 'tsx',
        '.java': 'java',
        '.rb': 'ruby',
        '.php': 'php',
        '.go': 'go',
        '.cs': 'csharp',
    }
    
    # Files/directories to skip
    SKIP_DIRS = {
        'node_modules', 'vendor', '.git', '__pycache__', 'venv', '.venv',
        'build', 'dist', 'target', 'bin', 'obj', '.idea', '.vscode'
    }
    
    def __init__(self, config: dict, context):
        """
        Initialize code analyzer.
        
        Args:
            config: Scan configuration
                - languages: List of languages to analyze (auto-detect if empty)
            context: SASTScanContext with repo_path
        """
        self.config = config
        self.context = context
        self.target_languages = config.get('languages', [])
    
    async def scan(self) -> List[Dict[str, Any]]:
        """
        Scan repository for code vulnerabilities.
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        repo_path = getattr(self.context, 'repo_path', None)
        if not repo_path or not os.path.exists(repo_path):
            logger.warning("No repository path available for code analysis")
            return findings
        
        # Walk through source files
        for root, dirs, files in os.walk(repo_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)
                
                # Get file language
                ext = os.path.splitext(file)[1].lower()
                language = self.EXTENSION_MAP.get(ext)
                
                if not language:
                    continue
                
                # Filter by target languages if specified
                if self.target_languages and language not in self.target_languages:
                    continue
                
                # Analyze file
                file_findings = await self._analyze_file(file_path, relative_path, language)
                findings.extend(file_findings)
        
        logger.info(f"Code analyzer found {len(findings)} potential vulnerabilities")
        return findings
    
    async def _analyze_file(self, file_path: str, relative_path: str, language: str) -> List[Dict[str, Any]]:
        """Analyze a single file for vulnerabilities"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Skip large files
            if len(content) > 500_000:  # 500KB
                return findings
            
            lines = content.split('\n')
            
            for pattern in VULN_PATTERNS:
                # Check if pattern applies to this language
                if pattern.languages and language not in pattern.languages:
                    continue
                
                # Check each line
                for line_num, line in enumerate(lines, 1):
                    # Skip comments
                    stripped = line.strip()
                    if self._is_comment(stripped, language):
                        continue
                    
                    match = pattern.pattern.search(line)
                    if match:
                        findings.append({
                            'id': f'CODE-{pattern.id.upper()}-{line_num}',
                            'category': pattern.category,
                            'severity': pattern.severity,
                            'title': pattern.name,
                            'description': pattern.description,
                            'file': relative_path,
                            'line': line_num,
                            'column': match.start() + 1,
                            'rule_id': pattern.id,
                            'cwe': pattern.cwe,
                            'evidence': line.strip()[:200],  # Truncate long lines
                            'language': language,
                            'remediation': pattern.remediation,
                        })
        
        except Exception as e:
            logger.debug(f"Error analyzing {file_path}: {e}")
        
        return findings
    
    def _is_comment(self, line: str, language: str) -> bool:
        """Check if line is a comment"""
        if not line:
            return True
        
        # Common comment patterns
        if line.startswith('#') and language in ['python', 'ruby', 'bash']:
            return True
        if line.startswith('//') and language in ['javascript', 'typescript', 'java', 'go', 'csharp', 'jsx', 'tsx']:
            return True
        if line.startswith('/*') or line.startswith('*'):
            return True
        
        return False


__all__ = ['CodeAnalyzer', 'VulnPattern', 'VULN_PATTERNS']
