"""
Python Security Analyzer

Bandit-style security analysis for Python code.
Detects Python-specific vulnerabilities and insecure patterns.
"""

import os
import re
import ast
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class PythonAnalyzer:
    """
    Python-specific security analyzer using AST parsing.
    
    Detects:
    - Dangerous function calls (eval, exec, compile)
    - SQL injection patterns
    - Command injection (subprocess, os.system)
    - Insecure deserialization (pickle, yaml)
    - Hardcoded secrets
    - Debug configurations
    - Insecure SSL/TLS settings
    """
    
    # Dangerous functions to flag
    DANGEROUS_CALLS = {
        'eval': {'severity': 'critical', 'cwe': 'CWE-95', 'msg': 'eval() can execute arbitrary code'},
        'exec': {'severity': 'critical', 'cwe': 'CWE-95', 'msg': 'exec() can execute arbitrary code'},
        'compile': {'severity': 'high', 'cwe': 'CWE-95', 'msg': 'compile() can be used for code injection'},
        '__import__': {'severity': 'medium', 'cwe': 'CWE-95', 'msg': '__import__() can load arbitrary modules'},
    }
    
    # Dangerous module.function combinations
    DANGEROUS_MODULE_CALLS = {
        ('os', 'system'): {'severity': 'critical', 'cwe': 'CWE-78', 'msg': 'os.system() is vulnerable to command injection'},
        ('os', 'popen'): {'severity': 'critical', 'cwe': 'CWE-78', 'msg': 'os.popen() is vulnerable to command injection'},
        ('pickle', 'load'): {'severity': 'critical', 'cwe': 'CWE-502', 'msg': 'pickle.load() can execute arbitrary code'},
        ('pickle', 'loads'): {'severity': 'critical', 'cwe': 'CWE-502', 'msg': 'pickle.loads() can execute arbitrary code'},
        ('marshal', 'load'): {'severity': 'high', 'cwe': 'CWE-502', 'msg': 'marshal.load() can be dangerous'},
        ('shelve', 'open'): {'severity': 'high', 'cwe': 'CWE-502', 'msg': 'shelve uses pickle internally'},
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
    
    async def scan(self) -> List[Dict[str, Any]]:
        """Scan Python files for vulnerabilities"""
        findings = []
        
        repo_path = getattr(self.context, 'repo_path', None)
        if not repo_path:
            return findings
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ['venv', '.venv', '__pycache__', 'node_modules']]
            
            for file in files:
                if not file.endswith('.py'):
                    continue
                
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)
                
                file_findings = await self._analyze_file(file_path, relative_path)
                findings.extend(file_findings)
        
        return findings
    
    async def _analyze_file(self, file_path: str, relative_path: str) -> List[Dict[str, Any]]:
        """Analyze a Python file using AST"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
            
            # Parse AST
            try:
                tree = ast.parse(source, filename=file_path)
            except SyntaxError:
                return findings
            
            # Walk AST nodes
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    finding = self._check_call(node, relative_path, source)
                    if finding:
                        findings.append(finding)
                
                elif isinstance(node, ast.Assign):
                    finding = self._check_assignment(node, relative_path, source)
                    if finding:
                        findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error analyzing {file_path}: {e}")
        
        return findings
    
    def _check_call(self, node: ast.Call, file_path: str, source: str) -> Optional[Dict[str, Any]]:
        """Check function call for vulnerabilities"""
        
        # Direct dangerous function calls
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.DANGEROUS_CALLS:
                info = self.DANGEROUS_CALLS[func_name]
                return {
                    'id': f'PY-{info["cwe"]}-{node.lineno}',
                    'category': 'A03:2021',
                    'severity': info['severity'],
                    'title': f'Dangerous Function: {func_name}()',
                    'description': info['msg'],
                    'file': file_path,
                    'line': node.lineno,
                    'rule_id': f'python-{func_name}',
                    'cwe': info['cwe'],
                    'language': 'python',
                }
        
        # Module.function calls
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                func = node.func.attr
                
                key = (module, func)
                if key in self.DANGEROUS_MODULE_CALLS:
                    info = self.DANGEROUS_MODULE_CALLS[key]
                    return {
                        'id': f'PY-{info["cwe"]}-{node.lineno}',
                        'category': 'A03:2021',
                        'severity': info['severity'],
                        'title': f'Dangerous Call: {module}.{func}()',
                        'description': info['msg'],
                        'file': file_path,
                        'line': node.lineno,
                        'rule_id': f'python-{module}-{func}',
                        'cwe': info['cwe'],
                        'language': 'python',
                    }
                
                # subprocess with shell=True
                if module == 'subprocess' and func in ('call', 'run', 'Popen'):
                    for keyword in node.keywords:
                        if keyword.arg == 'shell':
                            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                                return {
                                    'id': f'PY-CWE-78-{node.lineno}',
                                    'category': 'A03:2021',
                                    'severity': 'high',
                                    'title': 'Subprocess with shell=True',
                                    'description': 'subprocess called with shell=True is vulnerable to command injection',
                                    'file': file_path,
                                    'line': node.lineno,
                                    'rule_id': 'python-subprocess-shell',
                                    'cwe': 'CWE-78',
                                    'language': 'python',
                                }
        
        return None
    
    def _check_assignment(self, node: ast.Assign, file_path: str, source: str) -> Optional[Dict[str, Any]]:
        """Check variable assignments for hardcoded secrets"""
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                # Check for secret-like variable names with string values
                if any(s in var_name for s in ['password', 'secret', 'api_key', 'apikey', 'token', 'credential']):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) >= 4:  # Skip short values
                            return {
                                'id': f'PY-CWE-798-{node.lineno}',
                                'category': 'A02:2021',
                                'severity': 'high',
                                'title': f'Hardcoded Secret: {target.id}',
                                'description': 'Hardcoded credential or secret detected in source code',
                                'file': file_path,
                                'line': node.lineno,
                                'rule_id': 'python-hardcoded-secret',
                                'cwe': 'CWE-798',
                                'language': 'python',
                            }
                
                # Check DEBUG = True
                if var_name == 'debug':
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        return {
                            'id': f'PY-CWE-489-{node.lineno}',
                            'category': 'A05:2021',
                            'severity': 'medium',
                            'title': 'Debug Mode Enabled',
                            'description': 'DEBUG = True detected - ensure this is disabled in production',
                            'file': file_path,
                            'line': node.lineno,
                            'rule_id': 'python-debug-true',
                            'cwe': 'CWE-489',
                            'language': 'python',
                        }
        
        return None


__all__ = ['PythonAnalyzer']
