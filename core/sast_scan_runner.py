"""
SAST Scan Runner - Core Orchestrator for Static Analysis

Coordinates:
- Repository cloning
- Secret scanning
- Dependency scanning (SCA)
- Code vulnerability analysis
- Language-specific analysis
"""

import os
import shutil
import asyncio
import logging
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable, Awaitable

# Import from correct paths (providers for SCM, analyzers for analysis)
from attacks.sast.providers.github_scanner import GitHubScanner
from attacks.sast.providers.gitlab_scanner import GitLabScanner
from attacks.sast.analyzers.secret_scanner import SecretScanner
from attacks.sast.analyzers.dependency_scanner import DependencyScanner
from attacks.sast.analyzers.code_analyzer import CodeAnalyzer

logger = logging.getLogger(__name__)


class SASTScanRunner:
    """
    Orchestrates SAST (Static Application Security Testing) scans.
    
    Workflow:
    1. Clone repository (shallow clone for speed)
    2. Run secret scanning (find hardcoded credentials)
    3. Run dependency scanning (SCA - check for vulnerable packages)
    4. Run code analysis (find security vulnerabilities)
    5. Aggregate and return findings
    """
    
    def __init__(self, config: dict, progress_state: dict = None):
        """
        Initialize SAST scan runner.
        
        Args:
            config: Scan configuration including:
                - repository_url: Git repository URL
                - branch: Branch to scan (default: main)
                - access_token: OAuth token or PAT
                - scan_secrets: Enable secret scanning
                - scan_dependencies: Enable SCA
                - scan_code: Enable code analysis
                - languages: List of languages to analyze
                - exclude_paths: Paths to exclude
                - clone_dir: Directory for cloned repo
            progress_state: Shared dict for progress tracking
        """
        self.config = config
        self.progress = progress_state or {}
        
        # Callbacks
        self._stop_check: Optional[Callable[[], Awaitable[bool]]] = None
        self._log_callback: Optional[Callable[[str, str], None]] = None
        self._progress_callback: Optional[Callable[[int, str], None]] = None
        
        # Extract config
        self.repo_url = config.get('repository_url', '')
        self.branch = config.get('branch', 'main')
        self.access_token = config.get('access_token', '')
        self.scan_secrets = config.get('scan_secrets', True)
        self.scan_dependencies = config.get('scan_dependencies', True)
        self.scan_code = config.get('scan_code', True)
        self.languages = config.get('languages', [])
        self.exclude_paths = config.get('exclude_paths', [])
        self.scan_id = config.get('scan_id', f'sast_{uuid.uuid4().hex[:8]}')
        self.clone_dir = config.get('clone_dir', f'data/temp/sast/{self.scan_id}')
        
        # All findings
        self.findings: List[Dict[str, Any]] = []
    
    def set_stop_check(self, callback: Callable[[], Awaitable[bool]]):
        """Set callback to check if scan should stop"""
        self._stop_check = callback
    
    def set_log_callback(self, callback: Callable[[str, str], None]):
        """Set callback for logging"""
        self._log_callback = callback
    
    def set_progress_callback(self, callback: Callable[[int, str], None]):
        """Set callback for progress updates"""
        self._progress_callback = callback
    
    async def _should_stop(self) -> bool:
        """Check if scan should stop"""
        if self._stop_check:
            return await self._stop_check()
        return False
    
    def _log(self, level: str, message: str):
        """Log a message"""
        logger.log(getattr(logging, level.upper(), logging.INFO), message)
        if self._log_callback:
            self._log_callback(level, message)
    
    def _update_progress(self, progress: int, phase: str):
        """Update progress"""
        self.progress['progress'] = progress
        self.progress['phase'] = phase
        if self._progress_callback:
            self._progress_callback(progress, phase)
    
    async def run(self) -> List[Dict[str, Any]]:
        """
        Execute the full SAST scan.
        
        Returns:
            List of findings
        """
        try:
            # Phase 1: Clone repository
            self._update_progress(5, 'Cloning repository')
            self._log('info', f'Cloning {self.repo_url} (branch: {self.branch})')
            
            clone_success = await self._clone_repository()
            if not clone_success:
                raise Exception("Failed to clone repository")
            
            if await self._should_stop():
                return self.findings
            
            # Phase 2: Detect languages
            self._update_progress(15, 'Analyzing repository structure')
            self._log('info', 'Detecting languages and structure')
            
            detected_languages = await self._detect_languages()
            if not self.languages:
                self.languages = detected_languages
            self._log('info', f'Languages detected: {", ".join(self.languages) or "unknown"}')
            
            if await self._should_stop():
                return self.findings
            
            # Phase 3: Secret scanning
            if self.scan_secrets:
                self._update_progress(25, 'Scanning for secrets')
                self._log('info', 'Running secret scanner')
                
                secret_findings = await self._run_secret_scan()
                self.findings.extend(secret_findings)
                self._log('info', f'Found {len(secret_findings)} potential secrets')
            
            if await self._should_stop():
                return self.findings
            
            # Phase 4: Dependency scanning (SCA)
            if self.scan_dependencies:
                self._update_progress(45, 'Scanning dependencies')
                self._log('info', 'Running dependency scanner (SCA)')
                
                dep_findings = await self._run_dependency_scan()
                self.findings.extend(dep_findings)
                self._log('info', f'Found {len(dep_findings)} dependency issues')
            
            if await self._should_stop():
                return self.findings
            
            # Phase 5: Code analysis
            if self.scan_code:
                self._update_progress(65, 'Analyzing code')
                self._log('info', 'Running code vulnerability analysis')
                
                code_findings = await self._run_code_analysis()
                self.findings.extend(code_findings)
                self._log('info', f'Found {len(code_findings)} code vulnerabilities')
            
            if await self._should_stop():
                return self.findings
            
            # Phase 6: Language-specific analysis
            self._update_progress(85, 'Running language-specific analysis')
            self._log('info', f'Running language-specific analyzers for: {", ".join(self.languages)}')
            
            lang_findings = await self._run_language_analysis()
            self.findings.extend(lang_findings)
            self._log('info', f'Found {len(lang_findings)} language-specific issues')
            
            # Phase 7: Cleanup and finalize
            self._update_progress(95, 'Finalizing')
            
            # Deduplicate findings
            self.findings = self._deduplicate_findings(self.findings)
            
            # Sort by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            self.findings.sort(key=lambda f: severity_order.get(f.get('severity', 'info'), 5))
            
            self._log('success', f'Scan complete. Total findings: {len(self.findings)}')
            self._update_progress(100, 'Complete')
            
            return self.findings
            
        except Exception as e:
            self._log('error', f'Scan failed: {str(e)}')
            raise
        
        finally:
            # Cleanup cloned repository
            await self._cleanup()
    
    async def _clone_repository(self) -> bool:
        """Clone the repository using appropriate provider"""
        try:
            # Ensure clone directory exists and is empty
            if os.path.exists(self.clone_dir):
                shutil.rmtree(self.clone_dir)
            os.makedirs(self.clone_dir, exist_ok=True)
            
            # Determine provider
            if 'github.com' in self.repo_url:
                scanner = GitHubScanner(self.access_token, self.clone_dir)
            elif 'gitlab.com' in self.repo_url or 'gitlab' in self.repo_url.lower():
                scanner = GitLabScanner(self.access_token, self.clone_dir)
            else:
                # Generic git clone
                return await self._generic_clone()
            
            success = await scanner.clone_repository(self.repo_url, self.branch)
            return success
            
        except Exception as e:
            self._log('error', f'Clone failed: {str(e)}')
            return False
    
    async def _generic_clone(self) -> bool:
        """Generic git clone for unsupported providers"""
        try:
            # Construct authenticated URL if token provided
            if self.access_token:
                # Insert token into URL
                if 'https://' in self.repo_url:
                    auth_url = self.repo_url.replace('https://', f'https://x-access-token:{self.access_token}@')
                else:
                    auth_url = self.repo_url
            else:
                auth_url = self.repo_url
            
            # Run git clone
            process = await asyncio.create_subprocess_exec(
                'git', 'clone', '--depth', '1', '--branch', self.branch, auth_url, self.clone_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await process.communicate()
            
            if process.returncode != 0:
                self._log('error', f'Git clone failed: {stderr.decode()}')
                return False
            
            return True
            
        except Exception as e:
            self._log('error', f'Generic clone failed: {str(e)}')
            return False
    
    async def _detect_languages(self) -> List[str]:
        """Detect programming languages in the repository"""
        languages = set()
        
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.c': 'c',
            '.rs': 'rust',
            '.swift': 'swift',
            '.kt': 'kotlin',
        }
        
        try:
            for root, dirs, files in os.walk(self.clone_dir):
                # Skip common non-source directories
                dirs[:] = [d for d in dirs if d not in [
                    '.git', 'node_modules', '__pycache__', 'venv', '.venv',
                    'vendor', 'dist', 'build', '.idea', '.vscode'
                ]]
                
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in extension_map:
                        languages.add(extension_map[ext])
        except Exception as e:
            self._log('warning', f'Language detection failed: {str(e)}')
        
        return list(languages)
    
    async def _run_secret_scan(self) -> List[Dict[str, Any]]:
        """Run secret scanner"""
        try:
            scanner = SecretScanner(self.clone_dir, self.exclude_paths)
            return await scanner.scan()
        except Exception as e:
            self._log('error', f'Secret scan failed: {str(e)}')
            return []
    
    async def _run_dependency_scan(self) -> List[Dict[str, Any]]:
        """Run dependency scanner (SCA)"""
        try:
            scanner = DependencyScanner(self.clone_dir, self.exclude_paths)
            return await scanner.scan()
        except Exception as e:
            self._log('error', f'Dependency scan failed: {str(e)}')
            return []
    
    async def _run_code_analysis(self) -> List[Dict[str, Any]]:
        """Run code vulnerability analysis"""
        try:
            analyzer = CodeAnalyzer(self.clone_dir, self.languages, self.exclude_paths)
            return await analyzer.analyze()
        except Exception as e:
            self._log('error', f'Code analysis failed: {str(e)}')
            return []
    
    async def _run_language_analysis(self) -> List[Dict[str, Any]]:
        """Run language-specific analyzers"""
        findings = []
        
        try:
            from attacks.sast.language_analyzers import (
                PythonAnalyzer,
                JavaScriptAnalyzer,
                JavaAnalyzer,
                GoAnalyzer,
            )
            
            analyzers = {
                'python': PythonAnalyzer,
                'javascript': JavaScriptAnalyzer,
                'typescript': JavaScriptAnalyzer,  # Use same analyzer
                'java': JavaAnalyzer,
                'go': GoAnalyzer,
            }
            
            for lang in self.languages:
                if lang.lower() in analyzers:
                    analyzer = analyzers[lang.lower()](self.clone_dir, self.exclude_paths)
                    lang_findings = await analyzer.analyze()
                    findings.extend(lang_findings)
                    
        except Exception as e:
            self._log('error', f'Language analysis failed: {str(e)}')
        
        return findings
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings"""
        seen = set()
        unique = []
        
        for finding in findings:
            # Create unique key from essential fields
            key = (
                finding.get('file', ''),
                finding.get('line', 0),
                finding.get('rule_id', ''),
                finding.get('message', '')[:100],
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique
    
    async def _cleanup(self):
        """Cleanup cloned repository"""
        try:
            if os.path.exists(self.clone_dir):
                shutil.rmtree(self.clone_dir, ignore_errors=True)
                self._log('info', 'Cleaned up temporary files')
        except Exception as e:
            self._log('warning', f'Cleanup failed: {str(e)}')
