"""
SAST Service - Source Code Analysis Business Logic

Handles:
- Starting and managing SAST scans
- SCM OAuth flows (GitHub, GitLab, Bitbucket, Azure DevOps)
- Repository listing and access
- Scan progress tracking
"""

import os
import uuid
import asyncio
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any
from urllib.parse import urlencode

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import BackgroundTasks

from database.models import User, ScanHistory, SCMConnection
from database.crud import create_scan
from database.connection import AsyncSessionLocal

logger = logging.getLogger(__name__)


# OAuth configuration (should be in environment variables)
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID', '')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET', '')
GITLAB_CLIENT_ID = os.getenv('GITLAB_CLIENT_ID', '')
GITLAB_CLIENT_SECRET = os.getenv('GITLAB_CLIENT_SECRET', '')
BITBUCKET_CLIENT_ID = os.getenv('BITBUCKET_CLIENT_ID', '')
BITBUCKET_CLIENT_SECRET = os.getenv('BITBUCKET_CLIENT_SECRET', '')
AZURE_DEVOPS_CLIENT_ID = os.getenv('AZURE_DEVOPS_CLIENT_ID', '')
AZURE_DEVOPS_CLIENT_SECRET = os.getenv('AZURE_DEVOPS_CLIENT_SECRET', '')
OAUTH_REDIRECT_BASE = os.getenv('OAUTH_REDIRECT_BASE', 'http://localhost:8000')

# Supported SCM providers
SUPPORTED_PROVIDERS = [
    'github', 'gitlab', 'bitbucket', 'azure_devops', 
    'aws_codecommit', 'gitea', 'codeberg', 'sourceforge'
]


class SASTService:
    """
    Service layer for SAST (Static Application Security Testing) operations.
    """
    
    # In-memory scan progress tracking
    _progress: Dict[str, Dict[str, Any]] = {}
    _logs: Dict[str, List[Dict[str, Any]]] = {}
    _stop_flags: Dict[str, bool] = {}
    
    @classmethod
    async def start_scan(
        cls,
        db: AsyncSession,
        user: User,
        repository_url: str,
        branch: str,
        access_token: str,
        scan_secrets: bool = True,
        scan_dependencies: bool = True,
        scan_code: bool = True,
        languages: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None,
        notes: Optional[str] = None,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> Dict[str, Any]:
        """
        Start a new SAST scan.
        
        Returns:
            Dict with scan_id and status
        """
        # Generate scan ID
        scan_id = f"sast_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Create scan configuration
        config = {
            'repository_url': repository_url,
            'branch': branch,
            'access_token': access_token,  # Will be masked in logs
            'scan_secrets': scan_secrets,
            'scan_dependencies': scan_dependencies,
            'scan_code': scan_code,
            'languages': languages or [],
            'exclude_paths': exclude_paths or [],
            'scan_id': scan_id,
            'clone_dir': f'data/temp/sast/{scan_id}',
        }
        
        # Create database record
        scan_record = ScanHistory(
            id=uuid.uuid4(),
            user_id=user.id,
            scan_id=scan_id,
            target_url=repository_url,
            scan_type='sast',
            status='queued',
            progress=0,
            phase='Initializing',
            config={k: v for k, v in config.items() if k != 'access_token'},  # Don't store token
        )
        db.add(scan_record)
        await db.commit()
        
        # Initialize progress tracking
        cls._progress[scan_id] = {
            'status': 'queued',
            'progress': 0,
            'phase': 'Initializing',
            'findings': [],
        }
        cls._logs[scan_id] = []
        cls._stop_flags[scan_id] = False
        
        # Add log entry
        cls._add_log(scan_id, 'info', f'SAST scan queued for {repository_url}')
        
        # Start scan in background (no longer pass db - scan creates its own session)
        if background_tasks:
            background_tasks.add_task(cls._run_scan, scan_id, config)
        else:
            asyncio.create_task(cls._run_scan(scan_id, config))
        
        return {
            'scan_id': scan_id,
            'status': 'queued',
        }
    
    @classmethod
    async def _run_scan(cls, scan_id: str, config: dict):
        """Execute the SAST scan in background with its own DB session"""
        from core.sast_scan_runner import SASTScanRunner
        
        try:
            cls._update_progress(scan_id, 'running', 5, 'Starting scan')
            cls._add_log(scan_id, 'phase', 'Starting SAST scan')
            
            # Update database with new async session
            await cls._update_db_status_async(scan_id, 'running', 5, 'Starting')
            
            # Create and run scanner
            runner = SASTScanRunner(config, cls._progress[scan_id])
            
            # Check for stop flag periodically
            async def check_stop():
                return cls._stop_flags.get(scan_id, False)
            
            runner.set_stop_check(check_stop)
            runner.set_log_callback(lambda level, msg: cls._add_log(scan_id, level, msg))
            runner.set_progress_callback(
                lambda progress, phase: cls._update_progress(scan_id, 'running', progress, phase)
            )
            
            # Run scan
            findings = await runner.run()
            
            # Check if stopped
            if cls._stop_flags.get(scan_id):
                cls._update_progress(scan_id, 'stopped', cls._progress[scan_id]['progress'], 'Stopped by user')
                await cls._update_db_status_async(scan_id, 'stopped', cls._progress[scan_id]['progress'], 'Stopped')
                cls._add_log(scan_id, 'warning', 'Scan stopped by user')
                return
            
            # Count findings by severity
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for finding in findings:
                sev = finding.get('severity', 'info').lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
            
            # Update final status
            cls._update_progress(scan_id, 'completed', 100, 'Scan complete')
            cls._progress[scan_id]['findings'] = findings
            
            # Update database with results using async session
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(ScanHistory).where(ScanHistory.scan_id == scan_id)
                )
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = 'completed'
                    scan.progress = 100
                    scan.phase = 'Completed'
                    scan.completed_at = datetime.utcnow()
                    scan.findings_count = len(findings)
                    scan.critical_count = severity_counts['critical']
                    scan.high_count = severity_counts['high']
                    scan.medium_count = severity_counts['medium']
                    scan.low_count = severity_counts['low']
                    scan.info_count = severity_counts['info']
                    await db.commit()
            
            cls._add_log(scan_id, 'success', f'Scan completed. Found {len(findings)} issues.')
            logger.info(f"SAST scan {scan_id} completed with {len(findings)} findings")
            
        except Exception as e:
            logger.error(f"SAST scan {scan_id} failed: {e}")
            cls._update_progress(scan_id, 'error', cls._progress.get(scan_id, {}).get('progress', 0), str(e))
            cls._add_log(scan_id, 'error', f'Scan failed: {str(e)}')
            await cls._update_db_status_async(scan_id, 'error', 0, 'Error', error_message=str(e))
        
        finally:
            # Cleanup
            if scan_id in cls._stop_flags:
                del cls._stop_flags[scan_id]
    
    @classmethod
    def _update_progress(cls, scan_id: str, status: str, progress: int, phase: str):
        """Update in-memory progress"""
        if scan_id in cls._progress:
            cls._progress[scan_id]['status'] = status
            cls._progress[scan_id]['progress'] = progress
            cls._progress[scan_id]['phase'] = phase
    
    @classmethod
    async def _update_db_status_async(cls, scan_id: str, status: str, progress: int, phase: str, error_message: str = None):
        """Update database status using async session"""
        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(ScanHistory).where(ScanHistory.scan_id == scan_id)
                )
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = status
                    scan.progress = progress
                    scan.phase = phase
                    if error_message:
                        scan.error_message = error_message
                    if status in ['completed', 'error', 'stopped']:
                        scan.completed_at = datetime.utcnow()
                    await db.commit()
        except Exception as e:
            logger.error(f"Failed to update DB status for {scan_id}: {e}")
    
    @classmethod
    def _update_db_status(cls, db: AsyncSession, scan_id: str, status: str, progress: int, phase: str, error_message: str = None):
        """Legacy method - kept for compatibility, prefer _update_db_status_async"""
        # This method is deprecated - use _update_db_status_async instead
        logger.warning(f"_update_db_status called - should use async version")
    
    @classmethod
    def _add_log(cls, scan_id: str, level: str, message: str):
        """Add log entry"""
        if scan_id not in cls._logs:
            cls._logs[scan_id] = []
        
        cls._logs[scan_id].append({
            'timestamp': datetime.utcnow().isoformat(),
            'level': level,
            'message': message,
        })
    
    @classmethod
    def get_scan_logs(cls, scan_id: str, since: Optional[int] = None) -> List[Dict]:
        """Get logs for a scan"""
        logs = cls._logs.get(scan_id, [])
        if since is not None and since < len(logs):
            return logs[since:]
        return logs
    
    @classmethod
    def stop_scan(cls, scan_id: str):
        """Signal a scan to stop"""
        cls._stop_flags[scan_id] = True
    
    @classmethod
    def get_github_oauth_url(cls, user_id: str) -> str:
        """Generate GitHub OAuth authorization URL"""
        params = {
            'client_id': GITHUB_CLIENT_ID,
            'redirect_uri': f'{OAUTH_REDIRECT_BASE}/api/scan/sast/github/callback',
            'scope': 'repo read:user user:email',
            'state': user_id,  # Pass user ID in state for callback
        }
        return f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    
    @classmethod
    async def handle_github_callback(cls, db: AsyncSession, code: str, state: str) -> Dict[str, Any]:
        """Handle GitHub OAuth callback"""
        import httpx
        
        user_id = state  # User ID passed in state
        
        # Exchange code for token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                'https://github.com/login/oauth/access_token',
                data={
                    'client_id': GITHUB_CLIENT_ID,
                    'client_secret': GITHUB_CLIENT_SECRET,
                    'code': code,
                },
                headers={'Accept': 'application/json'}
            )
            
            if response.status_code != 200:
                raise Exception("Failed to exchange code for token")
            
            token_data = response.json()
            access_token = token_data.get('access_token')
            
            if not access_token:
                raise Exception(token_data.get('error_description', 'No access token returned'))
            
            # Get user info
            user_response = await client.get(
                'https://api.github.com/user',
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/vnd.github.v3+json'
                }
            )
            
            if user_response.status_code != 200:
                raise Exception("Failed to get GitHub user info")
            
            github_user = user_response.json()
            
            # Get user email
            email_response = await client.get(
                'https://api.github.com/user/emails',
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/vnd.github.v3+json'
                }
            )
            
            primary_email = None
            if email_response.status_code == 200:
                emails = email_response.json()
                for email in emails:
                    if email.get('primary'):
                        primary_email = email.get('email')
                        break
        
        # Save or update connection
        result = await db.execute(
            select(SCMConnection).where(
                SCMConnection.user_id == uuid.UUID(user_id),
                SCMConnection.provider == 'github'
            )
        )
        connection = result.scalar_one_or_none()
        
        if connection:
            connection.access_token = access_token
            connection.provider_username = github_user['login']
            connection.provider_user_id = str(github_user['id'])
            connection.provider_email = primary_email
            connection.scopes = token_data.get('scope', '').split(',')
            connection.is_active = True
            connection.updated_at = datetime.utcnow()
        else:
            connection = SCMConnection(
                user_id=uuid.UUID(user_id),
                provider='github',
                access_token=access_token,
                provider_user_id=str(github_user['id']),
                provider_username=github_user['login'],
                provider_email=primary_email,
                scopes=token_data.get('scope', '').split(','),
            )
            db.add(connection)
        
        await db.commit()
        
        return {
            'success': True,
            'username': github_user['login'],
        }
    
    @classmethod
    def get_gitlab_oauth_url(cls, user_id: str, base_url: Optional[str] = None) -> str:
        """Generate GitLab OAuth authorization URL"""
        gitlab_base = base_url or 'https://gitlab.com'
        params = {
            'client_id': GITLAB_CLIENT_ID,
            'redirect_uri': f'{OAUTH_REDIRECT_BASE}/api/scan/sast/gitlab/callback',
            'response_type': 'code',
            'scope': 'read_user read_repository read_api',
            'state': user_id,
        }
        return f"{gitlab_base}/oauth/authorize?{urlencode(params)}"
    
    @classmethod
    async def handle_gitlab_callback(cls, db: AsyncSession, code: str, state: str) -> Dict[str, Any]:
        """Handle GitLab OAuth callback"""
        import httpx
        
        user_id = state
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                'https://gitlab.com/oauth/token',
                data={
                    'client_id': GITLAB_CLIENT_ID,
                    'client_secret': GITLAB_CLIENT_SECRET,
                    'code': code,
                    'grant_type': 'authorization_code',
                    'redirect_uri': f'{OAUTH_REDIRECT_BASE}/api/scan/sast/gitlab/callback',
                }
            )
            
            if response.status_code != 200:
                raise Exception("Failed to exchange code for token")
            
            token_data = response.json()
            access_token = token_data.get('access_token')
            
            # Get user info
            user_response = await client.get(
                'https://gitlab.com/api/v4/user',
                headers={'Authorization': f'Bearer {access_token}'}
            )
            
            if user_response.status_code != 200:
                raise Exception("Failed to get GitLab user info")
            
            gitlab_user = user_response.json()
        
        # Save connection
        result = await db.execute(
            select(SCMConnection).where(
                SCMConnection.user_id == uuid.UUID(user_id),
                SCMConnection.provider == 'gitlab'
            )
        )
        connection = result.scalar_one_or_none()
        
        if connection:
            connection.access_token = access_token
            connection.refresh_token = token_data.get('refresh_token')
            connection.provider_username = gitlab_user['username']
            connection.provider_user_id = str(gitlab_user['id'])
            connection.provider_email = gitlab_user.get('email')
            connection.is_active = True
            connection.updated_at = datetime.utcnow()
        else:
            connection = SCMConnection(
                user_id=uuid.UUID(user_id),
                provider='gitlab',
                access_token=access_token,
                refresh_token=token_data.get('refresh_token'),
                provider_user_id=str(gitlab_user['id']),
                provider_username=gitlab_user['username'],
                provider_email=gitlab_user.get('email'),
            )
            db.add(connection)
        
        await db.commit()
        
        return {'success': True, 'username': gitlab_user['username']}
    
    @classmethod
    async def list_repositories(cls, connection: SCMConnection) -> List[Dict[str, Any]]:
        """List repositories for an SCM connection"""
        import httpx
        
        repos = []
        
        async with httpx.AsyncClient() as client:
            if connection.provider == 'github':
                page = 1
                while True:
                    response = await client.get(
                        f'https://api.github.com/user/repos?per_page=100&page={page}',
                        headers={
                            'Authorization': f'Bearer {connection.access_token}',
                            'Accept': 'application/vnd.github.v3+json'
                        }
                    )
                    
                    if response.status_code != 200:
                        break
                    
                    data = response.json()
                    if not data:
                        break
                    
                    repos.extend(data)
                    page += 1
                    if len(data) < 100:
                        break
            
            elif connection.provider == 'gitlab':
                base_url = connection.base_url or 'https://gitlab.com'
                page = 1
                while True:
                    response = await client.get(
                        f'{base_url}/api/v4/projects?membership=true&per_page=100&page={page}',
                        headers={'Authorization': f'Bearer {connection.access_token}'}
                    )
                    
                    if response.status_code != 200:
                        break
                    
                    data = response.json()
                    if not data:
                        break
                    
                    # Map GitLab format to common format
                    for project in data:
                        repos.append({
                            'id': project['id'],
                            'name': project['name'],
                            'full_name': project['path_with_namespace'],
                            'html_url': project['web_url'],
                            'private': project.get('visibility') == 'private',
                            'default_branch': project.get('default_branch', 'main'),
                            'language': None,
                            'updated_at': project.get('last_activity_at'),
                        })
                    
                    page += 1
                    if len(data) < 100:
                        break
        
        return repos
    
    @classmethod
    async def validate_token(cls, provider: str, access_token: str) -> Dict[str, Any]:
        """Validate a Personal Access Token"""
        import httpx
        
        async with httpx.AsyncClient() as client:
            if provider == 'github':
                response = await client.get(
                    'https://api.github.com/user',
                    headers={
                        'Authorization': f'Bearer {access_token}',
                        'Accept': 'application/vnd.github.v3+json'
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'valid': True,
                        'username': data['login'],
                        'email': data.get('email'),
                    }
                else:
                    return {'valid': False, 'error': 'Invalid token'}
            
            elif provider == 'gitlab':
                response = await client.get(
                    'https://gitlab.com/api/v4/user',
                    headers={'PRIVATE-TOKEN': access_token}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'valid': True,
                        'username': data['username'],
                        'email': data.get('email'),
                    }
                else:
                    return {'valid': False, 'error': 'Invalid token'}
            
            else:
                return {'valid': False, 'error': f'Unsupported provider: {provider}'}
