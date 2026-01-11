"""
Bitbucket Repository Scanner (with OAuth support)

Supports both Bitbucket Cloud and Bitbucket Server/Data Center.
"""

import os
import asyncio
import logging
from typing import Optional, List, Dict, Any
from urllib.parse import urlencode

logger = logging.getLogger(__name__)


class BitbucketScanner:
    """
    Scanner for Bitbucket repositories.
    
    Supports:
    - Bitbucket Cloud (bitbucket.org)
    - Bitbucket Server/Data Center (self-hosted)
    - OAuth 2.0 authentication
    - App passwords (PAT equivalent)
    """
    
    def __init__(
        self,
        access_token: str,
        clone_dir: str,
        base_url: str = "https://api.bitbucket.org/2.0",
        username: str = None,
        is_app_password: bool = False,
    ):
        """
        Initialize Bitbucket scanner.
        
        Args:
            access_token: OAuth token or App Password
            clone_dir: Directory to clone repository into
            base_url: API base URL (change for self-hosted)
            username: Required for App Password auth
            is_app_password: True if using App Password instead of OAuth
        """
        self.access_token = access_token
        self.clone_dir = clone_dir
        self.base_url = base_url
        self.username = username
        self.is_app_password = is_app_password
    
    async def clone_repository(self, repo_url: str, branch: str = "main") -> bool:
        """
        Clone a Bitbucket repository.
        
        Args:
            repo_url: Repository clone URL or workspace/repo format
            branch: Branch to clone
            
        Returns:
            True if successful
        """
        try:
            os.makedirs(self.clone_dir, exist_ok=True)
            
            # Construct authenticated URL
            if 'bitbucket.org' in repo_url:
                if self.is_app_password:
                    auth_url = repo_url.replace(
                        'https://',
                        f'https://{self.username}:{self.access_token}@'
                    )
                else:
                    auth_url = repo_url.replace(
                        'https://',
                        f'https://x-token-auth:{self.access_token}@'
                    )
            else:
                auth_url = repo_url
            
            process = await asyncio.create_subprocess_exec(
                'git', 'clone', '--depth', '1', '--branch', branch, auth_url, self.clone_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Bitbucket clone failed: {stderr.decode()}")
                return False
            
            logger.info(f"Successfully cloned Bitbucket repo to {self.clone_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Bitbucket clone error: {e}")
            return False
    
    async def validate_token(self) -> Dict[str, Any]:
        """Validate token and get user info"""
        import httpx
        
        try:
            async with httpx.AsyncClient() as client:
                if self.is_app_password:
                    auth = (self.username, self.access_token)
                    headers = {}
                else:
                    auth = None
                    headers = {'Authorization': f'Bearer {self.access_token}'}
                
                response = await client.get(
                    f"{self.base_url}/user",
                    headers=headers,
                    auth=auth
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'valid': True,
                        'username': data.get('username'),
                        'display_name': data.get('display_name'),
                        'uuid': data.get('uuid'),
                    }
                else:
                    return {'valid': False, 'error': 'Invalid token'}
                    
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    async def list_repositories(self, workspace: str = None) -> List[Dict[str, Any]]:
        """List repositories in workspace(s)"""
        import httpx
        
        repos = []
        try:
            async with httpx.AsyncClient() as client:
                if self.is_app_password:
                    auth = (self.username, self.access_token)
                    headers = {}
                else:
                    auth = None
                    headers = {'Authorization': f'Bearer {self.access_token}'}
                
                # Get workspaces if not specified
                if not workspace:
                    ws_response = await client.get(
                        f"{self.base_url}/workspaces",
                        headers=headers,
                        auth=auth
                    )
                    
                    if ws_response.status_code == 200:
                        workspaces = [w['slug'] for w in ws_response.json().get('values', [])]
                    else:
                        workspaces = []
                else:
                    workspaces = [workspace]
                
                # Get repos for each workspace
                for ws in workspaces:
                    page_url = f"{self.base_url}/repositories/{ws}"
                    
                    while page_url:
                        response = await client.get(page_url, headers=headers, auth=auth)
                        
                        if response.status_code != 200:
                            break
                        
                        data = response.json()
                        
                        for repo in data.get('values', []):
                            clone_url = None
                            for link in repo.get('links', {}).get('clone', []):
                                if link['name'] == 'https':
                                    clone_url = link['href']
                                    break
                            
                            repos.append({
                                'id': repo['uuid'],
                                'name': repo['name'],
                                'full_name': repo['full_name'],
                                'html_url': repo['links']['html']['href'],
                                'clone_url': clone_url,
                                'private': repo.get('is_private', True),
                                'default_branch': repo.get('mainbranch', {}).get('name', 'main'),
                                'workspace': ws,
                                'language': repo.get('language'),
                            })
                        
                        page_url = data.get('next')
                        
        except Exception as e:
            logger.error(f"Failed to list Bitbucket repos: {e}")
        
        return repos
    
    @staticmethod
    def get_oauth_url(client_id: str, redirect_uri: str, state: str) -> str:
        """Generate Bitbucket OAuth authorization URL"""
        params = {
            'client_id': client_id,
            'response_type': 'code',
            'state': state,
        }
        return f"https://bitbucket.org/site/oauth2/authorize?{urlencode(params)}"
    
    @staticmethod
    async def exchange_code(code: str, client_id: str, client_secret: str) -> Dict[str, Any]:
        """Exchange OAuth code for access token"""
        import httpx
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                'https://bitbucket.org/site/oauth2/access_token',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                },
                auth=(client_id, client_secret)
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                raise Exception(f"Token exchange failed: {response.text}")
