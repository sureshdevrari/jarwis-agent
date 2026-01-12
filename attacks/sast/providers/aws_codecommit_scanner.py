"""
AWS CodeCommit Repository Scanner

Supports AWS CodeCommit repository access using IAM credentials.
"""

import os
import asyncio
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class AWSCodeCommitScanner:
    """
    Scanner for AWS CodeCommit repositories.
    
    Authentication options:
    1. IAM User credentials (Access Key ID + Secret Access Key)
    2. IAM Role (for EC2/Lambda with instance profile)
    3. Git credentials (HTTPS Git credentials for IAM user)
    """
    
    def __init__(
        self,
        clone_dir: str,
        access_key_id: str = None,
        secret_access_key: str = None,
        region: str = "us-east-1",
        git_username: str = None,
        git_password: str = None,
    ):
        """
        Initialize AWS CodeCommit scanner.
        
        Args:
            clone_dir: Directory to clone repository into
            access_key_id: AWS Access Key ID
            secret_access_key: AWS Secret Access Key
            region: AWS region
            git_username: HTTPS Git credentials username
            git_password: HTTPS Git credentials password
        """
        self.clone_dir = clone_dir
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.region = region
        self.git_username = git_username
        self.git_password = git_password
    
    async def clone_repository(self, repo_name: str, branch: str = "main") -> bool:
        """
        Clone a CodeCommit repository.
        
        Args:
            repo_name: Repository name or full clone URL
            branch: Branch to clone
            
        Returns:
            True if successful
        """
        try:
            os.makedirs(self.clone_dir, exist_ok=True)
            
            # Determine clone URL
            if 'codecommit' in repo_name:
                clone_url = repo_name
            else:
                clone_url = f"https://git-codecommit.{self.region}.amazonaws.com/v1/repos/{repo_name}"
            
            # If using Git credentials (HTTPS)
            if self.git_username and self.git_password:
                auth_url = clone_url.replace(
                    'https://',
                    f'https://{self.git_username}:{self.git_password}@'
                )
                
                process = await asyncio.create_subprocess_exec(
                    'git', 'clone', '--depth', '1', '--branch', branch, auth_url, self.clone_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode != 0:
                    logger.error(f"CodeCommit clone failed: {stderr.decode()}")
                    return False
                    
            else:
                # Use AWS CLI credential helper
                # First, configure git to use the credential helper
                env = os.environ.copy()
                if self.access_key_id:
                    env['AWS_ACCESS_KEY_ID'] = self.access_key_id
                if self.secret_access_key:
                    env['AWS_SECRET_ACCESS_KEY'] = self.secret_access_key
                env['AWS_DEFAULT_REGION'] = self.region
                
                # Configure credential helper
                config_process = await asyncio.create_subprocess_exec(
                    'git', 'config', '--global', 'credential.helper',
                    f'!aws codecommit credential-helper $@',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env
                )
                await config_process.communicate()
                
                # Configure to use HTTPS
                config_process2 = await asyncio.create_subprocess_exec(
                    'git', 'config', '--global', 'credential.UseHttpPath', 'true',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env
                )
                await config_process2.communicate()
                
                # Clone
                process = await asyncio.create_subprocess_exec(
                    'git', 'clone', '--depth', '1', '--branch', branch, clone_url, self.clone_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode != 0:
                    logger.error(f"CodeCommit clone failed: {stderr.decode()}")
                    return False
            
            logger.info(f"Successfully cloned CodeCommit repo to {self.clone_dir}")
            return True
            
        except Exception as e:
            logger.error(f"CodeCommit clone error: {e}")
            return False
    
    async def validate_credentials(self) -> Dict[str, Any]:
        """Validate AWS credentials and CodeCommit access"""
        try:
            import boto3
            
            session = boto3.Session(
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=self.region
            )
            
            # Get caller identity
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            
            # Check CodeCommit access
            codecommit = session.client('codecommit')
            repos = codecommit.list_repositories(maxResults=1)
            
            return {
                'valid': True,
                'account_id': identity['Account'],
                'user_arn': identity['Arn'],
                'user_id': identity['UserId'],
            }
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    async def list_repositories(self) -> List[Dict[str, Any]]:
        """List all CodeCommit repositories"""
        repos = []
        
        try:
            import boto3
            
            session = boto3.Session(
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=self.region
            )
            
            codecommit = session.client('codecommit')
            
            # Paginate through all repos
            paginator = codecommit.get_paginator('list_repositories')
            for page in paginator.paginate():
                for repo in page.get('repositories', []):
                    # Get repo details
                    try:
                        details = codecommit.get_repository(repositoryName=repo['repositoryName'])
                        repo_meta = details['repositoryMetadata']
                        
                        repos.append({
                            'id': repo_meta['repositoryId'],
                            'name': repo_meta['repositoryName'],
                            'full_name': repo_meta['repositoryName'],
                            'html_url': f"https://{self.region}.console.aws.amazon.com/codesuite/codecommit/repositories/{repo_meta['repositoryName']}",
                            'clone_url': repo_meta.get('cloneUrlHttp'),
                            'private': True,
                            'default_branch': repo_meta.get('defaultBranch', 'main'),
                            'description': repo_meta.get('repositoryDescription', ''),
                        })
                    except Exception as e:
                        logger.warning(f"Could not get details for {repo['repositoryName']}: {e}")
                        
        except Exception as e:
            logger.error(f"Failed to list CodeCommit repos: {e}")
        
        return repos
