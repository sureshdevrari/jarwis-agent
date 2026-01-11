"""
Jarwis AGI Pen Test - Subdomain Takeover Scanner
Detects Subdomain Takeover vulnerabilities (A05:2021 - Security Misconfiguration)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import socket
import json
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from urllib.parse import urlparse
import aiohttp
import ssl
import dns.resolver
import dns.asyncresolver

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    id: str
    category: str
    severity: str
    title: str
    description: str
    url: str
    method: str
    parameter: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: str = ""
    poc: str = ""
    reasoning: str = ""
    request_data: str = ""
    response_data: str = ""


class SubdomainTakeoverScanner:
    """
    Scans for Subdomain Takeover vulnerabilities
    OWASP A05:2021 - Security Misconfiguration
    CWE-200: Exposure of Sensitive Information
    
    Attack vectors:
    - Dangling DNS records (CNAME, A records)
    - Expired cloud services
    - Unclaimed resources
    - Third-party service takeovers
    """
    
    # Vulnerable service fingerprints
    # Format: (service_name, [cname_patterns], [response_indicators])
    VULNERABLE_SERVICES = [
        # AWS
        ('AWS S3', ['s3.amazonaws.com', 's3-website', '.s3.'], 
         ['NoSuchBucket', 'The specified bucket does not exist']),
        ('AWS Elastic Beanstalk', ['.elasticbeanstalk.com'], 
         ['NXDOMAIN']),
        ('AWS CloudFront', ['.cloudfront.net'], 
         ['Bad Request', 'ERROR: The request could not be satisfied']),
        
        # Azure
        ('Azure', ['.azurewebsites.net', '.cloudapp.azure.com', '.azure-api.net', '.azurecontainer.io'],
         ['404 Web Site not found', 'Web App - Pair Up']),
        ('Azure Traffic Manager', ['.trafficmanager.net'],
         ['NXDOMAIN']),
        ('Azure CDN', ['.azureedge.net'],
         ['404 - Page not found']),
        
        # Google Cloud
        ('Google Cloud Storage', ['storage.googleapis.com', '.storage.googleapis.com'],
         ['NoSuchBucket', 'The specified bucket does not exist']),
        ('Google App Engine', ['.appspot.com'],
         ['404 Not Found', 'Error: Not Found']),
        ('Google Firebase', ['.firebaseapp.com', '.web.app'],
         ['Site Not Found']),
        
        # Other Cloud/Services
        ('GitHub Pages', ['.github.io', '.githubusercontent.com'],
         ["There isn't a GitHub Pages site here", '404 - Repository not found']),
        ('Heroku', ['.herokudns.com', '.herokuapp.com'],
         ['No such app', 'herokucdn.com/error-pages/no-such-app.html']),
        ('Shopify', ['.myshopify.com'],
         ['Sorry, this shop is currently unavailable']),
        ('Zendesk', ['.zendesk.com'],
         ['Help Center Closed', 'this help center no longer exists']),
        ('Tumblr', ['.tumblr.com'],
         ["There's nothing here.", "Whatever you were looking for doesn't currently exist"]),
        ('WordPress.com', ['.wordpress.com'],
         ["doesn't exist"]),
        ('Ghost', ['.ghost.io'],
         ['The thing you were looking for is no longer here']),
        ('Surge.sh', ['.surge.sh'],
         ['project not found']),
        ('Bitbucket', ['.bitbucket.io'],
         ['Repository not found']),
        ('Pantheon', ['.pantheonsite.io'],
         ['The gods are wise']),
        ('Readme.io', ['.readme.io'],
         ['Project doesnt exist']),
        ('Cargo', ['.cargocollective.com'],
         ['404 Not Found']),
        ('StatusPage', ['.statuspage.io'],
         ["isn't a StatusPage"]),
        ('UserVoice', ['.uservoice.com'],
         ['This UserVoice subdomain is currently available']),
        ('SmugMug', ['.smugmug.com'],
         ["doesn't exist"]),
        ('Intercom', ['.custom.intercom.help'],
         ["This page is reserved for"]),
        ('Webflow', ['.webflow.io'],
         ['The page you are looking for']),
        ('Wix', ['.wixsite.com'],
         ['Error connecting to the site']),
        ('Tilda', ['.tilda.ws'],
         ['Domain has been assigned']),
        ('Netlify', ['.netlify.app', '.netlify.com'],
         ['Not Found']),
        ('Vercel', ['.vercel.app', '.now.sh'],
         ['The deployment you are trying to access']),
        ('Fastly', ['.fastly.net', '.fastlylb.net'],
         ['Fastly error: unknown domain']),
        ('Unbounce', ['.unbounce.com'],
         ['The requested URL was not found']),
        ('HelpScout', ['.helpscoutdocs.com'],
         ["We couldn't find the page"]),
        ('Campaignmonitor', ['.createsend.com'],
         ['Double check the link']),
        ('Fly.io', ['.fly.dev'],
         ['404 Not Found']),
    ]
    
    # Common subdomains to enumerate
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging',
        'api', 'app', 'cdn', 'cloud', 'dashboard', 'demo', 'docs',
        'download', 'email', 'forum', 'help', 'images', 'img', 'irc',
        'login', 'mail2', 'mobile', 'mx', 'ns1', 'ns2', 'portal',
        'shop', 'smtp', 'ssl', 'static', 'store', 'support', 'vpn',
        'web', 'webmail', 'wiki', 'status', 'beta', 'alpha', 'stage',
        'preview', 'sandbox', 'secure', 'assets', 'old', 'new', 'legacy'
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.subdomains: Set[str] = set()
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Subdomain Takeover scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        parsed = urlparse(base_url)
        domain = parsed.netloc.split(':')[0]  # Remove port
        
        # Get base domain
        parts = domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:]) if len(parts[-1]) > 2 else '.'.join(parts[-3:])
        else:
            base_domain = domain
        
        # Enumerate subdomains
        await self._enumerate_subdomains(base_domain)
        
        # Test each subdomain for takeover
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            tasks = []
            for subdomain in list(self.subdomains)[:100]:  # Limit to 100 subdomains
                task = self._check_subdomain_takeover(session, subdomain)
                tasks.append(task)
            
            await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info(f"Subdomain takeover scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _enumerate_subdomains(self, base_domain: str):
        """Enumerate subdomains via DNS"""
        logger.info(f"Enumerating subdomains for {base_domain}")
        
        # Add common subdomains
        for sub in self.COMMON_SUBDOMAINS:
            self.subdomains.add(f"{sub}.{base_domain}")
        
        # Check for subdomains from context
        if hasattr(self.context, 'endpoints'):
            for endpoint in self.context.endpoints:
                url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if url:
                    parsed = urlparse(url)
                    if base_domain in parsed.netloc:
                        self.subdomains.add(parsed.netloc.split(':')[0])
        
        # Try to get subdomains from DNS
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            # Check for wildcard
            try:
                await resolver.resolve(f"nonexistent-test-subdomain.{base_domain}", 'A')
                logger.warning(f"Wildcard DNS detected for {base_domain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception):
                pass  # Good - no wildcard
                
        except Exception as e:
            logger.debug(f"DNS enumeration error: {e}")
        
        logger.info(f"Found {len(self.subdomains)} subdomains to check")
    
    async def _check_subdomain_takeover(self, session: aiohttp.ClientSession, subdomain: str):
        """Check a subdomain for takeover vulnerability"""
        try:
            # First, resolve DNS
            cname = await self._get_cname(subdomain)
            
            if cname:
                # Check if CNAME points to vulnerable service
                for service_name, patterns, indicators in self.VULNERABLE_SERVICES:
                    if any(pattern in cname.lower() for pattern in patterns):
                        # Found matching CNAME, check if resource exists
                        is_vulnerable = await self._check_vulnerability(
                            session, subdomain, service_name, indicators
                        )
                        
                        if is_vulnerable:
                            result = ScanResult(
                                id=f"TAKEOVER-{len(self.results)+1}",
                                category="A05:2021 - Security Misconfiguration",
                                severity="critical",
                                title=f"Subdomain Takeover - {service_name}",
                                description=f"Subdomain {subdomain} has dangling CNAME to {service_name}. Attacker can claim the resource and take over.",
                                url=f"https://{subdomain}",
                                method="DNS",
                                parameter="CNAME",
                                evidence=f"CNAME: {cname}",
                                remediation="Remove the DNS record or claim the resource on the third-party service.",
                                cwe_id="CWE-200",
                                poc=f"1. Create account on {service_name}\n2. Claim resource matching {cname}\n3. Control {subdomain}",
                                reasoning=f"Dangling CNAME to unclaimed {service_name} resource"
                            )
                            self.results.append(result)
                            return
            
            # Check for NXDOMAIN with A record (expired IPs)
            await self._check_dangling_a_record(session, subdomain)
            
        except Exception as e:
            logger.debug(f"Error checking {subdomain}: {e}")
    
    async def _get_cname(self, domain: str) -> Optional[str]:
        """Get CNAME record for domain"""
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            answers = await resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                return str(rdata.target).rstrip('.')
                
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            logger.debug(f"CNAME lookup error for {domain}: {e}")
        
        return None
    
    async def _check_vulnerability(self, session: aiohttp.ClientSession, 
                                   subdomain: str, service_name: str, 
                                   indicators: List[str]) -> bool:
        """Check if the subdomain is actually vulnerable"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            # Try HTTP
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    async with session.get(url, allow_redirects=True) as response:
                        body = await response.text()
                        
                        # Check for vulnerability indicators
                        for indicator in indicators:
                            if indicator.upper() == 'NXDOMAIN':
                                continue  # NXDOMAIN is handled separately
                            if indicator.lower() in body.lower():
                                return True
                                
                except aiohttp.ClientConnectorError:
                    # Connection error might indicate unclaimed resource
                    if 'NXDOMAIN' in indicators:
                        return True
                except Exception:
                    pass
                    
        except Exception as e:
            logger.debug(f"Vulnerability check error: {e}")
        
        return False
    
    async def _check_dangling_a_record(self, session: aiohttp.ClientSession, subdomain: str):
        """Check for dangling A records (IP no longer in use)"""
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            answers = await resolver.resolve(subdomain, 'A')
            ip_addresses = [str(rdata.address) for rdata in answers]
            
            for ip in ip_addresses:
                # Check if IP responds
                try:
                    url = f"https://{subdomain}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        # IP responds, not vulnerable
                        pass
                except aiohttp.ClientConnectorError:
                    # Can't connect - might be dangling
                    # Check if IP is in cloud ranges (more likely takeover)
                    if self._is_cloud_ip(ip):
                        result = ScanResult(
                            id=f"TAKEOVER-IP-{len(self.results)+1}",
                            category="A05:2021 - Security Misconfiguration",
                            severity="high",
                            title="Potential Dangling A Record",
                            description=f"Subdomain {subdomain} points to cloud IP {ip} that doesn't respond. Possible takeover.",
                            url=f"https://{subdomain}",
                            method="DNS",
                            parameter="A",
                            evidence=f"A record: {ip}",
                            remediation="Verify IP ownership or remove the DNS record.",
                            cwe_id="CWE-200",
                            reasoning="A record points to non-responding cloud IP"
                        )
                        self.results.append(result)
                        
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            logger.debug(f"A record check error: {e}")
    
    def _is_cloud_ip(self, ip: str) -> bool:
        """Check if IP is in known cloud provider ranges"""
        # Simplified check - in production, use full IP ranges
        cloud_prefixes = [
            '52.', '54.', '35.', '34.', '13.', '18.',  # AWS
            '20.', '40.', '104.', '168.',  # Azure
            '34.', '35.', '104.',  # GCP
            '172.67.', '104.16.',  # Cloudflare
        ]
        return any(ip.startswith(prefix) for prefix in cloud_prefixes)
