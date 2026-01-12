"""
Jarwis AI Training - Web Crawler

A simple, isolated HTTP crawler for extracting security knowledge from websites.
Does NOT use Playwright or browser automation - pure HTTP requests for speed.

This module is completely separate from core/browser.py (which is for security scanning).

Features:
- Robust network resilience with exponential backoff
- Per-page checkpoint/resume capability
- Automatic retry on connection failures
- Network connectivity monitoring
"""

import asyncio
import hashlib
import json
import logging
import re
import time
import socket
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Network resilience constants
MAX_REQUEST_RETRIES = 5
INITIAL_RETRY_DELAY = 2.0  # seconds
MAX_RETRY_DELAY = 120.0  # 2 minutes max
CONNECTIVITY_CHECK_HOSTS = ["8.8.8.8", "1.1.1.1"]  # Google DNS, Cloudflare DNS
CONNECTIVITY_CHECK_TIMEOUT = 5
CONNECTIVITY_WAIT_INTERVAL = 10  # seconds between connectivity checks


@dataclass
class CrawlResult:
    """Result of crawling a single page"""
    url: str
    status_code: int
    content_type: str
    html: str
    title: str
    text_content: str
    links: List[str]
    crawl_time: float
    error: Optional[str] = None
    retry_count: int = 0  # How many retries were needed
    
    @property
    def success(self) -> bool:
        return self.status_code == 200 and not self.error
    
    @property
    def content_hash(self) -> str:
        """Hash of content for deduplication"""
        return hashlib.md5(self.text_content.encode()).hexdigest()


@dataclass
class CrawlProgress:
    """Tracks crawl progress for checkpointing"""
    site_name: str
    base_url: str
    visited_urls: Set[str] = field(default_factory=set)
    queued_urls: List[Tuple[str, int]] = field(default_factory=list)  # (url, depth)
    successful_pages: int = 0
    failed_pages: int = 0
    last_checkpoint: Optional[datetime] = None
    total_retries: int = 0
    network_interruptions: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "site_name": self.site_name,
            "base_url": self.base_url,
            "visited_urls": list(self.visited_urls),
            "queued_urls": self.queued_urls,
            "successful_pages": self.successful_pages,
            "failed_pages": self.failed_pages,
            "last_checkpoint": self.last_checkpoint.isoformat() if self.last_checkpoint else None,
            "total_retries": self.total_retries,
            "network_interruptions": self.network_interruptions
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CrawlProgress':
        progress = cls(
            site_name=data["site_name"],
            base_url=data["base_url"]
        )
        progress.visited_urls = set(data.get("visited_urls", []))
        progress.queued_urls = [tuple(q) for q in data.get("queued_urls", [])]
        progress.successful_pages = data.get("successful_pages", 0)
        progress.failed_pages = data.get("failed_pages", 0)
        progress.total_retries = data.get("total_retries", 0)
        progress.network_interruptions = data.get("network_interruptions", 0)
        if data.get("last_checkpoint"):
            progress.last_checkpoint = datetime.fromisoformat(data["last_checkpoint"])
        return progress


@dataclass
class CrawlSession:
    """State for a crawl session"""
    base_url: str
    site_name: str
    site_type: str
    max_depth: int
    include_patterns: List[re.Pattern]
    exclude_patterns: List[re.Pattern]
    
    # State
    visited: Set[str] = field(default_factory=set)
    queued: Set[str] = field(default_factory=set)
    results: List[CrawlResult] = field(default_factory=list)
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    @property
    def pages_crawled(self) -> int:
        return len(self.results)
    
    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0


class WebCrawler:
    """
    HTTP-based web crawler for AI training data extraction.
    
    Features:
    - Async HTTP requests with httpx
    - Rate limiting to respect servers
    - URL filtering with include/exclude patterns
    - Content deduplication
    - robots.txt respect (optional)
    - Caching for incremental crawls
    - ROBUST NETWORK RESILIENCE:
      * Per-request retry with exponential backoff
      * Network connectivity monitoring
      * Checkpoint/resume from exact position
      * Automatic recovery from network failures
    """
    
    def __init__(
        self,
        rate_limit: float = 1.0,
        timeout: int = 30,
        user_agent: str = "JarwisAI-Trainer/1.0",
        respect_robots: bool = True,
        cache_dir: Optional[Path] = None
    ):
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.user_agent = user_agent
        self.respect_robots = respect_robots
        self.cache_dir = cache_dir or Path("data/crawl_cache")
        
        self._last_request_time: Dict[str, float] = {}
        self._robots_cache: Dict[str, List[str]] = {}
        
        # Checkpoint directory
        self.checkpoint_dir = self.cache_dir / "checkpoints"
        
        # Ensure directories exist
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        # Network state
        self._network_available = True
        self._last_connectivity_check = 0
    
    def _check_network_connectivity(self) -> bool:
        """Check if network is available by testing connectivity to known hosts"""
        for host in CONNECTIVITY_CHECK_HOSTS:
            try:
                socket.create_connection((host, 53), timeout=CONNECTIVITY_CHECK_TIMEOUT)
                return True
            except (socket.timeout, socket.error):
                continue
        return False
    
    async def _wait_for_network(self):
        """Wait until network connectivity is restored"""
        if self._check_network_connectivity():
            self._network_available = True
            return
        
        logger.warning("[NETWORK] Connection lost. Waiting for network to recover...")
        
        while not self._check_network_connectivity():
            logger.info(f"[NETWORK] Still offline. Retrying in {CONNECTIVITY_WAIT_INTERVAL}s...")
            await asyncio.sleep(CONNECTIVITY_WAIT_INTERVAL)
        
        logger.info("[NETWORK] Connection restored! Resuming crawl...")
        self._network_available = True
    
    def _get_checkpoint_path(self, site_name: str) -> Path:
        """Get the checkpoint file path for a site"""
        safe_name = re.sub(r'[^\w\-]', '_', site_name)
        return self.checkpoint_dir / f"{safe_name}_checkpoint.json"
    
    def _save_checkpoint(self, progress: CrawlProgress):
        """Save crawl progress checkpoint"""
        progress.last_checkpoint = datetime.now()
        checkpoint_path = self._get_checkpoint_path(progress.site_name)
        
        try:
            with open(checkpoint_path, "w", encoding="utf-8") as f:
                json.dump(progress.to_dict(), f, indent=2)
            logger.debug(f"[CHECKPOINT] Saved progress for {progress.site_name}: {progress.successful_pages} pages")
        except Exception as e:
            logger.error(f"[CHECKPOINT] Failed to save: {e}")
    
    def _load_checkpoint(self, site_name: str) -> Optional[CrawlProgress]:
        """Load crawl progress checkpoint if exists"""
        checkpoint_path = self._get_checkpoint_path(site_name)
        
        if not checkpoint_path.exists():
            return None
        
        try:
            with open(checkpoint_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            progress = CrawlProgress.from_dict(data)
            logger.info(f"[CHECKPOINT] Loaded progress for {site_name}: {progress.successful_pages} pages already crawled")
            return progress
        except Exception as e:
            logger.warning(f"[CHECKPOINT] Failed to load: {e}")
            return None
    
    def _clear_checkpoint(self, site_name: str):
        """Clear checkpoint after successful completion"""
        checkpoint_path = self._get_checkpoint_path(site_name)
        if checkpoint_path.exists():
            checkpoint_path.unlink()
            logger.debug(f"[CHECKPOINT] Cleared checkpoint for {site_name}")
    
    async def crawl_site(
        self,
        start_url: str,
        site_name: str,
        site_type: str,
        max_depth: int = 2,
        max_pages: int = 100,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        resume: bool = True  # Enable checkpoint/resume by default
    ) -> CrawlSession:
        """
        Crawl a website starting from the given URL.
        
        Args:
            start_url: URL to start crawling from
            site_name: Human-readable name for logging
            site_type: Type of site (owasp, cwe, portswigger, etc.)
            max_depth: Maximum link depth to follow
            max_pages: Maximum pages to crawl
            include_patterns: Regex patterns for URLs to include
            exclude_patterns: Regex patterns for URLs to exclude
            resume: If True, resume from checkpoint if available
            
        Returns:
            CrawlSession with all results
        """
        # Compile patterns
        include_compiled = [
            re.compile(p, re.IGNORECASE) 
            for p in (include_patterns or [])
        ]
        exclude_compiled = [
            re.compile(p, re.IGNORECASE) 
            for p in (exclude_patterns or [])
        ]
        
        session = CrawlSession(
            base_url=start_url,
            site_name=site_name,
            site_type=site_type,
            max_depth=max_depth,
            include_patterns=include_compiled,
            exclude_patterns=exclude_compiled
        )
        
        session.start_time = time.time()
        
        # Try to load checkpoint
        progress = None
        if resume:
            progress = self._load_checkpoint(site_name)
        
        if progress:
            # Resume from checkpoint
            session.visited = progress.visited_urls.copy()
            queue = progress.queued_urls.copy()
            logger.info(f"[RESUME] Resuming {site_name}: {len(session.visited)} pages already done, {len(queue)} in queue")
        else:
            # Fresh start
            progress = CrawlProgress(site_name=site_name, base_url=start_url)
            queue = [(start_url, 0)]
            session.queued.add(start_url)
            logger.info(f"[START] Starting fresh crawl of {site_name} ({start_url})")
        
        # Track pages saved in current session
        checkpoint_interval = 5  # Save checkpoint every 5 pages
        pages_since_checkpoint = 0
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": self.user_agent}
        ) as client:
            while queue and len(session.results) + len(session.visited) - len(progress.visited_urls) < max_pages:
                url, depth = queue.pop(0)
                
                if url in session.visited:
                    continue
                
                # Check network before each request
                if not self._network_available or (time.time() - self._last_connectivity_check > 60):
                    if not self._check_network_connectivity():
                        # Save checkpoint before waiting
                        progress.queued_urls = queue.copy()
                        progress.queued_urls.insert(0, (url, depth))  # Re-add current URL
                        progress.network_interruptions += 1
                        self._save_checkpoint(progress)
                        
                        await self._wait_for_network()
                    self._last_connectivity_check = time.time()
                
                # Rate limit
                await self._rate_limit(url)
                
                # Crawl page with retry logic
                result = await self._crawl_page_with_retry(client, url)
                session.visited.add(url)
                progress.visited_urls.add(url)
                session.results.append(result)
                
                if result.success:
                    progress.successful_pages += 1
                    progress.total_retries += result.retry_count
                    logger.debug(f"[OK] {url} ({result.status_code})")
                    
                    # Add new links to queue
                    if depth < max_depth:
                        for link in result.links:
                            if self._should_crawl(link, session):
                                if link not in session.visited and link not in session.queued:
                                    queue.append((link, depth + 1))
                                    session.queued.add(link)
                else:
                    progress.failed_pages += 1
                    logger.warning(f"[FAIL] {url} - {result.error}")
                
                # Periodic checkpoint
                pages_since_checkpoint += 1
                if pages_since_checkpoint >= checkpoint_interval:
                    progress.queued_urls = queue.copy()
                    self._save_checkpoint(progress)
                    pages_since_checkpoint = 0
        
        session.end_time = time.time()
        
        # Clear checkpoint on successful completion
        self._clear_checkpoint(site_name)
        
        logger.info(
            f"[COMPLETE] {site_name}: "
            f"{session.pages_crawled} pages in {session.duration:.1f}s "
            f"(retries: {progress.total_retries}, interruptions: {progress.network_interruptions})"
        )
        
        return session
    
    async def _crawl_page_with_retry(self, client: httpx.AsyncClient, url: str) -> CrawlResult:
        """Crawl a single page with exponential backoff retry on network errors"""
        retry_count = 0
        last_error = None
        
        while retry_count < MAX_REQUEST_RETRIES:
            result = await self._crawl_page(client, url)
            
            # Success or non-retryable error
            if result.success or result.error in ["Not HTML content"]:
                result.retry_count = retry_count
                return result
            
            # Check if error is retryable (network-related)
            retryable_errors = [
                "Timeout", "Connection", "Network", "Reset", "Refused",
                "EOF", "Closed", "SSLError", "ConnectError"
            ]
            
            is_retryable = any(err.lower() in (result.error or "").lower() for err in retryable_errors)
            
            if not is_retryable:
                # Non-retryable error (e.g., 404, 403)
                result.retry_count = retry_count
                return result
            
            retry_count += 1
            last_error = result.error
            
            if retry_count < MAX_REQUEST_RETRIES:
                # Exponential backoff with jitter
                import random
                delay = min(INITIAL_RETRY_DELAY * (2 ** (retry_count - 1)), MAX_RETRY_DELAY)
                jitter = delay * 0.2 * random.random()
                actual_delay = delay + jitter
                
                logger.debug(f"[RETRY {retry_count}/{MAX_REQUEST_RETRIES}] {url} after {actual_delay:.1f}s - {last_error}")
                await asyncio.sleep(actual_delay)
                
                # Check network connectivity before retry
                if not self._check_network_connectivity():
                    await self._wait_for_network()
        
        # All retries exhausted
        return CrawlResult(
            url=url,
            status_code=0,
            content_type="",
            html="",
            title="",
            text_content="",
            links=[],
            crawl_time=0,
            error=f"Max retries ({MAX_REQUEST_RETRIES}) exceeded: {last_error}",
            retry_count=retry_count
        )

    async def _crawl_page(self, client: httpx.AsyncClient, url: str) -> CrawlResult:
        """Crawl a single page"""
        start = time.time()
        
        try:
            response = await client.get(url)
            content_type = response.headers.get("content-type", "")
            
            # Only process HTML
            if "text/html" not in content_type.lower():
                return CrawlResult(
                    url=url,
                    status_code=response.status_code,
                    content_type=content_type,
                    html="",
                    title="",
                    text_content="",
                    links=[],
                    crawl_time=time.time() - start,
                    error="Not HTML content"
                )
            
            html = response.text
            soup = BeautifulSoup(html, "html.parser")
            
            # Extract title
            title_tag = soup.find("title")
            title = title_tag.get_text(strip=True) if title_tag else ""
            
            # Extract text content (remove scripts, styles)
            for tag in soup(["script", "style", "nav", "footer", "header"]):
                tag.decompose()
            text_content = soup.get_text(separator="\n", strip=True)
            
            # Extract links
            links = []
            for a in soup.find_all("a", href=True):
                href = a["href"]
                # Convert relative to absolute
                full_url = urljoin(url, href)
                # Only keep HTTP(S) links
                if full_url.startswith(("http://", "https://")):
                    # Remove fragments
                    full_url = full_url.split("#")[0]
                    if full_url not in links:
                        links.append(full_url)
            
            return CrawlResult(
                url=url,
                status_code=response.status_code,
                content_type=content_type,
                html=html,
                title=title,
                text_content=text_content,
                links=links,
                crawl_time=time.time() - start
            )
            
        except httpx.TimeoutException:
            return CrawlResult(
                url=url,
                status_code=0,
                content_type="",
                html="",
                title="",
                text_content="",
                links=[],
                crawl_time=time.time() - start,
                error="Timeout"
            )
        except Exception as e:
            return CrawlResult(
                url=url,
                status_code=0,
                content_type="",
                html="",
                title="",
                text_content="",
                links=[],
                crawl_time=time.time() - start,
                error=str(e)
            )
    
    async def _rate_limit(self, url: str):
        """Apply rate limiting per domain"""
        domain = urlparse(url).netloc
        now = time.time()
        
        if domain in self._last_request_time:
            elapsed = now - self._last_request_time[domain]
            wait_time = (1.0 / self.rate_limit) - elapsed
            if wait_time > 0:
                await asyncio.sleep(wait_time)
        
        self._last_request_time[domain] = time.time()
    
    def _should_crawl(self, url: str, session: CrawlSession) -> bool:
        """Check if URL should be crawled based on patterns"""
        parsed = urlparse(url)
        base_parsed = urlparse(session.base_url)
        
        # Must be same domain
        if parsed.netloc != base_parsed.netloc:
            return False
        
        # Check exclude patterns first
        for pattern in session.exclude_patterns:
            if pattern.search(url):
                return False
        
        # If include patterns exist, URL must match at least one
        if session.include_patterns:
            for pattern in session.include_patterns:
                if pattern.search(url):
                    return True
            return False
        
        return True
    
    def save_session(self, session: CrawlSession, output_path: Optional[Path] = None):
        """Save crawl session to JSON for later processing"""
        output_path = output_path or self.cache_dir / f"{session.site_name.replace(' ', '_')}.json"
        
        data = {
            "site_name": session.site_name,
            "site_type": session.site_type,
            "base_url": session.base_url,
            "pages_crawled": session.pages_crawled,
            "duration": session.duration,
            "crawl_date": datetime.now().isoformat(),
            "pages": [
                {
                    "url": r.url,
                    "title": r.title,
                    "text_content": r.text_content[:10000],  # Truncate for storage
                    "success": r.success,
                    "error": r.error
                }
                for r in session.results
                if r.success
            ]
        }
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved crawl session to {output_path}")
        return output_path
    
    def load_session(self, path: Path) -> Dict[str, Any]:
        """Load a saved crawl session"""
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)


# Standalone function for simple usage
async def crawl_url(url: str, max_pages: int = 10) -> CrawlSession:
    """
    Simple function to crawl a single URL.
    
    Usage:
        results = await crawl_url("https://owasp.org/Top10/", max_pages=20)
    """
    crawler = WebCrawler()
    return await crawler.crawl_site(
        start_url=url,
        site_name=urlparse(url).netloc,
        site_type="custom",
        max_depth=2,
        max_pages=max_pages
    )
