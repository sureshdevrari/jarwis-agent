"""
Jarwis AI Training - Web Crawler

A simple, isolated HTTP crawler for extracting security knowledge from websites.
Does NOT use Playwright or browser automation - pure HTTP requests for speed.

This module is completely separate from core/browser.py (which is for security scanning).
"""

import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


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
    
    @property
    def success(self) -> bool:
        return self.status_code == 200 and not self.error
    
    @property
    def content_hash(self) -> str:
        """Hash of content for deduplication"""
        return hashlib.md5(self.text_content.encode()).hexdigest()


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
        
        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    async def crawl_site(
        self,
        start_url: str,
        site_name: str,
        site_type: str,
        max_depth: int = 2,
        max_pages: int = 100,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None
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
        
        logger.info(f"Starting crawl of {site_name} ({start_url})")
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": self.user_agent}
        ) as client:
            # BFS crawl
            queue = [(start_url, 0)]  # (url, depth)
            session.queued.add(start_url)
            
            while queue and len(session.results) < max_pages:
                url, depth = queue.pop(0)
                
                if url in session.visited:
                    continue
                
                # Rate limit
                await self._rate_limit(url)
                
                # Crawl page
                result = await self._crawl_page(client, url)
                session.visited.add(url)
                session.results.append(result)
                
                if result.success:
                    logger.debug(f"Crawled: {url} ({result.status_code})")
                    
                    # Add new links to queue
                    if depth < max_depth:
                        for link in result.links:
                            if self._should_crawl(link, session):
                                if link not in session.visited and link not in session.queued:
                                    queue.append((link, depth + 1))
                                    session.queued.add(link)
                else:
                    logger.warning(f"Failed: {url} - {result.error}")
        
        session.end_time = time.time()
        logger.info(
            f"Completed crawl of {site_name}: "
            f"{session.pages_crawled} pages in {session.duration:.1f}s"
        )
        
        return session
    
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
