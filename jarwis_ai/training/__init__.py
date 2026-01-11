"""
Jarwis AI Training Module

This module is completely isolated from the security scanner (core/, attacks/).
It provides web crawling and knowledge extraction for training the Jarwis AI
without any external LLM or API dependencies.

Components:
- web_crawler.py: HTTP-based crawler for security websites
- knowledge_extractor.py: Extract structured knowledge from HTML
- train_from_websites.py: Orchestrator script
- sources.yaml: Configuration for websites to crawl
"""

from .web_crawler import WebCrawler, CrawlResult, CrawlSession
from .knowledge_extractor import KnowledgeExtractor, ExtractedKnowledge

__all__ = [
    "WebCrawler",
    "CrawlResult",
    "CrawlSession",
    "KnowledgeExtractor",
    "ExtractedKnowledge",
]
