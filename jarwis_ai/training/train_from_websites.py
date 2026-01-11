#!/usr/bin/env python3
"""
Jarwis AI Training - Main Training Script

Crawls cybersecurity websites and trains the Jarwis AI with extracted knowledge.
Completely isolated from scanner modules - no LLM or external API required.

Usage:
    python ai_training/train_from_websites.py
    python ai_training/train_from_websites.py --sources custom_sources.yaml
    python ai_training/train_from_websites.py --url https://example.com/security
"""

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import yaml

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai_training.web_crawler import WebCrawler, CrawlSession
from ai_training.knowledge_extractor import KnowledgeExtractor, ExtractedKnowledge

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class AITrainer:
    """
    Main training orchestrator.
    
    Coordinates crawling, extraction, and knowledge integration.
    """
    
    def __init__(self, sources_file: Path = None):
        self.sources_file = sources_file or Path(__file__).parent / "sources.yaml"
        self.config = self._load_config()
        
        # Initialize components
        self.crawler = WebCrawler(
            rate_limit=self.config.get("rate_limit", 1.0),
            timeout=self.config.get("timeout", 30),
            user_agent=self.config.get("user_agent", "JarwisAI-Trainer/1.0"),
            cache_dir=Path(self.config.get("crawl_cache_path", "data/crawl_cache"))
        )
        self.extractor = KnowledgeExtractor()
        
        # Output paths
        self.output_dir = PROJECT_ROOT / "data"
        self.knowledge_path = self.output_dir / "learned_knowledge.json"
        self.patterns_path = self.output_dir / "learned_patterns.json"
        self.vuln_defs_path = self.output_dir / "learned_vulnerability_definitions.json"
    
    def _load_config(self) -> dict:
        """Load configuration from YAML"""
        if self.sources_file.exists():
            with open(self.sources_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            
            config = data.get("config", {})
            config["sources"] = data.get("sources", [])
            config["custom_sources"] = data.get("custom_sources", [])
            config.update(data.get("output", {}))
            return config
        
        return {"sources": [], "custom_sources": []}
    
    async def train(
        self,
        single_url: str = None,
        skip_crawl: bool = False,
        merge_existing: bool = True
    ):
        """
        Run the full training pipeline.
        
        Args:
            single_url: If provided, crawl only this URL
            skip_crawl: Skip crawling, use cached data
            merge_existing: Merge with existing knowledge
        """
        print("=" * 60)
        print("🧠 JARWIS AI TRAINING")
        print("=" * 60)
        print()
        
        # Step 1: Crawl websites
        if single_url:
            sessions = await self._crawl_single(single_url)
        elif skip_crawl:
            sessions = self._load_cached_crawls()
        else:
            sessions = await self._crawl_all_sources()
        
        if not sessions:
            logger.warning("No crawl data available. Exiting.")
            return
        
        # Step 2: Extract knowledge
        print()
        print("=" * 60)
        print("📚 PHASE 2: Extracting Knowledge")
        print("=" * 60)
        
        all_knowledge = []
        for session in sessions:
            knowledge = self.extractor.extract_from_session(session)
            all_knowledge.extend(knowledge)
        
        print(f"✓ Total knowledge entries extracted: {len(all_knowledge)}")
        
        # Step 3: Merge with existing knowledge
        if merge_existing and self.knowledge_path.exists():
            existing = self.extractor.load_extracted(self.knowledge_path)
            all_knowledge = self._merge_knowledge(existing, all_knowledge)
        
        # Step 4: Save extracted knowledge
        self._save_knowledge(all_knowledge)
        
        # Step 5: Update Jarwis AI knowledge service
        self._update_knowledge_service(all_knowledge)
        
        # Step 6: Extract and save patterns
        patterns = self._extract_patterns(all_knowledge)
        self._save_patterns(patterns)
        
        # Summary
        print()
        print("=" * 60)
        print("✅ TRAINING COMPLETE")
        print("=" * 60)
        print(f"   Total knowledge entries: {len(all_knowledge)}")
        print(f"   Total patterns extracted: {len(patterns)}")
        print(f"   Knowledge saved to: {self.knowledge_path}")
        print(f"   Patterns saved to: {self.patterns_path}")
        print(f"   Vuln definitions: {self.vuln_defs_path}")
        print()
    
    async def _crawl_all_sources(self) -> List[CrawlSession]:
        """Crawl all configured sources"""
        print()
        print("=" * 60)
        print("🌐 PHASE 1: Crawling Security Websites")
        print("=" * 60)
        
        sources = self.config.get("sources", []) + self.config.get("custom_sources", [])
        
        if not sources:
            logger.warning("No sources configured. Add sources to ai_training/sources.yaml")
            return []
        
        sessions = []
        max_pages = self.config.get("max_pages_per_site", 100)
        
        for i, source in enumerate(sources, 1):
            try:
                print(f"\n[{i}/{len(sources)}] Crawling: {source['name']}")
                print(f"    URL: {source['url']}")
                
                session = await self.crawler.crawl_site(
                    start_url=source["url"],
                    site_name=source["name"],
                    site_type=source.get("type", "custom"),
                    max_depth=source.get("max_depth", 2),
                    max_pages=max_pages,
                    include_patterns=source.get("include_patterns"),
                    exclude_patterns=source.get("exclude_patterns")
                )
                sessions.append(session)
                
                print(f"    ✓ Crawled {session.pages_crawled} pages in {session.duration:.1f}s")
                
                # Save session for caching
                self.crawler.save_session(session)
                
            except Exception as e:
                logger.error(f"Failed to crawl {source['name']}: {e}")
                print(f"    ✗ Error: {e}")
        
        return sessions
    
    async def _crawl_single(self, url: str) -> List[CrawlSession]:
        """Crawl a single URL"""
        print(f"\n🌐 Crawling single URL: {url}")
        
        session = await self.crawler.crawl_site(
            start_url=url,
            site_name="Custom URL",
            site_type="custom",
            max_depth=2,
            max_pages=50
        )
        
        print(f"✓ Crawled {session.pages_crawled} pages")
        return [session]
    
    def _load_cached_crawls(self) -> List[CrawlSession]:
        """Load previously cached crawl sessions"""
        cache_dir = Path(self.config.get("crawl_cache_path", "data/crawl_cache"))
        sessions = []
        
        if cache_dir.exists():
            for cache_file in cache_dir.glob("*.json"):
                try:
                    data = self.crawler.load_session(cache_file)
                    # Create mock CrawlResult objects for the extractor
                    from ai_training.web_crawler import CrawlResult
                    
                    mock_results = []
                    for p in data.get("pages", []):
                        mock_results.append(CrawlResult(
                            url=p["url"],
                            status_code=200,
                            content_type="text/html",
                            html=f"<html><body>{p.get('text_content', '')}</body></html>",
                            title=p.get("title", ""),
                            text_content=p.get("text_content", ""),
                            links=[],
                            crawl_time=0,
                            error=None
                        ))
                    
                    # Create mock session
                    session = CrawlSession(
                        base_url=data["base_url"],
                        site_name=data["site_name"],
                        site_type=data["site_type"],
                        max_depth=2,
                        include_patterns=[],
                        exclude_patterns=[]
                    )
                    session.results = mock_results
                    sessions.append(session)
                    print(f"✓ Loaded cached: {data['site_name']} ({len(mock_results)} pages)")
                    
                except Exception as e:
                    logger.warning(f"Failed to load cache {cache_file}: {e}")
        
        return sessions
    
    def _merge_knowledge(
        self,
        existing: List[ExtractedKnowledge],
        new: List[ExtractedKnowledge]
    ) -> List[ExtractedKnowledge]:
        """Merge new knowledge with existing, avoiding duplicates"""
        existing_ids = {k.knowledge_id for k in existing}
        
        merged = list(existing)
        added = 0
        
        for entry in new:
            if entry.knowledge_id not in existing_ids:
                merged.append(entry)
                existing_ids.add(entry.knowledge_id)
                added += 1
        
        print(f"✓ Merged {added} new entries with {len(existing)} existing")
        return merged
    
    def _save_knowledge(self, knowledge: List[ExtractedKnowledge]):
        """Save extracted knowledge to JSON"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        data = {
            "generated_at": datetime.now().isoformat(),
            "total_entries": len(knowledge),
            "sources": list(set(k.source_type for k in knowledge)),
            "knowledge": [k.to_dict() for k in knowledge]
        }
        
        with open(self.knowledge_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Saved knowledge to {self.knowledge_path}")
    
    def _extract_patterns(self, knowledge: List[ExtractedKnowledge]) -> list:
        """Extract regex patterns from knowledge for pattern matcher"""
        patterns = []
        
        for entry in knowledge:
            # Extract patterns from examples
            for example in entry.examples:
                # Look for common vulnerability indicators
                if "'" in example or '"' in example:
                    patterns.append({
                        "category": "injection",
                        "source": entry.name,
                        "example": example[:200],
                        "knowledge_id": entry.knowledge_id
                    })
                
                if "<script" in example.lower() or "onerror" in example.lower():
                    patterns.append({
                        "category": "xss",
                        "source": entry.name,
                        "example": example[:200],
                        "knowledge_id": entry.knowledge_id
                    })
        
        return patterns
    
    def _save_patterns(self, patterns: list):
        """Save extracted patterns"""
        data = {
            "generated_at": datetime.now().isoformat(),
            "total_patterns": len(patterns),
            "patterns": patterns
        }
        
        with open(self.patterns_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        
        print(f"✓ Saved {len(patterns)} patterns to {self.patterns_path}")
    
    def _update_knowledge_service(self, knowledge: List[ExtractedKnowledge]):
        """
        Update the Jarwis AI knowledge service with learned data.
        Saves vulnerability definitions in a format the KnowledgeService can load.
        """
        # Convert to format expected by KnowledgeService
        vuln_definitions = {}
        
        for entry in knowledge:
            if entry.knowledge_type == "vulnerability":
                # Create a clean key
                key = entry.name.lower()
                key = key.replace(" ", "_").replace("-", "_")
                key = ''.join(c for c in key if c.isalnum() or c == '_')
                
                vuln_definitions[key] = {
                    "name": entry.name,
                    "owasp_category": entry.owasp_category or "Unknown",
                    "severity": entry.severity or "medium",
                    "description": entry.description,
                    "impact": entry.impact,
                    "remediation": entry.remediation,
                    "example_vulnerable": "\n".join(entry.examples[:2]) if entry.examples else "",
                    "example_secure": "",
                    "references": entry.references,
                    "source": entry.source_type,
                    "learned": True,
                    "learned_at": entry.extracted_at,
                    "confidence": entry.confidence
                }
        
        # Save as learned definitions file
        with open(self.vuln_defs_path, "w", encoding="utf-8") as f:
            json.dump(vuln_definitions, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Saved {len(vuln_definitions)} vulnerability definitions")


async def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Train Jarwis AI from cybersecurity websites",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train from all configured sources
  python ai_training/train_from_websites.py

  # Train from a single URL
  python ai_training/train_from_websites.py --url https://owasp.org/Top10/

  # Use cached crawl data (skip crawling)
  python ai_training/train_from_websites.py --skip-crawl

  # Use custom sources file
  python ai_training/train_from_websites.py --sources my_sources.yaml
        """
    )
    parser.add_argument(
        "--sources",
        type=Path,
        help="Path to sources.yaml configuration file"
    )
    parser.add_argument(
        "--url",
        type=str,
        help="Single URL to crawl and extract from"
    )
    parser.add_argument(
        "--skip-crawl",
        action="store_true",
        help="Skip crawling, use cached data"
    )
    parser.add_argument(
        "--no-merge",
        action="store_true",
        help="Don't merge with existing knowledge"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    trainer = AITrainer(sources_file=args.sources)
    
    await trainer.train(
        single_url=args.url,
        skip_crawl=args.skip_crawl,
        merge_existing=not args.no_merge
    )


if __name__ == "__main__":
    asyncio.run(main())
