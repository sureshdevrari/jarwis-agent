#!/usr/bin/env python3
"""
Jarwis AI - Autonomous Training Daemon
=======================================

A 24/7 background service that continuously trains the Jarwis AI from:
- Cybersecurity knowledge (OWASP, CWE, NVD, Exploit-DB, etc.)
- Mathematics and logic (probability, statistics, reasoning)
- Language patterns for better understanding

NO EXTERNAL LLM OR API REQUIRED - Pure statistical/algorithmic learning.

Usage:
    # Start the daemon
    python -m jarwis_ai.training.daemon start
    
    # Run in foreground
    python -m jarwis_ai.training.daemon run
    
    # Stop the daemon
    python -m jarwis_ai.training.daemon stop
    
    # Check status
    python -m jarwis_ai.training.daemon status

Author: BKD Labs
Created: January 2026
"""

import asyncio
import argparse
import json
import logging
import os
import signal
import sys
import time
import httpx
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import sqlite3
import hashlib
import pickle

# Add project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from jarwis_ai.training.web_crawler import WebCrawler, CrawlSession
from jarwis_ai.training.knowledge_extractor import KnowledgeExtractor, ExtractedKnowledge

# Configure logging - keep logs inside jarwis_ai folder
LOG_DIR = PROJECT_ROOT / "jarwis_ai" / "training" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Use UTF-8 encoding for file handler and safe encoding for console
file_handler = logging.FileHandler(LOG_DIR / "training_daemon.log", encoding='utf-8')
stream_handler = logging.StreamHandler()
stream_handler.setStream(open(1, 'w', encoding='utf-8', errors='replace', closefd=False))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[file_handler, stream_handler]
)
logger = logging.getLogger("jarwis.training.daemon")


@dataclass
class TrainingSource:
    """A source to crawl for training data"""
    name: str
    url: str
    source_type: str  # security, math, reasoning, nlp
    category: str     # owasp, cwe, nvd, educational, etc.
    priority: int     # 1=highest, 5=lowest
    refresh_hours: int  # How often to refresh
    max_pages: int = 50
    max_depth: int = 2
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    last_crawled: Optional[datetime] = None
    
    @property
    def needs_refresh(self) -> bool:
        if self.last_crawled is None:
            return True
        return datetime.now() - self.last_crawled > timedelta(hours=self.refresh_hours)


@dataclass
class TrainingStats:
    """Statistics for training progress"""
    total_pages_crawled: int = 0
    total_knowledge_entries: int = 0
    total_patterns_learned: int = 0
    total_words_indexed: int = 0
    last_training_time: Optional[datetime] = None
    sources_crawled: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    retry_count: Dict[str, int] = field(default_factory=dict)  # Track retries per source


@dataclass
class RetryItem:
    """An item in the retry stack"""
    source: 'TrainingSource'
    attempt: int = 1
    last_error: str = ""
    added_at: datetime = field(default_factory=datetime.now)


class StatisticalLearner:
    """
    Pure statistical learning engine - NO external LLM/API.
    
    Uses:
    - TF-IDF for text vectorization
    - N-gram analysis for pattern detection
    - Bayesian inference for weight updates
    - Word co-occurrence for semantic understanding
    """
    
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Word frequency and co-occurrence
        self.word_freq: Dict[str, int] = {}
        self.word_cooccurrence: Dict[str, Dict[str, int]] = {}
        self.ngram_freq: Dict[str, int] = {}  # 2-grams and 3-grams
        
        # Category statistics
        self.category_word_freq: Dict[str, Dict[str, int]] = {}  # category -> word -> count
        self.category_doc_count: Dict[str, int] = {}
        
        # Pattern statistics
        self.pattern_stats: Dict[str, Dict[str, int]] = {}  # pattern_id -> {tp, fp, matches}
        
        # Load existing data
        self._load_state()
    
    def _load_state(self):
        """Load saved state from disk"""
        state_file = self.data_dir / "learner_state.pkl"
        if state_file.exists():
            try:
                with open(state_file, "rb") as f:
                    state = pickle.load(f)
                    self.word_freq = state.get("word_freq", {})
                    self.word_cooccurrence = state.get("word_cooccurrence", {})
                    self.ngram_freq = state.get("ngram_freq", {})
                    self.category_word_freq = state.get("category_word_freq", {})
                    self.category_doc_count = state.get("category_doc_count", {})
                    self.pattern_stats = state.get("pattern_stats", {})
                logger.info(f"Loaded learner state: {len(self.word_freq)} words indexed")
            except Exception as e:
                logger.warning(f"Could not load state: {e}")
    
    def _save_state(self):
        """Save state to disk"""
        state_file = self.data_dir / "learner_state.pkl"
        state = {
            "word_freq": self.word_freq,
            "word_cooccurrence": self.word_cooccurrence,
            "ngram_freq": self.ngram_freq,
            "category_word_freq": self.category_word_freq,
            "category_doc_count": self.category_doc_count,
            "pattern_stats": self.pattern_stats,
            "saved_at": datetime.now().isoformat()
        }
        with open(state_file, "wb") as f:
            pickle.dump(state, f)
    
    def learn_from_text(self, text: str, category: str = "general"):
        """
        Learn from raw text using statistical methods.
        
        Extracts:
        - Word frequencies
        - N-grams (2 and 3 word phrases)
        - Word co-occurrence within sliding window
        - Category-specific word distributions
        """
        # Tokenize
        words = self._tokenize(text)
        
        if not words:
            return
        
        # Update document count for category
        self.category_doc_count[category] = self.category_doc_count.get(category, 0) + 1
        
        # Initialize category word freq if needed
        if category not in self.category_word_freq:
            self.category_word_freq[category] = {}
        
        # Process words
        for i, word in enumerate(words):
            # Global word frequency
            self.word_freq[word] = self.word_freq.get(word, 0) + 1
            
            # Category-specific frequency
            self.category_word_freq[category][word] = \
                self.category_word_freq[category].get(word, 0) + 1
            
            # Co-occurrence (window of 5 words)
            if word not in self.word_cooccurrence:
                self.word_cooccurrence[word] = {}
            
            context_start = max(0, i - 2)
            context_end = min(len(words), i + 3)
            for j in range(context_start, context_end):
                if i != j:
                    context_word = words[j]
                    self.word_cooccurrence[word][context_word] = \
                        self.word_cooccurrence[word].get(context_word, 0) + 1
            
            # 2-grams
            if i < len(words) - 1:
                bigram = f"{word} {words[i+1]}"
                self.ngram_freq[bigram] = self.ngram_freq.get(bigram, 0) + 1
            
            # 3-grams
            if i < len(words) - 2:
                trigram = f"{word} {words[i+1]} {words[i+2]}"
                self.ngram_freq[trigram] = self.ngram_freq.get(trigram, 0) + 1
    
    def learn_from_knowledge(self, knowledge: ExtractedKnowledge):
        """Learn from extracted knowledge entry"""
        # Combine all text
        text_parts = [
            knowledge.name,
            knowledge.description,
            " ".join(knowledge.impact),
            " ".join(knowledge.remediation),
            " ".join(knowledge.examples)
        ]
        full_text = " ".join(text_parts)
        
        # Determine category
        category = knowledge.owasp_category or knowledge.source_type or "general"
        
        # Learn from text
        self.learn_from_text(full_text, category)
        
        # Extract security-specific patterns
        self._extract_security_patterns(knowledge)
    
    def _extract_security_patterns(self, knowledge: ExtractedKnowledge):
        """Extract potential vulnerability detection patterns"""
        # Look for error messages, code snippets, indicators
        for example in knowledge.examples:
            # Find quoted strings (potential error messages)
            import re
            quoted = re.findall(r'"([^"]+)"', example)
            quoted += re.findall(r"'([^']+)'", example)
            
            for q in quoted:
                if len(q) > 10 and len(q) < 200:
                    # This could be a detection pattern
                    pattern_id = hashlib.md5(q.encode()).hexdigest()[:8]
                    if pattern_id not in self.pattern_stats:
                        self.pattern_stats[pattern_id] = {
                            "pattern": q,
                            "category": knowledge.owasp_category,
                            "source": knowledge.source_url,
                            "tp": 0,
                            "fp": 0,
                            "matches": 0
                        }
    
    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into words"""
        import re
        # Convert to lowercase, keep alphanumeric and some special chars
        text = text.lower()
        # Split on whitespace and punctuation
        words = re.findall(r'\b[a-z][a-z0-9_-]*\b', text)
        # Filter short words and stopwords
        stopwords = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been',
                     'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
                     'would', 'could', 'should', 'may', 'might', 'must', 'shall',
                     'can', 'need', 'dare', 'ought', 'used', 'to', 'of', 'in',
                     'for', 'on', 'with', 'at', 'by', 'from', 'as', 'into',
                     'through', 'during', 'before', 'after', 'above', 'below',
                     'between', 'under', 'again', 'further', 'then', 'once',
                     'and', 'but', 'or', 'nor', 'so', 'yet', 'both', 'either',
                     'neither', 'not', 'only', 'own', 'same', 'than', 'too',
                     'very', 'just', 'also', 'now', 'here', 'there', 'when',
                     'where', 'why', 'how', 'all', 'each', 'every', 'both',
                     'few', 'more', 'most', 'other', 'some', 'such', 'no',
                     'any', 'this', 'that', 'these', 'those', 'it', 'its'}
        return [w for w in words if len(w) > 2 and w not in stopwords]
    
    def calculate_tf_idf(self, word: str, category: str) -> float:
        """Calculate TF-IDF score for a word in a category"""
        # Term frequency in category
        tf = self.category_word_freq.get(category, {}).get(word, 0)
        if tf == 0:
            return 0.0
        
        # Document frequency (how many categories contain this word)
        df = sum(1 for cat in self.category_word_freq.values() if word in cat)
        
        # Total categories
        total_cats = len(self.category_word_freq) or 1
        
        # IDF
        import math
        idf = math.log(total_cats / (df + 1)) + 1
        
        return tf * idf
    
    def get_category_keywords(self, category: str, top_n: int = 50) -> List[tuple]:
        """Get top keywords for a category by TF-IDF"""
        if category not in self.category_word_freq:
            return []
        
        words = list(self.category_word_freq[category].keys())
        scored = [(w, self.calculate_tf_idf(w, category)) for w in words]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_n]
    
    def classify_text(self, text: str) -> Dict[str, float]:
        """
        Classify text into categories using Naive Bayes.
        Returns probability scores for each category.
        """
        words = self._tokenize(text)
        if not words:
            return {}
        
        scores = {}
        total_docs = sum(self.category_doc_count.values()) or 1
        
        for category in self.category_word_freq:
            # Prior probability
            prior = (self.category_doc_count.get(category, 0) + 1) / (total_docs + len(self.category_word_freq))
            
            # Likelihood (product of word probabilities)
            import math
            log_likelihood = math.log(prior)
            
            cat_total_words = sum(self.category_word_freq[category].values()) or 1
            vocab_size = len(self.word_freq)
            
            for word in words:
                word_count = self.category_word_freq[category].get(word, 0)
                # Laplace smoothing
                prob = (word_count + 1) / (cat_total_words + vocab_size)
                log_likelihood += math.log(prob)
            
            scores[category] = log_likelihood
        
        # Convert log probabilities to probabilities
        if scores:
            max_score = max(scores.values())
            exp_scores = {k: 2.718 ** (v - max_score) for k, v in scores.items()}
            total = sum(exp_scores.values())
            return {k: v / total for k, v in exp_scores.items()}
        
        return {}
    
    def get_similar_words(self, word: str, top_n: int = 10) -> List[tuple]:
        """Get words that frequently co-occur with the given word"""
        if word not in self.word_cooccurrence:
            return []
        
        cooc = self.word_cooccurrence[word]
        sorted_words = sorted(cooc.items(), key=lambda x: x[1], reverse=True)
        return sorted_words[:top_n]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get learning statistics"""
        return {
            "total_words": len(self.word_freq),
            "total_ngrams": len(self.ngram_freq),
            "categories": list(self.category_word_freq.keys()),
            "total_documents": sum(self.category_doc_count.values()),
            "patterns_discovered": len(self.pattern_stats)
        }
    
    def save(self):
        """Save all learned data"""
        self._save_state()
        
        # Also save human-readable summaries
        summary_dir = self.data_dir / "summaries"
        summary_dir.mkdir(exist_ok=True)
        
        # Save top words per category
        for category in self.category_word_freq:
            keywords = self.get_category_keywords(category, 100)
            with open(summary_dir / f"{category}_keywords.json", "w") as f:
                json.dump(keywords, f, indent=2)
        
        # Save discovered patterns
        with open(summary_dir / "discovered_patterns.json", "w") as f:
            json.dump(self.pattern_stats, f, indent=2)


class AutonomousTrainer:
    """
    24/7 Autonomous Training Daemon
    
    Continuously crawls the internet for:
    - Cybersecurity knowledge
    - Mathematical concepts
    - Reasoning patterns
    
    And trains the Jarwis AI using pure statistical methods.
    """
    
    # Default training sources - COMPREHENSIVE KNOWLEDGE BASE
    # Each source has 100 pages minimum for thorough learning
    DEFAULT_SOURCES = [
        # =====================================================================
        # CYBERSECURITY - HIGH PRIORITY (1-2)
        # =====================================================================
        TrainingSource(
            name="OWASP Top 10",
            url="https://owasp.org/Top10/",
            source_type="security",
            category="owasp",
            priority=1,
            refresh_hours=24,
            max_pages=10000,
            include_patterns=["/Top10/", "/www-project-"]
        ),
        TrainingSource(
            name="OWASP Cheat Sheets",
            url="https://cheatsheetseries.owasp.org/",
            source_type="security",
            category="owasp",
            priority=1,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["cheatsheets/"]
        ),
        TrainingSource(
            name="CWE Top 25",
            url="https://cwe.mitre.org/top25/",
            source_type="security",
            category="cwe",
            priority=1,
            refresh_hours=168,  # Weekly
            max_pages=10000,
            include_patterns=["/data/definitions/"]
        ),
        TrainingSource(
            name="PortSwigger Web Security",
            url="https://portswigger.net/web-security/all-topics",
            source_type="security",
            category="portswigger",
            priority=1,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["/web-security/"],
            exclude_patterns=["/burp/", "/blog/"]
        ),
        TrainingSource(
            name="HackTricks",
            url="https://book.hacktricks.xyz/",
            source_type="security",
            category="hacktricks",
            priority=2,
            refresh_hours=72,
            max_pages=200,
            include_patterns=[]
        ),
        TrainingSource(
            name="OWASP Testing Guide",
            url="https://owasp.org/www-project-web-security-testing-guide/",
            source_type="security",
            category="owasp",
            priority=1,
            refresh_hours=168,
            max_pages=10000,
            include_patterns=["/www-project-web-security-testing-guide/"]
        ),
        TrainingSource(
            name="Exploit Database",
            url="https://www.exploit-db.com/",
            source_type="security",
            category="exploits",
            priority=2,
            refresh_hours=24,
            max_pages=10000,
            include_patterns=["/exploits/", "/papers/"]
        ),
        TrainingSource(
            name="NIST NVD",
            url="https://nvd.nist.gov/vuln",
            source_type="security",
            category="cve",
            priority=2,
            refresh_hours=24,
            max_pages=10000,
            include_patterns=["/vuln/"]
        ),
        TrainingSource(
            name="PayloadsAllTheThings",
            url="https://swisskyrepo.github.io/PayloadsAllTheThings/",
            source_type="security",
            category="payloads",
            priority=2,
            refresh_hours=72,
            max_pages=10000
        ),
        TrainingSource(
            name="SecLists Documentation",
            url="https://github.com/danielmiessler/SecLists/wiki",
            source_type="security",
            category="wordlists",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        
        # =====================================================================
        # MATHEMATICS - PROBABILITY & STATISTICS (100 pages each)
        # =====================================================================
        TrainingSource(
            name="Math is Fun - Probability",
            url="https://www.mathsisfun.com/data/",
            source_type="math",
            category="probability",
            priority=3,
            refresh_hours=720,  # Monthly
            max_pages=10000,
            include_patterns=["/data/"]
        ),
        TrainingSource(
            name="Math is Fun - Statistics",
            url="https://www.mathsisfun.com/data/standard-deviation.html",
            source_type="math",
            category="statistics",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/data/"]
        ),
        TrainingSource(
            name="Statistics How To",
            url="https://www.statisticshowto.com/probability-and-statistics/",
            source_type="math",
            category="statistics",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/probability-and-statistics/"]
        ),
        TrainingSource(
            name="Stat Trek - Probability",
            url="https://stattrek.com/probability/probability.aspx",
            source_type="math",
            category="probability",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/probability/"]
        ),
        TrainingSource(
            name="Seeing Theory - Visual Probability",
            url="https://seeing-theory.brown.edu/",
            source_type="math",
            category="probability",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Stat Trek - Statistics",
            url="https://stattrek.com/statistics/statistics.aspx",
            source_type="math",
            category="statistics",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/statistics/"]
        ),
        TrainingSource(
            name="OnlineStatBook",
            url="https://onlinestatbook.com/2/index.html",
            source_type="math",
            category="statistics",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Probability Course",
            url="https://www.probabilitycourse.com/",
            source_type="math",
            category="probability",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="StatQuest Concepts",
            url="https://statquest.org/video-index/",
            source_type="math",
            category="statistics",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Khan Academy Statistics",
            url="https://www.khanacademy.org/math/statistics-probability",
            source_type="math",
            category="statistics",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/math/statistics-probability/"]
        ),
        
        # =====================================================================
        # MATHEMATICS - ALGEBRA, CALCULUS, LINEAR ALGEBRA (100 pages each)
        # =====================================================================
        TrainingSource(
            name="Math is Fun - Algebra",
            url="https://www.mathsisfun.com/algebra/",
            source_type="math",
            category="algebra",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/algebra/"]
        ),
        TrainingSource(
            name="Math is Fun - Calculus",
            url="https://www.mathsisfun.com/calculus/",
            source_type="math",
            category="calculus",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/calculus/"]
        ),
        TrainingSource(
            name="Paul's Math Notes - Calculus I",
            url="https://tutorial.math.lamar.edu/Classes/CalcI/CalcI.aspx",
            source_type="math",
            category="calculus",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/Classes/"]
        ),
        TrainingSource(
            name="Paul's Math Notes - Calculus II",
            url="https://tutorial.math.lamar.edu/Classes/CalcII/CalcII.aspx",
            source_type="math",
            category="calculus",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/Classes/"]
        ),
        TrainingSource(
            name="Paul's Math Notes - Linear Algebra",
            url="https://tutorial.math.lamar.edu/Classes/LinAlg/LinAlg.aspx",
            source_type="math",
            category="linear_algebra",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/Classes/"]
        ),
        TrainingSource(
            name="3Blue1Brown Essence of Linear Algebra",
            url="https://www.3blue1brown.com/topics/linear-algebra",
            source_type="math",
            category="linear_algebra",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Khan Academy - Algebra",
            url="https://www.khanacademy.org/math/algebra",
            source_type="math",
            category="algebra",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/math/algebra/"]
        ),
        TrainingSource(
            name="Khan Academy - Linear Algebra",
            url="https://www.khanacademy.org/math/linear-algebra",
            source_type="math",
            category="linear_algebra",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/math/linear-algebra/"]
        ),
        TrainingSource(
            name="Khan Academy - Calculus",
            url="https://www.khanacademy.org/math/calculus-1",
            source_type="math",
            category="calculus",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/math/calculus/"]
        ),
        TrainingSource(
            name="Math is Fun - Geometry",
            url="https://www.mathsisfun.com/geometry/",
            source_type="math",
            category="geometry",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/geometry/"]
        ),
        
        # =====================================================================
        # LOGIC & REASONING (100 pages each)
        # =====================================================================
        TrainingSource(
            name="Math is Fun - Logic",
            url="https://www.mathsisfun.com/sets/",
            source_type="reasoning",
            category="logic",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/sets/"]
        ),
        TrainingSource(
            name="Brilliant - Logic",
            url="https://brilliant.org/wiki/logic/",
            source_type="reasoning",
            category="logic",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Stanford Encyclopedia - Logic",
            url="https://plato.stanford.edu/entries/logic-classical/",
            source_type="reasoning",
            category="logic",
            priority=4,
            refresh_hours=2160,  # 3 months
            max_pages=10000
        ),
        TrainingSource(
            name="Stanford Encyclopedia - Reasoning",
            url="https://plato.stanford.edu/entries/reasoning-defeasible/",
            source_type="reasoning",
            category="reasoning",
            priority=4,
            refresh_hours=2160,
            max_pages=10000
        ),
        TrainingSource(
            name="Stanford Encyclopedia - Probability",
            url="https://plato.stanford.edu/entries/probability-interpret/",
            source_type="reasoning",
            category="probability_theory",
            priority=4,
            refresh_hours=2160,
            max_pages=10000
        ),
        TrainingSource(
            name="Critical Thinking Web",
            url="https://philosophy.hku.hk/think/",
            source_type="reasoning",
            category="critical_thinking",
            priority=4,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Logical Fallacies",
            url="https://yourlogicalfallacyis.com/",
            source_type="reasoning",
            category="fallacies",
            priority=4,
            refresh_hours=2160,
            max_pages=10000
        ),
        TrainingSource(
            name="Internet Encyclopedia of Philosophy - Logic",
            url="https://iep.utm.edu/logic/",
            source_type="reasoning",
            category="logic",
            priority=4,
            refresh_hours=2160,
            max_pages=10000
        ),
        TrainingSource(
            name="Propositional Logic",
            url="https://www.tutorialspoint.com/discrete_mathematics/propositional_logic.htm",
            source_type="reasoning",
            category="propositional_logic",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/discrete_mathematics/"]
        ),
        TrainingSource(
            name="Brilliant - Reasoning",
            url="https://brilliant.org/wiki/problem-solving-techniques/",
            source_type="reasoning",
            category="problem_solving",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        
        # =====================================================================
        # ALGORITHMS & DATA STRUCTURES (100+ pages each)
        # =====================================================================
        TrainingSource(
            name="GeeksforGeeks - Algorithms",
            url="https://www.geeksforgeeks.org/fundamentals-of-algorithms/",
            source_type="cs",
            category="algorithms",
            priority=2,
            refresh_hours=168,  # Weekly
            max_pages=200,
            include_patterns=["/fundamentals-of-algorithms/", "/data-structures/"]
        ),
        TrainingSource(
            name="GeeksforGeeks - Data Structures",
            url="https://www.geeksforgeeks.org/data-structures/",
            source_type="cs",
            category="data_structures",
            priority=2,
            refresh_hours=168,
            max_pages=200,
            include_patterns=["/data-structures/"]
        ),
        TrainingSource(
            name="Visualgo - Algorithm Visualizations",
            url="https://visualgo.net/en",
            source_type="cs",
            category="algorithms",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Big-O Cheat Sheet",
            url="https://www.bigocheatsheet.com/",
            source_type="cs",
            category="complexity",
            priority=3,
            refresh_hours=2160,
            max_pages=10000
        ),
        TrainingSource(
            name="Algorithm Wiki",
            url="https://thimbleby.gitlab.io/algorithm-wiki-site/",
            source_type="cs",
            category="algorithms",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="CP Algorithms",
            url="https://cp-algorithms.com/",
            source_type="cs",
            category="algorithms",
            priority=2,
            refresh_hours=168,
            max_pages=200
        ),
        TrainingSource(
            name="Algorithm Design Manual",
            url="https://www.algorist.com/",
            source_type="cs",
            category="algorithms",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="TutorialsPoint - Algorithms",
            url="https://www.tutorialspoint.com/data_structures_algorithms/",
            source_type="cs",
            category="algorithms",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/data_structures_algorithms/"]
        ),
        TrainingSource(
            name="Programiz - Algorithms",
            url="https://www.programiz.com/dsa",
            source_type="cs",
            category="algorithms",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/dsa/"]
        ),
        TrainingSource(
            name="LeetCode Patterns",
            url="https://seanprashad.com/leetcode-patterns/",
            source_type="cs",
            category="algorithms",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        
        # =====================================================================
        # COMPUTER SCIENCE FUNDAMENTALS (100 pages each)
        # =====================================================================
        TrainingSource(
            name="Teach Yourself CS",
            url="https://teachyourselfcs.com/",
            source_type="cs",
            category="cs_fundamentals",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="CS Fundamentals - BaseCS",
            url="https://medium.com/basecs",
            source_type="cs",
            category="cs_fundamentals",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Computer Science Wiki",
            url="https://computersciencewiki.org/index.php/Welcome",
            source_type="cs",
            category="cs_fundamentals",
            priority=3,
            refresh_hours=720,
            max_pages=150
        ),
        TrainingSource(
            name="MIT OpenCourseWare - CS",
            url="https://ocw.mit.edu/courses/6-00sc-introduction-to-computer-science-and-programming-spring-2011/",
            source_type="cs",
            category="cs_fundamentals",
            priority=3,
            refresh_hours=2160,
            max_pages=10000
        ),
        TrainingSource(
            name="Operating Systems Concepts",
            url="https://www.geeksforgeeks.org/operating-systems/",
            source_type="cs",
            category="operating_systems",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/operating-systems/"]
        ),
        TrainingSource(
            name="Database Concepts",
            url="https://www.geeksforgeeks.org/database-management-system/",
            source_type="cs",
            category="databases",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/database-management-system/"]
        ),
        TrainingSource(
            name="Compilers - Crafting Interpreters",
            url="https://craftinginterpreters.com/",
            source_type="cs",
            category="compilers",
            priority=3,
            refresh_hours=2160,
            max_pages=10000
        ),
        TrainingSource(
            name="Computer Architecture",
            url="https://www.geeksforgeeks.org/computer-organization-and-architecture-tutorials/",
            source_type="cs",
            category="architecture",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/computer-organization-and-architecture-tutorials/"]
        ),
        TrainingSource(
            name="Automata Theory",
            url="https://www.geeksforgeeks.org/introduction-of-theory-of-computation/",
            source_type="cs",
            category="automata",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Distributed Systems",
            url="https://www.geeksforgeeks.org/distributed-systems-tutorial/",
            source_type="cs",
            category="distributed_systems",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        
        # =====================================================================
        # PHYSICS - FUNDAMENTAL CONCEPTS (100 pages each)
        # =====================================================================
        TrainingSource(
            name="Physics Classroom",
            url="https://www.physicsclassroom.com/class",
            source_type="physics",
            category="physics",
            priority=4,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/class/"]
        ),
        TrainingSource(
            name="HyperPhysics",
            url="http://hyperphysics.phy-astr.gsu.edu/hbase/hframe.html",
            source_type="physics",
            category="physics",
            priority=4,
            refresh_hours=720,
            max_pages=150
        ),
        TrainingSource(
            name="Khan Academy - Physics",
            url="https://www.khanacademy.org/science/physics",
            source_type="physics",
            category="physics",
            priority=4,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/science/physics/"]
        ),
        TrainingSource(
            name="Feynman Lectures",
            url="https://www.feynmanlectures.caltech.edu/",
            source_type="physics",
            category="physics",
            priority=4,
            refresh_hours=2160,
            max_pages=10000
        ),
        TrainingSource(
            name="Physics LibreTexts",
            url="https://phys.libretexts.org/",
            source_type="physics",
            category="physics",
            priority=4,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="The Physics Hypertextbook",
            url="https://physics.info/",
            source_type="physics",
            category="physics",
            priority=4,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="MIT Physics Courses",
            url="https://ocw.mit.edu/courses/physics/",
            source_type="physics",
            category="physics",
            priority=4,
            refresh_hours=2160,
            max_pages=10000,
            include_patterns=["/courses/physics/"]
        ),
        TrainingSource(
            name="Physics Stack Exchange Concepts",
            url="https://physics.stackexchange.com/questions?tab=Votes",
            source_type="physics",
            category="physics",
            priority=4,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Brilliant Physics",
            url="https://brilliant.org/wiki/physics/",
            source_type="physics",
            category="physics",
            priority=4,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Physics Classroom - Waves",
            url="https://www.physicsclassroom.com/class/waves",
            source_type="physics",
            category="waves",
            priority=4,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/class/waves/"]
        ),
        
        # =====================================================================
        # DISCRETE MATHEMATICS & NUMBER THEORY (100 pages each)
        # =====================================================================
        TrainingSource(
            name="Discrete Math - LibreTexts",
            url="https://math.libretexts.org/Bookshelves/Combinatorics_and_Discrete_Mathematics",
            source_type="math",
            category="discrete_math",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Math is Fun - Number Theory",
            url="https://www.mathsisfun.com/numbers/",
            source_type="math",
            category="number_theory",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/numbers/"]
        ),
        TrainingSource(
            name="Discrete Math Tutorial",
            url="https://www.tutorialspoint.com/discrete_mathematics/",
            source_type="math",
            category="discrete_math",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/discrete_mathematics/"]
        ),
        TrainingSource(
            name="Khan Academy - Discrete Math",
            url="https://www.khanacademy.org/computing/computer-science/algorithms",
            source_type="math",
            category="discrete_math",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Graph Theory - GeeksforGeeks",
            url="https://www.geeksforgeeks.org/graph-data-structure-and-algorithms/",
            source_type="math",
            category="graph_theory",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/graph-data-structure-and-algorithms/"]
        ),
        TrainingSource(
            name="Combinatorics",
            url="https://www.geeksforgeeks.org/combinatorics-gq/",
            source_type="math",
            category="combinatorics",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Number Theory - GeeksforGeeks",
            url="https://www.geeksforgeeks.org/number-theory-competitive-programming/",
            source_type="math",
            category="number_theory",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Set Theory",
            url="https://www.tutorialspoint.com/discrete_mathematics/discrete_mathematics_sets.htm",
            source_type="math",
            category="set_theory",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/discrete_mathematics/"]
        ),
        TrainingSource(
            name="Boolean Algebra",
            url="https://www.electronics-tutorials.ws/boolean/",
            source_type="math",
            category="boolean_algebra",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/boolean/"]
        ),
        TrainingSource(
            name="Mathematical Proofs",
            url="https://www.tutorialspoint.com/discrete_mathematics/discrete_mathematical_induction.htm",
            source_type="math",
            category="proofs",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        
        # =====================================================================
        # PROGRAMMING & SOFTWARE ENGINEERING (100 pages each)
        # =====================================================================
        TrainingSource(
            name="Refactoring Guru - Design Patterns",
            url="https://refactoring.guru/design-patterns",
            source_type="cs",
            category="design_patterns",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/design-patterns/"]
        ),
        TrainingSource(
            name="Python Documentation",
            url="https://docs.python.org/3/tutorial/",
            source_type="cs",
            category="python",
            priority=2,
            refresh_hours=168,
            max_pages=10000,
            include_patterns=["/3/tutorial/", "/3/library/"]
        ),
        TrainingSource(
            name="Real Python",
            url="https://realpython.com/tutorials/",
            source_type="cs",
            category="python",
            priority=3,
            refresh_hours=168,
            max_pages=10000,
            include_patterns=["/tutorials/"]
        ),
        TrainingSource(
            name="Clean Code Concepts",
            url="https://www.geeksforgeeks.org/clean-code-principles/",
            source_type="cs",
            category="software_engineering",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="SOLID Principles",
            url="https://www.digitalocean.com/community/conceptual-articles/s-o-l-i-d-the-first-five-principles-of-object-oriented-design",
            source_type="cs",
            category="software_engineering",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="System Design Primer",
            url="https://github.com/donnemartin/system-design-primer/blob/master/README.md",
            source_type="cs",
            category="system_design",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Refactoring Guru - Refactoring",
            url="https://refactoring.guru/refactoring",
            source_type="cs",
            category="refactoring",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/refactoring/"]
        ),
        TrainingSource(
            name="Git Documentation",
            url="https://git-scm.com/doc",
            source_type="cs",
            category="version_control",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/doc/", "/book/"]
        ),
        TrainingSource(
            name="REST API Tutorial",
            url="https://restfulapi.net/",
            source_type="cs",
            category="apis",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Testing Concepts",
            url="https://www.guru99.com/software-testing.html",
            source_type="cs",
            category="testing",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/software-testing"]
        ),
        
        # =====================================================================
        # MACHINE LEARNING & AI CONCEPTS (NO API - Theory Only) (100 pages each)
        # =====================================================================
        TrainingSource(
            name="ML Glossary",
            url="https://ml-cheatsheet.readthedocs.io/en/latest/",
            source_type="cs",
            category="machine_learning",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Google ML Crash Course Concepts",
            url="https://developers.google.com/machine-learning/crash-course/ml-intro",
            source_type="cs",
            category="machine_learning",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/machine-learning/crash-course/"]
        ),
        TrainingSource(
            name="Distill.pub - ML Explanations",
            url="https://distill.pub/",
            source_type="cs",
            category="machine_learning",
            priority=4,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Neural Networks - 3Blue1Brown",
            url="https://www.3blue1brown.com/topics/neural-networks",
            source_type="cs",
            category="neural_networks",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Deep Learning Book",
            url="https://www.deeplearningbook.org/",
            source_type="cs",
            category="deep_learning",
            priority=3,
            refresh_hours=2160,
            max_pages=10000
        ),
        TrainingSource(
            name="Towards Data Science - ML",
            url="https://towardsdatascience.com/machine-learning/home",
            source_type="cs",
            category="machine_learning",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Scikit-Learn Tutorials",
            url="https://scikit-learn.org/stable/tutorial/index.html",
            source_type="cs",
            category="machine_learning",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/stable/tutorial/", "/stable/modules/"]
        ),
        TrainingSource(
            name="StatQuest ML",
            url="https://statquest.org/video-index/",
            source_type="cs",
            category="machine_learning",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Fast.ai Course Notes",
            url="https://course.fast.ai/",
            source_type="cs",
            category="deep_learning",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="NLP Concepts",
            url="https://www.geeksforgeeks.org/natural-language-processing-overview/",
            source_type="cs",
            category="nlp",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        
        # =====================================================================
        # CRYPTOGRAPHY & INFORMATION THEORY (100 pages each)
        # =====================================================================
        TrainingSource(
            name="Crypto101",
            url="https://www.crypto101.io/",
            source_type="security",
            category="cryptography",
            priority=2,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Practical Cryptography",
            url="http://practicalcryptography.com/",
            source_type="security",
            category="cryptography",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Cryptography - Khan Academy",
            url="https://www.khanacademy.org/computing/computer-science/cryptography",
            source_type="security",
            category="cryptography",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/computing/computer-science/cryptography/"]
        ),
        TrainingSource(
            name="Cryptography Tutorials",
            url="https://www.tutorialspoint.com/cryptography/",
            source_type="security",
            category="cryptography",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/cryptography/"]
        ),
        TrainingSource(
            name="Information Theory Basics",
            url="https://www.geeksforgeeks.org/information-theory/",
            source_type="math",
            category="information_theory",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Cryptopals Challenges",
            url="https://cryptopals.com/",
            source_type="security",
            category="cryptography",
            priority=3,
            refresh_hours=2160,
            max_pages=10000
        ),
        TrainingSource(
            name="SHA and Hash Functions",
            url="https://www.geeksforgeeks.org/sha-in-cryptography/",
            source_type="security",
            category="hashing",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Public Key Cryptography",
            url="https://www.geeksforgeeks.org/public-key-encryption/",
            source_type="security",
            category="cryptography",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="SSL/TLS Explained",
            url="https://www.cloudflare.com/learning/ssl/",
            source_type="security",
            category="tls",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/learning/ssl/"]
        ),
        TrainingSource(
            name="Entropy and Randomness",
            url="https://www.random.org/randomness/",
            source_type="math",
            category="randomness",
            priority=4,
            refresh_hours=2160,
            max_pages=10000
        ),
        
        # =====================================================================
        # NETWORKING & SYSTEMS (100 pages each)
        # =====================================================================
        TrainingSource(
            name="Computer Networking Fundamentals",
            url="https://www.geeksforgeeks.org/computer-network-tutorials/",
            source_type="cs",
            category="networking",
            priority=2,
            refresh_hours=168,
            max_pages=10000,
            include_patterns=["/computer-network-tutorials/"]
        ),
        TrainingSource(
            name="High Performance Browser Networking",
            url="https://hpbn.co/",
            source_type="cs",
            category="networking",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="TCP/IP Guide",
            url="http://www.tcpipguide.com/",
            source_type="cs",
            category="networking",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="DNS Explained",
            url="https://www.cloudflare.com/learning/dns/",
            source_type="cs",
            category="dns",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/learning/dns/"]
        ),
        TrainingSource(
            name="HTTP Protocol",
            url="https://developer.mozilla.org/en-US/docs/Web/HTTP",
            source_type="cs",
            category="http",
            priority=2,
            refresh_hours=168,
            max_pages=10000,
            include_patterns=["/docs/Web/HTTP/"]
        ),
        TrainingSource(
            name="Linux Networking",
            url="https://www.geeksforgeeks.org/linux-networking-commands/",
            source_type="cs",
            category="linux",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="WebSockets",
            url="https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API",
            source_type="cs",
            category="websockets",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Load Balancing Concepts",
            url="https://www.nginx.com/resources/glossary/load-balancing/",
            source_type="cs",
            category="infrastructure",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="CDN Concepts",
            url="https://www.cloudflare.com/learning/cdn/",
            source_type="cs",
            category="cdn",
            priority=3,
            refresh_hours=720,
            max_pages=10000,
            include_patterns=["/learning/cdn/"]
        ),
        TrainingSource(
            name="Network Security",
            url="https://www.geeksforgeeks.org/network-security/",
            source_type="security",
            category="network_security",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        
        # =====================================================================
        # STACK OVERFLOW & STACK EXCHANGE - MASSIVE KNOWLEDGE BASE
        # =====================================================================
        TrainingSource(
            name="Stack Overflow - Security",
            url="https://stackoverflow.com/questions/tagged/security",
            source_type="security",
            category="stackoverflow",
            priority=2,
            refresh_hours=24,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Stack Overflow - Python",
            url="https://stackoverflow.com/questions/tagged/python",
            source_type="programming",
            category="stackoverflow",
            priority=2,
            refresh_hours=24,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Stack Overflow - Algorithms",
            url="https://stackoverflow.com/questions/tagged/algorithm",
            source_type="algorithms",
            category="stackoverflow",
            priority=2,
            refresh_hours=24,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Stack Overflow - Data Structures",
            url="https://stackoverflow.com/questions/tagged/data-structures",
            source_type="algorithms",
            category="stackoverflow",
            priority=2,
            refresh_hours=24,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Stack Overflow - Cryptography",
            url="https://stackoverflow.com/questions/tagged/cryptography",
            source_type="security",
            category="stackoverflow",
            priority=2,
            refresh_hours=24,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Stack Overflow - Networking",
            url="https://stackoverflow.com/questions/tagged/networking",
            source_type="networking",
            category="stackoverflow",
            priority=2,
            refresh_hours=24,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Security Stack Exchange",
            url="https://security.stackexchange.com/questions",
            source_type="security",
            category="stackexchange",
            priority=1,
            refresh_hours=24,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Math Stack Exchange",
            url="https://math.stackexchange.com/questions",
            source_type="math",
            category="stackexchange",
            priority=2,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="CS Stack Exchange",
            url="https://cs.stackexchange.com/questions",
            source_type="cs",
            category="stackexchange",
            priority=2,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Crypto Stack Exchange",
            url="https://crypto.stackexchange.com/questions",
            source_type="security",
            category="stackexchange",
            priority=2,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Network Engineering Stack Exchange",
            url="https://networkengineering.stackexchange.com/questions",
            source_type="networking",
            category="stackexchange",
            priority=2,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Server Fault",
            url="https://serverfault.com/questions",
            source_type="sysadmin",
            category="stackexchange",
            priority=2,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Super User",
            url="https://superuser.com/questions",
            source_type="sysadmin",
            category="stackexchange",
            priority=3,
            refresh_hours=72,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Unix Stack Exchange",
            url="https://unix.stackexchange.com/questions",
            source_type="sysadmin",
            category="stackexchange",
            priority=2,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Ask Ubuntu",
            url="https://askubuntu.com/questions",
            source_type="sysadmin",
            category="stackexchange",
            priority=3,
            refresh_hours=72,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Software Engineering Stack Exchange",
            url="https://softwareengineering.stackexchange.com/questions",
            source_type="cs",
            category="stackexchange",
            priority=2,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Code Review Stack Exchange",
            url="https://codereview.stackexchange.com/questions",
            source_type="programming",
            category="stackexchange",
            priority=3,
            refresh_hours=72,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="AI Stack Exchange",
            url="https://ai.stackexchange.com/questions",
            source_type="ml",
            category="stackexchange",
            priority=2,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Data Science Stack Exchange",
            url="https://datascience.stackexchange.com/questions",
            source_type="ml",
            category="stackexchange",
            priority=2,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Cross Validated (Stats)",
            url="https://stats.stackexchange.com/questions",
            source_type="math",
            category="stackexchange",
            priority=2,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Physics Stack Exchange",
            url="https://physics.stackexchange.com/questions",
            source_type="physics",
            category="stackexchange",
            priority=2,
            refresh_hours=48,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        TrainingSource(
            name="Philosophy Stack Exchange",
            url="https://philosophy.stackexchange.com/questions",
            source_type="reasoning",
            category="stackexchange",
            priority=3,
            refresh_hours=72,
            max_pages=10000,
            include_patterns=["/questions/"]
        ),
        
        # =====================================================================
        # FORMAL MATHEMATICS & PROOFS
        # =====================================================================
        TrainingSource(
            name="ProofWiki",
            url="https://proofwiki.org/wiki/Main_Page",
            source_type="math",
            category="proofs",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Metamath Proof Explorer",
            url="https://us.metamath.org/mpeuni/mmset.html",
            source_type="math",
            category="proofs",
            priority=2,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Mathworld Wolfram",
            url="https://mathworld.wolfram.com/",
            source_type="math",
            category="reference",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Encyclopedia of Mathematics",
            url="https://encyclopediaofmath.org/wiki/Main_Page",
            source_type="math",
            category="reference",
            priority=2,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="nLab - Math Wiki",
            url="https://ncatlab.org/nlab/show/HomePage",
            source_type="math",
            category="advanced_math",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Cut The Knot - Math",
            url="https://www.cut-the-knot.org/",
            source_type="math",
            category="puzzles",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Art of Problem Solving",
            url="https://artofproblemsolving.com/wiki/",
            source_type="math",
            category="problem_solving",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Brilliant Math",
            url="https://brilliant.org/wiki/",
            source_type="math",
            category="problem_solving",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Math Insight",
            url="https://mathinsight.org/",
            source_type="math",
            category="calculus",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Interactive Mathematics",
            url="https://www.intmath.com/",
            source_type="math",
            category="applied_math",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Better Explained Math",
            url="https://betterexplained.com/",
            source_type="math",
            category="intuition",
            priority=2,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Math24 Analysis",
            url="https://www.math24.net/",
            source_type="math",
            category="analysis",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Abstract Algebra Theory",
            url="https://abstract.ups.edu/aata/aata.html",
            source_type="math",
            category="algebra",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Linear Algebra Done Right",
            url="https://linear.axler.net/",
            source_type="math",
            category="linear_algebra",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Immersive Linear Algebra",
            url="https://immersivemath.com/ila/index.html",
            source_type="math",
            category="linear_algebra",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Set Theory - Stanford",
            url="https://plato.stanford.edu/entries/set-theory/",
            source_type="math",
            category="set_theory",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Category Theory nLab",
            url="https://ncatlab.org/nlab/show/category+theory",
            source_type="math",
            category="category_theory",
            priority=4,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Number Theory Web",
            url="https://www.numbertheory.org/",
            source_type="math",
            category="number_theory",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Topology Atlas",
            url="https://at.yorku.ca/topology/",
            source_type="math",
            category="topology",
            priority=4,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Real Analysis",
            url="https://www.jirka.org/ra/",
            source_type="math",
            category="analysis",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        
        # =====================================================================
        # LOGIC, REASONING & CRITICAL THINKING
        # =====================================================================
        TrainingSource(
            name="Stanford Encyclopedia - Logic",
            url="https://plato.stanford.edu/entries/logic-classical/",
            source_type="reasoning",
            category="formal_logic",
            priority=2,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Internet Encyclopedia of Philosophy",
            url="https://iep.utm.edu/",
            source_type="reasoning",
            category="philosophy",
            priority=2,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Logical Fallacies",
            url="https://www.logicalfallacies.org/",
            source_type="reasoning",
            category="fallacies",
            priority=2,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Your Logical Fallacy Is",
            url="https://yourlogicalfallacyis.com/",
            source_type="reasoning",
            category="fallacies",
            priority=2,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Fallacy Files",
            url="https://www.fallacyfiles.org/",
            source_type="reasoning",
            category="fallacies",
            priority=2,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Critical Thinking Web",
            url="https://philosophy.hku.hk/think/",
            source_type="reasoning",
            category="critical_thinking",
            priority=2,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Argumentation Theory",
            url="https://plato.stanford.edu/entries/argumentation/",
            source_type="reasoning",
            category="argumentation",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Propositional Logic",
            url="https://plato.stanford.edu/entries/logic-propositional/",
            source_type="reasoning",
            category="propositional_logic",
            priority=2,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Modal Logic",
            url="https://plato.stanford.edu/entries/logic-modal/",
            source_type="reasoning",
            category="modal_logic",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="First Order Logic",
            url="https://plato.stanford.edu/entries/logic-firstorder/",
            source_type="reasoning",
            category="first_order_logic",
            priority=2,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Logic Matters",
            url="https://www.logicmatters.net/",
            source_type="reasoning",
            category="logic",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Open Logic Project",
            url="https://openlogicproject.org/",
            source_type="reasoning",
            category="formal_logic",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Formal Epistemology",
            url="https://plato.stanford.edu/entries/formal-epistemology/",
            source_type="reasoning",
            category="epistemology",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Decision Theory",
            url="https://plato.stanford.edu/entries/decision-theory/",
            source_type="reasoning",
            category="decision_theory",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Game Theory Stanford",
            url="https://plato.stanford.edu/entries/game-theory/",
            source_type="reasoning",
            category="game_theory",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Probability Logic",
            url="https://plato.stanford.edu/entries/logic-probability/",
            source_type="reasoning",
            category="probability_logic",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Inductive Logic",
            url="https://plato.stanford.edu/entries/logic-inductive/",
            source_type="reasoning",
            category="inductive_logic",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Deductive Reasoning",
            url="https://plato.stanford.edu/entries/reasoning-automated/",
            source_type="reasoning",
            category="automated_reasoning",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        
        # =====================================================================
        # COMMON SENSE & WORLD KNOWLEDGE
        # =====================================================================
        TrainingSource(
            name="Wikipedia - Mathematics",
            url="https://en.wikipedia.org/wiki/Portal:Mathematics",
            source_type="knowledge",
            category="wikipedia",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikipedia - Computer Science",
            url="https://en.wikipedia.org/wiki/Portal:Computer_science",
            source_type="knowledge",
            category="wikipedia",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikipedia - Physics",
            url="https://en.wikipedia.org/wiki/Portal:Physics",
            source_type="knowledge",
            category="wikipedia",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikipedia - Science",
            url="https://en.wikipedia.org/wiki/Portal:Science",
            source_type="knowledge",
            category="wikipedia",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikipedia - Technology",
            url="https://en.wikipedia.org/wiki/Portal:Technology",
            source_type="knowledge",
            category="wikipedia",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikipedia - Logic",
            url="https://en.wikipedia.org/wiki/Portal:Logic",
            source_type="knowledge",
            category="wikipedia",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikipedia - Philosophy",
            url="https://en.wikipedia.org/wiki/Portal:Philosophy",
            source_type="knowledge",
            category="wikipedia",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikipedia - Engineering",
            url="https://en.wikipedia.org/wiki/Portal:Engineering",
            source_type="knowledge",
            category="wikipedia",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikipedia - Electronics",
            url="https://en.wikipedia.org/wiki/Portal:Electronics",
            source_type="knowledge",
            category="wikipedia",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikipedia - Cryptography",
            url="https://en.wikipedia.org/wiki/Portal:Cryptography",
            source_type="security",
            category="wikipedia",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikipedia - Internet",
            url="https://en.wikipedia.org/wiki/Portal:Internet",
            source_type="knowledge",
            category="wikipedia",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikipedia - Software",
            url="https://en.wikipedia.org/wiki/Portal:Software",
            source_type="knowledge",
            category="wikipedia",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Simple Wikipedia - Science",
            url="https://simple.wikipedia.org/wiki/Portal:Science",
            source_type="knowledge",
            category="simple_wiki",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikibooks - Computing",
            url="https://en.wikibooks.org/wiki/Subject:Computing",
            source_type="knowledge",
            category="wikibooks",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikibooks - Mathematics",
            url="https://en.wikibooks.org/wiki/Subject:Mathematics",
            source_type="math",
            category="wikibooks",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikibooks - Physics",
            url="https://en.wikibooks.org/wiki/Subject:Physics",
            source_type="physics",
            category="wikibooks",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikiversity - Computer Science",
            url="https://en.wikiversity.org/wiki/Portal:Computer_Science",
            source_type="cs",
            category="wikiversity",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikiversity - Mathematics",
            url="https://en.wikiversity.org/wiki/Portal:Mathematics",
            source_type="math",
            category="wikiversity",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Wikiversity - Physics",
            url="https://en.wikiversity.org/wiki/Portal:Physics",
            source_type="physics",
            category="wikiversity",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="How Stuff Works - Tech",
            url="https://computer.howstuffworks.com/",
            source_type="knowledge",
            category="common_sense",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="How Stuff Works - Science",
            url="https://science.howstuffworks.com/",
            source_type="knowledge",
            category="common_sense",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Explain Like I'm Five",
            url="https://www.reddit.com/r/explainlikeimfive/",
            source_type="knowledge",
            category="common_sense",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        
        # =====================================================================
        # MORE PROGRAMMING & TECH RESOURCES
        # =====================================================================
        TrainingSource(
            name="Real Python",
            url="https://realpython.com/tutorials/",
            source_type="programming",
            category="python",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Python Docs",
            url="https://docs.python.org/3/",
            source_type="programming",
            category="python",
            priority=2,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="MDN Web Docs",
            url="https://developer.mozilla.org/en-US/docs/Web",
            source_type="programming",
            category="web",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="W3Schools",
            url="https://www.w3schools.com/",
            source_type="programming",
            category="web",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="DevDocs",
            url="https://devdocs.io/",
            source_type="programming",
            category="reference",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="freeCodeCamp",
            url="https://www.freecodecamp.org/news/",
            source_type="programming",
            category="tutorials",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Tutorialspoint",
            url="https://www.tutorialspoint.com/",
            source_type="programming",
            category="tutorials",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Javatpoint",
            url="https://www.javatpoint.com/",
            source_type="programming",
            category="tutorials",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Programiz",
            url="https://www.programiz.com/",
            source_type="programming",
            category="tutorials",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="LeetCode Discuss",
            url="https://leetcode.com/discuss/",
            source_type="algorithms",
            category="competitive",
            priority=2,
            refresh_hours=72,
            max_pages=10000
        ),
        TrainingSource(
            name="Codeforces",
            url="https://codeforces.com/blog/recent-actions",
            source_type="algorithms",
            category="competitive",
            priority=2,
            refresh_hours=72,
            max_pages=10000
        ),
        TrainingSource(
            name="TopCoder",
            url="https://www.topcoder.com/thrive/articles",
            source_type="algorithms",
            category="competitive",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="HackerRank",
            url="https://www.hackerrank.com/blog/",
            source_type="algorithms",
            category="competitive",
            priority=3,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Interview Cake",
            url="https://www.interviewcake.com/",
            source_type="algorithms",
            category="interview",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Tech Interview Handbook",
            url="https://www.techinterviewhandbook.org/",
            source_type="programming",
            category="interview",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        
        # =====================================================================
        # MORE SECURITY RESOURCES
        # =====================================================================
        TrainingSource(
            name="PayloadsAllTheThings",
            url="https://github.com/swisskyrepo/PayloadsAllTheThings",
            source_type="security",
            category="payloads",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="SANS Reading Room",
            url="https://www.sans.org/white-papers/",
            source_type="security",
            category="research",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Krebs on Security",
            url="https://krebsonsecurity.com/",
            source_type="security",
            category="news",
            priority=3,
            refresh_hours=24,
            max_pages=10000
        ),
        TrainingSource(
            name="The Hacker News",
            url="https://thehackernews.com/",
            source_type="security",
            category="news",
            priority=3,
            refresh_hours=24,
            max_pages=10000
        ),
        TrainingSource(
            name="Dark Reading",
            url="https://www.darkreading.com/",
            source_type="security",
            category="news",
            priority=3,
            refresh_hours=24,
            max_pages=10000
        ),
        TrainingSource(
            name="Security Weekly",
            url="https://securityweekly.com/",
            source_type="security",
            category="news",
            priority=3,
            refresh_hours=72,
            max_pages=10000
        ),
        TrainingSource(
            name="ThreatPost",
            url="https://threatpost.com/",
            source_type="security",
            category="news",
            priority=3,
            refresh_hours=24,
            max_pages=10000
        ),
        TrainingSource(
            name="Hack The Box Blog",
            url="https://www.hackthebox.com/blog/",
            source_type="security",
            category="pentesting",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="TryHackMe Blog",
            url="https://tryhackme.com/resources/blog/",
            source_type="security",
            category="pentesting",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Pentester Land",
            url="https://pentester.land/",
            source_type="security",
            category="pentesting",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="InfoSec Writeups",
            url="https://infosecwriteups.com/",
            source_type="security",
            category="writeups",
            priority=2,
            refresh_hours=72,
            max_pages=10000
        ),
        TrainingSource(
            name="Bug Bounty Reports",
            url="https://hackerone.com/hacktivity",
            source_type="security",
            category="bug_bounty",
            priority=2,
            refresh_hours=24,
            max_pages=10000
        ),
        
        # =====================================================================
        # MORE PHYSICS & SCIENCE
        # =====================================================================
        TrainingSource(
            name="Physics Classroom",
            url="https://www.physicsclassroom.com/",
            source_type="physics",
            category="fundamentals",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Physics LibreTexts",
            url="https://phys.libretexts.org/",
            source_type="physics",
            category="textbook",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Math LibreTexts",
            url="https://math.libretexts.org/",
            source_type="math",
            category="textbook",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Chemistry LibreTexts",
            url="https://chem.libretexts.org/",
            source_type="science",
            category="textbook",
            priority=4,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Engineering LibreTexts",
            url="https://eng.libretexts.org/",
            source_type="engineering",
            category="textbook",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="OpenStax Physics",
            url="https://openstax.org/subjects/science",
            source_type="physics",
            category="textbook",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="OpenStax Math",
            url="https://openstax.org/subjects/math",
            source_type="math",
            category="textbook",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="NIST Digital Library",
            url="https://dlmf.nist.gov/",
            source_type="math",
            category="reference",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
        TrainingSource(
            name="Wolfram Alpha",
            url="https://www.wolframalpha.com/examples",
            source_type="math",
            category="computation",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        
        # =====================================================================
        # AI & MACHINE LEARNING
        # =====================================================================
        TrainingSource(
            name="Papers With Code",
            url="https://paperswithcode.com/",
            source_type="ml",
            category="research",
            priority=2,
            refresh_hours=72,
            max_pages=10000
        ),
        TrainingSource(
            name="Distill ML",
            url="https://distill.pub/",
            source_type="ml",
            category="research",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Towards Data Science",
            url="https://towardsdatascience.com/",
            source_type="ml",
            category="tutorials",
            priority=3,
            refresh_hours=72,
            max_pages=10000
        ),
        TrainingSource(
            name="Machine Learning Mastery",
            url="https://machinelearningmastery.com/",
            source_type="ml",
            category="tutorials",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Google AI Blog",
            url="https://ai.googleblog.com/",
            source_type="ml",
            category="research",
            priority=2,
            refresh_hours=72,
            max_pages=10000
        ),
        TrainingSource(
            name="OpenAI Blog",
            url="https://openai.com/blog/",
            source_type="ml",
            category="research",
            priority=2,
            refresh_hours=72,
            max_pages=10000
        ),
        TrainingSource(
            name="DeepMind Blog",
            url="https://www.deepmind.com/blog",
            source_type="ml",
            category="research",
            priority=2,
            refresh_hours=72,
            max_pages=10000
        ),
        TrainingSource(
            name="Hugging Face Blog",
            url="https://huggingface.co/blog",
            source_type="ml",
            category="nlp",
            priority=2,
            refresh_hours=72,
            max_pages=10000
        ),
        TrainingSource(
            name="Fast.ai",
            url="https://www.fast.ai/",
            source_type="ml",
            category="tutorials",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="PyTorch Tutorials",
            url="https://pytorch.org/tutorials/",
            source_type="ml",
            category="tutorials",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="TensorFlow Tutorials",
            url="https://www.tensorflow.org/tutorials",
            source_type="ml",
            category="tutorials",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Scikit-learn Docs",
            url="https://scikit-learn.org/stable/user_guide.html",
            source_type="ml",
            category="reference",
            priority=2,
            refresh_hours=336,
            max_pages=10000
        ),
        
        # =====================================================================
        # SYSTEMS & INFRASTRUCTURE
        # =====================================================================
        TrainingSource(
            name="AWS Documentation",
            url="https://docs.aws.amazon.com/",
            source_type="cloud",
            category="aws",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Google Cloud Docs",
            url="https://cloud.google.com/docs/",
            source_type="cloud",
            category="gcp",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Azure Docs",
            url="https://learn.microsoft.com/en-us/azure/",
            source_type="cloud",
            category="azure",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Docker Docs",
            url="https://docs.docker.com/",
            source_type="devops",
            category="containers",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Kubernetes Docs",
            url="https://kubernetes.io/docs/",
            source_type="devops",
            category="orchestration",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Linux Documentation",
            url="https://www.kernel.org/doc/html/latest/",
            source_type="sysadmin",
            category="linux",
            priority=2,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Arch Wiki",
            url="https://wiki.archlinux.org/",
            source_type="sysadmin",
            category="linux",
            priority=2,
            refresh_hours=168,
            max_pages=10000
        ),
        TrainingSource(
            name="Gentoo Wiki",
            url="https://wiki.gentoo.org/wiki/Main_Page",
            source_type="sysadmin",
            category="linux",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Nginx Docs",
            url="https://nginx.org/en/docs/",
            source_type="sysadmin",
            category="webserver",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Redis Docs",
            url="https://redis.io/docs/",
            source_type="database",
            category="nosql",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="PostgreSQL Docs",
            url="https://www.postgresql.org/docs/current/",
            source_type="database",
            category="sql",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="MongoDB Docs",
            url="https://www.mongodb.com/docs/",
            source_type="database",
            category="nosql",
            priority=3,
            refresh_hours=336,
            max_pages=10000
        ),
        TrainingSource(
            name="Git Documentation",
            url="https://git-scm.com/doc",
            source_type="devops",
            category="version_control",
            priority=3,
            refresh_hours=720,
            max_pages=10000
        ),
    ]
    
    # Configuration for retry system
    MAX_RETRIES = 3  # Maximum retry attempts per source
    RETRY_DELAY_BASE = 60  # Base delay in seconds (exponential backoff)
    NETWORK_CHECK_INTERVAL = 30  # Seconds between network checks
    
    def __init__(self, data_dir: Path = None):
        # Store all training data INSIDE jarwis_ai folder - keeps AI self-contained
        self.data_dir = data_dir or PROJECT_ROOT / "jarwis_ai" / "training" / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.sources: List[TrainingSource] = []
        self.stats = TrainingStats()
        self.crawler = WebCrawler(
            rate_limit=10,  # FAST: 10 requests per second
            timeout=15,     # Reduced timeout for faster failures
            cache_dir=self.data_dir / "crawl_cache"
        )
        self.extractor = KnowledgeExtractor()
        self.learner = StatisticalLearner(self.data_dir / "learned")
        
        self.running = False
        self.paused = False
        self._last_network_check = 0
        self._network_available = True
        
        # Retry stack - failed sources go here for retry
        self.retry_stack: List[RetryItem] = []
        
        # Load sources
        self._load_sources()
        
        # Load stats
        self._load_stats()
        
        # Load retry stack from disk (in case of restart)
        self._load_retry_stack()
    
    def _check_network(self) -> bool:
        """Check network connectivity"""
        import socket
        for host in ["8.8.8.8", "1.1.1.1"]:
            try:
                socket.create_connection((host, 53), timeout=5)
                return True
            except (socket.timeout, socket.error):
                continue
        return False
    
    async def _wait_for_network(self):
        """Wait for network connectivity to be restored"""
        if self._check_network():
            self._network_available = True
            return
        
        logger.warning("[NETWORK] Connection lost. Saving state and waiting...")
        self._save_stats()
        self._save_sources()
        self.learner.save()
        
        wait_time = 10
        max_wait = 300  # 5 minutes max wait between checks
        
        while not self._check_network():
            logger.info(f"[NETWORK] Still offline. Checking again in {wait_time}s...")
            await asyncio.sleep(wait_time)
            wait_time = min(wait_time * 1.5, max_wait)
        
        logger.info("[NETWORK] Connection restored! Resuming training...")
        self._network_available = True
    
    def _load_sources(self):
        """Load training sources from config or use defaults"""
        sources_file = self.data_dir / "sources.json"
        
        if sources_file.exists():
            try:
                with open(sources_file, "r") as f:
                    data = json.load(f)
                    for s in data:
                        source = TrainingSource(
                            name=s["name"],
                            url=s["url"],
                            source_type=s["source_type"],
                            category=s["category"],
                            priority=s["priority"],
                            refresh_hours=s["refresh_hours"],
                            max_pages=s.get("max_pages", 50),
                            max_depth=s.get("max_depth", 2),
                            include_patterns=s.get("include_patterns", []),
                            exclude_patterns=s.get("exclude_patterns", []),
                            last_crawled=datetime.fromisoformat(s["last_crawled"]) if s.get("last_crawled") else None
                        )
                        self.sources.append(source)
                logger.info(f"Loaded {len(self.sources)} sources from config")
            except Exception as e:
                logger.warning(f"Could not load sources: {e}")
                self.sources = self.DEFAULT_SOURCES.copy()
        else:
            self.sources = self.DEFAULT_SOURCES.copy()
            self._save_sources()
    
    def _save_sources(self):
        """Save sources to config"""
        sources_file = self.data_dir / "sources.json"
        data = []
        for s in self.sources:
            data.append({
                "name": s.name,
                "url": s.url,
                "source_type": s.source_type,
                "category": s.category,
                "priority": s.priority,
                "refresh_hours": s.refresh_hours,
                "max_pages": s.max_pages,
                "max_depth": s.max_depth,
                "include_patterns": s.include_patterns,
                "exclude_patterns": s.exclude_patterns,
                "last_crawled": s.last_crawled.isoformat() if s.last_crawled else None
            })
        with open(sources_file, "w") as f:
            json.dump(data, f, indent=2)
    
    def _load_stats(self):
        """Load training statistics"""
        stats_file = self.data_dir / "stats.json"
        if stats_file.exists():
            try:
                with open(stats_file, "r") as f:
                    data = json.load(f)
                    self.stats.total_pages_crawled = data.get("total_pages_crawled", 0)
                    self.stats.total_knowledge_entries = data.get("total_knowledge_entries", 0)
                    self.stats.total_patterns_learned = data.get("total_patterns_learned", 0)
                    self.stats.total_words_indexed = data.get("total_words_indexed", 0)
                    self.stats.sources_crawled = data.get("sources_crawled", {})
                    self.stats.retry_count = data.get("retry_count", {})
                    if data.get("last_training_time"):
                        self.stats.last_training_time = datetime.fromisoformat(data["last_training_time"])
            except Exception as e:
                logger.warning(f"Could not load stats: {e}")
    
    def _save_stats(self):
        """Save training statistics"""
        stats_file = self.data_dir / "stats.json"
        data = {
            "total_pages_crawled": self.stats.total_pages_crawled,
            "total_knowledge_entries": self.stats.total_knowledge_entries,
            "total_patterns_learned": self.stats.total_patterns_learned,
            "total_words_indexed": len(self.learner.word_freq),
            "last_training_time": self.stats.last_training_time.isoformat() if self.stats.last_training_time else None,
            "sources_crawled": self.stats.sources_crawled,
            "retry_count": self.stats.retry_count,
            "retry_stack_size": len(self.retry_stack),
            "learner_stats": self.learner.get_stats()
        }
        with open(stats_file, "w") as f:
            json.dump(data, f, indent=2)
    
    def _load_retry_stack(self):
        """Load retry stack from disk"""
        retry_file = self.data_dir / "retry_stack.json"
        if retry_file.exists():
            try:
                with open(retry_file, "r") as f:
                    data = json.load(f)
                    for item in data:
                        # Find the source by name
                        source = next((s for s in self.sources if s.name == item["source_name"]), None)
                        if source:
                            retry_item = RetryItem(
                                source=source,
                                attempt=item.get("attempt", 1),
                                last_error=item.get("last_error", ""),
                                added_at=datetime.fromisoformat(item["added_at"]) if item.get("added_at") else datetime.now()
                            )
                            self.retry_stack.append(retry_item)
                logger.info(f"Loaded {len(self.retry_stack)} items from retry stack")
            except Exception as e:
                logger.warning(f"Could not load retry stack: {e}")
    
    def _save_retry_stack(self):
        """Save retry stack to disk"""
        retry_file = self.data_dir / "retry_stack.json"
        data = []
        for item in self.retry_stack:
            data.append({
                "source_name": item.source.name,
                "attempt": item.attempt,
                "last_error": item.last_error,
                "added_at": item.added_at.isoformat()
            })
        with open(retry_file, "w") as f:
            json.dump(data, f, indent=2)
    
    def _add_to_retry_stack(self, source: TrainingSource, error: str):
        """Add a failed source to the retry stack"""
        # Check if already in stack
        existing = next((item for item in self.retry_stack if item.source.name == source.name), None)
        
        if existing:
            existing.attempt += 1
            existing.last_error = error
            if existing.attempt > self.MAX_RETRIES:
                logger.warning(f"[RETRY] {source.name} exceeded max retries ({self.MAX_RETRIES}). Removing from stack.")
                self.retry_stack.remove(existing)
                self.stats.retry_count[source.name] = existing.attempt
            else:
                logger.info(f"[RETRY] {source.name} - attempt {existing.attempt}/{self.MAX_RETRIES}")
        else:
            retry_item = RetryItem(source=source, attempt=1, last_error=error)
            self.retry_stack.insert(0, retry_item)  # Add to front (stack behavior)
            logger.info(f"[RETRY] Added {source.name} to retry stack (attempt 1/{self.MAX_RETRIES})")
        
        self._save_retry_stack()
    
    def _remove_from_retry_stack(self, source: TrainingSource):
        """Remove a source from retry stack after successful crawl"""
        self.retry_stack = [item for item in self.retry_stack if item.source.name != source.name]
        self._save_retry_stack()
    
    def get_next_sources(self) -> List[TrainingSource]:
        """Get sources that need to be crawled, ordered by priority"""
        needs_refresh = [s for s in self.sources if s.needs_refresh]
        # Sort by priority (1=highest)
        needs_refresh.sort(key=lambda s: s.priority)
        return needs_refresh
    
    async def crawl_source(self, source: TrainingSource) -> Optional[CrawlSession]:
        """Crawl a single source with network resilience"""
        logger.info(f"[CRAWL] Starting: {source.name} ({source.url})")
        
        # Check network before starting
        if not self._check_network():
            await self._wait_for_network()
        
        try:
            session = await self.crawler.crawl_site(
                start_url=source.url,
                site_name=source.name,
                site_type=source.category,
                max_depth=source.max_depth,
                max_pages=source.max_pages,
                include_patterns=source.include_patterns if source.include_patterns else None,
                exclude_patterns=source.exclude_patterns if source.exclude_patterns else None,
                resume=True  # Enable checkpoint/resume
            )
            
            source.last_crawled = datetime.now()
            self.stats.total_pages_crawled += session.pages_crawled
            self.stats.sources_crawled[source.name] = \
                self.stats.sources_crawled.get(source.name, 0) + 1
            
            logger.info(f"[CRAWL OK] {source.name}: {session.pages_crawled} pages")
            
            # Save crawl session
            self.crawler.save_session(session)
            
            return session
        
        except (httpx.ConnectError, httpx.TimeoutException, ConnectionError) as e:
            logger.warning(f"[NETWORK ERROR] {source.name}: {e}")
            # Network error - wait and return None (will be retried)
            await self._wait_for_network()
            return None
            
        except Exception as e:
            logger.error(f"[CRAWL FAILED] {source.name}: {e}")
            self.stats.errors.append(f"{datetime.now()}: {source.name} - {e}")
            return None
    
    def process_session(self, session: CrawlSession, source: TrainingSource):
        """Process crawl session - extract knowledge and learn"""
        logger.info(f"Processing {session.pages_crawled} pages from {session.site_name}")
        
        # Extract knowledge
        knowledge_entries = self.extractor.extract_from_session(session)
        self.stats.total_knowledge_entries += len(knowledge_entries)
        
        logger.info(f"Extracted {len(knowledge_entries)} knowledge entries")
        
        # Learn from each entry
        for entry in knowledge_entries:
            self.learner.learn_from_knowledge(entry)
        
        # Also learn from raw text of all pages
        for page in session.results:
            if page.success and page.text_content:
                self.learner.learn_from_text(
                    page.text_content,
                    category=source.category
                )
        
        self.stats.total_words_indexed = len(self.learner.word_freq)
    
    async def train_cycle(self):
        """Run one training cycle - crawl websites with network resilience"""
        logger.info("=" * 60)
        logger.info("Starting training cycle")
        logger.info("=" * 60)
        
        # Check network first
        if not self._check_network():
            logger.warning("[NETWORK] No connection at cycle start. Waiting...")
            await self._wait_for_network()
        
        sources_to_crawl = self.get_next_sources()
        
        if not sources_to_crawl:
            # Calculate time until next source needs refresh
            next_refresh_hours = float('inf')
            next_source_name = ""
            for s in self.sources:
                if s.last_crawled:
                    hours_since = (datetime.now() - s.last_crawled).total_seconds() / 3600
                    hours_until = s.refresh_hours - hours_since
                    if hours_until > 0 and hours_until < next_refresh_hours:
                        next_refresh_hours = hours_until
                        next_source_name = s.name
            
            if next_refresh_hours < float('inf'):
                logger.info(f"[COMPLETE] All {len(self.sources)} sources crawled!")
                logger.info(f"[WAITING] Next refresh in {next_refresh_hours:.1f} hours ({next_source_name})")
                logger.info(f"[TIP] Use --force flag or 'reset' command to re-crawl immediately")
            else:
                logger.info("No sources need refreshing")
            return
        
        logger.info(f"Sources to crawl: {len(sources_to_crawl)}")
        
        # Process in batches of 20 concurrent crawls
        BATCH_SIZE = 20
        
        for i in range(0, len(sources_to_crawl), BATCH_SIZE):
            if not self.running or self.paused:
                break
            
            # Check network before each batch
            if not self._check_network():
                logger.warning("[NETWORK] Connection lost before batch. Waiting...")
                await self._wait_for_network()
            
            batch = sources_to_crawl[i:i + BATCH_SIZE]
            logger.info(f"\n--- Batch {i//BATCH_SIZE + 1}: Crawling {len(batch)} sites ---")
            
            # Create tasks for concurrent crawling
            async def crawl_and_process(source):
                if not self.running:
                    return
                try:
                    session = await self.crawl_source(source)
                    
                    if session:
                        try:
                            self.process_session(session, source)
                            self._remove_from_retry_stack(source)
                            logger.info(f"[OK] {source.name} - {session.pages_crawled} pages")
                        except Exception as e:
                            logger.error(f"Failed to process {source.name}: {e}")
                            self.stats.errors.append(f"{datetime.now()}: Processing {source.name} - {e}")
                            self._add_to_retry_stack(source, str(e))
                    else:
                        self._add_to_retry_stack(source, "Crawl returned no data")
                        
                except Exception as e:
                    logger.error(f"Unexpected error with {source.name}: {e}")
                    self.stats.errors.append(f"{datetime.now()}: {source.name} - {e}")
                    self._add_to_retry_stack(source, str(e))
            
            # Run batch concurrently
            tasks = [crawl_and_process(source) for source in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Save progress after each batch
            self._save_sources()
            self._save_stats()
            self.learner.save()
            logger.info(f"[SAVED] Batch {i//BATCH_SIZE + 1} complete")
            
            # Brief pause between batches
            await asyncio.sleep(2)
        
        self.stats.last_training_time = datetime.now()
        self._save_stats()
        
        logger.info("Training cycle complete")
        logger.info(f"Stats: {self.learner.get_stats()}")
    
    async def process_retry_stack(self):
        """Process the retry stack - retry failed sources"""
        if not self.retry_stack:
            return
        
        logger.info("=" * 60)
        logger.info(f"Processing retry stack ({len(self.retry_stack)} items)")
        logger.info("=" * 60)
        
        # Process items from the stack (LIFO - last in, first out)
        # Make a copy since we modify during iteration
        items_to_process = list(self.retry_stack)
        
        for retry_item in items_to_process:
            if not self.running or self.paused:
                break
            
            source = retry_item.source
            
            # Calculate delay with exponential backoff
            delay = self.RETRY_DELAY_BASE * (2 ** (retry_item.attempt - 1))
            delay = min(delay, 600)  # Cap at 10 minutes
            
            logger.info(f"[RETRY] Retrying {source.name} (attempt {retry_item.attempt}/{self.MAX_RETRIES}) after {delay}s delay")
            await asyncio.sleep(delay)
            
            try:
                session = await self.crawl_source(source)
                
                if session:
                    try:
                        self.process_session(session, source)
                        # Success! Remove from retry stack
                        self._remove_from_retry_stack(source)
                        logger.info(f"[RETRY SUCCESS] {source.name} completed successfully!")
                    except Exception as e:
                        logger.error(f"[RETRY FAILED] Processing {source.name}: {e}")
                        self._add_to_retry_stack(source, str(e))
                else:
                    logger.warning(f"[RETRY FAILED] {source.name} returned no data")
                    self._add_to_retry_stack(source, "Crawl returned no data")
                
                # Save after each retry attempt
                self._save_sources()
                self._save_stats()
                self.learner.save()
                
            except Exception as e:
                logger.error(f"[RETRY FAILED] {source.name}: {e}")
                self._add_to_retry_stack(source, str(e))
        
        if self.retry_stack:
            logger.info(f"Retry stack still has {len(self.retry_stack)} items remaining")
        else:
            logger.info("Retry stack is now empty - all sources processed!")
    
    async def run_forever(self):
        """Run the daemon continuously with network resilience"""
        self.running = True
        logger.info("=" * 60)
        logger.info("JARWIS AI AUTONOMOUS TRAINER STARTED")
        logger.info("=" * 60)
        logger.info(f"Data directory: {self.data_dir}")
        logger.info(f"Sources configured: {len(self.sources)}")
        logger.info(f"Retry stack: {len(self.retry_stack)} pending")
        
        # Check for existing checkpoints (resume capability)
        checkpoint_dir = self.data_dir / "crawl_cache" / "checkpoints"
        if checkpoint_dir.exists():
            checkpoints = list(checkpoint_dir.glob("*_checkpoint.json"))
            if checkpoints:
                logger.info(f"[RESUME] Found {len(checkpoints)} checkpoints - will resume interrupted crawls")
        
        logger.info("Press Ctrl+C to stop")
        logger.info("")
        
        # Check network at startup
        if not self._check_network():
            logger.warning("[NETWORK] No internet connection at startup. Waiting...")
            await self._wait_for_network()
        else:
            logger.info("[NETWORK] Connection verified")
        
        # Track signal count for force exit
        self._signal_count = 0
        
        # Register signal handlers
        def signal_handler(sig, frame):
            self._signal_count += 1
            if self._signal_count == 1:
                logger.info("\nShutdown signal received... finishing current operation")
                logger.info("All progress will be saved and can be resumed")
                logger.info("Press Ctrl+C again to force exit immediately")
                self.running = False
            else:
                logger.info("\nForce exit requested!")
                # Save state before exiting
                try:
                    self._save_sources()
                    self._save_stats()
                    self._save_retry_stack()
                    self.learner.save()
                    logger.info("State saved. Exiting...")
                except:
                    pass
                os._exit(0)  # Force immediate exit
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        cycle_count = 0
        
        while self.running:
            try:
                cycle_count += 1
                logger.info(f"\n--- Cycle {cycle_count} ---")
                
                # First, process the retry stack (failed items get priority)
                if self.retry_stack:
                    await self.process_retry_stack()
                
                # Then run normal training cycle
                await self.train_cycle()
                
                # Calculate next cycle time
                next_sources = self.get_next_sources()
                if next_sources:
                    # Something needs refresh soon
                    wait_time = 60  # Check again in 1 minute
                    logger.info(f"[ACTIVE] {len(next_sources)} sources pending. Next check in 1 minute...")
                else:
                    # Find minimum time until next refresh
                    min_wait = float('inf')
                    next_source = ""
                    for s in self.sources:
                        if s.last_crawled:
                            next_refresh = s.last_crawled + timedelta(hours=s.refresh_hours)
                            wait = (next_refresh - datetime.now()).total_seconds()
                            if wait > 0 and wait < min_wait:
                                min_wait = wait
                                next_source = s.name
                    
                    # Cap at 1 hour
                    wait_time = min(min_wait, 3600)
                    if wait_time == float('inf'):
                        wait_time = 3600
                    
                    # Show clear message about training being complete
                    hours = wait_time / 3600
                    if hours > 1:
                        logger.info(f"[IDLE] Training complete! Next refresh in {hours:.1f} hours")
                        logger.info(f"       Daemon will stay running and auto-refresh sources.")
                        logger.info(f"       Use --force to re-train now, or Ctrl+C to stop.")
                    else:
                        logger.info(f"[IDLE] Waiting {wait_time/60:.1f} minutes for next refresh ({next_source})")
                
                # Wait (check every 60 seconds for stop signal - no need to spam logs)
                wait_end = time.time() + wait_time
                while time.time() < wait_end and self.running:
                    await asyncio.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in training cycle: {e}")
                self.stats.errors.append(f"{datetime.now()}: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying
        
        # Cleanup
        logger.info("Saving final state...")
        self._save_sources()
        self._save_stats()
        self.learner.save()
        logger.info("Daemon stopped")
    
    def add_source(self, source: TrainingSource):
        """Add a new training source"""
        self.sources.append(source)
        self._save_sources()
        logger.info(f"Added source: {source.name}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current daemon status"""
        return {
            "running": self.running,
            "paused": self.paused,
            "stats": {
                "total_pages_crawled": self.stats.total_pages_crawled,
                "total_knowledge_entries": self.stats.total_knowledge_entries,
                "total_words_indexed": len(self.learner.word_freq),
                "categories": list(self.learner.category_word_freq.keys()),
                "patterns_discovered": len(self.learner.pattern_stats),
                "last_training": self.stats.last_training_time.isoformat() if self.stats.last_training_time else None
            },
            "sources": [
                {
                    "name": s.name,
                    "priority": s.priority,
                    "last_crawled": s.last_crawled.isoformat() if s.last_crawled else None,
                    "needs_refresh": s.needs_refresh
                }
                for s in self.sources
            ]
        }


# ===== PID FILE MANAGEMENT =====
PID_FILE = PROJECT_ROOT / "jarwis_ai" / "training" / "daemon.pid"


def is_daemon_running() -> bool:
    """Check if daemon is already running"""
    if PID_FILE.exists():
        try:
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            # Check if process exists
            import psutil
            if psutil.pid_exists(pid):
                return True
        except:
            pass
    return False


def write_pid():
    """Write current PID to file"""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def remove_pid():
    """Remove PID file"""
    if PID_FILE.exists():
        PID_FILE.unlink()


def stop_daemon():
    """Stop the running daemon"""
    if PID_FILE.exists():
        try:
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            import psutil
            if psutil.pid_exists(pid):
                p = psutil.Process(pid)
                p.terminate()
                p.wait(timeout=10)
                print(f"Daemon (PID {pid}) stopped")
            remove_pid()
        except Exception as e:
            print(f"Error stopping daemon: {e}")
    else:
        print("Daemon is not running")


def show_status():
    """Show daemon status with checkpoint information"""
    if is_daemon_running():
        with open(PID_FILE) as f:
            pid = f.read().strip()
        print(f"[RUNNING] Daemon is running (PID: {pid})")
        
        # Load and show stats
        stats_file = PROJECT_ROOT / "jarwis_ai" / "training" / "data" / "stats.json"
        if stats_file.exists():
            with open(stats_file) as f:
                stats = json.load(f)
            print(f"\nTraining Statistics:")
            print(f"   Pages crawled: {stats.get('total_pages_crawled', 0)}")
            print(f"   Knowledge entries: {stats.get('total_knowledge_entries', 0)}")
            print(f"   Words indexed: {stats.get('total_words_indexed', 0)}")
            if stats.get('last_training_time'):
                print(f"   Last training: {stats['last_training_time']}")
            if stats.get('learner_stats'):
                ls = stats['learner_stats']
                print(f"   Categories: {', '.join(ls.get('categories', []))}")
                print(f"   Patterns discovered: {ls.get('patterns_discovered', 0)}")
            
            # Show retry stack info
            retry_size = stats.get('retry_stack_size', 0)
            if retry_size > 0:
                print(f"\n[RETRY STACK] {retry_size} sources pending retry")
                retry_file = PROJECT_ROOT / "jarwis_ai" / "training" / "data" / "retry_stack.json"
                if retry_file.exists():
                    with open(retry_file) as f:
                        retry_data = json.load(f)
                    for item in retry_data[:5]:  # Show first 5
                        print(f"   - {item['source_name']} (attempt {item['attempt']})")
                    if len(retry_data) > 5:
                        print(f"   ... and {len(retry_data) - 5} more")
            else:
                print(f"\n[RETRY STACK] Empty - all sources processed successfully")
        
        # Show active checkpoints (in-progress crawls that can be resumed)
        checkpoint_dir = PROJECT_ROOT / "jarwis_ai" / "training" / "data" / "crawl_cache" / "checkpoints"
        if checkpoint_dir.exists():
            checkpoints = list(checkpoint_dir.glob("*_checkpoint.json"))
            if checkpoints:
                print(f"\n[CHECKPOINTS] {len(checkpoints)} crawls can be resumed:")
                for cp_file in checkpoints[:10]:
                    try:
                        with open(cp_file) as f:
                            cp_data = json.load(f)
                        name = cp_data.get('site_name', 'Unknown')
                        pages = cp_data.get('successful_pages', 0)
                        queued = len(cp_data.get('queued_urls', []))
                        print(f"   - {name}: {pages} pages done, {queued} in queue")
                    except:
                        pass
                if len(checkpoints) > 10:
                    print(f"   ... and {len(checkpoints) - 10} more")
    else:
        print("[STOPPED] Daemon is not running")
        
        # Still show checkpoint info even when stopped
        checkpoint_dir = PROJECT_ROOT / "jarwis_ai" / "training" / "data" / "crawl_cache" / "checkpoints"
        if checkpoint_dir.exists():
            checkpoints = list(checkpoint_dir.glob("*_checkpoint.json"))
            if checkpoints:
                print(f"\n[RESUME INFO] {len(checkpoints)} crawls will resume from checkpoint on next start:")
                for cp_file in checkpoints[:5]:
                    try:
                        with open(cp_file) as f:
                            cp_data = json.load(f)
                        name = cp_data.get('site_name', 'Unknown')
                        pages = cp_data.get('successful_pages', 0)
                        last_cp = cp_data.get('last_checkpoint', 'Unknown')
                        print(f"   - {name}: {pages} pages (last checkpoint: {last_cp})")
                    except:
                        pass


async def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Jarwis AI Autonomous Training Daemon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run in foreground (Ctrl+C to stop)
  python -m jarwis_ai.training.daemon run
  
  # Force re-crawl all sources (ignore refresh timers)
  python -m jarwis_ai.training.daemon run --force
  
  # Start as background process
  python -m jarwis_ai.training.daemon start
  
  # Stop the daemon
  python -m jarwis_ai.training.daemon stop
  
  # Check status
  python -m jarwis_ai.training.daemon status
        """
    )
    parser.add_argument(
        "command",
        choices=["run", "start", "stop", "status", "reset"],
        help="Command to execute (reset = clear last_crawled times to force re-crawl)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Force re-crawl all sources (ignore refresh timers)"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.command == "run":
        # Run in foreground
        if is_daemon_running():
            print("Daemon is already running!")
            return
        
        write_pid()
        try:
            trainer = AutonomousTrainer()
            
            # Force re-crawl if requested
            if args.force:
                print("[FORCE] Resetting all sources for immediate re-crawl...")
                for source in trainer.sources:
                    source.last_crawled = None
                trainer._save_sources()
                print(f"[FORCE] Reset {len(trainer.sources)} sources")
            
            await trainer.run_forever()
        finally:
            remove_pid()
    
    elif args.command == "start":
        # Start as background process
        if is_daemon_running():
            print("Daemon is already running!")
            return
        
        print("Starting daemon in background...")
        # On Windows, use pythonw or subprocess
        import subprocess
        script_path = Path(__file__)
        cmd = [sys.executable, str(script_path), "run"]
        if args.force:
            cmd.append("--force")
        subprocess.Popen(
            cmd,
            stdout=open(LOG_DIR / "daemon_stdout.log", "w"),
            stderr=open(LOG_DIR / "daemon_stderr.log", "w"),
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        )
        print("Daemon started. Check status with: python -m jarwis_ai.training.daemon status")
    
    elif args.command == "stop":
        stop_daemon()
    
    elif args.command == "status":
        show_status()
    
    elif args.command == "reset":
        # Reset all last_crawled times
        print("Resetting all source crawl times...")
        sources_file = PROJECT_ROOT / "jarwis_ai" / "training" / "data" / "sources.json"
        if sources_file.exists():
            with open(sources_file, "r") as f:
                data = json.load(f)
            for s in data:
                s["last_crawled"] = None
            with open(sources_file, "w") as f:
                json.dump(data, f, indent=2)
            print(f"Reset {len(data)} sources. Run 'start' or 'run' to begin fresh crawl.")
        else:
            print("No sources file found.")


if __name__ == "__main__":
    asyncio.run(main())
