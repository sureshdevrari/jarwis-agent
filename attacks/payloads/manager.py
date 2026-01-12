"""
PayloadManager - Centralized Payload Loading and Management

Provides efficient loading, caching, and serving of attack payloads
from the external payload library.
"""

import os
import random
from pathlib import Path
from typing import List, Dict, Optional, Iterator, Set
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class PayloadCategory(Enum):
    """Categories of attack payloads."""
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    CMDI = "cmdi"
    XXE = "xxe"
    LFI = "lfi"
    NOSQL = "nosql"


@dataclass
class PayloadSet:
    """A set of payloads for a specific attack type."""
    category: PayloadCategory
    subcategory: str
    payloads: List[str] = field(default_factory=list)
    file_path: Optional[str] = None
    
    def __len__(self) -> int:
        return len(self.payloads)
    
    def __iter__(self) -> Iterator[str]:
        return iter(self.payloads)
    
    def sample(self, n: int) -> List[str]:
        """Get a random sample of n payloads."""
        if n >= len(self.payloads):
            return self.payloads.copy()
        return random.sample(self.payloads, n)


class PayloadManager:
    """
    Centralized manager for loading and serving attack payloads.
    
    Features:
    - Lazy loading of payload files
    - Caching for performance
    - Filtering and sampling
    - Context-aware payload selection
    """
    
    # Base directory for payloads
    PAYLOADS_DIR = Path(__file__).parent
    
    # Payload file mappings
    PAYLOAD_FILES: Dict[PayloadCategory, Dict[str, str]] = {
        PayloadCategory.SQLI: {
            "error_based": "sqli/error_based.txt",
            "auth_bypass": "sqli/auth_bypass.txt",
            "time_blind": "sqli/time_blind.txt",
            "union_based": "sqli/union_based.txt",
        },
        PayloadCategory.XSS: {
            "basic": "xss/basic.txt",
            "filter_bypass": "xss/filter_bypass.txt",
            "polyglots": "xss/polyglots.txt",
            "html_injection": "xss/html_injection.txt",
        },
        PayloadCategory.SSTI: {
            "all_engines": "ssti/all_engines.txt",
        },
        PayloadCategory.CMDI: {
            "all": "cmdi/all.txt",
        },
        PayloadCategory.XXE: {
            "all": "xxe/all.txt",
        },
        PayloadCategory.LFI: {
            "all": "lfi/all.txt",
        },
        PayloadCategory.NOSQL: {
            "all": "nosql/all.txt",
        },
    }
    
    def __init__(self, payloads_dir: Optional[Path] = None):
        """
        Initialize PayloadManager.
        
        Args:
            payloads_dir: Custom directory for payloads (optional)
        """
        self.payloads_dir = payloads_dir or self.PAYLOADS_DIR
        self._cache: Dict[str, PayloadSet] = {}
        self._loaded_categories: Set[PayloadCategory] = set()
    
    def _load_file(self, file_path: Path) -> List[str]:
        """
        Load payloads from a file.
        
        Filters out:
        - Empty lines
        - Comment lines (starting with #)
        - Whitespace-only lines
        
        Args:
            file_path: Path to the payload file
            
        Returns:
            List of payload strings
        """
        payloads = []
        
        if not file_path.exists():
            logger.warning(f"Payload file not found: {file_path}")
            return payloads
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.rstrip('\n\r')
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except Exception as e:
            logger.error(f"Error loading payloads from {file_path}: {e}")
        
        logger.debug(f"Loaded {len(payloads)} payloads from {file_path}")
        return payloads
    
    def _get_cache_key(self, category: PayloadCategory, subcategory: str) -> str:
        """Generate cache key for a payload set."""
        return f"{category.value}:{subcategory}"
    
    def load_category(self, category: PayloadCategory) -> Dict[str, PayloadSet]:
        """
        Load all payloads for a category.
        
        Args:
            category: The payload category to load
            
        Returns:
            Dictionary of subcategory -> PayloadSet
        """
        if category in self._loaded_categories:
            # Return from cache
            result = {}
            for subcategory in self.PAYLOAD_FILES.get(category, {}):
                key = self._get_cache_key(category, subcategory)
                if key in self._cache:
                    result[subcategory] = self._cache[key]
            return result
        
        result = {}
        files = self.PAYLOAD_FILES.get(category, {})
        
        for subcategory, rel_path in files.items():
            file_path = self.payloads_dir / rel_path
            payloads = self._load_file(file_path)
            
            payload_set = PayloadSet(
                category=category,
                subcategory=subcategory,
                payloads=payloads,
                file_path=str(file_path)
            )
            
            key = self._get_cache_key(category, subcategory)
            self._cache[key] = payload_set
            result[subcategory] = payload_set
        
        self._loaded_categories.add(category)
        return result
    
    def get_payloads(
        self,
        category: PayloadCategory,
        subcategory: Optional[str] = None,
        limit: Optional[int] = None,
        shuffle: bool = False
    ) -> List[str]:
        """
        Get payloads for a specific category/subcategory.
        
        Args:
            category: The payload category
            subcategory: Specific subcategory (optional, gets all if None)
            limit: Maximum number of payloads to return
            shuffle: Randomize payload order
            
        Returns:
            List of payload strings
        """
        # Ensure category is loaded
        self.load_category(category)
        
        payloads = []
        
        if subcategory:
            # Get specific subcategory
            key = self._get_cache_key(category, subcategory)
            if key in self._cache:
                payloads = list(self._cache[key].payloads)
        else:
            # Get all subcategories for this category
            for sub in self.PAYLOAD_FILES.get(category, {}):
                key = self._get_cache_key(category, sub)
                if key in self._cache:
                    payloads.extend(self._cache[key].payloads)
        
        if shuffle:
            random.shuffle(payloads)
        
        if limit and limit < len(payloads):
            payloads = payloads[:limit]
        
        return payloads
    
    def get_sqli_payloads(
        self,
        types: Optional[List[str]] = None,
        limit: Optional[int] = None
    ) -> List[str]:
        """
        Get SQL injection payloads.
        
        Args:
            types: List of types: "error_based", "auth_bypass", "time_blind", "union_based"
            limit: Maximum number of payloads
            
        Returns:
            List of SQLi payloads
        """
        types = types or ["error_based", "auth_bypass", "time_blind", "union_based"]
        payloads = []
        
        for t in types:
            payloads.extend(self.get_payloads(PayloadCategory.SQLI, t))
        
        if limit and limit < len(payloads):
            return random.sample(payloads, limit)
        return payloads
    
    def get_xss_payloads(
        self,
        types: Optional[List[str]] = None,
        limit: Optional[int] = None
    ) -> List[str]:
        """
        Get XSS payloads.
        
        Args:
            types: List of types: "basic", "filter_bypass", "polyglots", "html_injection"
            limit: Maximum number of payloads
            
        Returns:
            List of XSS payloads
        """
        types = types or ["basic", "filter_bypass", "polyglots"]
        payloads = []
        
        for t in types:
            payloads.extend(self.get_payloads(PayloadCategory.XSS, t))
        
        if limit and limit < len(payloads):
            return random.sample(payloads, limit)
        return payloads
    
    def get_auth_bypass_payloads(self, limit: Optional[int] = None) -> List[str]:
        """Get payloads specifically for login bypass testing."""
        payloads = self.get_payloads(PayloadCategory.SQLI, "auth_bypass")
        
        if limit and limit < len(payloads):
            return random.sample(payloads, limit)
        return payloads
    
    def get_time_blind_payloads(self, limit: Optional[int] = None) -> List[str]:
        """Get time-based blind injection payloads."""
        payloads = self.get_payloads(PayloadCategory.SQLI, "time_blind")
        
        if limit and limit < len(payloads):
            return random.sample(payloads, limit)
        return payloads
    
    def get_ssti_payloads(self, limit: Optional[int] = None) -> List[str]:
        """Get Server-Side Template Injection payloads."""
        payloads = self.get_payloads(PayloadCategory.SSTI)
        
        if limit and limit < len(payloads):
            return random.sample(payloads, limit)
        return payloads
    
    def get_cmdi_payloads(self, limit: Optional[int] = None) -> List[str]:
        """Get Command Injection payloads."""
        payloads = self.get_payloads(PayloadCategory.CMDI)
        
        if limit and limit < len(payloads):
            return random.sample(payloads, limit)
        return payloads
    
    def get_lfi_payloads(self, limit: Optional[int] = None) -> List[str]:
        """Get Local File Inclusion payloads."""
        payloads = self.get_payloads(PayloadCategory.LFI)
        
        if limit and limit < len(payloads):
            return random.sample(payloads, limit)
        return payloads
    
    def get_nosql_payloads(self, limit: Optional[int] = None) -> List[str]:
        """Get NoSQL injection payloads."""
        payloads = self.get_payloads(PayloadCategory.NOSQL)
        
        if limit and limit < len(payloads):
            return random.sample(payloads, limit)
        return payloads
    
    def get_xxe_payloads(self, limit: Optional[int] = None) -> List[str]:
        """Get XXE payloads."""
        payloads = self.get_payloads(PayloadCategory.XXE)
        
        if limit and limit < len(payloads):
            return random.sample(payloads, limit)
        return payloads
    
    def get_context_payloads(
        self,
        field_type: str,
        field_name: str = "",
        limit: int = 100
    ) -> Dict[str, List[str]]:
        """
        Get contextually relevant payloads based on field type and name.
        
        Args:
            field_type: Type of input field (text, password, email, search, textarea, etc.)
            field_name: Name attribute of the field
            limit: Max payloads per category
            
        Returns:
            Dictionary of attack_type -> payloads
        """
        result = {}
        field_name_lower = field_name.lower()
        
        # Always include XSS for text inputs
        result["xss"] = self.get_xss_payloads(limit=limit)
        
        # Login fields get auth bypass payloads
        if field_type == "password" or any(
            x in field_name_lower for x in ["pass", "pwd", "login", "auth"]
        ):
            result["sqli_auth"] = self.get_auth_bypass_payloads(limit=limit)
        
        # Username/email fields
        if any(x in field_name_lower for x in ["user", "email", "login", "name"]):
            result["sqli_auth"] = self.get_auth_bypass_payloads(limit=limit)
        
        # Search fields - good for all injection types
        if field_type == "search" or any(
            x in field_name_lower for x in ["search", "query", "q", "find", "filter"]
        ):
            result["sqli"] = self.get_sqli_payloads(limit=limit)
            result["ssti"] = self.get_ssti_payloads(limit=limit // 2)
            result["cmdi"] = self.get_cmdi_payloads(limit=limit // 2)
        
        # Textarea - good for template injection
        if field_type == "textarea":
            result["ssti"] = self.get_ssti_payloads(limit=limit)
            result["xss"] = self.get_xss_payloads(types=["polyglots"], limit=limit)
        
        # File path inputs
        if any(x in field_name_lower for x in ["file", "path", "url", "dir", "folder"]):
            result["lfi"] = self.get_lfi_payloads(limit=limit)
        
        # ID parameters
        if any(x in field_name_lower for x in ["id", "_id", "uid", "pid"]):
            result["sqli"] = self.get_sqli_payloads(
                types=["error_based", "union_based"],
                limit=limit
            )
            result["nosql"] = self.get_nosql_payloads(limit=limit // 2)
        
        return result
    
    def get_all_categories(self) -> List[PayloadCategory]:
        """Get list of all available payload categories."""
        return list(PayloadCategory)
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics about loaded payloads."""
        stats = {}
        
        for category in PayloadCategory:
            self.load_category(category)
            total = 0
            for subcategory in self.PAYLOAD_FILES.get(category, {}):
                key = self._get_cache_key(category, subcategory)
                if key in self._cache:
                    count = len(self._cache[key])
                    stats[f"{category.value}:{subcategory}"] = count
                    total += count
            stats[f"{category.value}:total"] = total
        
        stats["grand_total"] = sum(
            v for k, v in stats.items() if k.endswith(":total")
        )
        return stats
    
    def clear_cache(self):
        """Clear the payload cache."""
        self._cache.clear()
        self._loaded_categories.clear()


# Singleton instance
_manager: Optional[PayloadManager] = None


def get_payload_manager() -> PayloadManager:
    """Get or create the singleton PayloadManager instance."""
    global _manager
    if _manager is None:
        _manager = PayloadManager()
    return _manager
