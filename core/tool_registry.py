"""
Tool Registry with Caching

Provides cached availability checks for security tools.
Reduces overhead by caching tool availability for 5 minutes.

Usage:
    from core.tool_registry import ToolRegistry
    
    registry = ToolRegistry()
    available = registry.is_tool_available('nmap')
    all_tools = registry.get_available_tools()
"""

import logging
import shutil
import time
from typing import Dict, Set, Optional
from dataclasses import dataclass
from threading import Lock

logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """Information about a security tool"""
    name: str
    executable: str  # Actual executable name (may differ from name)
    available: bool
    checked_at: float  # Timestamp of last check
    version: Optional[str] = None
    path: Optional[str] = None


class ToolRegistry:
    """
    Centralized tool availability registry with caching.
    
    Features:
    - Caches tool availability checks for 5 minutes (configurable)
    - Thread-safe operations
    - Supports alternative tool names (e.g., crackmapexec/netexec)
    - Python library detection (sslyze, gvm-tools)
    """
    
    # Tool name mappings (logical name → executable name)
    TOOL_MAPPINGS = {
        'testssl': 'testssl.sh',
        'crackmapexec': 'crackmapexec',  # Check both cme and netexec
        'vulners': 'nmap',  # Vulners uses nmap
        'metasploit': 'msfconsole',
    }
    
    # Alternative executables to try
    TOOL_ALTERNATIVES = {
        'crackmapexec': ['crackmapexec', 'netexec', 'cme'],
    }
    
    # Python libraries to check
    PYTHON_LIBRARIES = {
        'sslyze': 'sslyze',
        'gvm-tools': 'gvm.connections',
    }
    
    def __init__(self, cache_ttl: int = 300):
        """
        Initialize tool registry.
        
        Args:
            cache_ttl: Cache time-to-live in seconds (default: 300 = 5 minutes)
        """
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, ToolInfo] = {}
        self._lock = Lock()
        logger.info(f"ToolRegistry initialized with {cache_ttl}s cache TTL")
    
    def is_tool_available(self, tool_name: str) -> bool:
        """
        Check if a tool is available (cached).
        
        Args:
            tool_name: Logical tool name (e.g., 'nmap', 'crackmapexec')
        
        Returns:
            True if tool is available, False otherwise
        """
        tool_info = self._get_tool_info(tool_name)
        return tool_info.available
    
    def get_tool_info(self, tool_name: str) -> Optional[ToolInfo]:
        """Get full tool information (cached)"""
        return self._get_tool_info(tool_name)
    
    def get_available_tools(self) -> Set[str]:
        """Get set of all available tool names"""
        available = set()
        
        # Check standard CLI tools
        cli_tools = [
            'nmap', 'masscan', 'rustscan',
            'nuclei', 'openvas',
            'netdiscover', 'arp-scan', 'snmpwalk', 'dnsrecon',
            'sslscan', 'testssl', 'sslyze',
            'crackmapexec',
            'zeek', 'suricata', 'snort', 'tshark',
            'metasploit',
        ]
        
        for tool in cli_tools:
            if self.is_tool_available(tool):
                available.add(tool)
        
        # Check Python libraries
        for lib_name in self.PYTHON_LIBRARIES.keys():
            if self._is_python_library_available(lib_name):
                available.add(lib_name)
        
        return available
    
    def clear_cache(self, tool_name: Optional[str] = None):
        """
        Clear cache for a specific tool or all tools.
        
        Args:
            tool_name: Tool to clear cache for, or None to clear all
        """
        with self._lock:
            if tool_name:
                self._cache.pop(tool_name, None)
                logger.debug(f"Cleared cache for tool: {tool_name}")
            else:
                self._cache.clear()
                logger.debug("Cleared all tool cache")
    
    def _get_tool_info(self, tool_name: str) -> ToolInfo:
        """Internal method to get tool info with caching"""
        now = time.time()
        
        with self._lock:
            # Check cache first
            if tool_name in self._cache:
                cached = self._cache[tool_name]
                age = now - cached.checked_at
                
                # Return cached if still valid
                if age < self.cache_ttl:
                    logger.debug(f"Tool cache hit: {tool_name} (age: {age:.1f}s)")
                    return cached
                else:
                    logger.debug(f"Tool cache expired: {tool_name} (age: {age:.1f}s)")
        
        # Cache miss or expired - perform fresh check
        tool_info = self._check_tool_availability(tool_name)
        
        with self._lock:
            self._cache[tool_name] = tool_info
        
        logger.debug(
            f"Tool check: {tool_name} → {'available' if tool_info.available else 'not found'}"
        )
        
        return tool_info
    
    def _check_tool_availability(self, tool_name: str) -> ToolInfo:
        """Perform actual tool availability check (not cached)"""
        # Get executable name (may differ from logical name)
        executable = self.TOOL_MAPPINGS.get(tool_name, tool_name)
        
        # Check for alternatives
        alternatives = self.TOOL_ALTERNATIVES.get(tool_name, [executable])
        
        for alt in alternatives:
            path = shutil.which(alt)
            if path:
                return ToolInfo(
                    name=tool_name,
                    executable=alt,
                    available=True,
                    checked_at=time.time(),
                    path=path,
                )
        
        # Tool not found
        return ToolInfo(
            name=tool_name,
            executable=executable,
            available=False,
            checked_at=time.time(),
        )
    
    def _is_python_library_available(self, lib_name: str) -> bool:
        """Check if Python library is available"""
        import_path = self.PYTHON_LIBRARIES.get(lib_name)
        if not import_path:
            return False
        
        try:
            __import__(import_path)
            return True
        except ImportError:
            return False
    
    def get_cache_stats(self) -> Dict[str, any]:
        """Get cache statistics"""
        with self._lock:
            total = len(self._cache)
            available = sum(1 for t in self._cache.values() if t.available)
            
            return {
                'total_cached': total,
                'available': available,
                'unavailable': total - available,
                'cache_ttl': self.cache_ttl,
                'cached_tools': list(self._cache.keys()),
            }


# Singleton instance
_registry_instance: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Get singleton ToolRegistry instance"""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = ToolRegistry()
    return _registry_instance
