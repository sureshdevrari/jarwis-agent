"""
Core Engines Package

This package contains engine adapters that wrap existing scan runners
to work with the unified ScanOrchestrator.

Adapters:
- LegacyEngineAdapter: Wraps any existing runner dynamically
- WebEngineAdapter: Wraps WebScanRunner
- NetworkEngineAdapter: Wraps NetworkOrchestrator
- CloudEngineAdapter: Wraps CloudScanRunner
- SASTEngineAdapter: Wraps SASTScanRunner
- MobileEngineAdapter: Wraps MobilePenTestOrchestrator
"""

from core.engine_protocol import (
    EngineType,
    EngineResult,
    ProgressUpdate,
    ScanEngineProtocol,
    ScanEngineAdapter,
)

__all__ = [
    "EngineType",
    "EngineResult",
    "ProgressUpdate",
    "ScanEngineProtocol",
    "ScanEngineAdapter",
]
