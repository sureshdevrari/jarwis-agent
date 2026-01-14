"""
Jarwis AGI Pen Test - Shared Attacks Module

Provides unified base classes and utilities for both web and mobile scanners.
"""

from .base_scanner import (
    BaseAPIScanner,
    Finding,
    Severity,
    Confidence,
)

__all__ = [
    'BaseAPIScanner',
    'Finding',
    'Severity',
    'Confidence',
]
