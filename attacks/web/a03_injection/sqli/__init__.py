"""
SQL Injection (SQLi) Attack Module
===================================

Sub-categories:
- error_based.py    - Error-based SQLi (visible error messages)
- blind_boolean.py  - Blind Boolean-based SQLi (true/false inference)
- blind_time.py     - Blind Time-based SQLi (delay inference)
- union_based.py    - UNION-based SQLi (data extraction via UNION)

Each sub-type requires different detection and exploitation techniques.
"""

from .base import SQLiBase, SQLiResult, DatabaseType
from .error_based import SQLiErrorBased
from .blind_boolean import SQLiBlindBoolean
from .blind_time import SQLiBlindTime
from .union_based import SQLiUnionBased

__all__ = [
    'SQLiBase',
    'SQLiResult',
    'DatabaseType',
    'SQLiErrorBased',
    'SQLiBlindBoolean',
    'SQLiBlindTime',
    'SQLiUnionBased',
]
