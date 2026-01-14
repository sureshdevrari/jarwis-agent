"""
XSS (Cross-Site Scripting) Attack Module
=========================================

Sub-categories:
- reflected.py  - XSS Reflected (non-persistent)
- stored.py     - XSS Stored (persistent)
- dom.py        - XSS DOM-based (client-side)

Each sub-type has distinct detection methods and evidence requirements.
"""

from .base import XSSBase, XSSResult, XSSContext
from .reflected import XSSReflected
from .stored import XSSStored
from .dom import XSSDom

__all__ = [
    'XSSBase',
    'XSSResult', 
    'XSSContext',
    'XSSReflected',
    'XSSStored',
    'XSSDom',
]
