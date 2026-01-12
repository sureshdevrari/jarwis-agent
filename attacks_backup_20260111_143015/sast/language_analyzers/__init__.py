"""
Language-specific Analyzers for SAST

Provides specialized vulnerability detection for:
- Python (Bandit-style rules)
- JavaScript/TypeScript (ESLint security rules)
- Java (FindSecBugs patterns)
- Go (gosec patterns)

Each analyzer understands language-specific idioms and patterns
for more accurate vulnerability detection.
"""

from .python_analyzer import PythonAnalyzer
from .javascript_analyzer import JavaScriptAnalyzer
from .java_analyzer import JavaAnalyzer
from .go_analyzer import GoAnalyzer

__all__ = [
    'PythonAnalyzer',
    'JavaScriptAnalyzer',
    'JavaAnalyzer',
    'GoAnalyzer',
]
