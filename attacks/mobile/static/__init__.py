"""
Mobile Static Analysis Module

Components:
- StaticAnalyzer: Basic APK/IPA analysis using aapt
- DeepCodeScanner: Advanced Android decompilation analysis using Jadx/APKTool
- IOSDeepCodeScanner: Advanced iOS IPA analysis
- AppUnpacker: Extracts and unpacks mobile app files

Android DeepCodeScanner provides:
- Hardcoded API key detection (AWS, Google, Firebase, Stripe, etc.)
- Insecure SharedPreferences usage detection
- Weak cryptography pattern detection
- SQL injection vulnerabilities
- Sensitive data logging

iOS IOSDeepCodeScanner provides:
- Binary string extraction and analysis
- Insecure Keychain/NSUserDefaults detection
- ATS (App Transport Security) bypass detection
- URL scheme vulnerability detection
- Binary protection analysis (PIE, encryption)
"""

from .static_analyzer import StaticAnalysisResult, AppMetadata, StaticAnalyzer
from .unpacker import SecretFinding, UnpackResult, AppUnpacker
from .deep_code_scanner import (
    DeepCodeScanner,
    DeepScanConfig,
    CodeFinding,
    FindingSeverity,
    FindingCategory,
    SecretPattern,
    scan_apk_deep
)
from .ios_deep_scanner import (
    IOSDeepCodeScanner,
    IOSScanConfig,
    IOSCodeFinding,
    IOSAppMetadata,
    FindingSeverity as IOSFindingSeverity,
    FindingCategory as IOSFindingCategory,
    scan_ipa_deep
)

__all__ = [
    # Basic static analysis
    'StaticAnalysisResult', 
    'AppMetadata', 
    'StaticAnalyzer',
    
    # Unpacker
    'SecretFinding', 
    'UnpackResult', 
    'AppUnpacker',
    
    # Android deep code scanner (Jadx/APKTool)
    'DeepCodeScanner',
    'DeepScanConfig',
    'CodeFinding',
    'FindingSeverity',
    'FindingCategory',
    'SecretPattern',
    'scan_apk_deep',
    
    # iOS deep code scanner (NEW)
    'IOSDeepCodeScanner',
    'IOSScanConfig',
    'IOSCodeFinding',
    'IOSAppMetadata',
    'IOSFindingSeverity',
    'IOSFindingCategory',
    'scan_ipa_deep',
]
