"""
File Upload Attack Module

Contains scanners and tools for testing file upload vulnerabilities:
- FileUploadScanner: Legacy scanner
- FileUploadScannerV2: Enhanced MITM-based scanner with polyglot support
- polyglot_generator: Generates malicious test files
"""

from .file_upload_scanner import ScanResult, FileUploadScanner, CommandInjectionScanner
from .upload_scanner import ScanResult, UploadScanner
from .file_upload_scanner_v2 import FileUploadScannerV2, scan_common_endpoints
from .polyglot_generator import (
    create_polyglot,
    generate_all_polyglots,
    get_test_file_path,
    list_test_files,
    IMAGE_HEADERS,
    PHP_SHELLS,
    OTHER_SHELLS,
)

__all__ = [
    # Legacy scanners
    'ScanResult',
    'FileUploadScanner',
    'CommandInjectionScanner',
    'UploadScanner',
    
    # New MITM-based scanner
    'FileUploadScannerV2',
    'scan_common_endpoints',
    
    # Polyglot generator
    'create_polyglot',
    'generate_all_polyglots',
    'get_test_file_path',
    'list_test_files',
    'IMAGE_HEADERS',
    'PHP_SHELLS',
    'OTHER_SHELLS',
]
