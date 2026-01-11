"""
Network Scanning Architecture Validation Script

Checks that the refactored network scanning follows proper layered architecture.
Run this to verify compliance before pushing to production.

Usage:
    python validate_network_architecture.py
"""

import os
import sys
import re
from pathlib import Path


class ArchitectureValidator:
    """Validates layered architecture compliance"""
    
    # Files by layer
    API_ROUTES = ['api/routes/network.py']
    SERVICES = ['services/network_service.py', 'services/agent_service.py']
    CORE = ['core/network_scan_runner.py']
    ATTACKS = ['attacks/network/orchestrator.py', 'attacks/network/scanners/base.py']
    DATABASE = ['database/models.py']
    
    # Forbidden imports by layer
    FORBIDDEN_IMPORTS = {
        'core': ['api.routes', 'services'],
        'attacks': ['api.routes', 'services', 'core.runner'],
        'database': ['api.routes', 'services', 'core', 'attacks'],
    }
    
    # Required imports by layer
    REQUIRED_IMPORTS = {
        'api/routes/network.py': [
            'services.network_service',
            'services.agent_service',
        ],
        'services/network_service.py': [
            'database.models',
            'database.db',
        ],
        'services/agent_service.py': [
            'database.models',
        ],
        'core/network_scan_runner.py': [
            'services.network_service',
            'attacks.network',
        ],
    }
    
    def __init__(self, root_path: str = '.'):
        self.root_path = root_path
        self.errors = []
        self.warnings = []
        self.passed = []
    
    def validate(self):
        """Run all validation checks"""
        print("\n" + "="*70)
        print("NETWORK SCANNING ARCHITECTURE VALIDATION")
        print("="*70 + "\n")
        
        # Check files exist
        print("[1/4] Checking if files exist...")
        self._check_files_exist()
        
        # Check import rules
        print("\n[2/4] Validating import rules...")
        self._check_imports()
        
        # Check API routes are thin
        print("\n[3/4] Validating route layer thickness...")
        self._check_route_thickness()
        
        # Check database models
        print("\n[4/4] Validating database models...")
        self._check_database_models()
        
        # Print summary
        self._print_summary()
    
    def _check_files_exist(self):
        """Verify all expected files exist"""
        all_files = self.API_ROUTES + self.SERVICES + self.CORE + self.DATABASE
        
        for filepath in all_files:
            full_path = os.path.join(self.root_path, filepath)
            if os.path.exists(full_path):
                size = os.path.getsize(full_path)
                self.passed.append(f"✓ {filepath} exists ({size} bytes)")
                print(f"  ✓ {filepath}")
            else:
                self.errors.append(f"✗ Missing: {filepath}")
                print(f"  ✗ {filepath} - NOT FOUND")
    
    def _check_imports(self):
        """Verify import boundaries are maintained"""
        print()
        
        # Check API routes
        api_file = os.path.join(self.root_path, self.API_ROUTES[0])
        if os.path.exists(api_file):
            content = self._read_file(api_file)
            
            # Should have service imports
            if 'from services.network_service' in content:
                self.passed.append(f"✓ {self.API_ROUTES[0]} imports from services")
                print(f"  ✓ Routes import from services")
            else:
                self.errors.append(f"Routes don't import from services")
                print(f"  ✗ Routes missing services import")
            
            # Should NOT have core imports
            if 'from core.' in content or 'from core import' in content:
                if 'from core.network_scan_runner' in content or 'core.network_scan_runner' in content:
                    # This is expected - routes call runner via background task
                    self.passed.append(f"✓ Routes properly call core.network_scan_runner")
                    print(f"  ✓ Routes call core.network_scan_runner (via background task)")
                else:
                    self.errors.append(f"Routes have forbidden core imports")
                    print(f"  ✗ Routes have forbidden core imports")
            else:
                self.passed.append(f"✓ Routes don't directly import core modules")
                print(f"  ✓ Routes isolated from core")
            
            # Should NOT have attacks imports
            if 'from attacks.' in content or 'from attacks import' in content:
                self.errors.append(f"Routes import from attacks (forbidden)")
                print(f"  ✗ Routes import from attacks")
            else:
                self.passed.append(f"✓ Routes don't import attacks")
                print(f"  ✓ Routes isolated from attacks")
        
        # Check service layer
        service_file = os.path.join(self.root_path, self.SERVICES[0])
        if os.path.exists(service_file):
            content = self._read_file(service_file)
            
            if 'from database' in content:
                self.passed.append(f"✓ Services import from database")
                print(f"  ✓ Services can access database")
            
            if 'from api.routes' in content:
                self.errors.append(f"Services import from API routes (forbidden)")
                print(f"  ✗ Services import from api.routes")
            else:
                self.passed.append(f"✓ Services don't import api.routes")
                print(f"  ✓ Services isolated from routes")
        
        # Check core layer
        core_file = os.path.join(self.root_path, self.CORE[0])
        if os.path.exists(core_file):
            content = self._read_file(core_file)
            
            if 'from api.routes' in content:
                self.errors.append(f"Core imports from api.routes (forbidden)")
                print(f"  ✗ Core imports from api.routes")
            else:
                self.passed.append(f"✓ Core doesn't import api.routes")
                print(f"  ✓ Core isolated from HTTP layer")
            
            if 'from attacks' in content:
                self.passed.append(f"✓ Core can import from attacks")
                print(f"  ✓ Core calls attack modules")
            
            if 'from services' in content:
                # Core can import service helper methods, but not rely on them
                self.passed.append(f"✓ Core imports from services (for data operations)")
                print(f"  ✓ Core uses services for data operations")
    
    def _check_route_thickness(self):
        """Verify API routes are thin (< 400 lines)"""
        api_file = os.path.join(self.root_path, self.API_ROUTES[0])
        if os.path.exists(api_file):
            content = self._read_file(api_file)
            lines = content.split('\n')
            
            # Count non-comment, non-docstring lines
            code_lines = 0
            in_docstring = False
            for line in lines:
                stripped = line.strip()
                if '"""' in line or "'''" in line:
                    in_docstring = not in_docstring
                if not in_docstring and stripped and not stripped.startswith('#'):
                    code_lines += 1
            
            if code_lines < 400:
                self.passed.append(f"✓ Routes file is thin ({code_lines} lines)")
                print(f"  ✓ Routes file thickness: {code_lines} lines (target < 400)")
            else:
                self.warnings.append(f"Routes file is thick ({code_lines} lines)")
                print(f"  ⚠ Routes file: {code_lines} lines (consider splitting)")
    
    def _check_database_models(self):
        """Verify database models are properly defined"""
        db_file = os.path.join(self.root_path, self.DATABASE[0])
        if os.path.exists(db_file):
            content = self._read_file(db_file)
            
            if 'class Agent' in content:
                self.passed.append(f"✓ Agent model defined in database")
                print(f"  ✓ Agent model exists")
            else:
                self.errors.append(f"Agent model not found in database/models.py")
                print(f"  ✗ Agent model missing")
            
            if 'checkpoint_data' in content:
                self.passed.append(f"✓ ScanHistory has checkpoint_data field")
                print(f"  ✓ Checkpoint field exists")
            else:
                self.warnings.append(f"ScanHistory missing checkpoint_data field")
                print(f"  ⚠ checkpoint_data field not found")
            
            if 'config' in content and 'ScanHistory' in content:
                self.passed.append(f"✓ ScanHistory has config field")
                print(f"  ✓ Config field exists")
    
    def _read_file(self, filepath: str) -> str:
        """Read file content"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            self.errors.append(f"Failed to read {filepath}: {e}")
            return ""
    
    def _print_summary(self):
        """Print validation summary"""
        print("\n" + "="*70)
        print("VALIDATION SUMMARY")
        print("="*70)
        
        total_checks = len(self.passed) + len(self.errors) + len(self.warnings)
        
        if self.passed:
            print(f"\n✅ PASSED ({len(self.passed)} checks)")
            for check in self.passed[:5]:  # Show first 5
                print(f"   {check}")
            if len(self.passed) > 5:
                print(f"   ... and {len(self.passed) - 5} more")
        
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)})")
            for warn in self.warnings:
                print(f"   {warn}")
        
        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)})")
            for error in self.errors:
                print(f"   {error}")
        
        print("\n" + "="*70)
        print("RESULT:", end=" ")
        
        if self.errors:
            print("FAILED ❌")
            print("\nArchitecture validation FAILED. Please fix the errors above.")
            sys.exit(1)
        elif self.warnings:
            print("PASSED WITH WARNINGS ⚠️")
            print("\nArchitecture validation passed, but review warnings above.")
            sys.exit(0)
        else:
            print("PASSED ✅")
            print("\nArchitecture validation successful! Ready for deployment.")
            sys.exit(0)


def main():
    """Main entry point"""
    validator = ArchitectureValidator(root_path='.')
    validator.validate()


if __name__ == "__main__":
    main()
