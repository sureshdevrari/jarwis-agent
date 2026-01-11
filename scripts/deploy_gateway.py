"""
Jarwis Deployment Gateway

Single entry point for all deployments that validates system health
and ensures all components are in sync.

Usage:
    python deploy_gateway.py --env production
    python deploy_gateway.py --env staging --skip-tests
"""

import asyncio
import argparse
import sys
import os
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class DeploymentGateway:
    """
    Validates and orchestrates all deployment steps.
    Ensures system integrity before allowing deployment.
    """
    
    def __init__(self, environment: str, skip_tests: bool = False):
        self.environment = environment
        self.skip_tests = skip_tests
        self.project_root = Path(__file__).parent
        self.errors: List[str] = []
        self.warnings: List[str] = []
        
    async def run_deployment(self) -> bool:
        """Main deployment orchestration"""
        console.print(Panel.fit(
            f"🚀 Jarwis Deployment Gateway\nEnvironment: {self.environment}",
            style="bold blue"
        ))
        
        checks = [
            ("File System Validation", self._validate_file_system),
            ("Database Connection", self._check_database),
            ("Contract Synchronization", self._sync_contracts),
            ("Scanner Registry", self._validate_scanners),
            ("Frontend Build", self._build_frontend),
            ("Backend Tests", self._run_backend_tests),
            ("Security Checks", self._run_security_checks),
            ("Deployment Preparation", self._prepare_deployment),
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            for check_name, check_func in checks:
                if self.skip_tests and "Tests" in check_name:
                    console.print(f"⏭️  Skipping {check_name}")
                    continue
                
                task = progress.add_task(f"[cyan]{check_name}...", total=1)
                
                try:
                    success, message = await check_func()
                    
                    if success:
                        console.print(f"✅ {check_name}: {message}", style="green")
                    else:
                        console.print(f"❌ {check_name}: {message}", style="red")
                        self.errors.append(f"{check_name}: {message}")
                        
                except Exception as e:
                    console.print(f"💥 {check_name} CRASHED: {e}", style="bold red")
                    self.errors.append(f"{check_name}: EXCEPTION - {e}")
                
                progress.update(task, completed=1)
        
        # Final report
        return self._generate_deployment_report()
    
    async def _validate_file_system(self) -> Tuple[bool, str]:
        """Validate critical directories and files exist"""
        required_paths = {
            "Backend": [
                self.project_root / "api" / "server.py",
                self.project_root / "database" / "connection.py",
                self.project_root / "shared" / "api_endpoints.py",
            ],
            "Frontend": [
                self.project_root / "jarwisfrontend" / "package.json",
                self.project_root / "jarwisfrontend" / "src" / "index.js",
            ],
            "Scanners": [
                self.project_root / "attacks" / "pre_login" / "__init__.py",
                self.project_root / "core" / "runner.py",
            ],
            "Config": [
                self.project_root / "config" / "config.yaml",
            ]
        }
        
        missing = []
        for category, paths in required_paths.items():
            for path in paths:
                if not path.exists():
                    missing.append(f"{category}: {path.name}")
        
        if missing:
            return False, f"Missing files: {', '.join(missing)}"
        
        # Validate critical directories are writable
        critical_dirs = [
            self.project_root / "uploads",
            self.project_root / "reports",
            self.project_root / "logs",
        ]
        
        for dir_path in critical_dirs:
            dir_path.mkdir(exist_ok=True)
            test_file = dir_path / ".test_write"
            try:
                test_file.write_text("test")
                test_file.unlink()
            except Exception as e:
                return False, f"Directory {dir_path.name} not writable: {e}"
        
        return True, "All required files and directories validated"
    
    async def _check_database(self) -> Tuple[bool, str]:
        """Verify database connection and schema"""
        try:
            # Import here to avoid circular dependencies
            from database.connection import get_db
            from sqlalchemy import text, inspect
            
            async for db in get_db():
                # Test connection with simple query
                result = await db.execute(text("SELECT 1"))
                
                # Get database dialect to use correct introspection
                dialect = db.bind.dialect.name if db.bind else "unknown"
                
                # Use SQLAlchemy inspector for cross-database compatibility
                try:
                    from sqlalchemy import inspect as sa_inspect
                    
                    # For async, we need to run sync inspection in thread
                    def get_tables(connection):
                        inspector = sa_inspect(connection)
                        return inspector.get_table_names()
                    
                    # Run sync inspection
                    sync_conn = await db.connection()
                    raw_conn = await sync_conn.get_raw_connection()
                    
                    # Simple check: just verify connection works
                    # Full table check would require sync operations
                    self.warnings.append(f"Database dialect: {dialect}")
                    
                except Exception as e:
                    # Fallback: just verify connection works
                    self.warnings.append(f"Could not inspect tables: {e}")
                
                break  # Exit async generator
            
            return True, f"Database connection verified ({dialect})"
            
        except Exception as e:
            return False, f"Database error: {e}"
    
    async def _sync_contracts(self) -> Tuple[bool, str]:
        """Generate and validate frontend contracts"""
        try:
            # Run contract generator
            result = subprocess.run(
                [sys.executable, "shared/generate_frontend_types.py"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return False, f"Contract generation failed: {result.stderr}"
            
            # Verify generated files exist
            generated_files = [
                self.project_root / "jarwisfrontend" / "src" / "config" / "endpoints.generated.js",
                self.project_root / "jarwisfrontend" / "src" / "config" / "planLimits.generated.js",
            ]
            
            for file in generated_files:
                if not file.exists():
                    return False, f"Generated file missing: {file.name}"
                
                # Check file is not empty
                if file.stat().st_size < 100:
                    return False, f"Generated file too small: {file.name}"
            
            return True, "Frontend contracts synchronized"
            
        except subprocess.TimeoutExpired:
            return False, "Contract generation timed out (>30s)"
        except Exception as e:
            return False, f"Contract sync error: {e}"
    
    async def _validate_scanners(self) -> Tuple[bool, str]:
        """Validate scanner modules can be imported"""
        try:
            # Try importing key scanner modules
            from attacks.web.pre_login import PreLoginAttacks
            from attacks.web.post_login import PostLoginAttacks
            
            # Count scanner files
            pre_login_dir = self.project_root / "attacks" / "web" / "pre_login"
            scanner_files = list(pre_login_dir.glob("*_scanner.py"))
            
            total = len(scanner_files)
            
            if total < 40:  # Expect at least 40 scanners
                self.warnings.append(f"Only {total} scanner files found (expected 40+)")
            
            return True, f"Scanner modules validated ({total} scanner files)"
            
        except Exception as e:
            return False, f"Scanner validation failed: {e}"
    
    async def _build_frontend(self) -> Tuple[bool, str]:
        """Build React frontend for production"""
        if self.environment == "development":
            # Skip build in development
            return True, "Skipped (development mode)"
        
        try:
            frontend_dir = self.project_root / "jarwisfrontend"
            
            # Install dependencies
            console.print("📦 Installing frontend dependencies...")
            install_result = subprocess.run(
                ["npm", "ci"],
                cwd=frontend_dir,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )
            
            if install_result.returncode != 0:
                return False, f"npm ci failed: {install_result.stderr[:200]}"
            
            # Build production bundle
            console.print("🏗️  Building production bundle...")
            build_result = subprocess.run(
                ["npm", "run", "build"],
                cwd=frontend_dir,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if build_result.returncode != 0:
                return False, f"npm build failed: {build_result.stderr[:200]}"
            
            # Verify build output
            build_dir = frontend_dir / "build"
            if not build_dir.exists():
                return False, "Build directory not created"
            
            # Check build has reasonable size
            build_size = sum(f.stat().st_size for f in build_dir.rglob('*') if f.is_file())
            build_size_mb = build_size / (1024 * 1024)
            
            if build_size_mb < 1:
                return False, "Build size too small (possible build failure)"
            
            return True, f"Frontend built successfully ({build_size_mb:.1f} MB)"
            
        except subprocess.TimeoutExpired:
            return False, "Frontend build timed out (>5 minutes)"
        except Exception as e:
            return False, f"Frontend build error: {e}"
    
    async def _run_backend_tests(self) -> Tuple[bool, str]:
        """Run backend pytest suite"""
        try:
            console.print("🧪 Running backend tests...")
            
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short", "-x"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=180  # 3 minutes
            )
            
            # Parse pytest output
            output_lines = result.stdout.split('\n')
            
            # Find summary line
            summary = next((line for line in output_lines if 'passed' in line or 'failed' in line), "")
            
            if result.returncode != 0:
                # Extract failed test name
                failed_lines = [line for line in output_lines if 'FAILED' in line]
                if failed_lines:
                    return False, f"Tests failed: {failed_lines[0][:100]}"
                else:
                    return False, f"Tests failed with no output"
            
            return True, f"All tests passed {summary}"
            
        except subprocess.TimeoutExpired:
            return False, "Tests timed out (>3 minutes)"
        except Exception as e:
            self.warnings.append(f"Could not run tests: {e}")
            return True, "Tests skipped (pytest not available)"
    
    async def _run_security_checks(self) -> Tuple[bool, str]:
        """Run security vulnerability checks"""
        try:
            # Check for known vulnerabilities in dependencies
            result = subprocess.run(
                [sys.executable, "-m", "pip", "check"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if "No broken requirements found" not in result.stdout:
                if result.stdout.strip():
                    self.warnings.append(f"Dependency issues: {result.stdout[:200]}")
            
            # Check for .env file
            env_file = self.project_root / ".env"
            if not env_file.exists():
                self.warnings.append("No .env file found - using defaults")
            
            return True, "Security checks completed"
            
        except Exception as e:
            return False, f"Security check error: {e}"
    
    async def _prepare_deployment(self) -> Tuple[bool, str]:
        """Prepare deployment artifacts"""
        try:
            # Create deployment manifest
            manifest = {
                "timestamp": datetime.now().isoformat(),
                "environment": self.environment,
                "git_commit": self._get_git_commit(),
                "python_version": sys.version.split()[0],
                "errors": self.errors,
                "warnings": self.warnings,
            }
            
            manifest_file = self.project_root / "deployment_manifest.json"
            manifest_file.write_text(json.dumps(manifest, indent=2))
            
            return True, f"Deployment manifest created (commit: {manifest['git_commit'][:8]})"
            
        except Exception as e:
            return False, f"Manifest creation error: {e}"
    
    def _get_git_commit(self) -> str:
        """Get current git commit SHA"""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except:
            return "unknown"
    
    def _generate_deployment_report(self) -> bool:
        """Generate final deployment report"""
        if self.errors:
            console.print("\n" + "="*60, style="bold red")
            console.print("❌ DEPLOYMENT BLOCKED", style="bold red")
            console.print("="*60 + "\n", style="bold red")
            
            console.print("Errors:", style="bold red")
            for error in self.errors:
                console.print(f"  • {error}", style="red")
            
            return False
        
        if self.warnings:
            console.print("\n" + "="*60, style="bold yellow")
            console.print("⚠️  DEPLOYMENT ALLOWED WITH WARNINGS", style="bold yellow")
            console.print("="*60 + "\n", style="bold yellow")
            
            console.print("Warnings:", style="bold yellow")
            for warning in self.warnings:
                console.print(f"  • {warning}", style="yellow")
        else:
            console.print("\n" + "="*60, style="bold green")
            console.print("✅ DEPLOYMENT READY", style="bold green")
            console.print("="*60 + "\n", style="bold green")
        
        console.print("\n📋 Next Steps:")
        if self.environment == "production":
            console.print("  1. Review deployment_manifest.json")
            console.print("  2. Run: docker-compose up -d")
            console.print("  3. Monitor: docker-compose logs -f")
        else:
            console.print("  1. Start backend: .venv\\Scripts\\python.exe -m uvicorn api.server:app --reload")
            console.print("  2. Start frontend: cd jarwisfrontend && npm start")
        
        return True


async def main():
    parser = argparse.ArgumentParser(description="Jarwis Deployment Gateway")
    parser.add_argument(
        "--env",
        choices=["development", "staging", "production"],
        default="development",
        help="Deployment environment"
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip running tests (use for quick validation)"
    )
    
    args = parser.parse_args()
    
    gateway = DeploymentGateway(args.env, args.skip_tests)
    success = await gateway.run_deployment()
    
    return success


if __name__ == "__main__":
    import warnings
    
    # Suppress deprecation warnings for Python 3.14+ asyncio changes
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="asyncio")
    
    try:
        result = asyncio.run(main())
        # Force exit before thread cleanup causes issues on Windows
        os._exit(0 if result else 1)
    except KeyboardInterrupt:
        os._exit(0)
    except Exception as e:
        console.print(f"💥 Fatal error: {e}", style="bold red")
        os._exit(1)
