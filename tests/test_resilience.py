#!/usr/bin/env python
"""
Test Resilience Implementation

Tests the self-healing scan architecture:
1. Preflight validation
2. Scanner validation
3. Checkpoint system
4. Circuit breaker
5. Recovery manager
"""

import asyncio
import sys
import logging
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Setup logging
logging.basicConfig(level=logging.INFO)
console = Console()

def test_preflight_validator():
    """Test the PreflightValidator system"""
    console.print("\n[bold blue]═══ Testing PreflightValidator ═══[/bold blue]")
    
    try:
        from core.preflight_validator import PreflightValidator
        
        async def run_validation():
            validator = PreflightValidator()
            return await validator.validate_all()
        
        result = asyncio.run(run_validation())
        
        table = Table(title="Preflight Validation Results")
        table.add_column("Check", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Details", style="yellow")
        
        for issue in result.issues:
            status = "⚠️ Warning" if issue.severity == "warning" else "❌ Error"
            table.add_row(issue.check_name, status, issue.message)
        
        if result.passed:
            console.print("[green]✅ All preflight checks passed![/green]")
        else:
            console.print(table)
            console.print(f"[red]❌ {len([i for i in result.issues if i.severity == 'error'])} errors found[/red]")
        
        return result.passed
        
    except ImportError as e:
        console.print(f"[red]Failed to import PreflightValidator: {e}[/red]")
        return False


def test_scanner_validation():
    """Test scanner signature validation"""
    console.print("\n[bold blue]═══ Testing Scanner Validation ═══[/bold blue]")
    
    try:
        from attacks.scanner_registry import get_registry, discover_all_scanners
        
        # Discover all scanners with validation
        total = discover_all_scanners(validate=True)
        
        registry = get_registry()
        valid = registry.get_valid_scanners()
        invalid = registry.get_invalid_scanners()
        
        console.print(f"[cyan]Total scanners discovered: {total}[/cyan]")
        console.print(f"[green]✅ Valid scanners: {len(valid)}[/green]")
        
        if invalid:
            console.print(f"[red]❌ Invalid scanners: {len(invalid)}[/red]")
            for scanner in invalid:
                console.print(f"  - {scanner.name}")
                for issue in scanner.validation_issues:
                    console.print(f"    ❌ {issue.message}")
        
        return len(invalid) == 0
        
    except Exception as e:
        console.print(f"[red]Failed to validate scanners: {e}[/red]")
        import traceback
        traceback.print_exc()
        return False


def test_checkpoint_system():
    """Test the ScanCheckpoint system"""
    console.print("\n[bold blue]═══ Testing Checkpoint System ═══[/bold blue]")
    
    try:
        from core.scan_checkpoint import ScanCheckpoint, ScanPhase
        import tempfile
        import shutil
        
        # Use temp directory
        test_dir = Path(tempfile.mkdtemp())
        
        try:
            # Create checkpoint
            checkpoint = ScanCheckpoint(
                scan_id="test-checkpoint-001",
                base_dir=str(test_dir)
            )
            
            # Test initialization with required config
            test_config = {"target": {"url": "https://example.com"}}
            checkpoint.initialize(target_url="https://example.com", config=test_config)
            console.print("[green]✅ Checkpoint initialized[/green]")
            
            # Test phase tracking
            checkpoint.start_phase(ScanPhase.CRAWL)
            checkpoint.add_endpoints(["/api/users", "/api/login", "/api/data"])
            checkpoint.complete_phase(ScanPhase.CRAWL, status="success")
            console.print("[green]✅ Phase tracking works[/green]")
            
            # Test finding storage
            test_finding = {
                "id": "VULN-001",
                "title": "Test Vulnerability",
                "severity": "high"
            }
            checkpoint.add_findings([test_finding])
            console.print("[green]✅ Finding storage works[/green]")
            
            # Test resume
            resume_point = checkpoint.get_resume_point()
            console.print(f"[cyan]Resume point: {resume_point}[/cyan]")
            
            # Test summary
            summary = checkpoint.get_summary()
            console.print(f"[cyan]Summary: {summary}[/cyan]")
            
            return True
            
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)
        
    except Exception as e:
        console.print(f"[red]Failed to test checkpoint: {e}[/red]")
        import traceback
        traceback.print_exc()
        return False


def test_circuit_breaker():
    """Test the circuit breaker in UnifiedExecutor"""
    console.print("\n[bold blue]═══ Testing Circuit Breaker ═══[/bold blue]")
    
    try:
        from core.unified_executor import UnifiedExecutor
        
        # Check if circuit breaker methods exist
        assert hasattr(UnifiedExecutor, 'reset_circuit_breaker'), "Missing reset_circuit_breaker"
        assert hasattr(UnifiedExecutor, 'get_circuit_breaker_status'), "Missing get_circuit_breaker_status"
        assert hasattr(UnifiedExecutor, 'get_problematic_scanners'), "Missing get_problematic_scanners"
        
        console.print("[green]✅ Circuit breaker methods exist[/green]")
        
        # Get current status
        status = UnifiedExecutor.get_circuit_breaker_status()
        console.print(f"[cyan]Active circuit breakers: {len(status)}[/cyan]")
        
        # Check problematic scanners
        problematic = UnifiedExecutor.get_problematic_scanners()
        if problematic:
            console.print(f"[yellow]⚠️ Problematic scanners: {problematic}[/yellow]")
        else:
            console.print("[green]✅ No problematic scanners[/green]")
        
        return True
        
    except Exception as e:
        console.print(f"[red]Failed to test circuit breaker: {e}[/red]")
        import traceback
        traceback.print_exc()
        return False


def test_recovery_manager():
    """Test the ScanRecoveryManager"""
    console.print("\n[bold blue]═══ Testing Recovery Manager ═══[/bold blue]")
    
    try:
        from core.scan_recovery import ScanRecoveryManager, GlobalRecoveryMonitor
        
        # Create recovery manager
        manager = ScanRecoveryManager(scan_id="test-recovery-001")
        
        # Check methods
        assert hasattr(manager, 'start_monitoring'), "Missing start_monitoring"
        assert hasattr(manager, 'heartbeat'), "Missing heartbeat"
        assert hasattr(manager, 'stop_monitoring'), "Missing stop_monitoring"
        assert hasattr(manager, 'diagnose_failure'), "Missing diagnose_failure"
        
        console.print("[green]✅ Recovery manager methods exist[/green]")
        
        # Test global monitor
        global_monitor = GlobalRecoveryMonitor()
        
        # Check global monitor methods
        assert hasattr(global_monitor, 'register_scan'), "Missing register_scan"
        assert hasattr(global_monitor, 'get_all_health_status'), "Missing get_all_health_status"
        assert hasattr(global_monitor, 'get_unhealthy_scans'), "Missing get_unhealthy_scans"
        
        # Get all health status (works like get_global_stats)
        health_status = global_monitor.get_all_health_status()
        console.print(f"[cyan]Active scans monitored: {len(health_status)}[/cyan]")
        
        # Test unhealthy scans
        unhealthy = global_monitor.get_unhealthy_scans()
        console.print(f"[cyan]Unhealthy scans: {len(unhealthy)}[/cyan]")
        
        return True
        
    except Exception as e:
        console.print(f"[red]Failed to test recovery manager: {e}[/red]")
        import traceback
        traceback.print_exc()
        return False


async def test_web_scan_runner_integration():
    """Test WebScanRunner has resilience integration"""
    console.print("\n[bold blue]═══ Testing WebScanRunner Integration ═══[/bold blue]")
    
    try:
        from core.web_scan_runner import WebScanRunner
        import inspect
        
        # Check for resilience imports
        source = inspect.getsource(WebScanRunner)
        
        checks = [
            ("checkpoint", "ScanCheckpoint" in source),
            ("preflight", "PreflightValidator" in source or "preflight" in source.lower()),
            ("recovery", "ScanRecoveryManager" in source or "recovery_manager" in source),
            ("heartbeat", "_send_heartbeat" in source),
            ("partial_save", "_save_partial_findings" in source),
        ]
        
        table = Table(title="WebScanRunner Resilience Features")
        table.add_column("Feature", style="cyan")
        table.add_column("Integrated", style="green")
        
        all_passed = True
        for feature, present in checks:
            status = "✅ Yes" if present else "❌ No"
            table.add_row(feature, status)
            if not present:
                all_passed = False
        
        console.print(table)
        
        return all_passed
        
    except Exception as e:
        console.print(f"[red]Failed to test WebScanRunner: {e}[/red]")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all resilience tests"""
    console.print(Panel.fit(
        "[bold cyan]Jarwis Resilience Architecture Test Suite[/bold cyan]\n"
        "Testing self-healing scan capabilities",
        border_style="blue"
    ))
    
    results = {}
    
    # Run tests
    results["Preflight Validator"] = test_preflight_validator()
    results["Scanner Validation"] = test_scanner_validation()
    results["Checkpoint System"] = test_checkpoint_system()
    results["Circuit Breaker"] = test_circuit_breaker()
    results["Recovery Manager"] = test_recovery_manager()
    results["WebScanRunner Integration"] = asyncio.run(test_web_scan_runner_integration())
    
    # Summary
    console.print("\n" + "=" * 60)
    console.print("[bold]Test Summary[/bold]")
    console.print("=" * 60)
    
    table = Table()
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    
    passed = 0
    for component, result in results.items():
        status = "[green]✅ PASSED[/green]" if result else "[red]❌ FAILED[/red]"
        table.add_row(component, status)
        if result:
            passed += 1
    
    console.print(table)
    
    total = len(results)
    console.print(f"\n[bold]Results: {passed}/{total} tests passed[/bold]")
    
    if passed == total:
        console.print("[bold green]🎉 All resilience components working![/bold green]")
        return 0
    else:
        console.print(f"[bold yellow]⚠️ {total - passed} components need attention[/bold yellow]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
