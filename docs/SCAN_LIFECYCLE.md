# Scan Lifecycle Management - Implementation Guide

## Overview
Jarwis now enforces robust lifecycle management for both web and mobile scans to handle:
- Process cleanup on user stop
- Orphaned process recovery on server restart
- Graceful shutdown on server termination
- Stale scan detection with auto-stall marking

## Process Registry Pattern

### Web Scans
- Registry: `BrowserController._instances` (core/browser.py)
- Tracks Playwright browser instances by `scan_id`
- Enables force-kill on stop or crash

### Mobile Scans
- Registry: `MobileProcessRegistry` (core/mobile_process_registry.py)
- Tracks emulator PID, Frida process, MITM proxy, orchestrator by `scan_id`
- Enables comprehensive cleanup of all mobile resources

## Lifecycle Flows

### Web Stop Flow
1. `/api/scans/{scan_id}/stop`
2. Force-kill browser via `BrowserController.force_close_by_scan_id()`
3. Stop orchestrator if running
4. Update DB status, broadcast WebSocket

### Mobile Stop Flow
1. `/api/mobile/{scan_id}/stop`
2. `MobileProcessRegistry.signal_stop(scan_id)` (cooperative)
3. `MobileProcessRegistry.force_cleanup_by_scan_id(scan_id)` (emulator, Frida, MITM)
4. Update DB status, refund credit

### Cleanup Implementations
- Web: `BrowserController.close()` unregisters from registry
- Mobile: `MobilePenTestOrchestrator._cleanup()` stops emulator, Frida server, MITM proxy, crawler, simulator

### Startup Recovery
- `recover_running_scans()` (api/server.py)
- Marks orphaned "running" scans as `stalled` when checkpoint is stale or missing
- Rehydrates `scan_progress` when recent

### Graceful Shutdown
- `graceful_shutdown()` (api/server.py)
  1) Stops active web scans
  2) Cleans all mobile scans via `MobileProcessRegistry.cleanup_all()`
  3) Kills orphaned browsers via `BrowserController.cleanup_orphaned_browsers_async(force=True)`

### Stale Detection
- Background task every 5 minutes
- Marks scans with no DB updates beyond threshold as `stalled`

## State Machine Updates

```python
class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_FOR_MANUAL_AUTH = "waiting_for_manual_auth"
    WAITING_FOR_OTP = "waiting_for_otp"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPED = "stopped"
    CANCELLED = "cancelled"
    STALLED = "stalled"  # Orphaned scan from crash/restart
```

Transitions:
- RUNNING → STALLED (detected by startup recovery or stale detector)
- STALLED → QUEUED (retry)
- STALLED → ERROR (unrecoverable)

## Key Files (Jan 11, 2026)
- core/browser.py — Browser registry for web scans
- core/mobile_process_registry.py — Mobile process registry
- attacks/mobile/orchestration/mobile_orchestrator.py — Full cleanup of mobile resources
- attacks/mobile/platform/android/emulator_manager.py — PID tracking and PID kill fallback
- services/mobile_service.py — stop_mobile_scan terminates processes via registry
- api/server.py — Startup recovery, graceful shutdown, stale detection
- services/scan_state_machine.py — STALLED status added
- api/routes/scans.py — scan_progress covers web + mobile live status

## Best Practices for New Scan Types
1. Create a process registry with `register`, `update`, `cleanup_by_scan_id`, `cleanup_all`.
2. Track all resources (PIDs, sockets, temp files, external services).
3. Implement cooperative stop plus force-kill fallback.
4. Hook into startup recovery and graceful shutdown.
5. Add stale detection and STALLED state transitions.

## Troubleshooting
- Orphaned Chrome: `Get-Process chrome | Where-Object { $_.CommandLine -like "*--disable-blink-features*" }`
- Orphaned emulator: `Get-Process emulator`
- Live scans: `curl http://localhost:8000/api/scans/live`
- DB mismatch: `SELECT scan_id, status FROM scan_history WHERE status='running';`
- Recovery issues: verify `recover_running_scans()` in lifespan and checkpoints in `data/temp/checkpoints/`
