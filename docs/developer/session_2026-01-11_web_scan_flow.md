# Session: January 11, 2026 - Web Scan Data Flow Complete Fix

## Summary
Traced and fixed the complete web scan data flow from frontend button click to scanner execution. Identified and resolved 15+ gaps where data was being lost between steps.

## Changes Made

### Step 1: Frontend (ScanWizard.jsx)
**Files Modified:** `jarwisfrontend/src/components/scan/ScanWizard.jsx`

| Fix | Description |
|-----|-------------|
| URL normalization | Auto-prefix `https://` with visual hint "Will scan as: https://..." |
| Scope input field | Added textarea in WebTargetStep for regex scope patterns |
| Auth method selector | 4 methods: Username/Password, Phone OTP, Social Login, Manual Session |
| 2FA configuration | Toggle + radio buttons for email/sms/authenticator |
| Phone OTP fields | phone_number input when auth_method = phone_otp |
| Social login fields | Checkboxes for Google, Facebook, LinkedIn, Apple |
| Manual session fields | session_cookie and session_token textareas |
| handleStartScan() | Updated to pass all new fields to api.js |

### Step 2: API Layer (api.js)
**Files Modified:** `jarwisfrontend/src/services/api.js`

| Fix | Description |
|-----|-------------|
| `scan_name` | Now passed to backend |
| `rate_limit` | Now passed to backend |
| `auth_method` | Auto-detected from credentials OR uses explicit selection |
| `scope` | Now passed in `config.scope` |
| `phone_number` | Now passed for phone OTP auth |
| `session_cookie` | Now passed for manual session |
| `session_token` | Now passed for manual session |
| `social_providers` | Now passed as array for social login |
| `two_factor` | Now passed as config object |

### Step 3: Backend (scans.py, schemas.py)
**Files Modified:** 
- `database/schemas.py`
- `api/routes/scans.py`

| Fix | Description |
|-----|-------------|
| ScanCreate.scan_name | Added optional scan_name field |
| ScanResponse.scan_name | Added scan_name to response |
| ScanResponse.can_resume | Added for checkpoint recovery status |
| scope in runner_config | Now reads from `scan.config.scope` |
| scan_profile in runner_config | Now affects crawl settings (full: 100/4, quick: 25/2) |

### Step 4: Runner Config (scans.py)
**Files Modified:** `api/routes/scans.py`

| Fix | Description |
|-----|-------------|
| `proxy.enabled` | Now configurable from scan.config |
| `timeout` | Now reads from scan.config |
| `report.formats` | Now reads from scan.config.report_formats |
| `_build_attacks_config()` | Now accepts scan_profile for attack selection |
| Crawl limits | Profile-based: full=100/4, quick=25/2, api=50/3, authenticated=150/5 |

## Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│ ScanWizard.jsx                                                   │
│ └─ target_url, scope, auth_method, phone_number, session_cookie  │
│    session_token, social_providers, two_factor, scan_profile     │
└────────────────────────────┬─────────────────────────────────────┘
                             │ handleStartScan()
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│ api.js scanAPI.startScan()                                       │
│ └─ Transform + POST /api/scans/                                  │
└────────────────────────────┬─────────────────────────────────────┘
                             │ HTTP POST
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│ scans.py POST /api/scans/                                        │
│ └─ Validate ScanCreate → crud.create_scan() → BackgroundTask     │
└────────────────────────────┬─────────────────────────────────────┘
                             │ Background execution
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│ _build_runner_config()                                           │
│ └─ scope, rate_limit, timeout, proxy, report_formats, attacks    │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│ WebScanRunner.run()                                              │
│ └─ 6-phase execution with all config applied                     │
└──────────────────────────────────────────────────────────────────┘
```

## Testing Notes

To verify the complete flow:
1. Start frontend: `cd jarwisfrontend && npm start`
2. Start backend: `uvicorn api.server:app --port 8000`
3. Open browser console, start a web scan
4. Check console logs for `scanAPI.startScan request:` - verify all fields present
5. Check backend logs for received config

## Documentation Updated

- `.github/copilot-instructions.md` - System status updated to January 11, 2026
- `docs/implementation_rules/02_SCAN_FLOW.md` - Added 4-step data pipeline
- `docs/architecture/architecture_flow.md` - Added complete data pipeline diagram
- `docs/CORE_ARCHITECTURE.md` - Updated with auth methods, 2FA, scan profiles
