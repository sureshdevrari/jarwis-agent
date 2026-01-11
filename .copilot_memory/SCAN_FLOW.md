# Jarwis Scan Flow - Master Reference

> **CRITICAL**: This document defines the correct scanning flow. Read this FIRST in any session.
> Last Updated: January 8, 2026

---

## 🎯 Core Principle

**ALL attacks run on BOTH pre-login AND post-login requests.**

Pre-login and post-login are NOT different attack types - they are different **authentication contexts**.
The SAME 48+ attack modules run against BOTH sets of captured requests.

### Why Both Matter:
- **Pre-login vulnerabilities** = Public-facing risks (anyone can exploit)
- **Post-login vulnerabilities** = User-impacting risks (affects logged-in users, often MORE DANGEROUS)

---

## 🌐 Web Application Scanning Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: PRE-LOGIN CRAWL                                                    │
│                                                                             │
│  • Start MITM proxy                                                         │
│  • Crawl ALL accessible pages (unauthenticated)                             │
│  • Capture EVERY request/response via MITM proxy                            │
│  • Save to: temp/scans/{scan_id}/pre_login_requests.json                    │
│                                                                             │
│  Captured data includes:                                                    │
│  - Full request headers                                                     │
│  - Request body (GET/POST parameters)                                       │
│  - Full response headers                                                    │
│  - Response body                                                            │
│  - Cookies set/sent                                                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 2: LOGIN (if credentials provided)                                   │
│                                                                             │
│  • Navigate to login page                                                   │
│  • Fill form using selectors                                                │
│  • Submit and capture authentication response                               │
│  • Extract tokens: JWT, session cookies, API keys, etc.                     │
│  • Store tokens in RequestStore.auth_tokens                                 │
│                                                                             │
│  Token types to detect:                                                     │
│  - JWT (Bearer tokens with 3 dot-separated parts)                           │
│  - Session cookies (PHPSESSID, JSESSIONID, etc.)                            │
│  - API keys (X-API-Key header)                                              │
│  - Basic auth                                                               │
│  - OAuth tokens                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 3: POST-LOGIN CRAWL                                                   │
│                                                                             │
│  • Crawl ALL authenticated pages (more pages unlocked after login)          │
│  • Find and interact with forms using selectors                             │
│  • Submit forms with random/test data to trigger POST requests              │
│  • Capture ALL request/response headers via MITM                            │
│  • Save to: temp/scans/{scan_id}/post_login_requests.json                   │
│                                                                             │
│  KEY DIFFERENCE: Post-login requests contain auth tokens!                   │
│  This is what we'll manipulate in attacks.                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 4: ANALYZE CAPTURED DATA                                              │
│                                                                             │
│  Before attacking, analyze:                                                 │
│  • What token type is used? (JWT, session, etc.)                            │
│  • Token location (header, cookie, body)                                    │
│  • Token format and structure                                               │
│  • Which endpoints require auth vs public                                   │
│  • Which requests have parameters (attack targets)                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 5: RUN ALL ATTACKS ON PRE-LOGIN REQUESTS                              │
│                                                                             │
│  For EACH captured pre-login request:                                       │
│  • Modify request with attack payloads                                      │
│  • Send modified request via MITM proxy                                     │
│  • Capture and analyze response                                             │
│  • Detect vulnerabilities based on response behavior                        │
│                                                                             │
│  Run ALL 48+ attack modules:                                                │
│  SQLi, XSS, SSRF, XXE, CSRF, Path Traversal, Command Injection,             │
│  IDOR, JWT attacks, Session attacks, etc.                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 6: RUN ALL ATTACKS ON POST-LOGIN REQUESTS                             │
│                                                                             │
│  Run the SAME 48+ attacks on post-login requests.                           │
│  PLUS additional auth-specific tests:                                       │
│                                                                             │
│  • Remove token entirely - does request still work? (Broken Auth)           │
│  • Use expired token - proper rejection?                                    │
│  • Use invalid token - proper rejection?                                    │
│  • Use another user's token - access other's data? (IDOR)                   │
│  • Modify JWT claims - privilege escalation?                                │
│  • Replay old tokens - token reuse vulnerability?                           │
│                                                                             │
│  IMPORTANT: Same attacks may find DIFFERENT vulnerabilities in              │
│  authenticated context vs unauthenticated context!                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 7: TOKEN REFRESH DURING TESTING                                       │
│                                                                             │
│  Tokens may expire during long scans!                                       │
│  • Monitor for 401/403 responses                                            │
│  • If token expired, re-login and get fresh token                           │
│  • Update RequestStore.auth_tokens                                          │
│  • Continue testing with new token                                          │
│                                                                             │
│  This is CRITICAL for long-running scans.                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 8: AUTHORIZATION-SPECIFIC ATTACKS (Post-Login Only)                   │
│                                                                             │
│  Special attacks for authenticated endpoints:                               │
│                                                                             │
│  • IDOR: Change user_id in request, see other user's data                   │
│  • Privilege Escalation: Access admin endpoints as regular user             │
│  • Mass Assignment: Add admin=true to request body                          │
│  • Horizontal AuthZ: Access peer user's resources                           │
│  • Vertical AuthZ: Access higher-privilege resources                        │
│  • Token removal: Does endpoint work without token?                         │
│  • Token manipulation: Modify claims, signature, etc.                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 9: GENERATE REPORT                                                    │
│                                                                             │
│  Combine all findings:                                                      │
│  • Pre-login vulnerabilities (marked as "Unauthenticated")                  │
│  • Post-login vulnerabilities (marked as "Authenticated")                   │
│  • Auth-specific vulnerabilities                                            │
│                                                                             │
│  Generate: HTML, JSON, SARIF, PDF                                           │
│  Cleanup: Delete temp/scans/{scan_id}/ folder                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📱 Mobile Application Scanning Flow

Same concept - capture requests via MITM, run ALL attacks.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: STATIC ANALYSIS                                                    │
│                                                                             │
│  • Decompile APK/IPA                                                        │
│  • Extract: API endpoints, hardcoded secrets, permissions                   │
│  • Identify authentication mechanism                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 2: SETUP INTERCEPTION                                                 │
│                                                                             │
│  • Start MITM proxy                                                         │
│  • Install CA certificate on device/emulator                                │
│  • Use Frida to bypass SSL pinning                                          │
│  • Configure device to route through proxy                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 3: CAPTURE PRE-LOGIN TRAFFIC                                          │
│                                                                             │
│  • Launch app without logging in                                            │
│  • Navigate through all accessible screens                                  │
│  • Capture all API requests/responses via MITM                              │
│  • Save to RequestStore.pre_login_requests                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 4: LOGIN & CAPTURE POST-LOGIN TRAFFIC                                 │
│                                                                             │
│  • Login with provided credentials                                          │
│  • Capture authentication tokens                                            │
│  • Navigate through ALL authenticated screens                               │
│  • Trigger all possible actions (forms, buttons, etc.)                      │
│  • Capture all API requests/responses via MITM                              │
│  • Save to RequestStore.post_login_requests                                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 5: RUN ALL ATTACKS                                                    │
│                                                                             │
│  Same as web scanning:                                                      │
│  • Run ALL 48+ attacks on pre-login requests                                │
│  • Run ALL 48+ attacks on post-login requests                               │
│  • Run auth-specific attacks (token manipulation)                           │
│  • Monitor for token expiry, refresh if needed                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  STEP 6: MOBILE-SPECIFIC ATTACKS                                            │
│                                                                             │
│  Additional checks for mobile:                                              │
│  • Insecure local storage (SharedPreferences, Keychain)                     │
│  • Hardcoded credentials in binary                                          │
│  • Weak certificate pinning                                                 │
│  • Deep link vulnerabilities                                                │
│  • WebView JavaScript interface exploitation                                │
│  • Intent sniffing/spoofing                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Attack Execution Pattern

**How each attack module works:**

```python
# Pseudocode for attack execution
class AttackModule:
    def run(self, captured_requests: List[CapturedRequest]) -> List[Finding]:
        findings = []
        
        for request in captured_requests:
            # Get the original captured request
            original_request = request
            
            # For each attack payload
            for payload in self.payloads:
                # Modify the request with payload
                modified_request = self.inject_payload(original_request, payload)
                
                # Send via MITM proxy (this is how we intercept response)
                response = mitm_proxy.send(modified_request)
                
                # Analyze response for vulnerability indicators
                if self.is_vulnerable(response, payload):
                    findings.append(Finding(
                        request=modified_request,
                        response=response,
                        payload=payload,
                        vulnerability_type=self.type
                    ))
        
        return findings
```

---

## 📂 Key Files

| File | Purpose |
|------|---------|
| `core/request_store.py` | Stores captured requests/responses |
| `core/web_scan_runner.py` | New runner using MITM + RequestStore |
| `core/attack_engine.py` | Runs attacks on captured requests |
| `core/mitm_proxy.py` | MITM proxy for interception |
| `core/runner.py` | OLD runner (being replaced) |

---

## ⚠️ Common Mistakes to Avoid

1. **DON'T think pre-login and post-login need different attacks**
   - ALL attacks run on BOTH
   - The difference is only the authentication context

2. **DON'T scan endpoints directly**
   - Capture requests via MITM first
   - Then replay/modify captured requests with payloads

3. **DON'T forget token expiry**
   - Long scans may exceed token lifetime
   - Must re-authenticate and continue

4. **DON'T ignore response headers**
   - Response headers reveal security configs
   - CORS, CSP, Set-Cookie flags, etc.

5. **DON'T skip POST method testing**
   - Use selectors to fill forms with test data
   - Capture the resulting POST requests
   - These are often the most vulnerable endpoints

---

## 🔄 Request/Response Flow

```
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│   Browser/   │ ────▶ │  MITM Proxy  │ ────▶ │   Target     │
│   Scanner    │       │  (capture)   │       │   Server     │
│              │ ◀──── │              │ ◀──── │              │
└──────────────┘       └──────────────┘       └──────────────┘
                              │
                              ▼
                       ┌──────────────┐
                       │ RequestStore │
                       │              │
                       │ pre_login:   │
                       │   requests[] │
                       │   responses[]│
                       │              │
                       │ post_login:  │
                       │   requests[] │
                       │   responses[]│
                       │   auth_tokens│
                       └──────────────┘
                              │
                              ▼
                       ┌──────────────┐
                       │ Attack Engine│
                       │              │
                       │ For each req │
                       │   Modify     │
                       │   Send       │
                       │   Analyze    │
                       └──────────────┘
```

---

## 📋 Checklist for Each Scan

- [ ] MITM proxy started and capturing
- [ ] Pre-login pages crawled
- [ ] Pre-login requests/responses saved
- [ ] Login performed (if credentials provided)
- [ ] Auth tokens extracted and stored
- [ ] Post-login pages crawled (including form submissions)
- [ ] Post-login requests/responses saved
- [ ] ALL attacks run on pre-login requests
- [ ] ALL attacks run on post-login requests
- [ ] Auth-specific attacks run (token removal, manipulation)
- [ ] Token expiry monitored and refreshed if needed
- [ ] Findings marked with auth context (pre/post login)
- [ ] Report generated
- [ ] Temp files cleaned up
