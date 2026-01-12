# Security Bypass Scanners - Developer Documentation

**Created:** January 4, 2026  
**Category:** Pentesting Modules  
**Based On:** Defensive security implementations discussed in previous sessions

## Overview

These scanners convert defensive security knowledge into offensive testing capabilities. Each scanner tests for bypass techniques based on common security implementations that we've seen or discussed.

## New Scanners Added

### 1. AuthBypassScanner (`auth_bypass_scanner.py`)
**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Tests Performed:**
- **JWT Algorithm None Attack**: Tests if server accepts `alg: none` tokens
- **JWT Weak Secret Bruteforce**: Tests common weak secrets (secret, password, etc.)
- **JWT Key Confusion**: Tests RS256→HS256 algorithm confusion attack
- **JWT Expiry Bypass**: Tests if expired tokens are still accepted
- **Authentication Header Bypass**: Tests X-Forwarded-For, X-Original-URL, etc.
- **Default Credentials**: Tests common admin/password combinations
- **Password Reset Token Weakness**: Checks for predictable/exposed tokens
- **Session Fixation Detection**: Identifies pre-auth session IDs
- **MFA Bypass**: Tests empty OTP, default OTP (000000), rate limiting

**Configuration:**
```yaml
owasp:
  auth_bypass:
    enabled: true
```

---

### 2. SessionSecurityScanner (`session_scanner.py`)
**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Tests Performed:**
- **Cookie Security Flags**: Checks for missing HttpOnly, Secure, SameSite
- **Session Token Entropy**: Analyzes randomness of session tokens
- **Token Predictability**: Detects sequential or timestamp-based tokens
- **Session in URL**: Finds session tokens exposed in URLs
- **Session Timeout**: Checks for excessive cookie lifetimes
- **Logout Invalidation**: Verifies sessions are cleared on logout

**Configuration:**
```yaml
owasp:
  session_security:
    enabled: true
```

---

### 3. RateLimitBypassScanner (`rate_limit_scanner.py`)
**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Tests Performed:**
- **Missing Rate Limits**: Tests critical endpoints (login, reset, OTP, contact)
- **Header-Based Bypass**: Tests X-Forwarded-For IP rotation
- **Parameter Pollution**: Tests if modified parameters escape rate limiting
- **Race Condition**: Tests concurrent requests to bypass atomic checks
- **API Key Bypass**: Tests if API keys bypass rate limits entirely

**Configuration:**
```yaml
owasp:
  rate_limit_bypass:
    enabled: true
```

---

### 4. OAuthSecurityScanner (`oauth_scanner.py`)
**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Tests Performed:**
- **State Parameter Missing/Weak**: CSRF protection bypass
- **Redirect URI Bypass**: Path traversal, subdomain confusion, URL tricks
- **Open Redirect**: Tests callback endpoint redirect parameters
- **Token Exposure**: Finds tokens in URLs (implicit flow issues)
- **PKCE Missing**: Checks if code_challenge is required
- **OAuth Misconfiguration**: Analyzes OpenID Connect discovery

**Configuration:**
```yaml
owasp:
  oauth_security:
    enabled: true
```

---

### 5. CaptchaBypassScanner (`captcha_scanner.py`)
**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Tests Performed:**
- **Missing CAPTCHA**: Finds sensitive forms without CAPTCHA
- **Empty Value Bypass**: Tests if empty CAPTCHA is accepted
- **Null Value Bypass**: Tests if null CAPTCHA is accepted
- **Parameter Removal**: Tests if removing CAPTCHA param works
- **Static Token Bypass**: Tests predictable token values
- **Token Reuse**: Checks if same token works multiple times
- **Client-Side Only**: Detects JavaScript-only validation

**Configuration:**
```yaml
owasp:
  captcha_bypass:
    enabled: true
```

---

### 6. MobileSecurityScanner (`mobile_security_scanner.py`)
**OWASP Mobile Category:** M3, M4 (Insecure Communication, Insecure Authentication)

**Tests Performed:**
- **SSL/TLS Configuration**: Checks for weak protocols (TLS 1.0, 1.1)
- **Weak Ciphers**: Detects RC4, DES, 3DES, NULL ciphers
- **Mobile API Discovery**: Finds mobile-specific API endpoints
- **Device Binding Bypass**: Tests fake attestation tokens
- **Root/Jailbreak Detection Bypass**: Tests header-based bypasses
- **Biometric Auth Bypass**: Tests client-asserted biometric results
- **PIN Bruteforce**: Checks for lockout mechanisms
- **Certificate Transparency**: Checks for HSTS, Expect-CT headers

**Configuration:**
```yaml
owasp:
  mobile_security:
    enabled: true
```

---

## Usage

### In Scan Configuration

All new scanners are automatically included when `PreLoginAttacks` is initialized. They can be individually enabled/disabled via the config:

```yaml
attacks:
  owasp:
    auth_bypass:
      enabled: true
    session_security:
      enabled: true
    rate_limit_bypass:
      enabled: true
    oauth_security:
      enabled: true
    captcha_bypass:
      enabled: true
    mobile_security:
      enabled: true
```

### Programmatic Usage

```python
# New OWASP-organized imports (recommended)
from attacks.web.a07_auth_failures import AuthBypassScanner, SessionSecurityScanner
from attacks.web.a04_insecure_design import RateLimitBypassScanner, CaptchaBypassScanner
from attacks.web.a07_auth_failures import OAuthSecurityScanner

# Or use backward-compatible imports
from attacks.web.pre_login import (
    AuthBypassScanner,
    SessionSecurityScanner,
    RateLimitBypassScanner,
    OAuthSecurityScanner,
    CaptchaBypassScanner,
)

# Individual scanner usage
scanner = AuthBypassScanner(config, context)
findings = await scanner.scan()
```

---

## Findings Format

All scanners return `ScanResult` dataclass objects with:

```python
@dataclass
class ScanResult:
    id: str           # Unique finding ID
    category: str     # OWASP category (A07:2021, M3:2024, etc.)
    severity: str     # critical, high, medium, low, info
    title: str        # Short description
    description: str  # Detailed explanation
    url: str          # Affected URL
    method: str       # HTTP method
    parameter: str    # Affected parameter
    evidence: str     # Proof of vulnerability
    remediation: str  # How to fix
    cwe_id: str       # CWE reference
    poc: str          # Proof of concept
    reasoning: str    # Why this is a vulnerability
```

---

## Response Swap Attack - Proper Understanding

### The Attack Explained

The response swap/manipulation attack works as follows:

1. **Attacker logs into their own account** (attacker@email.com)
2. **Attacker captures the SUCCESS response** containing JWT token
3. **Attacker tries to login as victim** (victim@email.com) with wrong password
4. **Server returns FAILED response** (401/403)
5. **MITM proxy intercepts and REPLACES** failed response with captured success
6. **Frontend receives "success"** and stores attacker's JWT

### What Makes It a VULNERABILITY?

| Scenario | After Response Swap | Verdict |
|----------|---------------------|---------|
| Frontend shows VICTIM's data | Attacker accesses victim's account | **CRITICAL VULNERABILITY** |
| Frontend shows ATTACKER's data | Attacker only sees their own account | **NOT VULNERABLE** (expected) |
| Request rejected by server | Server validates user-token binding | **SECURE** |

### Key Insight

**If the user ends up in the SAME account as the JWT token owner, it's NOT a vulnerability.**

The attack only works when:
- Server doesn't bind tokens to user identity
- Frontend trusts response without server validation
- No additional server-side session tracking exists

### Testing Requirements

To properly test, you need:
```yaml
auth:
  username: "attacker@test.com"     # First test account
  password: "attacker_password"
  test_account_2:                   # Optional: second test account
    username: "victim@test.com"
    password: "victim_password"
```

---

## Security Considerations

⚠️ **These scanners are for authorized testing only!**

- Only use on systems you have permission to test
- Some tests (brute force, rate limit) may cause account lockouts
- Some tests send many requests quickly - respect rate limits
- Mobile tests may require physical/emulated device for full coverage

---

## Future Enhancements

- [ ] Add GraphQL-specific auth bypass tests
- [ ] Add WebSocket authentication tests
- [ ] Add certificate pinning bypass with Frida integration
- [ ] Add API key enumeration scanner
- [ ] Add password policy bypass tests
- [ ] Add account enumeration scanner
- [ ] Add cross-user token test automation (requires 2 accounts)
- [ ] Add replay attack detection
