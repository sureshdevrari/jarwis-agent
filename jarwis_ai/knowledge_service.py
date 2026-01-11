"""
Jarwis Knowledge Service
========================

Handles knowledge-based responses for the AI chatbot.
Provides vulnerability definitions, OWASP info, remediation guidance,
and security best practices WITHOUT requiring an LLM.

Author: Jarwis AI Team
Created: January 2026
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import logging
import json
import os

logger = logging.getLogger(__name__)


# ===== BRAND KNOWLEDGE =====

BRAND_RESPONSES = {
    # ===== CORE BRAND IDENTITY =====
    "what_is_jarwis": """
**Jarwis AGI** is an AI-powered security engineering platform built to help modern engineering teams build secure software faster.

**Tagline:** AGI Security Engineer

**Core Mission:** ↓ false positives, ↑ developer trust — Security that keeps pace with releases.

Jarwis focuses on practical, developer-first security without fear-based marketing. We believe security should be:
- **Simple** - No complex configurations or security expertise required
- **Practical** - Integrated into real engineering workflows
- **Trustworthy** - Low false positives that developers actually act on

**What Jarwis Does:**
🔹 **Web Applications** - OWASP Top 10 testing, authentication flaws, business logic vulnerabilities
🔹 **Mobile Apps** - Android/iOS static & dynamic analysis
🔹 **Network Infrastructure** - Port scanning, service enumeration, credential testing
🔹 **Cloud Environments** - AWS, Azure, GCP security configuration audits
🔹 **Source Code (SAST)** - Static analysis for Python, JavaScript, Java, and more

Unlike simple vulnerability scanners, Jarwis uses **attack chain detection** to identify how multiple vulnerabilities can be combined for maximum impact.
""",

    # ===== FOUNDER PROFILE =====
    "founder": """
**Suresh Devrari** is the Founder and CEO of Jarwis AGI.

Suresh is a security-focused technologist and entrepreneur who believes security should be simple, practical, and integrated into real engineering workflows.

**His Focus Areas:**
- Security engineering mindset
- Practical AI systems that work in production
- Building tools developers actually trust
- Long-term scalable security thinking

Jarwis was created to make professional security testing accessible to engineering teams of all sizes through intelligent, developer-friendly automation.
""",

    # ===== CAPABILITIES =====
    "capabilities": """
Here's what I can help you with:

**🔍 Vulnerability Intelligence**
- Explain any vulnerability type (SQL injection, XSS, CSRF, etc.)
- Provide OWASP Top 10 category details
- Show exploitation scenarios and real-world impact

**🔧 Remediation Guidance**
- Step-by-step fix instructions
- Code examples in multiple languages
- Security best practices that fit your workflow

**📊 Scan Analysis**
- Summarize scan results clearly
- Highlight critical findings
- Identify attack chains
- Prioritize fixes by actual risk

**💬 Security Consultation**
- Answer security questions
- Explain security concepts in engineering terms
- Compliance mapping (PCI, HIPAA, GDPR)

Ask me anything about your security findings or general cybersecurity!
""",

    # ===== TARGET AUDIENCE =====
    "who_is_jarwis_for": """
**Jarwis AGI is built for:**

🛠️ **Engineering Teams** - Developers who want security integrated into their workflow, not blocking it
🔒 **Security Teams** - Security professionals who need scalable, automated testing
⚙️ **Platform Teams** - DevOps and platform engineers building secure infrastructure

We focus on practical security that engineers actually use, not checkbox compliance that sits on a shelf.
""",

    # ===== REPLACING ENGINEERS =====
    "replacing_engineers": """
**No. Jarwis supports engineers, not replaces them.**

Jarwis is designed to:
- Augment human expertise, not substitute it
- Handle repetitive security testing at scale
- Free up security engineers for complex, creative work
- Provide actionable findings that developers can fix

Think of Jarwis as a tireless security assistant that helps your team move faster while staying secure.
""",

    # ===== BRAND VOICE =====
    "brand_tone": """
**Jarwis Brand Voice:**

✅ **Confident** - We know security, but we're not arrogant about it
✅ **Engineering-driven** - We think like engineers, speak like humans
✅ **Calm and trustworthy** - No fear-based marketing or hype
✅ **Slightly playful** - Security can be serious without being boring

**We avoid:**
- Hype and buzzwords
- Fear-based messaging
- Complex jargon when simple words work
- Overpromising capabilities
""",

    # ===== DO'S AND DON'TS =====
    "dos_and_donts": """
**What Jarwis Does:**
✅ Explain security concepts clearly
✅ Encourage secure development practices
✅ Promote best practices that actually work
✅ Be respectful, factual, and actionable

**What Jarwis Doesn't Do:**
❌ Share private or internal data
❌ Reveal internal architecture details
❌ Invent customer names or metrics
❌ Overpromise capabilities we can't deliver
❌ Use fear to sell security
""",

    # ===== BEHAVIOR RULES =====
    "behavior_rules": """
**Jarwis AI Behavior Guidelines:**

1. **Act as a security engineering assistant** - Practical, helpful, focused
2. **Avoid hallucinations** - Only state facts we're confident about
3. **Be honest about uncertainty** - If unsure, say "I don't have enough information"
4. **Protect confidentiality** - Never expose internal or customer data
5. **Maintain brand values** - Calm, confident, engineering-driven tone
"""
}


# ===== VULNERABILITY KNOWLEDGE BASE =====

VULNERABILITY_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "name": "SQL Injection (SQLi)",
        "owasp_category": "A03:2021 - Injection",
        "severity": "Critical to High",
        "description": """
**SQL Injection** occurs when untrusted data is sent to an interpreter as part of a command or query. 
The attacker's hostile data can trick the interpreter into executing unintended commands or accessing 
data without proper authorization.
""",
        "impact": [
            "Complete database compromise",
            "Data theft (credentials, PII, financial data)",
            "Data modification or deletion",
            "Authentication bypass",
            "Remote code execution (in some cases)"
        ],
        "example_vulnerable": """
```python
# VULNERABLE CODE
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
```
""",
        "example_secure": """
```python
# SECURE CODE - Parameterized Query
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```
""",
        "remediation": [
            "Use parameterized queries / prepared statements",
            "Use ORM frameworks (SQLAlchemy, Django ORM)",
            "Apply input validation with allowlists",
            "Implement least privilege for database accounts",
            "Use Web Application Firewall (WAF)"
        ],
        "related": ["xss", "command_injection", "ldap_injection"]
    },
    
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "owasp_category": "A03:2021 - Injection",
        "severity": "Medium to High",
        "description": """
**Cross-Site Scripting (XSS)** occurs when an application includes untrusted data in a web page 
without proper validation or escaping, allowing attackers to execute scripts in the victim's browser.

**Types:**
- **Reflected XSS**: Payload reflected from request
- **Stored XSS**: Payload stored in database/server
- **DOM XSS**: Client-side JavaScript vulnerabilities
""",
        "impact": [
            "Session hijacking (cookie theft)",
            "Account takeover",
            "Keylogging and credential theft",
            "Defacement",
            "Malware distribution",
            "Phishing attacks"
        ],
        "example_vulnerable": """
```html
<!-- VULNERABLE CODE -->
<div>Welcome, <?php echo $_GET['name']; ?></div>
```
""",
        "example_secure": """
```html
<!-- SECURE CODE -->
<div>Welcome, <?php echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8'); ?></div>
```
""",
        "remediation": [
            "Encode output (HTML, JavaScript, URL, CSS context-aware)",
            "Use Content Security Policy (CSP)",
            "Use HTTPOnly and Secure cookie flags",
            "Validate and sanitize input",
            "Use modern frameworks with auto-escaping (React, Vue)"
        ],
        "related": ["csrf", "html_injection", "open_redirect"]
    },
    
    "csrf": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "owasp_category": "A01:2021 - Broken Access Control",
        "severity": "Medium to High",
        "description": """
**CSRF** attacks force authenticated users to submit unwanted requests to a web application. 
The attacker tricks users into executing actions they didn't intend, leveraging their authenticated session.
""",
        "impact": [
            "Unauthorized state changes",
            "Password/email changes",
            "Fund transfers",
            "Account deletion",
            "Privilege escalation"
        ],
        "example_vulnerable": """
```html
<!-- VULNERABLE: No CSRF token -->
<form action="/transfer" method="POST">
    <input name="amount" value="1000">
    <input name="to" value="attacker">
    <button>Transfer</button>
</form>
```
""",
        "example_secure": """
```html
<!-- SECURE: With CSRF token -->
<form action="/transfer" method="POST">
    <input type="hidden" name="csrf_token" value="{{csrf_token}}">
    <input name="amount" value="1000">
    <input name="to" value="recipient">
    <button>Transfer</button>
</form>
```
""",
        "remediation": [
            "Implement anti-CSRF tokens (synchronizer tokens)",
            "Use SameSite cookie attribute",
            "Verify Origin and Referer headers",
            "Require re-authentication for sensitive actions",
            "Use framework-provided CSRF protection"
        ],
        "related": ["xss", "session_fixation", "clickjacking"]
    },
    
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "owasp_category": "A10:2021 - Server-Side Request Forgery",
        "severity": "High to Critical",
        "description": """
**SSRF** allows attackers to induce the server-side application to make HTTP requests to an 
arbitrary domain of the attacker's choosing. This can expose internal services, cloud metadata, 
or enable port scanning of internal networks.
""",
        "impact": [
            "Access to internal services (databases, admin panels)",
            "Cloud metadata exposure (AWS IAM credentials)",
            "Internal network port scanning",
            "Bypass firewalls and access controls",
            "Remote code execution (in chained attacks)"
        ],
        "example_vulnerable": """
```python
# VULNERABLE CODE
url = request.args.get('url')
response = requests.get(url)  # No validation!
return response.content
```
""",
        "example_secure": """
```python
# SECURE CODE
from urllib.parse import urlparse

ALLOWED_HOSTS = ['api.trusted.com', 'cdn.trusted.com']

url = request.args.get('url')
parsed = urlparse(url)

if parsed.hostname not in ALLOWED_HOSTS:
    abort(403, "URL not in allowlist")
    
# Additional: Block private IPs
if is_private_ip(parsed.hostname):
    abort(403, "Internal IPs not allowed")
    
response = requests.get(url, timeout=10)
```
""",
        "remediation": [
            "Implement URL allowlisting",
            "Block requests to private/internal IP ranges",
            "Disable unnecessary URL schemes (file://, gopher://)",
            "Use network segmentation",
            "Disable cloud metadata endpoints when possible",
            "Validate and sanitize user-supplied URLs"
        ],
        "related": ["xxe", "lfi", "rfi"]
    },
    
    "idor": {
        "name": "Insecure Direct Object Reference (IDOR)",
        "owasp_category": "A01:2021 - Broken Access Control",
        "severity": "Medium to High",
        "description": """
**IDOR** occurs when an application exposes a reference to an internal implementation object 
(like a database ID) in a way that allows attackers to access unauthorized data by manipulating 
the reference value.
""",
        "impact": [
            "Unauthorized data access",
            "View other users' data",
            "Modify other users' records",
            "Delete other users' content",
            "Horizontal/vertical privilege escalation"
        ],
        "example_vulnerable": """
```javascript
// VULNERABLE: No authorization check
GET /api/users/1234/profile
// Attacker changes to /api/users/5678/profile
```
""",
        "example_secure": """
```python
# SECURE: Authorization check
@app.get("/api/users/{user_id}/profile")
def get_profile(user_id: int, current_user = Depends(get_current_user)):
    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(403, "Access denied")
    return get_user_profile(user_id)
```
""",
        "remediation": [
            "Implement proper authorization checks",
            "Use indirect references (UUIDs) instead of sequential IDs",
            "Verify user ownership/permissions for every request",
            "Log and monitor access patterns",
            "Implement role-based access control (RBAC)"
        ],
        "related": ["broken_access_control", "privilege_escalation", "path_traversal"]
    },
    
    "xxe": {
        "name": "XML External Entity (XXE) Injection",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "severity": "High to Critical",
        "description": """
**XXE** attacks exploit vulnerable XML parsers that process external entity references within 
XML documents. This can lead to file disclosure, SSRF, denial of service, or remote code execution.
""",
        "impact": [
            "Server file disclosure (/etc/passwd, config files)",
            "Server-side request forgery (SSRF)",
            "Denial of Service (Billion Laughs attack)",
            "Port scanning via error messages",
            "Remote code execution (in some configurations)"
        ],
        "example_vulnerable": """
```xml
<!-- Malicious XML payload -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>
```
""",
        "example_secure": """
```python
# SECURE: Disable external entities
import defusedxml.ElementTree as ET

# defusedxml automatically disables dangerous features
tree = ET.parse(xml_file)
```
""",
        "remediation": [
            "Disable external entity processing in XML parsers",
            "Use defusedxml or similar safe libraries",
            "Prefer JSON over XML where possible",
            "Validate and sanitize XML input",
            "Update XML libraries to latest versions"
        ],
        "related": ["ssrf", "lfi", "injection"]
    },
    
    "ssti": {
        "name": "Server-Side Template Injection (SSTI)",
        "owasp_category": "A03:2021 - Injection",
        "severity": "Critical",
        "description": """
**SSTI** occurs when user input is embedded in a server-side template in an unsafe manner. 
This allows attackers to inject template directives to execute arbitrary code on the server.
""",
        "impact": [
            "Remote code execution",
            "Server compromise",
            "Data exfiltration",
            "Privilege escalation",
            "Complete system takeover"
        ],
        "example_vulnerable": """
```python
# VULNERABLE CODE - Jinja2
@app.route('/hello')
def hello():
    name = request.args.get('name')
    template = f"Hello {{{{ {name} }}}}"  # User input in template!
    return render_template_string(template)
```
""",
        "example_secure": """
```python
# SECURE CODE
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return render_template_string("Hello {{ name }}", name=name)
```
""",
        "remediation": [
            "Never embed user input directly in templates",
            "Use template sandboxing (Jinja2 sandbox mode)",
            "Whitelist allowed template expressions",
            "Prefer logic-less templates",
            "Implement input validation"
        ],
        "related": ["rce", "xss", "code_injection"]
    },
    
    "path_traversal": {
        "name": "Path Traversal / Directory Traversal",
        "owasp_category": "A01:2021 - Broken Access Control",
        "severity": "High",
        "description": """
**Path Traversal** (also known as Directory Traversal or LFI - Local File Inclusion) allows 
attackers to access files outside the intended directory by manipulating file path inputs 
with sequences like `../`.
""",
        "impact": [
            "Read sensitive server files",
            "Access configuration files with credentials",
            "Read application source code",
            "Access log files",
            "In some cases, write to files"
        ],
        "example_vulnerable": """
```python
# VULNERABLE CODE
filename = request.args.get('file')
with open(f'/var/www/files/{filename}', 'r') as f:
    return f.read()
# Attacker: ?file=../../../etc/passwd
```
""",
        "example_secure": """
```python
# SECURE CODE
import os

filename = request.args.get('file')
base_dir = '/var/www/files'

# Resolve to absolute path and check if still within base
filepath = os.path.realpath(os.path.join(base_dir, filename))
if not filepath.startswith(base_dir):
    abort(403, "Access denied")
    
with open(filepath, 'r') as f:
    return f.read()
```
""",
        "remediation": [
            "Use absolute paths with allowlisting",
            "Validate and sanitize file path input",
            "Use realpath() to resolve symlinks",
            "Implement chroot jails where possible",
            "Never use user input directly in file operations"
        ],
        "related": ["lfi", "rfi", "idor"]
    },
    
    "command_injection": {
        "name": "OS Command Injection",
        "owasp_category": "A03:2021 - Injection",
        "severity": "Critical",
        "description": """
**Command Injection** occurs when an application passes unsafe user-supplied data to a system 
shell. Attackers can inject arbitrary OS commands to be executed with the privileges of the 
vulnerable application.
""",
        "impact": [
            "Remote code execution",
            "Complete server compromise",
            "Data exfiltration",
            "Lateral movement to other systems",
            "Ransomware deployment"
        ],
        "example_vulnerable": """
```python
# VULNERABLE CODE
import os
filename = request.args.get('file')
os.system(f'cat /logs/{filename}')  # Dangerous!
# Attacker: ?file=log.txt; rm -rf /
```
""",
        "example_secure": """
```python
# SECURE CODE - Use subprocess with list arguments
import subprocess

filename = request.args.get('file')
# Validate filename (alphanumeric only)
if not filename.isalnum():
    abort(400, "Invalid filename")

# Use list format (prevents injection)
result = subprocess.run(['cat', f'/logs/{filename}'], 
                       capture_output=True, text=True)
return result.stdout
```
""",
        "remediation": [
            "Avoid calling OS commands with user input",
            "Use language-native libraries instead of shell commands",
            "If shell is required, use subprocess with list arguments",
            "Implement strict input validation (allowlisting)",
            "Run applications with minimal privileges"
        ],
        "related": ["sql_injection", "ssti", "code_injection"]
    },
    
    "auth_bypass": {
        "name": "Authentication Bypass",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "severity": "Critical",
        "description": """
**Authentication Bypass** vulnerabilities allow attackers to circumvent authentication mechanisms 
and gain unauthorized access without valid credentials. This can occur through logic flaws, 
insecure defaults, or improper validation.
""",
        "impact": [
            "Unauthorized account access",
            "Privilege escalation",
            "Data breach",
            "Account takeover",
            "Complete application compromise"
        ],
        "example_vulnerable": """
```python
# VULNERABLE: Logic flaw
def check_admin(user):
    if user.role == 'admin' or user.is_superuser:
        return True
    if request.headers.get('X-Admin') == 'true':  # Backdoor!
        return True
    return False
```
""",
        "example_secure": """
```python
# SECURE: Proper checks
def check_admin(user):
    if not user or not user.is_authenticated:
        return False
    return user.role == 'admin' or user.is_superuser
```
""",
        "remediation": [
            "Implement proper session management",
            "Use established authentication libraries/frameworks",
            "Require multi-factor authentication (MFA)",
            "Rate limit authentication attempts",
            "Implement account lockout policies",
            "Log and monitor authentication failures"
        ],
        "related": ["idor", "session_fixation", "jwt_vulnerabilities"]
    },
    
    "jwt": {
        "name": "JWT Vulnerabilities",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "severity": "High to Critical",
        "description": """
**JWT (JSON Web Token) Vulnerabilities** include algorithm confusion attacks, weak secrets, 
token manipulation, and improper validation that allow attackers to forge or manipulate tokens.

**Common Issues:**
- Algorithm confusion (none/HS256 vs RS256)
- Weak signing secrets
- Missing expiration validation
- JWT injection (jku/x5u attacks)
""",
        "impact": [
            "Authentication bypass",
            "Privilege escalation (change role claim)",
            "Account takeover",
            "Impersonation of any user"
        ],
        "example_vulnerable": """
```python
# VULNERABLE: Accepting 'none' algorithm
token_data = jwt.decode(token, options={"verify_signature": False})
```
""",
        "example_secure": """
```python
# SECURE: Explicit algorithm and verification
token_data = jwt.decode(
    token,
    key=SECRET_KEY,
    algorithms=["HS256"],  # Only allow specific algorithm
    options={"require": ["exp", "iat", "sub"]}  # Require claims
)
```
""",
        "remediation": [
            "Use strong, unique secrets (256+ bits)",
            "Explicitly specify allowed algorithms",
            "Validate all claims (exp, nbf, iss, aud)",
            "Use short expiration times",
            "Implement token refresh mechanism",
            "Store secrets securely (not in code)"
        ],
        "related": ["auth_bypass", "session_management", "crypto_failures"]
    },
    
    "security_headers": {
        "name": "Missing Security Headers",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "severity": "Low to Medium",
        "description": """
**Missing Security Headers** leave web applications vulnerable to various client-side attacks. 
Modern browsers support several security headers that provide defense-in-depth protection.
""",
        "impact": [
            "Increased XSS risk (no CSP)",
            "Clickjacking attacks (no X-Frame-Options)",
            "MIME sniffing attacks",
            "Man-in-the-middle attacks (no HSTS)"
        ],
        "headers": {
            "Content-Security-Policy": "Prevents XSS by restricting script sources",
            "X-Frame-Options": "Prevents clickjacking by controlling iframe embedding",
            "X-Content-Type-Options": "Prevents MIME sniffing attacks",
            "Strict-Transport-Security": "Enforces HTTPS connections",
            "X-XSS-Protection": "Legacy XSS filter (deprecated, use CSP)",
            "Referrer-Policy": "Controls referrer information leakage",
            "Permissions-Policy": "Controls browser feature access"
        },
        "example_secure": """
```python
# FastAPI Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
```
""",
        "remediation": [
            "Implement Content-Security-Policy",
            "Add X-Frame-Options: DENY",
            "Add X-Content-Type-Options: nosniff",
            "Enable HSTS with long max-age",
            "Configure appropriate Referrer-Policy",
            "Use security header testing tools"
        ],
        "related": ["xss", "clickjacking", "misconfiguration"]
    }
}


# ===== OWASP TOP 10 KNOWLEDGE =====

OWASP_TOP_10: Dict[str, Dict[str, Any]] = {
    "A01": {
        "name": "A01:2021 - Broken Access Control",
        "description": """
**Broken Access Control** moved up from #5 to the #1 spot. 94% of applications were tested for 
some form of broken access control. This category covers failures to properly restrict users 
from acting outside their intended permissions.
""",
        "examples": [
            "IDOR (Insecure Direct Object References)",
            "Missing function-level access control",
            "CORS misconfiguration",
            "Path traversal",
            "Privilege escalation"
        ],
        "prevention": [
            "Deny by default (except public resources)",
            "Implement access control mechanisms centrally",
            "Log access control failures and alert on anomalies",
            "Rate limit API access",
            "Invalidate sessions on logout"
        ]
    },
    
    "A02": {
        "name": "A02:2021 - Cryptographic Failures",
        "description": """
**Cryptographic Failures** (previously "Sensitive Data Exposure") focuses on failures related 
to cryptography that lead to exposure of sensitive data. This includes weak encryption, 
improper key management, and using deprecated algorithms.
""",
        "examples": [
            "Transmitting sensitive data in cleartext",
            "Using deprecated algorithms (MD5, SHA1 for passwords)",
            "Weak or hardcoded encryption keys",
            "Not enforcing HTTPS",
            "Improper certificate validation"
        ],
        "prevention": [
            "Classify data and apply appropriate protection",
            "Don't store sensitive data unnecessarily",
            "Encrypt all data in transit (TLS 1.2+)",
            "Use strong adaptive hashing for passwords (Argon2, bcrypt)",
            "Use authenticated encryption modes"
        ]
    },
    
    "A03": {
        "name": "A03:2021 - Injection",
        "description": """
**Injection** dropped from #1 to #3. This category now includes Cross-Site Scripting. 94% of 
applications were tested for some form of injection. Injection flaws occur when untrusted 
data is sent to an interpreter as part of a command or query.
""",
        "examples": [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Command Injection",
            "LDAP Injection",
            "Template Injection (SSTI)"
        ],
        "prevention": [
            "Use parameterized queries / prepared statements",
            "Use positive server-side validation",
            "Escape special characters",
            "Use LIMIT to prevent mass disclosure in SQL",
            "Use context-aware output encoding"
        ]
    },
    
    "A04": {
        "name": "A04:2021 - Insecure Design",
        "description": """
**Insecure Design** is a new category focusing on design and architectural flaws. It calls 
for more use of threat modeling, secure design patterns, and reference architectures.
""",
        "examples": [
            "Missing rate limiting on sensitive operations",
            "No protection against credential stuffing",
            "Allowing weak questions for password recovery",
            "Business logic flaws",
            "Missing fraud detection"
        ],
        "prevention": [
            "Establish secure development lifecycle (SDLC)",
            "Use threat modeling for critical flows",
            "Integrate security language in user stories",
            "Write unit and integration tests for security controls",
            "Segregate tiers at network and application level"
        ]
    },
    
    "A05": {
        "name": "A05:2021 - Security Misconfiguration",
        "description": """
**Security Misconfiguration** moved up from #6. 90% of applications were tested for some form 
of misconfiguration. This includes missing security hardening, improper permissions, 
unnecessary features enabled, and default credentials.
""",
        "examples": [
            "Unnecessary features enabled (ports, services)",
            "Default accounts/passwords unchanged",
            "Error handling reveals stack traces",
            "Missing security headers",
            "Software out of date"
        ],
        "prevention": [
            "Implement minimal platform without extras",
            "Review and update configurations regularly",
            "Implement automated processes for configuration",
            "Use separate configurations for dev/test/prod",
            "Implement security headers"
        ]
    },
    
    "A06": {
        "name": "A06:2021 - Vulnerable and Outdated Components",
        "description": """
**Vulnerable and Outdated Components** was previously titled "Using Components with Known 
Vulnerabilities." It focuses on the risks of using software with known security issues.
""",
        "examples": [
            "Using libraries with known CVEs",
            "Not knowing versions of all components",
            "Using unsupported/unmaintained software",
            "Not scanning for vulnerabilities regularly",
            "Not updating in a timely manner"
        ],
        "prevention": [
            "Maintain inventory of all components",
            "Monitor CVE databases and security advisories",
            "Obtain components from official sources only",
            "Remove unused dependencies",
            "Use software composition analysis (SCA) tools"
        ]
    },
    
    "A07": {
        "name": "A07:2021 - Identification and Authentication Failures",
        "description": """
**Identification and Authentication Failures** (previously "Broken Authentication") covers 
weaknesses in authentication and session management that could lead to unauthorized access.
""",
        "examples": [
            "Permitting brute force attacks",
            "Permitting weak passwords",
            "Improper session management",
            "Credential stuffing vulnerability",
            "Missing MFA"
        ],
        "prevention": [
            "Implement multi-factor authentication",
            "Don't ship with default credentials",
            "Check passwords against breach databases",
            "Implement rate limiting",
            "Use secure session management"
        ]
    },
    
    "A08": {
        "name": "A08:2021 - Software and Data Integrity Failures",
        "description": """
**Software and Data Integrity Failures** is a new category focusing on assumptions related 
to software updates, critical data, and CI/CD pipelines without verifying integrity.
""",
        "examples": [
            "Using libraries from untrusted sources",
            "Auto-update without integrity verification",
            "Insecure CI/CD pipeline",
            "Insecure deserialization",
            "Unsigned or unverified code"
        ],
        "prevention": [
            "Use digital signatures to verify software",
            "Ensure libraries are from trusted repositories",
            "Use software supply chain security tools",
            "Implement integrity verification in CI/CD",
            "Serialize data in a safe manner"
        ]
    },
    
    "A09": {
        "name": "A09:2021 - Security Logging and Monitoring Failures",
        "description": """
**Security Logging and Monitoring Failures** was previously "Insufficient Logging & Monitoring." 
This category helps detect, escalate, and respond to active breaches.
""",
        "examples": [
            "Login failures not being logged",
            "Warnings and errors generate unclear logs",
            "Logs not monitored for suspicious activity",
            "No alerting for real-time attacks",
            "Logs only stored locally"
        ],
        "prevention": [
            "Log all authentication failures and access control",
            "Ensure logs have sufficient context",
            "Centralize log management",
            "Implement real-time alerting",
            "Create incident response plan"
        ]
    },
    
    "A10": {
        "name": "A10:2021 - Server-Side Request Forgery (SSRF)",
        "description": """
**SSRF** is a new category added based on industry survey. SSRF occurs when a web application 
fetches a remote resource without validating the user-supplied URL. This can lead to scanning 
and attacking internal systems.
""",
        "examples": [
            "Fetching URLs from user input",
            "Accessing cloud metadata endpoints",
            "Scanning internal network",
            "Bypassing access controls",
            "Reading local files"
        ],
        "prevention": [
            "Validate and sanitize all user-supplied URLs",
            "Implement URL allowlist",
            "Block requests to private IP ranges",
            "Disable HTTP redirections",
            "Use network segmentation"
        ]
    }
}


# ===== SECURITY CONCEPTS =====

SECURITY_CONCEPTS: Dict[str, str] = {
    "defense_in_depth": """
**Defense in Depth** is a security strategy that employs multiple layers of security controls 
throughout a system. If one layer fails, another layer provides protection.

**Layers include:**
- **Physical**: Door locks, security guards
- **Network**: Firewalls, IDS/IPS, network segmentation
- **Host**: Antivirus, host-based firewalls, hardening
- **Application**: WAF, input validation, secure coding
- **Data**: Encryption, access controls, DLP
- **User**: Training, MFA, least privilege
""",

    "least_privilege": """
**Principle of Least Privilege (PoLP)** states that users and systems should only have the 
minimum access rights needed to perform their legitimate tasks.

**Implementation:**
- Grant only necessary permissions
- Use role-based access control (RBAC)
- Remove access when no longer needed
- Regular access reviews
- Separate admin and regular accounts
""",

    "zero_trust": """
**Zero Trust** is a security model based on "never trust, always verify." It assumes breach 
and verifies every request as though it originated from an untrusted network.

**Core Principles:**
1. Verify explicitly (authenticate and authorize)
2. Use least privilege access
3. Assume breach (minimize blast radius)

**Implementation:**
- Strong identity verification (MFA)
- Device health validation
- Micro-segmentation
- Real-time analytics
""",

    "secure_by_design": """
**Secure by Design** means building security into products from the beginning rather than 
adding it as an afterthought.

**Practices:**
- Threat modeling during design
- Security requirements in specifications
- Secure coding standards
- Security testing in CI/CD
- Regular security reviews
""",

    "shift_left": """
**Shift Left** refers to integrating security earlier in the software development lifecycle 
(SDLC), rather than only at the end.

**Benefits:**
- Find vulnerabilities earlier (cheaper to fix)
- Reduce security technical debt
- Faster release cycles
- Better security culture

**Practices:**
- Security training for developers
- SAST in IDE and CI/CD
- Pre-commit hooks for secrets detection
- Threat modeling in design phase
"""
}


@dataclass
class KnowledgeResponse:
    """Response from knowledge service"""
    content: str
    response_type: str = "text"  # text, code, list
    related_topics: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    confidence: float = 1.0


class KnowledgeService:
    """
    Knowledge Service for AI Chatbot
    
    Provides vulnerability definitions, remediation guidance,
    and security concepts without requiring an LLM.
    """
    
    def __init__(self):
        """Initialize knowledge service"""
        self.vuln_definitions = VULNERABILITY_DEFINITIONS
        self.owasp_info = OWASP_TOP_10
        self.brand_responses = BRAND_RESPONSES
        self.security_concepts = SECURITY_CONCEPTS
    
    def get_brand_response(self, query_type: str) -> KnowledgeResponse:
        """Get brand-related response"""
        content_map = {
            # Core brand
            "brand_info": self.brand_responses["what_is_jarwis"],
            "what_is_jarwis": self.brand_responses["what_is_jarwis"],
            "about_jarwis": self.brand_responses["what_is_jarwis"],
            
            # Founder
            "founder_info": self.brand_responses["founder"],
            "founder": self.brand_responses["founder"],
            "who_created": self.brand_responses["founder"],
            "suresh": self.brand_responses["founder"],
            
            # Capabilities
            "capabilities": self.brand_responses["capabilities"],
            "what_can_you_do": self.brand_responses["capabilities"],
            "help": self.brand_responses["capabilities"],
            
            # Target audience
            "who_is_jarwis_for": self.brand_responses["who_is_jarwis_for"],
            "target_audience": self.brand_responses["who_is_jarwis_for"],
            "who_uses": self.brand_responses["who_is_jarwis_for"],
            
            # Replacing engineers
            "replacing_engineers": self.brand_responses["replacing_engineers"],
            "replace_humans": self.brand_responses["replacing_engineers"],
            "ai_vs_humans": self.brand_responses["replacing_engineers"],
            
            # Brand tone
            "brand_tone": self.brand_responses["brand_tone"],
            "voice": self.brand_responses["brand_tone"],
            
            # Guidelines
            "dos_and_donts": self.brand_responses["dos_and_donts"],
            "behavior_rules": self.brand_responses["behavior_rules"],
        }
        
        return KnowledgeResponse(
            content=content_map.get(query_type, self.brand_responses["what_is_jarwis"]),
            response_type="text"
        )
    
    def get_vulnerability_definition(self, vuln_type: str) -> KnowledgeResponse:
        """Get vulnerability definition and remediation"""
        vuln_type = vuln_type.lower().replace("-", "_").replace(" ", "_")
        
        vuln = self.vuln_definitions.get(vuln_type)
        if not vuln:
            # Try partial match
            for key, val in self.vuln_definitions.items():
                if vuln_type in key or key in vuln_type:
                    vuln = val
                    break
        
        if not vuln:
            return KnowledgeResponse(
                content=f"I don't have detailed information about '{vuln_type}' yet. "
                        f"Please ask about common vulnerabilities like SQL injection, XSS, CSRF, etc.",
                confidence=0.5
            )
        
        # Build comprehensive response
        content = f"## {vuln['name']}\n\n"
        content += f"**OWASP Category:** {vuln['owasp_category']}\n"
        content += f"**Severity:** {vuln['severity']}\n\n"
        content += vuln['description'].strip() + "\n\n"
        
        content += "### Impact\n"
        for impact in vuln['impact']:
            content += f"- {impact}\n"
        
        content += "\n### Vulnerable Example\n"
        content += vuln['example_vulnerable']
        
        content += "\n### Secure Example\n"
        content += vuln['example_secure']
        
        content += "\n### Remediation\n"
        for rem in vuln['remediation']:
            content += f"- {rem}\n"
        
        return KnowledgeResponse(
            content=content,
            response_type="text",
            related_topics=vuln.get('related', []),
            confidence=1.0
        )
    
    def get_owasp_info(self, category: str) -> KnowledgeResponse:
        """Get OWASP Top 10 category information"""
        category = category.upper()
        
        # Handle various formats (A01, A1, a01, etc.)
        if not category.startswith("A"):
            category = f"A{category}"
        if len(category) == 2:  # A1 -> A01
            category = f"A0{category[1]}"
        
        owasp = self.owasp_info.get(category)
        
        if not owasp:
            return KnowledgeResponse(
                content="Please specify an OWASP category (A01 through A10).\n\n"
                        "For example: 'What is A03?' or 'Tell me about A01 Broken Access Control'",
                confidence=0.5
            )
        
        content = f"## {owasp['name']}\n\n"
        content += owasp['description'].strip() + "\n\n"
        
        content += "### Common Examples\n"
        for example in owasp['examples']:
            content += f"- {example}\n"
        
        content += "\n### Prevention\n"
        for prevention in owasp['prevention']:
            content += f"- {prevention}\n"
        
        return KnowledgeResponse(
            content=content,
            response_type="text",
            confidence=1.0
        )
    
    def get_security_concept(self, concept: str) -> KnowledgeResponse:
        """Get security concept explanation"""
        concept_key = concept.lower().replace(" ", "_").replace("-", "_")
        
        # Try direct match
        content = self.security_concepts.get(concept_key)
        
        if not content:
            # Try partial match
            for key, val in self.security_concepts.items():
                if concept_key in key or key in concept_key:
                    content = val
                    break
        
        if not content:
            return KnowledgeResponse(
                content=f"I don't have detailed information about '{concept}'. "
                        f"Try asking about: defense in depth, least privilege, zero trust, "
                        f"secure by design, or shift left.",
                confidence=0.5
            )
        
        return KnowledgeResponse(
            content=content.strip(),
            response_type="text",
            confidence=1.0
        )
    
    def get_remediation(
        self,
        vuln_type: str,
        language: Optional[str] = None
    ) -> KnowledgeResponse:
        """Get remediation guidance for a vulnerability type"""
        vuln_type = vuln_type.lower().replace("-", "_").replace(" ", "_")
        
        vuln = self.vuln_definitions.get(vuln_type)
        if not vuln:
            for key, val in self.vuln_definitions.items():
                if vuln_type in key:
                    vuln = val
                    break
        
        if not vuln:
            return KnowledgeResponse(
                content=f"No remediation guidance found for '{vuln_type}'.",
                confidence=0.5
            )
        
        content = f"## How to Fix {vuln['name']}\n\n"
        
        content += "### Remediation Steps\n"
        for i, rem in enumerate(vuln['remediation'], 1):
            content += f"{i}. {rem}\n"
        
        content += "\n### Secure Code Example\n"
        content += vuln['example_secure']
        
        return KnowledgeResponse(
            content=content,
            response_type="text",
            related_topics=vuln.get('related', []),
            confidence=1.0
        )
    
    def get_off_topic_response(self) -> KnowledgeResponse:
        """Response for off-topic queries"""
        return KnowledgeResponse(
            content="""I'm Jarwis, your cybersecurity assistant. I'm designed to help with:

🔹 **Vulnerability Information** - Learn about security issues
🔹 **Remediation Guidance** - How to fix vulnerabilities
🔹 **Scan Analysis** - Understand your security findings
🔹 **Security Concepts** - Defense strategies and best practices

Please ask me something related to cybersecurity or your scan results!""",
            response_type="text",
            confidence=1.0
        )


# Convenience functions
def get_vuln_info(vuln_type: str) -> str:
    """Quick vulnerability lookup"""
    service = KnowledgeService()
    result = service.get_vulnerability_definition(vuln_type)
    return result.content


def get_fix_guidance(vuln_type: str) -> str:
    """Quick remediation guidance"""
    service = KnowledgeService()
    result = service.get_remediation(vuln_type)
    return result.content


def get_owasp(category: str) -> str:
    """Quick OWASP info"""
    service = KnowledgeService()
    result = service.get_owasp_info(category)
    return result.content
