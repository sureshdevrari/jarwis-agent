"""
Test Mobile Scan with SSL Pinning Test APK
Uses user2 account to verify mobile scanning functionality

This script:
1. Creates a valid test APK with SSL pinning indicators
2. Logs in as user2 (professional plan)
3. Uploads the APK and starts a mobile scan
4. Monitors scan progress
5. Displays results
"""

import os
import sys
import time
import zipfile
import struct
import requests
import json
from pathlib import Path
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
USER2_EMAIL = "user2@jarwis.ai"
USER2_PASSWORD = "12341234"

# Paths
SCRIPT_DIR = Path(__file__).parent
SAMPLE_APP_DIR = SCRIPT_DIR / "sample_apps" / "android" / "ssl_pinning_test"
OUTPUT_DIR = SCRIPT_DIR / "output"
APK_PATH = OUTPUT_DIR / "ssl_pinning_test.apk"


def create_minimal_apk():
    """
    Create a minimal but valid APK file structure for testing.
    The APK contains the source files that demonstrate SSL pinning.
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    print("📦 Creating test APK with SSL pinning...")
    
    with zipfile.ZipFile(APK_PATH, 'w', zipfile.ZIP_DEFLATED) as apk:
        # Add AndroidManifest.xml (binary format header + our content)
        manifest_path = SAMPLE_APP_DIR / "AndroidManifest.xml"
        if manifest_path.exists():
            # Read our manifest
            manifest_content = manifest_path.read_text()
            
            # Create a simplified binary manifest representation
            # Real APKs have AXML format, but for static analysis, text-based works
            apk.writestr("AndroidManifest.xml", manifest_content)
        else:
            # Create minimal manifest
            manifest = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.jarwis.sslpinningtest"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application 
        android:allowBackup="true"
        android:networkSecurityConfig="@xml/network_security_config"
        android:label="SSL Pinning Test">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>'''
            apk.writestr("AndroidManifest.xml", manifest)
        
        # Add network security config
        nsc_path = SAMPLE_APP_DIR / "res" / "xml" / "network_security_config.xml"
        if nsc_path.exists():
            apk.writestr("res/xml/network_security_config.xml", nsc_path.read_text())
        else:
            nsc = '''<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.jarwis.ai</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>'''
            apk.writestr("res/xml/network_security_config.xml", nsc)
        
        # Add Java source files (simulated as smali/dex content for static analysis)
        java_files = [
            ("java/com/jarwis/sslpinningtest/MainActivity.java", "MainActivity.java"),
            ("java/com/jarwis/sslpinningtest/network/SecureApiClient.java", "SecureApiClient.java"),
            ("java/com/jarwis/sslpinningtest/security/RootDetector.java", "RootDetector.java"),
            ("java/com/jarwis/sslpinningtest/data/UserDataManager.java", "UserDataManager.java"),
            ("java/com/jarwis/sslpinningtest/WebViewActivity.java", "WebViewActivity.java"),
        ]
        
        for rel_path, name in java_files:
            source_path = SAMPLE_APP_DIR / rel_path
            if source_path.exists():
                # Add to APK as source reference (for static analysis)
                content = source_path.read_text()
                apk.writestr(f"sources/{name}", content)
                
                # Also add a simulated smali representation
                smali_content = convert_java_to_simulated_smali(content, name)
                smali_path = f"smali/com/jarwis/sslpinningtest/{name.replace('.java', '.smali')}"
                apk.writestr(smali_path, smali_content)
        
        # Add classes.dex placeholder (minimal valid structure)
        dex_header = create_minimal_dex()
        apk.writestr("classes.dex", dex_header)
        
        # Add resources.arsc placeholder
        apk.writestr("resources.arsc", b'\x02\x00\x0c\x00' + b'\x00' * 100)
        
        # Add META-INF with signing info
        apk.writestr("META-INF/MANIFEST.MF", """Manifest-Version: 1.0
Created-By: Jarwis Test APK Generator
Built-By: jarwis

Name: classes.dex
SHA-256-Digest: test-digest-placeholder
""")
        
        apk.writestr("META-INF/CERT.SF", """Signature-Version: 1.0
Created-By: Jarwis Test APK Generator
SHA-256-Digest-Manifest: test-digest
""")
        
        # Add a fake certificate (placeholder)
        apk.writestr("META-INF/CERT.RSA", b'\x30\x82' + b'\x00' * 100)
        
        # Add build.gradle reference
        gradle_path = SAMPLE_APP_DIR / "build.gradle"
        if gradle_path.exists():
            apk.writestr("build-info/build.gradle", gradle_path.read_text())
    
    print(f"✅ Created APK: {APK_PATH}")
    print(f"   Size: {APK_PATH.stat().st_size:,} bytes")
    return APK_PATH


def convert_java_to_simulated_smali(java_content: str, filename: str) -> str:
    """
    Convert Java source to simulated Smali format for static analysis.
    This preserves the security-relevant patterns that scanners look for.
    """
    lines = []
    lines.append(f"# Simulated smali for {filename}")
    lines.append(".class public Lcom/jarwis/sslpinningtest/{};".format(
        filename.replace('.java', '')))
    lines.append(".super Ljava/lang/Object;")
    lines.append("")
    
    # Extract and preserve security-relevant strings
    import re
    
    # Find hardcoded keys/secrets
    secrets = re.findall(r'(API_KEY|SECRET_KEY|ENCRYPTION_KEY|AWS_.*_KEY|GOOGLE_API_KEY)\s*=\s*"([^"]+)"', java_content)
    for name, value in secrets:
        lines.append(f'# SECURITY: Hardcoded {name}')
        lines.append(f'.field private static final {name}:Ljava/lang/String; = "{value}"')
    
    # Find SSL pinning patterns
    if 'CertificatePinner' in java_content:
        lines.append("")
        lines.append("# SSL PINNING DETECTED")
        lines.append("# Uses OkHttp CertificatePinner")
        pins = re.findall(r'sha256/([A-Za-z0-9+/=]+)', java_content)
        for pin in pins:
            lines.append(f".field private static final PIN:Ljava/lang/String; = \"sha256/{pin}\"")
    
    if 'pin-set' in java_content or 'network-security-config' in java_content:
        lines.append("# Uses Android Network Security Config")
    
    # Find WebView vulnerabilities
    webview_issues = []
    if 'setJavaScriptEnabled(true)' in java_content:
        webview_issues.append("JavaScript enabled")
    if 'setAllowFileAccess(true)' in java_content:
        webview_issues.append("File access enabled")
    if 'setAllowFileAccessFromFileURLs(true)' in java_content:
        webview_issues.append("File URL access enabled - CRITICAL")
    if 'setAllowUniversalAccessFromFileURLs(true)' in java_content:
        webview_issues.append("Universal file access - CRITICAL")
    if 'addJavascriptInterface' in java_content:
        webview_issues.append("JavaScript interface exposed")
    if 'setWebContentsDebuggingEnabled(true)' in java_content:
        webview_issues.append("WebView debugging enabled")
    if 'MIXED_CONTENT_ALWAYS_ALLOW' in java_content:
        webview_issues.append("Mixed content allowed")
    
    if webview_issues:
        lines.append("")
        lines.append("# WEBVIEW SECURITY ISSUES:")
        for issue in webview_issues:
            lines.append(f"# - {issue}")
    
    # Find root detection
    if 'isDeviceRooted' in java_content or 'checkRootBinaries' in java_content:
        lines.append("")
        lines.append("# ROOT DETECTION IMPLEMENTED")
        lines.append(".method public static isDeviceRooted()Z")
    
    # Find logging of sensitive data
    if re.search(r'Log\.[dwei]\s*\([^)]*password|token|key|credential', java_content, re.IGNORECASE):
        lines.append("")
        lines.append("# SECURITY ISSUE: Logging sensitive data")
    
    # Add the original Java as comment for reference
    lines.append("")
    lines.append("# Original Java source follows:")
    for line in java_content.split('\n')[:50]:  # First 50 lines
        lines.append(f"# {line}")
    
    return '\n'.join(lines)


def create_minimal_dex():
    """Create minimal valid DEX file header"""
    # DEX magic number and minimal header
    dex_magic = b'dex\n035\x00'
    checksum = b'\x00' * 4
    signature = b'\x00' * 20
    file_size = struct.pack('<I', 112)
    header_size = struct.pack('<I', 112)
    endian = struct.pack('<I', 0x12345678)
    
    # Rest of header (zeros for minimal file)
    rest = b'\x00' * (112 - len(dex_magic) - 4 - 20 - 4 - 4 - 4)
    
    return dex_magic + checksum + signature + file_size + header_size + endian + rest


def login_user2():
    """Login as user2 and get auth token"""
    print(f"\n🔐 Logging in as {USER2_EMAIL}...")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": USER2_EMAIL, "password": USER2_PASSWORD},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            token = data.get("access_token")
            print(f"✅ Logged in successfully!")
            print(f"   Plan: {data.get('user', {}).get('plan', 'unknown')}")
            return token
        else:
            print(f"❌ Login failed: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return None
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Is Jarwis backend running?")
        print(f"   Expected at: {BASE_URL}")
        return None
    except Exception as e:
        print(f"❌ Login error: {e}")
        return None


def start_mobile_scan(token: str, apk_path: Path):
    """Upload APK and start mobile scan"""
    print(f"\n📱 Starting mobile scan...")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    with open(apk_path, 'rb') as f:
        files = {
            "app_file": (apk_path.name, f, "application/vnd.android.package-archive")
        }
        data = {
            "app_name": "SSL Pinning Test App",
            "platform": "android",
            "ssl_pinning_bypass": "true",
            "frida_scripts": "true",
            "intercept_traffic": "true",
            "notes": "Test app with SSL pinning for Jarwis verification"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/scan/mobile/start",
            headers=headers,
            files=files,
            data=data,
            timeout=60
        )
    
    if response.status_code == 201:
        result = response.json()
        scan_id = result.get("scan_id")
        print(f"✅ Scan started successfully!")
        print(f"   Scan ID: {scan_id}")
        print(f"   Status: {result.get('status')}")
        return scan_id
    elif response.status_code == 403:
        print("❌ Access denied - mobile scanning may require higher subscription")
        print(f"   Response: {response.text}")
        return None
    else:
        print(f"❌ Failed to start scan: {response.status_code}")
        print(f"   Response: {response.text[:500]}")
        return None


def monitor_scan_progress(token: str, scan_id: str, timeout: int = 300):
    """Monitor scan progress until completion"""
    print(f"\n⏳ Monitoring scan progress...")
    
    headers = {"Authorization": f"Bearer {token}"}
    start_time = time.time()
    last_progress = -1
    
    while time.time() - start_time < timeout:
        try:
            response = requests.get(
                f"{BASE_URL}/api/scan/mobile/{scan_id}/status",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                status = response.json()
                progress = status.get("progress", 0)
                phase = status.get("phase", "unknown")
                scan_status = status.get("status", "unknown")
                findings = status.get("findings_count", 0)
                
                if progress != last_progress:
                    print(f"   [{progress:3d}%] {phase} - {findings} findings")
                    last_progress = progress
                
                if scan_status in ["completed", "failed", "error"]:
                    print(f"\n{'✅' if scan_status == 'completed' else '❌'} Scan {scan_status}")
                    return status
                    
            elif response.status_code == 404:
                print("❌ Scan not found")
                return None
                
        except Exception as e:
            print(f"   Error checking status: {e}")
        
        time.sleep(2)
    
    print("⏰ Timeout waiting for scan to complete")
    return None


def get_scan_results(token: str, scan_id: str):
    """Get detailed scan results"""
    print(f"\n📊 Fetching scan results...")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.get(
        f"{BASE_URL}/api/scan/mobile/{scan_id}/results",
        headers=headers,
        timeout=30
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"❌ Failed to get results: {response.status_code}")
        return None


def display_results(results: dict):
    """Display scan results in a formatted way"""
    if not results:
        return
    
    print("\n" + "=" * 60)
    print("📋 MOBILE SCAN RESULTS")
    print("=" * 60)
    
    # App info
    app_info = results.get("app_info", {})
    print(f"\n📱 App: {app_info.get('name', 'Unknown')}")
    print(f"   Package: {app_info.get('package_name', 'Unknown')}")
    print(f"   Platform: {app_info.get('platform', 'Unknown')}")
    print(f"   Version: {app_info.get('version', 'Unknown')}")
    
    # Findings summary
    findings = results.get("findings", [])
    print(f"\n🔍 Total Findings: {len(findings)}")
    
    # Count by severity
    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    print("\n   By Severity:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in severity_counts:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "⚫")
            print(f"   {emoji} {sev.upper()}: {severity_counts[sev]}")
    
    # SSL Pinning status
    ssl_findings = [f for f in findings if "ssl" in f.get("title", "").lower() or "pinning" in f.get("title", "").lower()]
    print(f"\n🔒 SSL Pinning Related: {len(ssl_findings)} findings")
    for f in ssl_findings[:5]:
        print(f"   - [{f.get('severity', '?').upper()}] {f.get('title', 'Unknown')}")
    
    # Top findings
    print("\n📌 Top Findings:")
    for i, f in enumerate(findings[:10], 1):
        sev = f.get("severity", "unknown")
        title = f.get("title", "Unknown")
        category = f.get("category", "")
        print(f"   {i}. [{sev.upper()}] {title}")
        if f.get("description"):
            desc = f.get("description", "")[:100]
            print(f"      {desc}...")
    
    # OWASP coverage
    owasp = results.get("owasp_coverage", {})
    if owasp:
        print("\n📊 OWASP Mobile Top 10 Coverage:")
        for cat, data in list(owasp.items())[:5]:
            status = "✅" if data.get("tested") else "⬜"
            print(f"   {status} {cat}: {data.get('findings', 0)} findings")
    
    print("\n" + "=" * 60)


def main():
    """Main test function"""
    print("=" * 60)
    print("🧪 JARWIS MOBILE SCAN TEST")
    print(f"   Testing SSL Pinning Detection")
    print(f"   Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Step 1: Create test APK
    apk_path = create_minimal_apk()
    
    # Step 2: Login as user2
    token = login_user2()
    if not token:
        print("\n❌ Cannot proceed without authentication")
        print("   Make sure the Jarwis backend is running:")
        print("   cd D:\\jarwis-ai-pentest && .venv\\Scripts\\python.exe -m uvicorn api.server:app --host 0.0.0.0 --port 8000")
        return 1
    
    # Step 3: Start mobile scan
    scan_id = start_mobile_scan(token, apk_path)
    if not scan_id:
        print("\n❌ Failed to start mobile scan")
        return 1
    
    # Step 4: Monitor progress
    final_status = monitor_scan_progress(token, scan_id)
    
    # Step 5: Get and display results
    if final_status and final_status.get("status") == "completed":
        results = get_scan_results(token, scan_id)
        display_results(results)
        print("\n✅ Mobile scan test completed successfully!")
        return 0
    else:
        print("\n⚠️  Scan did not complete successfully")
        return 1


if __name__ == "__main__":
    sys.exit(main())
