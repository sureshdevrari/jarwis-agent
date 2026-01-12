# SSL Pinning Test Android App

This is a test Android application with SSL certificate pinning implemented for Jarwis security testing.

## Security Features Implemented
- SSL Certificate Pinning using OkHttp CertificatePinner
- Network Security Config with pin-set
- Root/Jailbreak detection
- Frida detection
- Xposed detection

## Intentional Vulnerabilities (for testing)
The app includes intentional security vulnerabilities that Jarwis should detect:

### High Severity
1. Hardcoded API keys and secrets in source code
2. Insecure WebView configuration (JS interface, file access)
3. SQL injection vulnerability
4. Arbitrary command execution via JavaScript interface
5. SSL error handling that ignores certificate errors
6. Debug build left debuggable

### Medium Severity
1. Sensitive data stored in SharedPreferences without encryption
2. Logging of sensitive information
3. Insecure deep link handling
4. External storage file export

### Low Severity
1. Backup allowed
2. Exported broadcast receiver

## SSL Pinning Implementation

### 1. Network Security Config (Android 7.0+)
Located at `res/xml/network_security_config.xml`:
```xml
<pin-set expiration="2027-01-01">
    <pin digest="SHA-256">...</pin>
</pin-set>
```

### 2. OkHttp CertificatePinner
Located in `SecureApiClient.java`:
```java
CertificatePinner certificatePinner = new CertificatePinner.Builder()
    .add(API_HOST, PIN_SHA256_1)
    .add(API_HOST, PIN_SHA256_2)
    .build();
```

## Building

```bash
./gradlew assembleDebug
```

The APK will be at `build/outputs/apk/debug/app-debug.apk`

## Testing with Jarwis

This APK can be scanned with Jarwis to verify:
1. SSL pinning detection works
2. Static analysis finds hardcoded secrets
3. WebView vulnerabilities are detected
4. Root detection bypass (with Frida) works
