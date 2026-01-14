# Module Exports Reference

> **Auto-generated**: 2026-01-14 02:09:34
> **Do not edit manually** - Run `python scripts/generate_architecture_docs.py`

## Critical __init__.py Files

These files control what gets exported and imported at module load time.
**High import counts = fragile wiring**

| File | Imports | Exports | Risk | Has __all__ |
|------|---------|---------|------|-------------|
| `attacks/mobile/__init__.py` | 29 | 64 | 🟠 high | ✅ |
| `api/routes/__init__.py` | 23 | 17 | 🟠 high | ✅ |
| `attacks/cloud/__init__.py` | 19 | 25 | 🟠 high | ✅ |
| `attacks/__init__.py` | 15 | 6 | 🟡 medium | ✅ |
| `core/__init__.py` | 11 | 38 | 🟡 medium | ✅ |
| `attacks/network/__init__.py` | 10 | 44 | 🟡 medium | ✅ |
| `attacks/web/__init__.py` | 6 | 3 | 🟡 medium | ✅ |
| `services/__init__.py` | 5 | 5 | 🟢 low | ✅ |
| `database/__init__.py` | 2 | 11 | 🟢 low | ✅ |
| `shared/__init__.py` | 2 | 8 | 🟢 low | ✅ |
| `api/__init__.py` | 0 | 0 | 🟢 low | ❌ |

## Risk Levels

- 🟢 **Low** (< 5 imports): Safe, minimal wiring
- 🟡 **Medium** (5-15 imports): Moderate complexity
- 🟠 **High** (15-30 imports): Breaking changes likely to cascade
- 🔴 **Critical** (> 30 imports): Any error breaks entire module

## Detailed Exports

### `api/routes/__init__.py` 🟠

**Exports:**
- `api_router`
- `auth_router`
- `users_router`
- `api_keys_router`
- `scans_router`
- `network_router`
- `chat_router`
- `chat_gateway_router`
- `contact_router`
- `payments_router`
- `two_factor_router`
- `scan_otp_router`
- `scan_manual_auth_router`
- `mobile_router`
- `cloud_router`
- `sast_router`
- `health_router`

### `attacks/__init__.py` 🟡

**Exports:**
- `AttackDispatcher`
- `ScanType`
- `PreLoginAttacks`
- `PostLoginAttacks`
- `MobileSecurityScanner`
- `CloudSecurityScanner`

### `attacks/cloud/__init__.py` 🟠

**Exports:**
- `CloudAttacks`
- `CloudSecurityScanner`
- `CloudScannerBase`
- `IaCScanner`
- `IaCSecurityScanner`
- `ComplianceMapper`
- `CloudConfig`
- `CloudFinding`
- `CloudResource`
- `CloudScannerError`
- `AWSSecurityScanner`
- `AWSScanner`
- `AzureSecurityScanner`
- `AzureScanner`
- `GCPSecurityScanner`
- `GCPScanner`
- `KubernetesSecurityScanner`
- `ContainerScanner`
- `ContainerSecurityScanner`
- `CIEMScanner`
- `RuntimeScanner`
- `RuntimeThreatScanner`
- `DriftDetectionScanner`
- `SensitiveDataScanner`
- `SBOMGenerator`

### `attacks/mobile/__init__.py` 🟠

**Exports:**
- `MobileAttacks`
- `MobileSecurityScanner`
- `StaticAnalyzer`
- `AppUnpacker`
- `get_unpacker`
- `RuntimeAnalyzer`
- `MobileAppCrawler`
- `create_app_crawler`
- `CrawledEndpoint`
- `CrawlResult`
- `DynamicAppCrawler`
- `DiscoveredAPI`
- `DynamicCrawlResult`
- `crawl_app_dynamically`
- `FridaSSLBypass`
- `SSLBypassResult`
- `InterceptedSSLRequest`
- `FridaRequestBridge`
- `FridaHttpMessage`
- `AndroidAttackScanner`
- `EmulatorManager`
- `EmulatorConfig`
- `EmulatorStatus`
- `create_emulator_manager`
- `setup_emulator`
- `IOSAttackScanner`
- `IOSSimulatorManager`
- `SimulatorConfig`
- `SimulatorDevice`
- `SimulatorStatus`
- `APIDiscoveryEngine`
- `MobileMITMProxy`
- `create_mobile_proxy`
- `BurpStyleInterceptor`
- `InterceptedTraffic`
- `FridaTrafficIntegration`
- `MobileSQLiScanner`
- `MobileIDORScanner`
- `MobileAPIXSSScanner`
- `BaseMobileScanner`
- `MobileFinding`
- `MobilePenTestOrchestrator`
- `MobileScanConfig`
- `MobileScanContext`
- `MobileEndpoint`
- `MobileVulnerability`
- `MobilePostScanner`
- `MobileAuthDetector`
- `AuthType`
- `create_auth_detector`
- `SecureOTPHandler`
- `SocialAuthHandler`
- `UsernamePasswordHandler`
- `create_otp_handler`
- `create_social_auth_handler`
- `create_password_handler`
- `OTPStatus`
- `AuthSessionStatus`
- `MobileLLMAnalyzer`
- `create_llm_analyzer`
- `DeeplinkScanner`
- `MobileXSSScanner`
- `MobileXSSTester`
- `MobileWebSecurityScanner`

### `attacks/network/__init__.py` 🟡

**Exports:**
- `NetworkAttacks`
- `ScanPhase`
- `ScanResult`
- `Finding`
- `Severity`
- `ScannerRegistry`
- `BaseScanner`
- `ToolInstaller`
- `NetworkOrchestrator`
- `ScanProfile`
- `ScanState`
- `PhaseConfig`
- `NetworkSecurityScanner`
- `PortScanner`
- `ServiceDetector`
- `VulnerabilityScanner`
- `CredentialScanner`
- `NmapScanner`
- `MasscanScanner`
- `RustScanScanner`
- `NucleiScanner`
- `OpenVASScanner`
- `VulnersNmapScanner`
- `NetdiscoverScanner`
- `SNMPScanner`
- `DNSReconScanner`
- `ARPScanScanner`
- `SSLScanScanner`
- `TestSSLScanner`
- `SSLyzeScanner`
- `CrackMapExecScanner`
- `ImpacketScanner`
- `MetasploitScanner`
- `ZeekScanner`
- `SuricataScanner`
- `SnortScanner`
- `TSharkScanner`
- `PORT_SCANNERS`
- `VULN_SCANNERS`
- `ENUM_SCANNERS`
- `SSL_SCANNERS`
- `EXPLOIT_SCANNERS`
- `TRAFFIC_SCANNERS`
- `ALL_SCANNERS`

### `attacks/web/__init__.py` 🟡

**Exports:**
- `WebAttacks`
- `PreLoginAttacks`
- `PostLoginAttacks`

### `core/__init__.py` 🟡

**Exports:**
- `__version__`
- `PenTestRunner`
- `WebScanRunner`
- `MobileScanRunner`
- `BrowserController`
- `ProxyInterceptor`
- `MITMProxy`
- `AIPlanner`
- `ReportGenerator`
- `OOBCallbackServer`
- `OOBIntegration`
- `OOBPayloadTemplates`
- `get_callback_server`
- `ensure_callback_server_running`
- `RequestStore`
- `CapturedRequest`
- `CapturedResponse`
- `AttackEngine`
- `AttackResult`
- `BaseAttack`
- `MobileAttackEngine`
- `MobileAppInfo`
- `MobileVulnerability`
- `SQLInjectionAttack`
- `XSSAttack`
- `NoSQLInjectionAttack`
- `CommandInjectionAttack`
- `SSTIAttack`
- `XXEAttack`
- `IDORAttack`
- `BOLAAttack`
- `BFLAAttack`
- `AuthBypassAttack`
- `JWTAttack`
- `SSRFAttack`
- `CSRFAttack`
- `CORSAttack`
- `PathTraversalAttack`

### `database/__init__.py` 🟢

**Exports:**
- `get_db`
- `engine`
- `AsyncSessionLocal`
- `Base`
- `init_db`
- `close_db`
- `User`
- `ScanHistory`
- `Finding`
- `APIKey`
- `RefreshToken`

### `services/__init__.py` 🟢

**Exports:**
- `AuthService`
- `ScanService`
- `OTPService`
- `DomainService`
- `SubscriptionService`

### `shared/__init__.py` 🟢

**Exports:**
- `APIEndpoints`
- `build_endpoint`
- `PlanLimits`
- `PLAN_LIMITS`
- `TokenLimits`
- `RateLimits`
- `ScanTypes`
- `SeverityLevels`

---

## Best Practices

1. **Use lazy imports** for heavy modules (see `core/scan_orchestrator.py` pattern)
2. **Always define `__all__`** to make exports explicit
3. **Avoid circular imports** - use `importlib.import_module()` inside functions
4. **Test imports in isolation** before committing
