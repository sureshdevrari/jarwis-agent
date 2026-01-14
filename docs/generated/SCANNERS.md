# Scanner Registry Reference

> **Auto-generated**: 2026-01-14 02:09:34
> **Do not edit manually** - Run `python scripts/generate_architecture_docs.py`

## Summary

Total scanners discovered: **104**

| Scan Type | Count |
|-----------|-------|
| CLOUD | 13 |
| MOBILE | 13 |
| NETWORK | 12 |
| SAST | 9 |
| WEB | 57 |

## Registry Files

| Registry | Location | Purpose |
|----------|----------|---------|
| **ScannerRegistry** | `attacks/registry.py` | ✅ UNIFIED - Use this one |
| UnifiedScannerRegistry | `attacks/unified_registry.py` | Health checking, fallbacks |
| scanner_registry | `attacks/scanner_registry.py` | Auto-discovery |

**⚠️ Use `attacks/registry.py` for all new code**

## CLOUD Scanners (13)

| Scanner | Class | OWASP | CWE |
|---------|-------|-------|-----|
| `AWSSecurityScanner` | `AWSSecurityScanner` | - | - |
| `AzureSecurityScanner` | `AzureSecurityScanner` | - | - |
| `CIEMScanner` | `CIEMScanner` | - | - |
| `CloudScanner` | `CloudScanner` | - | - |
| `CloudSecurityScanner` | `CloudSecurityScanner` | - | - |
| `ContainerScanner` | `ContainerScanner` | - | - |
| `DriftDetectionScanner` | `DriftDetectionScanner` | - | - |
| `GCPSecurityScanner` | `GCPSecurityScanner` | - | - |
| `IaCScanner` | `IaCScanner` | - | - |
| `KubernetesSecurityScanner` | `KubernetesSecurityScanner` | - | - |
| `RuntimeScanner` | `RuntimeScanner` | - | - |
| `ScannerMetadata` | `ScannerMetadata` | - | - |
| `SensitiveDataScanner` | `SensitiveDataScanner` | - | - |

## MOBILE Scanners (13)

| Scanner | Class | OWASP | CWE |
|---------|-------|-------|-----|
| `AndroidAttackScanner` | `AndroidAttackScanner` | - | - |
| `BaseMobileScanner` | `BaseMobileScanner` | - | - |
| `DeepCodeScanner` | `DeepCodeScanner` | - | - |
| `DeepLinkHijackingScanner` | `DeepLinkHijackingScanner` | - | - |
| `IOSAttackScanner` | `IOSAttackScanner` | - | - |
| `IOSDeepCodeScanner` | `IOSDeepCodeScanner` | - | - |
| `MobilePostMethodScanner` | `MobilePostMethodScanner` | - | - |
| `MobileSecurityScanner` | `MobileSecurityScanner` | - | - |
| `MobileSecurityScanner` | `MobileSecurityScanner` | - | - |
| `MobileXSSScanner` | `MobileXSSScanner` | - | - |
| `mobile_idor` | `MobileIDORScanner` | M3 | CWE-639 |
| `mobile_sqli` | `MobileSQLiScanner` | M4 | CWE-89 |
| `mobile_xss` | `MobileXSSScanner` | M4 | CWE-79 |

## NETWORK Scanners (12)

| Scanner | Class | OWASP | CWE |
|---------|-------|-------|-----|
| `BaseScanner` | `BaseScanner` | - | - |
| `CrackMapExecScanner` | `CrackMapExecScanner` | - | - |
| `CredentialScanner` | `CredentialScanner` | - | - |
| `MetasploitAdvancedScanner` | `MetasploitAdvancedScanner` | - | - |
| `NetdiscoverScanner` | `NetdiscoverScanner` | - | - |
| `NetworkSecurityScanner` | `NetworkSecurityScanner` | - | - |
| `NmapScanner` | `NmapScanner` | - | - |
| `NucleiScanner` | `NucleiScanner` | - | - |
| `PortScanner` | `PortScanner` | - | - |
| `SSLScanScanner` | `SSLScanScanner` | - | - |
| `VulnerabilityScanner` | `VulnerabilityScanner` | - | - |
| `ZeekScanner` | `ZeekScanner` | - | - |

## SAST Scanners (9)

| Scanner | Class | OWASP | CWE |
|---------|-------|-------|-----|
| `AWSCodeCommitScanner` | `AWSCodeCommitScanner` | - | - |
| `AzureDevOpsScanner` | `AzureDevOpsScanner` | - | - |
| `BitbucketScanner` | `BitbucketScanner` | - | - |
| `DependencyScanner` | `DependencyScanner` | - | - |
| `GenericGitScanner` | `GenericGitScanner` | - | - |
| `GitHubScanner` | `GitHubScanner` | - | - |
| `GitLabScanner` | `GitLabScanner` | - | - |
| `GiteaScanner` | `GiteaScanner` | - | - |
| `SecretScanner` | `SecretScanner` | - | - |

## WEB Scanners (57)

| Scanner | Class | OWASP | CWE |
|---------|-------|-------|-----|
| `APIScanner` | `APIScanner` | - | - |
| `APISecurityScanner` | `APISecurityScanner` | - | - |
| `AccessControlScanner` | `AccessControlScanner` | - | - |
| `AdvancedXSSScanner` | `AdvancedXSSScanner` | - | - |
| `AuthBypassScanner` | `AuthBypassScanner` | - | - |
| `AuthenticatedScannerMixin` | `AuthenticatedScannerMixin` | - | - |
| `AuthenticationScanner` | `AuthenticationScanner` | - | - |
| `BaseAttackScanner` | `BaseAttackScanner` | - | - |
| `BusinessLogicScanner` | `BusinessLogicScanner` | - | - |
| `CORSScanner` | `CORSScanner` | - | - |
| `CSRFScanner` | `CSRFScanner` | - | - |
| `CaptchaBypassScanner` | `CaptchaBypassScanner` | - | - |
| `ClickjackingScanner` | `ClickjackingScanner` | - | - |
| `FileUploadScanner` | `FileUploadScanner` | - | - |
| `GraphQLScanner` | `GraphQLScanner` | - | - |
| `HTTPParameterPollutionScanner` | `HTTPParameterPollutionScanner` | - | - |
| `HTTPSmugglingScanner` | `HTTPSmugglingScanner` | - | - |
| `HostHeaderInjectionScanner` | `HostHeaderInjectionScanner` | - | - |
| `IDORScanner` | `IDORScanner` | - | - |
| `InformationDisclosureScanner` | `InformationDisclosureScanner` | - | - |
| `InjectionScanner` | `InjectionScanner` | - | - |
| `JWTAttackScanner` | `JWTAttackScanner` | - | - |
| `LDAPInjectionScanner` | `LDAPInjectionScanner` | - | - |
| `Log4ShellScanner` | `Log4ShellScanner` | - | - |
| `MisconfigScanner` | `MisconfigScanner` | - | - |
| `OAuthSecurityScanner` | `OAuthSecurityScanner` | - | - |
| `OAuthVulnScanner` | `OAuthVulnScanner` | - | - |
| `OpenRedirectScanner` | `OpenRedirectScanner` | - | - |
| `PathTraversalScanner` | `PathTraversalScanner` | - | - |
| `PostLoginCSRFScanner` | `PostLoginCSRFScanner` | - | - |
| `PostLoginIDORScanner` | `PostLoginIDORScanner` | - | - |
| `PostMethodScanner` | `PostMethodScanner` | - | - |
| `PostMethodScanner` | `PostMethodScanner` | - | - |
| `PrototypePollutionScanner` | `PrototypePollutionScanner` | - | - |
| `RaceConditionScanner` | `RaceConditionScanner` | - | - |
| `RateLimitBypassScanner` | `RateLimitBypassScanner` | - | - |
| `ResponseManipulationScanner` | `ResponseManipulationScanner` | - | - |
| `ResponseSwapScanner` | `ResponseSwapScanner` | - | - |
| `SQLInjectionScanner` | `SQLInjectionScanner` | - | - |
| `SSRFScanner` | `SSRFScanner` | - | - |
| `SSRFScanner` | `SSRFScanner` | - | - |
| `SSTIScanner` | `SSTIScanner` | - | - |
| `SecurityHeadersScanner` | `SecurityHeadersScanner` | - | - |
| `SensitiveDataScanner` | `SensitiveDataScanner` | - | - |
| `SessionSecurityScanner` | `SessionSecurityScanner` | - | - |
| `StoredXSSScanner` | `StoredXSSScanner` | - | - |
| `StoredXSSScanner` | `StoredXSSScanner` | - | - |
| `SubdomainTakeoverScanner` | `SubdomainTakeoverScanner` | - | - |
| `UploadScanner` | `UploadScanner` | - | - |
| `WebSocketScanner` | `WebSocketScanner` | - | - |
| `XSSReflectedScanner` | `XSSReflectedScanner` | - | - |
| `XSSReflectedScanner` | `XSSReflectedScanner` | - | - |
| `XSSScanner` | `XSSScanner` | - | - |
| `XXEScanner` | `XXEScanner` | - | - |
| `file_upload_v2` | `FileUploadScannerV2` | - | - |
| `input_field_attacker` | `InputFieldAttacker` | - | - |
| `sqli_v2` | `SQLInjectionScannerV2` | A03:2021 | CWE-89 |

---

## Adding New Scanners

1. Create scanner in appropriate folder: `attacks/{type}/{category}/`
2. Inherit from `BaseAttackScanner`
3. Set class attributes: `scanner_name`, `owasp_category`, `cwe_id`
4. Scanner will be auto-discovered by `ScannerRegistry.initialize()`

**Do NOT** manually register scanners - discovery is automatic.
