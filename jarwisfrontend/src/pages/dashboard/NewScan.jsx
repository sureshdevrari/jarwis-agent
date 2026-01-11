// src/pages/dashboard/NewScan.jsx - Full Scan Support with Web/Mobile/Cloud/Network/SAST
import { useState, useEffect, useCallback } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { AlertTriangle, Globe, Smartphone, Rocket, Info, Lock, Wifi, Code } from "lucide-react";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import { scanAPI, mobileScanAPI, cloudScanAPI, networkScanAPI, domainVerificationAPI, sastScanAPI } from "../../services/api";
import NetworkScanConfig from "../../components/scan/NetworkScanConfig";

// Subscription limit warning banner
const SubscriptionLimitBanner = ({ usage, isDarkMode, onUpgrade }) => {
  const scansLimit = usage?.scans;
  if (!scansLimit || scansLimit.unlimited) return null;
  
  const remaining = scansLimit.remaining;
  const percentage = scansLimit.percentage;
  
  // Show warning if usage is above 70%
  if (percentage < 70) return null;
  
  const isAtLimit = remaining <= 0;
  
  return (
    <div className={`mb-6 p-4 rounded-lg border ${
      isAtLimit 
        ? isDarkMode ? "bg-red-500/10 border-red-500/30" : "bg-red-50 border-red-200"
        : isDarkMode ? "bg-amber-500/10 border-amber-500/30" : "bg-amber-50 border-amber-200"
    }`}>
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <span className="text-2xl">{isAtLimit ? "" : <AlertTriangle className="w-6 h-6" />}</span>
          <div>
            <p className={`font-semibold ${
              isAtLimit 
                ? isDarkMode ? "text-red-400" : "text-red-700"
                : isDarkMode ? "text-amber-400" : "text-amber-700"
            }`}>
              {isAtLimit 
                ? "Monthly Scan Limit Reached" 
                : `${remaining} Scan${remaining !== 1 ? 's' : ''} Remaining`}
            </p>
            <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              {isAtLimit 
                ? "You've used all your scans for this month. Upgrade for more."
                : `You've used ${scansLimit.current} of ${scansLimit.max} scans this month.`}
            </p>
          </div>
        </div>
        <button
          onClick={onUpgrade}
          className={`px-4 py-2 rounded-lg font-medium transition-colors ${
            isAtLimit
              ? "bg-gradient-to-r from-blue-500 to-purple-500 text-white hover:from-blue-600 hover:to-purple-600"
              : isDarkMode 
                ? "bg-amber-500/20 text-amber-400 hover:bg-amber-500/30" 
                : "bg-amber-100 text-amber-700 hover:bg-amber-200"
          }`}
        >
          {isAtLimit ? "Upgrade Now" : "View Plans"}
        </button>
      </div>
      
      {/* Progress bar */}
      <div className={`mt-3 h-2 rounded-full overflow-hidden ${isDarkMode ? "bg-gray-700" : "bg-gray-200"}`}>
        <div 
          className={`h-full rounded-full transition-all ${
            isAtLimit ? "bg-red-500" : percentage > 90 ? "bg-amber-500" : "bg-blue-500"
          }`}
          style={{ width: `${Math.min(percentage, 100)}%` }}
        />
      </div>
    </div>
  );
};

const NewScan = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { isDarkMode } = useTheme();
  const { canPerformAction, getActionLimit, getAllUsageStats, checkActionAllowed, refreshSubscription, subscription } = useSubscription();

  // Scan type from navigation state
  const [scanType, setScanType] = useState(
    location.state?.scanType || "web"
  );

  // Web scan form
  const [webForm, setWebForm] = useState({
    domain: "",
    username: "",
    password: "",
    apiToken: "",
    scope: "Web + API (recommended)",
    notes: "",
  });

  // Mobile scan form
  const [mobileForm, setMobileForm] = useState({
    appFile: null,
    appName: "",
    platform: "android",
    sslPinningBypass: true,
    fridaScripts: true,
    interceptTraffic: true,
    notes: "",
  });

  // Cloud scan form
  const [cloudForm, setCloudForm] = useState({
    provider: "aws",
    accessKeyId: "",
    secretAccessKey: "",
    region: "us-east-1",
    subscriptionId: "",
    tenantId: "",
    clientId: "",
    clientSecret: "",
    projectId: "",
    serviceAccountKey: null,
    notes: "",
  });

  // Network scan form - uses NetworkScanConfig component
  const [networkConfig, setNetworkConfig] = useState({
    networkType: "public",
    targets: "",
    profile: "standard",
    customPhases: [],
    portRange: "top1000",
    customPorts: "",
    useAgent: false,
    agentId: "",
    serviceDetection: true,
    vulnScan: true,
    sslAudit: true,
    safeChecks: true,
    maxConcurrentHosts: 10,
    timeoutPerHost: 300,
    rateLimit: 100,
    credentials: {
      enabled: false,
      ssh: { enabled: false, username: "", password: "", privateKey: "" },
      windows: { enabled: false, username: "", password: "", domain: "" },
      snmp: { enabled: false, community: "public", version: "2c" },
    },
  });

  // Network config change handler
  const handleNetworkConfigChange = useCallback((newConfig) => {
    setNetworkConfig(newConfig);
  }, []);

  // SAST (Source Code Review) form
  const [sastForm, setSastForm] = useState({
    repositoryUrl: "",
    branch: "main",
    accessToken: "",
    provider: "github",  // github, gitlab, bitbucket
    useOAuth: false,     // Use OAuth connection instead of PAT
    scanSecrets: true,
    scanDependencies: true,
    scanCode: true,
    languages: [],       // Empty = auto-detect
    excludePaths: "",    // Comma-separated paths to exclude
    notes: "",
  });

  // SCM connections state
  const [scmConnections, setScmConnections] = useState([]);
  const [scmRepositories, setScmRepositories] = useState([]);
  const [loadingConnections, setLoadingConnections] = useState(false);
  const [loadingRepos, setLoadingRepos] = useState(false);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [validationErrors, setValidationErrors] = useState({});

  // Validate domain/URL format
  const validateDomain = (domain) => {
    if (!domain || domain.trim() === "") {
      return "Domain is required";
    }
    
    // Remove protocol if present for validation
    let cleanDomain = domain.trim();
    if (cleanDomain.startsWith("http://") || cleanDomain.startsWith("https://")) {
      try {
        const url = new URL(cleanDomain);
        cleanDomain = url.hostname;
      } catch {
        return "Invalid URL format";
      }
    }
    
    // Basic domain validation regex
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    
    // Also allow localhost and IP addresses for testing
    const localhostRegex = /^localhost(:\d+)?$/;
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/;
    
    if (!domainRegex.test(cleanDomain) && !localhostRegex.test(cleanDomain) && !ipRegex.test(cleanDomain)) {
      return "Please enter a valid domain (e.g., example.com)";
    }
    
    return null;
  };

  const handleWebInputChange = (e) => {
    const { name, value } = e.target;
    setWebForm((prev) => ({ ...prev, [name]: value }));
    
    // Clear validation error for this field when user types
    if (validationErrors[name]) {
      setValidationErrors((prev) => ({ ...prev, [name]: null }));
    }
  };

  const handleMobileInputChange = (e) => {
    const { name, value, type, checked, files } = e.target;
    if (type === "file") {
      setMobileForm((prev) => ({ ...prev, [name]: files[0] }));
    } else if (type === "checkbox") {
      setMobileForm((prev) => ({ ...prev, [name]: checked }));
    } else {
      setMobileForm((prev) => ({ ...prev, [name]: value }));
    }
  };

  // Note: handleNetworkInputChange removed - using NetworkScanConfig component

  const handleCloudInputChange = (e) => {
    const { name, value, files } = e.target;
    if (name === "serviceAccountKey") {
      setCloudForm((prev) => ({ ...prev, [name]: files[0] }));
    } else {
      setCloudForm((prev) => ({ ...prev, [name]: value }));
    }
  };

  // SAST form handlers
  const handleSASTInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    if (type === "checkbox") {
      setSastForm((prev) => ({ ...prev, [name]: checked }));
    } else {
      setSastForm((prev) => ({ ...prev, [name]: value }));
    }
    
    // Clear validation error for this field
    if (validationErrors[name]) {
      setValidationErrors((prev) => ({ ...prev, [name]: null }));
    }
  };

  // Load SCM connections when SAST tab is selected
  useEffect(() => {
    if (scanType === "sast") {
      loadSCMConnections();
    }
  }, [scanType]);

  const loadSCMConnections = async () => {
    setLoadingConnections(true);
    try {
      const response = await sastScanAPI.listConnections();
      setScmConnections(response.connections || []);
    } catch (err) {
      console.error("Failed to load SCM connections:", err);
    } finally {
      setLoadingConnections(false);
    }
  };

  const loadRepositories = async (provider) => {
    setLoadingRepos(true);
    try {
      const response = await sastScanAPI.listRepositories(provider);
      setScmRepositories(response.repositories || []);
    } catch (err) {
      console.error("Failed to load repositories:", err);
      setScmRepositories([]);
    } finally {
      setLoadingRepos(false);
    }
  };

  const handleConnectGitHub = async () => {
    try {
      const response = await sastScanAPI.connectGitHub();
      if (response.oauth_url) {
        window.location.href = response.oauth_url;
      }
    } catch (err) {
      setError("Failed to connect to GitHub: " + (err.message || "Unknown error"));
    }
  };

  const handleConnectGitLab = async () => {
    try {
      const response = await sastScanAPI.connectGitLab();
      if (response.oauth_url) {
        window.location.href = response.oauth_url;
      }
    } catch (err) {
      setError("Failed to connect to GitLab: " + (err.message || "Unknown error"));
    }
  };

  const handleWebSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);
    setValidationErrors({});

    // Validate domain first
    const domainError = validateDomain(webForm.domain);
    if (domainError) {
      setValidationErrors({ domain: domainError });
      setError(domainError);
      setIsSubmitting(false);
      return;
    }

    try {
      // Run preflight checks first
      try {
        const preflightResult = await scanAPI.runPreflight();
        if (!preflightResult.passed) {
          const errors = preflightResult.issues
            .filter(i => i.severity === 'error')
            .map(i => i.message)
            .join('; ');
          if (errors) {
            setError(`System check failed: ${errors}. Please contact support.`);
            setIsSubmitting(false);
            return;
          }
        }
      } catch (preflightErr) {
        console.warn("Preflight check skipped:", preflightErr);
        // Continue anyway if preflight endpoint not available
      }

      // Check subscription limits before starting scan
      const canScan = canPerformAction("startScan");
      if (!canScan) {
        // Double-check with server
        const serverCheck = await checkActionAllowed("start_scan");
        if (!serverCheck.allowed) {
          throw new Error(serverCheck.message || "You've reached your scan limit. Please upgrade your plan.");
        }
      }

      // Extract domain from URL for verification check
      const targetUrl = webForm.domain.startsWith("http")
        ? webForm.domain
        : `https://${webForm.domain}`;
      
      let domainPart;
      try {
        domainPart = new URL(targetUrl).hostname;
      } catch (urlError) {
        throw new Error("Invalid URL format. Please enter a valid domain.");
      }

      // If credentials are provided, require domain verification (except for developer plan)
      const hasCredentials = webForm.username || webForm.password || webForm.apiToken;
      const isDeveloperPlan = subscription?.plan === "developer";
      
      if (hasCredentials && !isDeveloperPlan) {
        try {
          const verificationStatus = await domainVerificationAPI.getVerificationStatus(domainPart);
          if (!verificationStatus.verified) {
            // Show user-friendly dialog explaining why verification is needed
            const userChoice = window.confirm(
              `🔒 Domain Verification Required\n\n` +
              `For security reasons, credential-based scans require proof that you own or have authorization to test "${domainPart}".\n\n` +
              `This protects against unauthorized penetration testing of third-party websites.\n\n` +
              `Options:\n` +
              `• Click OK to verify domain ownership (takes 2-5 minutes)\n` +
              `• Click Cancel to scan WITHOUT credentials (unauthenticated scan only)\n\n` +
              `Note: If your email domain matches the target domain, verification may be automatic.`
            );
            
            if (userChoice) {
              // User chose to verify domain
              navigate("/dashboard/verify-domain", {
                state: { 
                  scanConfig: { 
                    domain: domainPart, 
                    scope: webForm.scope,
                    hasCredentials: true,
                    // Pass credentials to return after verification
                    returnData: {
                      username: webForm.username,
                      password: webForm.password,
                      apiToken: webForm.apiToken,
                    }
                  },
                  returnPath: "/dashboard/new-scan",
                  message: "Domain verification is required for credential-based scans to protect against unauthorized testing."
                }
              });
              return;
            } else {
              // User chose to scan without credentials - clear them and continue
              setWebForm(prev => ({
                ...prev,
                username: "",
                password: "",
                apiToken: ""
              }));
              // Continue with unauthenticated scan
              setError(null);
              // Show info message that we're proceeding without credentials
              console.log("Proceeding with unauthenticated scan (user declined domain verification)");
            }
          }
        } catch (verifyError) {
          console.warn("Domain verification check failed:", verifyError);
          // If verification service is unavailable, prompt user
          const confirmScan = window.confirm(
            "⚠️ Domain Verification Recommended\n\n" +
            "We couldn't check if this domain is verified. " +
            "For credential-based scans, we recommend verifying domain ownership first.\n\n" +
            "Click OK to verify domain, or Cancel to proceed anyway."
          );
          if (confirmScan) {
            navigate("/dashboard/verify-domain", {
              state: { 
                scanConfig: { domain: domainPart, scope: webForm.scope },
                returnPath: "/dashboard/new-scan"
              }
            });
            return;
          }
        }
      }

      const config = {
        target: {
          url: targetUrl,
          scope: [webForm.domain],
        },
        auth: {
          username: webForm.username || null,
          password: webForm.password || null,
          api_token: webForm.apiToken || null,
        },
        attacks: {
          owasp: {
            a01_broken_access: true,
            a02_crypto: true,
            a03_injection: true,
            a05_security_misconfig: true,
            a07_xss: true,
          },
        },
      };

      console.log("Starting scan with config:", config);
      const response = await scanAPI.startScan(config);
      console.log("Scan response:", response);

      if (response.scan_id) {
        // Refresh subscription data to update usage counts
        refreshSubscription();
        
        navigate("/dashboard/scanning", {
          state: { scanId: response.scan_id, scanType: "web", scanConfig: webForm },
        });
      } else {
        throw new Error(response.error || response.detail || "Failed to start scan");
      }
    } catch (err) {
      console.error("Start scan error:", err);
      console.error("Error response:", err.response?.data);
      
      // Extract error message from various error formats
      let errorMessage = "Failed to start scan";
      if (err.response?.data?.detail) {
        // FastAPI error format
        const detail = err.response.data.detail;
        if (typeof detail === "string") {
          errorMessage = detail;
        } else if (detail.message) {
          errorMessage = detail.message;
        } else if (detail.error) {
          errorMessage = detail.error;
        }
      } else if (err.message) {
        errorMessage = err.message;
      }
      
      setError(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleMobileSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      // Check subscription for mobile pentesting feature
      const canUseMobile = canPerformAction("useMobileAppTesting");
      if (!canUseMobile) {
        const serverCheck = await checkActionAllowed("mobile_pentest");
        if (!serverCheck.allowed) {
          throw new Error(serverCheck.message || "Mobile app testing requires a Professional or Enterprise plan.");
        }
      }
      
      if (!mobileForm.appFile) {
        throw new Error("Please select an APK or IPA file");
      }

      const config = {
        app_name: mobileForm.appName || mobileForm.appFile.name,
        platform: mobileForm.platform,
        ssl_pinning_bypass: mobileForm.sslPinningBypass,
        frida_scripts: mobileForm.fridaScripts,
        intercept_traffic: mobileForm.interceptTraffic,
      };

      const response = await mobileScanAPI.startScan(mobileForm.appFile, config);

      if (response.scan_id) {
        navigate("/dashboard/scanning", {
          state: { scanId: response.scan_id, scanType: "mobile" },
        });
      } else {
        throw new Error(response.error || "Failed to start mobile scan");
      }
    } catch (err) {
      console.error("Start mobile scan error:", err);
      setError(err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCloudSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      let credentials = {};

      switch (cloudForm.provider) {
        case "aws":
          credentials = {
            access_key_id: cloudForm.accessKeyId,
            secret_access_key: cloudForm.secretAccessKey,
            region: cloudForm.region,
          };
          break;
        case "azure":
          credentials = {
            subscription_id: cloudForm.subscriptionId,
            tenant_id: cloudForm.tenantId,
            client_id: cloudForm.clientId,
            client_secret: cloudForm.clientSecret,
          };
          break;
        case "gcp":
          credentials = {
            project_id: cloudForm.projectId,
            service_account_key: cloudForm.serviceAccountKey,
          };
          break;
      }

      const response = await cloudScanAPI.startScan(cloudForm.provider, credentials);

      if (response.scan_id) {
        navigate("/dashboard/scanning", {
          state: { scanId: response.scan_id, scanType: "cloud" },
        });
      } else {
        throw new Error(response.error || "Failed to start cloud scan");
      }
    } catch (err) {
      console.error("Start cloud scan error:", err);
      setError(err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleNetworkSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      if (!networkConfig.targets.trim()) {
        setError("Please specify at least one target (IP, hostname, or CIDR)");
        setIsSubmitting(false);
        return;
      }

      // Check if private network requires agent
      if ((networkConfig.networkType === "private" || networkConfig.networkType === "cloud_vpc") && !networkConfig.agentId) {
        setError("Private network scans require a Jarwis Agent. Please register and select an agent.");
        setIsSubmitting(false);
        return;
      }

      // Build port range value
      let portRangeValue = networkConfig.portRange;
      if (networkConfig.portRange === "custom") {
        portRangeValue = networkConfig.customPorts || "1-65535";
      } else if (networkConfig.portRange === "top100") {
        portRangeValue = "top100";
      } else if (networkConfig.portRange === "top1000") {
        portRangeValue = "top1000";
      } else if (networkConfig.portRange === "common") {
        portRangeValue = "common";
      } else if (networkConfig.portRange === "all") {
        portRangeValue = "1-65535";
      }

      // Build credentials object
      const credentials = networkConfig.credentials.enabled ? {
        enabled: true,
        ssh: networkConfig.credentials.ssh.enabled ? {
          username: networkConfig.credentials.ssh.username,
          password: networkConfig.credentials.ssh.password,
          private_key: networkConfig.credentials.ssh.privateKey,
        } : null,
        windows: networkConfig.credentials.windows.enabled ? {
          username: networkConfig.credentials.windows.username,
          password: networkConfig.credentials.windows.password,
          domain: networkConfig.credentials.windows.domain,
        } : null,
        snmp: networkConfig.credentials.snmp.enabled ? {
          community: networkConfig.credentials.snmp.community,
          version: networkConfig.credentials.snmp.version,
        } : null,
      } : { enabled: false };

      const response = await networkScanAPI.startScan({
        targets: networkConfig.targets,
        profile: networkConfig.profile,
        port_range: portRangeValue,
        service_detection: networkConfig.serviceDetection,
        vuln_scan_enabled: networkConfig.vulnScan,
        ssl_audit_enabled: networkConfig.sslAudit,
        safe_checks: networkConfig.safeChecks,
        use_agent: networkConfig.useAgent,
        agent_id: networkConfig.agentId || null,
        credentials: credentials,
        max_concurrent_hosts: networkConfig.maxConcurrentHosts,
        timeout_per_host: networkConfig.timeoutPerHost,
        rate_limit: networkConfig.rateLimit,
      });

      if (response.scan_id) {
        // Refresh subscription data to update usage counts
        refreshSubscription();
        
        navigate("/dashboard/scanning", {
          state: { scanId: response.scan_id, scanType: "network" },
        });
      } else {
        throw new Error(response.error || response.detail || "Failed to start network scan");
      }
    } catch (err) {
      console.error("Start network scan error:", err);
      // Extract error message from various error formats
      let errorMessage = "Failed to start network scan";
      if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        if (typeof detail === "string") {
          errorMessage = detail;
        } else if (detail.message) {
          errorMessage = detail.message;
        }
      } else if (err.message) {
        errorMessage = err.message;
      }
      setError(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  // SAST scan submit handler
  const handleSASTSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);
    setValidationErrors({});

    try {
      // Validate repository URL
      if (!sastForm.repositoryUrl && !sastForm.useOAuth) {
        setValidationErrors({ repositoryUrl: "Repository URL is required" });
        setError("Please enter a repository URL or connect via OAuth");
        setIsSubmitting(false);
        return;
      }

      // Validate access token if not using OAuth
      if (!sastForm.useOAuth && !sastForm.accessToken) {
        setValidationErrors({ accessToken: "Access token is required" });
        setError("Please provide a Personal Access Token or connect via OAuth");
        setIsSubmitting(false);
        return;
      }

      // Check subscription limits
      const canScan = canPerformAction("startScan");
      if (!canScan) {
        setError("You've reached your scan limit. Please upgrade your plan.");
        navigate("/pricing");
        setIsSubmitting(false);
        return;
      }

      // Prepare scan configuration
      const scanConfig = {
        repository_url: sastForm.repositoryUrl,
        branch: sastForm.branch || "main",
        access_token: sastForm.accessToken,
        scan_secrets: sastForm.scanSecrets,
        scan_dependencies: sastForm.scanDependencies,
        scan_code: sastForm.scanCode,
        languages: sastForm.languages.length > 0 ? sastForm.languages : null,
        exclude_paths: sastForm.excludePaths 
          ? sastForm.excludePaths.split(",").map(p => p.trim()).filter(p => p)
          : null,
        notes: sastForm.notes,
      };

      const response = await sastScanAPI.startScan(scanConfig);

      if (response.scan_id) {
        refreshSubscription();
        navigate("/dashboard/scanning", {
          state: { scanId: response.scan_id, scanType: "sast" },
        });
      } else {
        throw new Error(response.error || "Failed to start SAST scan");
      }
    } catch (err) {
      console.error("Start SAST scan error:", err);
      let errorMessage = "Failed to start SAST scan";
      if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        errorMessage = typeof detail === "string" ? detail : detail.message || errorMessage;
      } else if (err.message) {
        errorMessage = err.message;
      }
      setError(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  const scopeOptions = [
    "Web only (pre‑login)",
    "Web + post‑login (form/session)",
    "API only",
    "Web + API (recommended)",
  ];

  const inputClass = isDarkMode
    ? "w-full px-4 py-3 bg-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-xl text-white placeholder-gray-400 focus:border-blue-500/50 focus:ring-2 focus:ring-blue-500/20 transition-all duration-300 outline-none"
    : "w-full px-4 py-3 bg-white border border-gray-300 rounded-xl text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-300 outline-none shadow-sm";

  const labelClass = isDarkMode
    ? "block text-sm font-semibold text-white uppercase tracking-wide"
    : "block text-sm font-semibold text-gray-900 uppercase tracking-wide";

  return (
    <MiftyJarwisLayout>
      <div className="space-y-8 p-6">
        {/* Subscription Limit Warning */}
        <SubscriptionLimitBanner 
          usage={getAllUsageStats()} 
          isDarkMode={isDarkMode}
          onUpgrade={() => navigate("/pricing")}
        />

        {/* Header */}
        <div>
          <h1
            className={
              isDarkMode
                ? "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400 mb-4"
                : "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-cyan-600 mb-4"
            }
          >
            New Scan Setup
          </h1>

          {/* Scan Type Tabs */}
          <div className="flex gap-2 mb-6 flex-wrap">
            {[
              { id: "web", label: "Web Scan", icon: Globe, color: "blue", feature: null },
              { id: "mobile", label: "Mobile Scan", icon: Smartphone, color: "purple", feature: "useMobileAppTesting" },
              { id: "network", label: "Network Scan", icon: Wifi, color: "cyan", feature: "useNetworkScanning" },
              { id: "cloud", label: "Cloud Scan", icon: Rocket, color: "amber", feature: "useCloudScanning" },
              { id: "sast", label: "Code Review", icon: Code, color: "emerald", feature: "useSASTScanning" },
            ].map((type) => {
              const isLocked = type.feature && !canPerformAction(type.feature);
              return (
                <button
                  key={type.id}
                  onClick={() => {
                    if (isLocked) {
                      navigate("/pricing");
                    } else {
                      setScanType(type.id);
                    }
                  }}
                  className={`px-4 py-2 rounded-xl font-medium transition-all duration-300 relative ${
                    scanType === type.id && !isLocked
                      ? type.id === "web"
                        ? "bg-blue-600 text-white"
                        : type.id === "mobile"
                        ? "bg-purple-600 text-white"
                        : type.id === "network"
                        ? "bg-cyan-600 text-white"
                        : type.id === "sast"
                        ? "bg-emerald-600 text-white"
                        : "bg-amber-600 text-white"
                      : isLocked
                      ? isDarkMode
                        ? "bg-slate-800/50 border border-slate-700/50 text-gray-500 cursor-not-allowed"
                        : "bg-gray-200 border border-gray-300 text-gray-400 cursor-not-allowed"
                      : isDarkMode
                      ? "bg-slate-700/50 border border-slate-600/50 text-gray-300 hover:bg-slate-600/50"
                      : "bg-gray-100 border border-gray-300 text-gray-700 hover:bg-gray-200"
                  }`}
                >
                  {type.icon && <span className="mr-1"><type.icon className="w-4 h-4 inline" /></span>}{type.label}
                  {isLocked && (
                    <span className="ml-2 text-xs"><Lock className="w-3 h-3 inline" /></span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Error Display */}
          {error && (
            <div className="p-4 mb-4 bg-red-500/20 border border-red-500/50 rounded-xl text-red-400">
              {error}
            </div>
          )}

          {/* Info Banner */}
          <div
            className={
              isDarkMode
                ? "p-6 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/20 rounded-2xl backdrop-blur-xl"
                : "p-6 bg-gradient-to-r from-cyan-50 to-blue-50 border border-cyan-200 rounded-2xl shadow-lg"
            }
          >
            <p
              className={
                isDarkMode
                  ? "text-gray-300 leading-relaxed"
                  : "text-gray-700 leading-relaxed"
              }
            >
              <strong
                className={isDarkMode ? "text-cyan-300" : "text-cyan-700"}
              >
                {scanType === "web" && "Web Scan: "}
                {scanType === "mobile" && "Mobile Scan: "}
                {scanType === "network" && "Network Scan: "}
                {scanType === "cloud" && "Cloud Scan: "}
                {scanType === "sast" && "Code Review: "}
              </strong>
              {scanType === "web" &&
                "Provide your target domain, credentials (optional), and scope. Jarwis will perform OWASP Top 10 testing."}
              {scanType === "mobile" &&
                "Upload your APK/IPA file. Jarwis will analyze the app, bypass SSL pinning with Frida, and intercept traffic."}
              {scanType === "network" &&
                "Specify target hosts/IPs and port ranges. Jarwis will perform host discovery, port scanning, and protocol analysis."}
              {scanType === "cloud" &&
                "Connect your cloud provider. Jarwis will audit IAM, storage, and security configurations."}
              {scanType === "sast" &&
                "Connect your GitHub/GitLab repository. Jarwis will scan for secrets, vulnerable dependencies, and code vulnerabilities."}
            </p>
          </div>
        </div>

        {/* Web Scan Form */}
        {scanType === "web" && (
          <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
          <form onSubmit={handleWebSubmit} className="max-w-4xl space-y-6">
            <div className="space-y-2">
              <label htmlFor="domain" className={labelClass}>
                Target Domain *
              </label>
              <input
                id="domain"
                name="domain"
                type="text"
                placeholder="e.g., portal.example.com"
                value={webForm.domain}
                onChange={handleWebInputChange}
                required
                className={`${inputClass} ${validationErrors.domain ? (isDarkMode ? "border-red-500/50 focus:border-red-400" : "border-red-400 focus:border-red-500") : ""}`}
              />
              {validationErrors.domain && (
                <p className="text-sm text-red-400 mt-1 flex items-center gap-1">
                  <span>⚠️</span> {validationErrors.domain}
                </p>
              )}
              <p className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                Enter the target website domain. Use HTTPS for secure connections.
              </p>
            </div>

            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <label className={labelClass}>Authentication (optional)</label>
                <span className={`text-xs px-2 py-0.5 rounded-full ${isDarkMode ? "bg-amber-500/20 text-amber-400" : "bg-amber-100 text-amber-700"}`}>
                  Requires Domain Verification
                </span>
              </div>
              <p className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"} -mt-2`}>
                Adding credentials enables authenticated testing. Domain ownership verification is required for security.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <input
                  name="username"
                  type="text"
                  placeholder="Username or email"
                  value={webForm.username}
                  onChange={handleWebInputChange}
                  className={inputClass}
                />
                <input
                  name="password"
                  type="password"
                  placeholder="Password"
                  value={webForm.password}
                  onChange={handleWebInputChange}
                  className={inputClass}
                />
              </div>
              <input
                name="apiToken"
                type="text"
                placeholder="API token / Bearer token (optional)"
                value={webForm.apiToken}
                onChange={handleWebInputChange}
                className={inputClass}
              />
            </div>

            <div className="space-y-2">
              <label htmlFor="scope" className={labelClass}>
                Scope
              </label>
              <select
                id="scope"
                name="scope"
                value={webForm.scope}
                onChange={handleWebInputChange}
                className={inputClass}
              >
                {scopeOptions.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-2">
              <label htmlFor="notes" className={labelClass}>
                Notes (optional)
              </label>
              <textarea
                id="notes"
                name="notes"
                rows={3}
                placeholder="Any test accounts, flows, or exclusions..."
                value={webForm.notes}
                onChange={handleWebInputChange}
                className={inputClass}
              />
            </div>

            <div className="flex gap-4 pt-4">
              <button
                type="submit"
                disabled={isSubmitting || !webForm.domain}
                className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-600 to-blue-500 text-white rounded-xl hover:from-blue-500 hover:to-blue-400 disabled:opacity-50 transition-all duration-300 font-semibold"
              >
                {isSubmitting ? "Starting..." : <><Rocket className="w-4 h-4" /> Start Web Scan</>}
              </button>
              <button
                type="button"
                onClick={() => navigate("/dashboard")}
                className={
                  isDarkMode
                    ? "px-6 py-3 bg-slate-700/50 border border-slate-600/50 text-gray-300 rounded-xl hover:bg-slate-600/50 transition-all"
                    : "px-6 py-3 bg-gray-100 border border-gray-300 text-gray-700 rounded-xl hover:bg-gray-200 transition-all"
                }
              >
                Cancel
              </button>
            </div>
          </form>
          </div>
        )}

        {/* Mobile Scan Form */}
        {scanType === "mobile" && (
          <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
          <form onSubmit={handleMobileSubmit} className="max-w-4xl space-y-6">
            <div className="space-y-2">
              <label className={labelClass}>App File (APK/IPA) *</label>
              <input
                type="file"
                name="appFile"
                accept=".apk,.ipa"
                onChange={handleMobileInputChange}
                required
                className={inputClass}
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className={labelClass}>App Name</label>
                <input
                  name="appName"
                  type="text"
                  placeholder="My Mobile App"
                  value={mobileForm.appName}
                  onChange={handleMobileInputChange}
                  className={inputClass}
                />
              </div>
              <div className="space-y-2">
                <label className={labelClass}>Platform</label>
                <select
                  name="platform"
                  value={mobileForm.platform}
                  onChange={handleMobileInputChange}
                  className={inputClass}
                >
                  <option value="android">Android (APK)</option>
                  <option value="ios">iOS (IPA)</option>
                </select>
              </div>
            </div>

            <div className="space-y-4">
              <label className={labelClass}>Testing Options</label>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  { name: "sslPinningBypass", label: "SSL Pinning Bypass", desc: "Use Frida to bypass" },
                  { name: "fridaScripts", label: "Frida Scripts", desc: "Runtime analysis" },
                  { name: "interceptTraffic", label: "Traffic Interception", desc: "MITM proxy capture" },
                ].map((opt) => (
                  <label
                    key={opt.name}
                    className={`flex items-start gap-3 p-4 rounded-xl cursor-pointer ${
                      isDarkMode
                        ? "bg-slate-700/50 border border-slate-600/50 hover:border-purple-500/50"
                        : "bg-gray-50 border border-gray-200 hover:border-purple-300"
                    }`}
                  >
                    <input
                      type="checkbox"
                      name={opt.name}
                      checked={mobileForm[opt.name]}
                      onChange={handleMobileInputChange}
                      className="mt-1"
                    />
                    <div>
                      <div className={isDarkMode ? "text-white font-medium" : "text-gray-900 font-medium"}>
                        {opt.label}
                      </div>
                      <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>
                        {opt.desc}
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <div className="flex gap-4 pt-4">
              <button
                type="submit"
                disabled={isSubmitting || !mobileForm.appFile}
                className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-purple-600 to-purple-500 text-white rounded-xl hover:from-purple-500 hover:to-purple-400 disabled:opacity-50 transition-all duration-300 font-semibold"
              >
                {isSubmitting ? "Starting..." : <><Smartphone className="w-4 h-4" /> Start Mobile Scan</>}
              </button>
              <button
                type="button"
                onClick={() => navigate("/dashboard")}
                className={
                  isDarkMode
                    ? "px-6 py-3 bg-slate-700/50 border border-slate-600/50 text-gray-300 rounded-xl hover:bg-slate-600/50 transition-all"
                    : "px-6 py-3 bg-gray-100 border border-gray-300 text-gray-700 rounded-xl hover:bg-gray-200 transition-all"
                }
              >
                Cancel
              </button>
            </div>
          </form>
          </div>
        )}

        {/* Network Scan Form - Using Enhanced NetworkScanConfig Component */}
        {scanType === "network" && (
          <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
            <form onSubmit={handleNetworkSubmit}>
              <NetworkScanConfig
                onConfigChange={handleNetworkConfigChange}
                initialConfig={networkConfig}
                showAgentSetup={true}
              />
              
              {/* Submit Buttons */}
              <div className="mt-8 flex gap-4 justify-end">
                <button
                  type="button"
                  onClick={() => setScanType("web")}
                  className={
                    isDarkMode
                      ? "px-6 py-3 bg-slate-700/50 border border-slate-600/50 text-gray-300 rounded-xl hover:bg-slate-600/50 transition-all font-medium"
                      : "px-6 py-3 bg-gray-100 border border-gray-300 text-gray-700 rounded-xl hover:bg-gray-200 transition-all font-medium"
                  }
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting || !networkConfig.targets.trim()}
                  className={`flex items-center gap-2 px-6 py-3 rounded-xl font-semibold transition-all ${
                    isSubmitting || !networkConfig.targets.trim()
                      ? "bg-gray-400 text-white cursor-not-allowed"
                      : isDarkMode
                      ? "bg-gradient-to-r from-cyan-600 to-blue-600 text-white hover:from-cyan-700 hover:to-blue-700"
                      : "bg-gradient-to-r from-cyan-500 to-blue-500 text-white hover:from-cyan-600 hover:to-blue-600"
                  }`}
                >
                  <Wifi className="w-5 h-5" />
                  {isSubmitting ? "Starting Scan..." : "Start Network Scan"}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Cloud Scan Form */}
        {scanType === "cloud" && (
          <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
          <form onSubmit={handleCloudSubmit} className="max-w-4xl space-y-6">
            <div className="space-y-2">
              <label className={labelClass}>Cloud Provider *</label>
              <div className="grid grid-cols-1 xs:grid-cols-3 gap-3 sm:gap-4">
                {[
                  { id: "aws", label: "AWS", icon: "☁️" },
                  { id: "azure", label: "Azure", icon: "☁️" },
                  { id: "gcp", label: "GCP", icon: "☁️" },
                ].map((provider) => (
                  <button
                    key={provider.id}
                    type="button"
                    onClick={() => setCloudForm((prev) => ({ ...prev, provider: provider.id }))}
                    className={`p-3 sm:p-4 rounded-xl font-medium transition-all min-h-[60px] sm:min-h-[80px] active:scale-95 ${
                      cloudForm.provider === provider.id
                        ? "bg-amber-600 text-white border-2 border-amber-400"
                        : isDarkMode
                        ? "bg-slate-700/50 border border-slate-600/50 text-gray-300 hover:border-amber-500/50"
                        : "bg-gray-50 border border-gray-200 text-gray-700 hover:border-amber-300"
                    }`}
                  >
                    <span className="text-xl sm:text-2xl">{provider.icon}</span>
                    <div className="mt-1 sm:mt-2 text-sm sm:text-base">{provider.label}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* AWS Credentials */}
            {cloudForm.provider === "aws" && (
              <div className="space-y-4">
                <input
                  name="accessKeyId"
                  type="text"
                  placeholder="AWS Access Key ID"
                  value={cloudForm.accessKeyId}
                  onChange={handleCloudInputChange}
                  required
                  className={inputClass}
                />
                <input
                  name="secretAccessKey"
                  type="password"
                  placeholder="AWS Secret Access Key"
                  value={cloudForm.secretAccessKey}
                  onChange={handleCloudInputChange}
                  required
                  className={inputClass}
                />
                <input
                  name="region"
                  type="text"
                  placeholder="Region (e.g., us-east-1)"
                  value={cloudForm.region}
                  onChange={handleCloudInputChange}
                  className={inputClass}
                />
              </div>
            )}

            {/* Azure Credentials */}
            {cloudForm.provider === "azure" && (
              <div className="space-y-4">
                <input
                  name="subscriptionId"
                  type="text"
                  placeholder="Subscription ID"
                  value={cloudForm.subscriptionId}
                  onChange={handleCloudInputChange}
                  required
                  className={inputClass}
                />
                <input
                  name="tenantId"
                  type="text"
                  placeholder="Tenant ID"
                  value={cloudForm.tenantId}
                  onChange={handleCloudInputChange}
                  required
                  className={inputClass}
                />
                <input
                  name="clientId"
                  type="text"
                  placeholder="Client ID"
                  value={cloudForm.clientId}
                  onChange={handleCloudInputChange}
                  required
                  className={inputClass}
                />
                <input
                  name="clientSecret"
                  type="password"
                  placeholder="Client Secret"
                  value={cloudForm.clientSecret}
                  onChange={handleCloudInputChange}
                  required
                  className={inputClass}
                />
              </div>
            )}

            {/* GCP Credentials */}
            {cloudForm.provider === "gcp" && (
              <div className="space-y-4">
                <input
                  name="projectId"
                  type="text"
                  placeholder="GCP Project ID"
                  value={cloudForm.projectId}
                  onChange={handleCloudInputChange}
                  required
                  className={inputClass}
                />
                <div className="space-y-2">
                  <label className={labelClass}>Service Account Key (JSON)</label>
                  <input
                    type="file"
                    name="serviceAccountKey"
                    accept=".json"
                    onChange={handleCloudInputChange}
                    required
                    className={inputClass}
                  />
                </div>
              </div>
            )}

            <div className="flex gap-4 pt-4">
              <button
                type="submit"
                disabled={isSubmitting}
                className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-amber-600 to-amber-500 text-white rounded-xl hover:from-amber-500 hover:to-amber-400 disabled:opacity-50 transition-all duration-300 font-semibold"
              >
                {isSubmitting ? "Starting..." : " Start Cloud Scan"}
              </button>
              <button
                type="button"
                onClick={() => navigate("/dashboard")}
                className={
                  isDarkMode
                    ? "px-6 py-3 bg-slate-700/50 border border-slate-600/50 text-gray-300 rounded-xl hover:bg-slate-600/50 transition-all"
                    : "px-6 py-3 bg-gray-100 border border-gray-300 text-gray-700 rounded-xl hover:bg-gray-200 transition-all"
                }
              >
                Cancel
              </button>
            </div>
          </form>
          </div>
        )}

        {/* SAST (Source Code Review) Scan Form */}
        {scanType === "sast" && (
          <div
            className={
              isDarkMode
                ? "function-card-dark p-6"
                : "function-card-light p-6"
            }
          >
          <form onSubmit={handleSASTSubmit} className="max-w-4xl space-y-6">
            {/* SCM Connection Section */}
            <div className={`p-6 rounded-2xl ${isDarkMode ? "bg-slate-800/30 border border-slate-700/50" : "bg-emerald-50 border border-emerald-200"}`}>
              <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                Connect Your Source Code
              </h3>
              
              {/* OAuth Connection Buttons */}
              <div className="flex flex-wrap gap-4 mb-6">
                <button
                  type="button"
                  onClick={handleConnectGitHub}
                  className="flex items-center gap-2 px-4 py-2 bg-gray-900 text-white rounded-lg hover:bg-gray-800 transition-colors"
                >
                  <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 21.795 24 17.295 24 12c0-6.63-5.37-12-12-12"/></svg>
                  Connect GitHub
                </button>
                <button
                  type="button"
                  onClick={handleConnectGitLab}
                  className="flex items-center gap-2 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-500 transition-colors"
                >
                  <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 0 1-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 0 1 4.82 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0 1 18.6 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.51L23 13.45a.84.84 0 0 1-.35.94z"/></svg>
                  Connect GitLab
                </button>
              </div>

              {/* Connected Accounts */}
              {loadingConnections ? (
                <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>Loading connections...</p>
              ) : scmConnections.length > 0 ? (
                <div className="mb-4">
                  <p className={`text-sm mb-2 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>Connected accounts:</p>
                  <div className="flex flex-wrap gap-2">
                    {scmConnections.map(conn => (
                      <span key={conn.id} className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm ${
                        isDarkMode ? "bg-emerald-500/20 text-emerald-400" : "bg-emerald-100 text-emerald-700"
                      }`}>
                        {conn.provider === "github" ? "🐙" : "🦊"} {conn.provider_username}
                      </span>
                    ))}
                  </div>
                </div>
              ) : (
                <p className={`text-sm mb-4 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                  No accounts connected. Connect via OAuth above or enter a Personal Access Token below.
                </p>
              )}
            </div>

            {/* Manual Repository Entry */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="lg:col-span-2">
                <label className={labelClass}>Repository URL *</label>
                <input
                  type="text"
                  name="repositoryUrl"
                  value={sastForm.repositoryUrl}
                  onChange={handleSASTInputChange}
                  placeholder="https://github.com/username/repository"
                  className={`${inputClass} ${validationErrors.repositoryUrl ? "border-red-500" : ""}`}
                />
                {validationErrors.repositoryUrl && (
                  <p className="mt-1 text-sm text-red-500">{validationErrors.repositoryUrl}</p>
                )}
              </div>

              <div>
                <label className={labelClass}>Branch</label>
                <input
                  type="text"
                  name="branch"
                  value={sastForm.branch}
                  onChange={handleSASTInputChange}
                  placeholder="main"
                  className={inputClass}
                />
              </div>

              <div>
                <label className={labelClass}>Personal Access Token</label>
                <input
                  type="password"
                  name="accessToken"
                  value={sastForm.accessToken}
                  onChange={handleSASTInputChange}
                  placeholder="ghp_xxxx or glpat-xxxx"
                  className={`${inputClass} ${validationErrors.accessToken ? "border-red-500" : ""}`}
                />
                {validationErrors.accessToken && (
                  <p className="mt-1 text-sm text-red-500">{validationErrors.accessToken}</p>
                )}
                <p className={`mt-1 text-xs ${isDarkMode ? "text-gray-500" : "text-gray-500"}`}>
                  Required for private repos if not using OAuth connection
                </p>
              </div>
            </div>

            {/* Scan Options */}
            <div className={`p-6 rounded-2xl ${isDarkMode ? "bg-slate-800/30 border border-slate-700/50" : "bg-gray-50 border border-gray-200"}`}>
              <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                Scan Options
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <label className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer ${
                  isDarkMode ? "bg-slate-700/50 hover:bg-slate-700" : "bg-white border border-gray-200 hover:bg-gray-50"
                }`}>
                  <input
                    type="checkbox"
                    name="scanSecrets"
                    checked={sastForm.scanSecrets}
                    onChange={handleSASTInputChange}
                    className="w-5 h-5 rounded text-emerald-500 focus:ring-emerald-500"
                  />
                  <div>
                    <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>Secret Detection</p>
                    <p className={`text-xs ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>Find hardcoded credentials</p>
                  </div>
                </label>

                <label className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer ${
                  isDarkMode ? "bg-slate-700/50 hover:bg-slate-700" : "bg-white border border-gray-200 hover:bg-gray-50"
                }`}>
                  <input
                    type="checkbox"
                    name="scanDependencies"
                    checked={sastForm.scanDependencies}
                    onChange={handleSASTInputChange}
                    className="w-5 h-5 rounded text-emerald-500 focus:ring-emerald-500"
                  />
                  <div>
                    <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>Dependency Scan (SCA)</p>
                    <p className={`text-xs ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>Check for vulnerable packages</p>
                  </div>
                </label>

                <label className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer ${
                  isDarkMode ? "bg-slate-700/50 hover:bg-slate-700" : "bg-white border border-gray-200 hover:bg-gray-50"
                }`}>
                  <input
                    type="checkbox"
                    name="scanCode"
                    checked={sastForm.scanCode}
                    onChange={handleSASTInputChange}
                    className="w-5 h-5 rounded text-emerald-500 focus:ring-emerald-500"
                  />
                  <div>
                    <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>Code Analysis</p>
                    <p className={`text-xs ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>Find security vulnerabilities</p>
                  </div>
                </label>
              </div>

              <div>
                <label className={labelClass}>Exclude Paths (comma-separated)</label>
                <input
                  type="text"
                  name="excludePaths"
                  value={sastForm.excludePaths}
                  onChange={handleSASTInputChange}
                  placeholder="node_modules, dist, vendor, *.test.js"
                  className={inputClass}
                />
                <p className={`mt-1 text-xs ${isDarkMode ? "text-gray-500" : "text-gray-500"}`}>
                  Paths or patterns to exclude from scanning
                </p>
              </div>
            </div>

            {/* Notes */}
            <div>
              <label className={labelClass}>Notes (Optional)</label>
              <textarea
                name="notes"
                value={sastForm.notes}
                onChange={handleSASTInputChange}
                rows={3}
                placeholder="Any additional context for this scan..."
                className={inputClass}
              />
            </div>

            <div className="flex gap-4 pt-4">
              <button
                type="submit"
                disabled={isSubmitting}
                className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-emerald-600 to-emerald-500 text-white rounded-xl hover:from-emerald-500 hover:to-emerald-400 disabled:opacity-50 transition-all duration-300 font-semibold"
              >
                {isSubmitting ? "Starting..." : "🔍 Start Code Review"}
              </button>
              <button
                type="button"
                onClick={() => navigate("/dashboard")}
                className={
                  isDarkMode
                    ? "px-6 py-3 bg-slate-700/50 border border-slate-600/50 text-gray-300 rounded-xl hover:bg-slate-600/50 transition-all"
                    : "px-6 py-3 bg-gray-100 border border-gray-300 text-gray-700 rounded-xl hover:bg-gray-200 transition-all"
                }
              >
                Cancel
              </button>
            </div>
          </form>
          </div>
        )}

        {/* Security & Privacy Information */}
        <div
          className={
            isDarkMode
              ? "function-card-dark p-6"
              : "function-card-light p-6"
          }
        >
          <h3
            className={
              isDarkMode
                ? "text-xl font-semibold text-white mb-6"
                : "text-xl font-semibold text-gray-900 mb-6"
            }
          >
            Security & Privacy
          </h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div className="space-y-4">
              <h4
                className={
                  isDarkMode
                    ? "flex items-center gap-2 text-blue-400 font-semibold"
                    : "flex items-center gap-2 text-blue-600 font-semibold"
                }
              >
                <span className="text-lg"><Lock className="w-5 h-5" /></span>
                Data Protection
              </h4>
              <ul className="space-y-2 text-sm">
                <li className="flex items-start gap-2">
                  <span className="text-green-400 mt-1">*</span>
                  <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                    All credentials are encrypted in transit and at rest
                  </span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-400 mt-1">*</span>
                  <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                    Scan data is automatically deleted after 90 days
                  </span>
                </li>
              </ul>
            </div>
            <div className="space-y-4">
              <h4
                className={
                  isDarkMode
                    ? "flex items-center gap-2 text-blue-400 font-semibold"
                    : "flex items-center gap-2 text-blue-600 font-semibold"
                }
              >
                <span className="text-lg"><Info className="w-5 h-5" /></span>
                Scan Process
              </h4>
              <ul className="space-y-2 text-sm">
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 mt-1">*</span>
                  <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                    Non-destructive testing methods only
                  </span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 mt-1">*</span>
                  <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                    Real-time progress monitoring available
                  </span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </MiftyJarwisLayout>
  );
};

export default NewScan;
