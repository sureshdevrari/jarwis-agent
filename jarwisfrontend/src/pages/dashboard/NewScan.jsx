// src/pages/dashboard/NewScan.jsx - Full Scan Support with Web/Mobile/Cloud
import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import { scanAPI, mobileScanAPI, cloudScanAPI, domainVerificationAPI } from "../../services/api";

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
          <span className="text-2xl">{isAtLimit ? "" : "[!]"}</span>
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
  const { canPerformAction, getActionLimit, getAllUsageStats, checkActionAllowed, refreshSubscription } = useSubscription();

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

  const handleCloudInputChange = (e) => {
    const { name, value, files } = e.target;
    if (name === "serviceAccountKey") {
      setCloudForm((prev) => ({ ...prev, [name]: files[0] }));
    } else {
      setCloudForm((prev) => ({ ...prev, [name]: value }));
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

      // If credentials are provided, require domain verification
      const hasCredentials = webForm.username || webForm.password || webForm.apiToken;
      if (hasCredentials) {
        try {
          const verificationStatus = await domainVerificationAPI.getVerificationStatus(domainPart);
          if (!verificationStatus.verified) {
            // Redirect to domain verification page
            navigate("/dashboard/verify-domain", {
              state: { 
                scanConfig: { 
                  domain: domainPart, 
                  scope: webForm.scope,
                  hasCredentials: true 
                },
                returnPath: "/dashboard/new-scan",
                message: "Domain verification is required for credential-based scans to protect against unauthorized testing."
              }
            });
            return;
          }
        } catch (verifyError) {
          console.warn("Domain verification check failed:", verifyError);
          // If verification service is unavailable, prompt user
          const confirmScan = window.confirm(
            "Domain verification is recommended for credential-based scans. " +
            "This helps ensure you have authorization to test this domain.\n\n" +
            "Do you want to verify domain ownership first?"
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

      const response = await scanAPI.startScan(config);

      if (response.scan_id) {
        // Refresh subscription data to update usage counts
        refreshSubscription();
        
        navigate("/dashboard/scanning", {
          state: { scanId: response.scan_id, scanType: "web", scanConfig: webForm },
        });
      } else {
        throw new Error(response.error || "Failed to start scan");
      }
    } catch (err) {
      console.error("Start scan error:", err);
      // Handle subscription limit errors specially
      if (err.message?.includes("limit") || err.message?.includes("upgrade")) {
        setError(err.message);
      } else {
        setError(err.message);
      }
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
          <div className="flex gap-2 mb-6">
            {[
              { id: "web", label: "[WEB] Web Scan", color: "blue", feature: null },
              { id: "mobile", label: "[MOBILE] Mobile Scan", color: "purple", feature: "useMobileAppTesting" },
              { id: "cloud", label: " Cloud Scan", color: "amber", feature: "useCloudScanning" },
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
                  {type.label}
                  {isLocked && (
                    <span className="ml-2 text-xs">[LOCK]</span>
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
                {scanType === "cloud" && "Cloud Scan: "}
              </strong>
              {scanType === "web" &&
                "Provide your target domain, credentials (optional), and scope. Jarwis will perform OWASP Top 10 testing."}
              {scanType === "mobile" &&
                "Upload your APK/IPA file. Jarwis will analyze the app, bypass SSL pinning with Frida, and intercept traffic."}
              {scanType === "cloud" &&
                "Connect your cloud provider. Jarwis will audit IAM, storage, and security configurations."}
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
                {isSubmitting ? "Starting..." : "[LAUNCH] Start Web Scan"}
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
                {isSubmitting ? "Starting..." : "[MOBILE] Start Mobile Scan"}
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

        {/* Cloud Scan Form */}
        {scanType === "cloud" && (
          <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
          <form onSubmit={handleCloudSubmit} className="max-w-4xl space-y-6">
            <div className="space-y-2">
              <label className={labelClass}>Cloud Provider *</label>
              <div className="grid grid-cols-1 xs:grid-cols-3 gap-3 sm:gap-4">
                {[
                  { id: "aws", label: "AWS", icon: "" },
                  { id: "azure", label: "Azure", icon: "[BLUE]" },
                  { id: "gcp", label: "GCP", icon: "[GREEN]" },
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
                <span className="text-lg">[LOCK]</span>
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
                <span className="text-lg">[!]</span>
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
