// WebScanForm - Dedicated web scan configuration form
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Rocket, Lock } from "lucide-react";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import { scanAPI, domainVerificationAPI } from "../../services/api";
import { getInputClass, getLabelClass, getCancelButtonClass } from "./scanFormStyles";

const WebScanForm = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();
  const { canPerformAction, checkActionAllowed, refreshSubscription, subscription } = useSubscription();

  const [webForm, setWebForm] = useState({
    domain: "",
    username: "",
    password: "",
    apiToken: "",
    scope: "Web + API (recommended)",
    notes: "",
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [validationErrors, setValidationErrors] = useState({});

  const inputClass = getInputClass(isDarkMode);
  const labelClass = getLabelClass(isDarkMode);
  const cancelButtonClass = getCancelButtonClass(isDarkMode);

  const scopeOptions = [
    "Web only (pre‑login)",
    "Web + post‑login (form/session)",
    "API only",
    "Web + API (recommended)",
  ];

  // Validate domain/URL format
  const validateDomain = (domain) => {
    if (!domain || domain.trim() === "") {
      return "Domain is required";
    }
    
    let cleanDomain = domain.trim();
    if (cleanDomain.startsWith("http://") || cleanDomain.startsWith("https://")) {
      try {
        const url = new URL(cleanDomain);
        cleanDomain = url.hostname;
      } catch {
        return "Invalid URL format";
      }
    }
    
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    const localhostRegex = /^localhost(:\d+)?$/;
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/;
    
    if (!domainRegex.test(cleanDomain) && !localhostRegex.test(cleanDomain) && !ipRegex.test(cleanDomain)) {
      return "Please enter a valid domain (e.g., example.com)";
    }
    
    return null;
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setWebForm((prev) => ({ ...prev, [name]: value }));
    
    if (validationErrors[name]) {
      setValidationErrors((prev) => ({ ...prev, [name]: null }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);
    setValidationErrors({});

    const domainError = validateDomain(webForm.domain);
    if (domainError) {
      setValidationErrors({ domain: domainError });
      setError(domainError);
      setIsSubmitting(false);
      return;
    }

    try {
      // Preflight check
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
      }

      // Check subscription limits
      const canScan = canPerformAction("startScan");
      if (!canScan) {
        const serverCheck = await checkActionAllowed("start_scan");
        if (!serverCheck.allowed) {
          throw new Error(serverCheck.message || "You've reached your scan limit. Please upgrade your plan.");
        }
      }

      const targetUrl = webForm.domain.startsWith("http")
        ? webForm.domain
        : `https://${webForm.domain}`;
      
      let domainPart;
      try {
        domainPart = new URL(targetUrl).hostname;
      } catch (urlError) {
        throw new Error("Invalid URL format. Please enter a valid domain.");
      }

      // Domain verification for credential-based scans (skip for developer plan)
      const hasCredentials = webForm.username || webForm.password || webForm.apiToken;
      const isDeveloperPlan = subscription?.plan === "developer";
      
      if (hasCredentials && !isDeveloperPlan) {
        try {
          const verificationStatus = await domainVerificationAPI.getVerificationStatus(domainPart);
          if (!verificationStatus.verified) {
            const userChoice = window.confirm(
              `🔒 Domain Verification Required\n\n` +
              `For security reasons, credential-based scans require proof that you own or have authorization to test "${domainPart}".\n\n` +
              `Click OK to verify domain ownership, or Cancel to scan WITHOUT credentials.`
            );
            
            if (userChoice) {
              navigate("/dashboard/verify-domain", {
                state: { 
                  scanConfig: { 
                    domain: domainPart, 
                    scope: webForm.scope,
                    hasCredentials: true,
                    returnData: {
                      username: webForm.username,
                      password: webForm.password,
                      apiToken: webForm.apiToken,
                    }
                  },
                  returnPath: "/dashboard/scan/web",
                  message: "Domain verification is required for credential-based scans."
                }
              });
              return;
            } else {
              setWebForm(prev => ({ ...prev, username: "", password: "", apiToken: "" }));
            }
          }
        } catch (verifyError) {
          console.warn("Domain verification check failed:", verifyError);
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
        refreshSubscription();
        navigate("/dashboard/scanning", {
          state: { scanId: response.scan_id, scanType: "web", scanConfig: webForm },
        });
      } else {
        throw new Error(response.error || response.detail || "Failed to start scan");
      }
    } catch (err) {
      console.error("Start scan error:", err);
      let errorMessage = "Failed to start scan";
      if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        if (typeof detail === "string") errorMessage = detail;
        else if (detail.message) errorMessage = detail.message;
        else if (detail.error) errorMessage = detail.error;
      } else if (err.message) {
        errorMessage = err.message;
      }
      setError(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="max-w-4xl space-y-6">
      {error && (
        <div className="p-4 mb-4 bg-red-500/20 border border-red-500/50 rounded-xl text-red-400">
          {error}
        </div>
      )}

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
          onChange={handleInputChange}
          required
          className={`${inputClass} ${validationErrors.domain ? (isDarkMode ? "border-red-500/50" : "border-red-400") : ""}`}
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
            onChange={handleInputChange}
            className={inputClass}
          />
          <input
            name="password"
            type="password"
            placeholder="Password"
            value={webForm.password}
            onChange={handleInputChange}
            className={inputClass}
          />
        </div>
        <input
          name="apiToken"
          type="text"
          placeholder="API token / Bearer token (optional)"
          value={webForm.apiToken}
          onChange={handleInputChange}
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
          onChange={handleInputChange}
          className={inputClass}
        >
          {scopeOptions.map((option) => (
            <option key={option} value={option}>{option}</option>
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
          onChange={handleInputChange}
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
          className={cancelButtonClass}
        >
          Cancel
        </button>
      </div>
    </form>
  );
};

export default WebScanForm;
