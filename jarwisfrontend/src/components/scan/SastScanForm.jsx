// SastScanForm - Dedicated SAST/Code Review scan configuration form
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Code } from "lucide-react";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import { sastScanAPI } from "../../services/api";
import { getInputClass, getLabelClass, getCancelButtonClass } from "./scanFormStyles";

const SastScanForm = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();
  const { canPerformAction, refreshSubscription } = useSubscription();

  const [sastForm, setSastForm] = useState({
    repositoryUrl: "",
    branch: "main",
    accessToken: "",
    provider: "github",
    useOAuth: false,
    scanSecrets: true,
    scanDependencies: true,
    scanCode: true,
    languages: [],
    excludePaths: "",
    notes: "",
  });

  const [scmConnections, setScmConnections] = useState([]);
  const [loadingConnections, setLoadingConnections] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [validationErrors, setValidationErrors] = useState({});

  const inputClass = getInputClass(isDarkMode);
  const labelClass = getLabelClass(isDarkMode);
  const cancelButtonClass = getCancelButtonClass(isDarkMode);

  // Load SCM connections on mount
  useEffect(() => {
    loadSCMConnections();
  }, []);

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

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    if (type === "checkbox") {
      setSastForm((prev) => ({ ...prev, [name]: checked }));
    } else {
      setSastForm((prev) => ({ ...prev, [name]: value }));
    }
    
    if (validationErrors[name]) {
      setValidationErrors((prev) => ({ ...prev, [name]: null }));
    }
  };

  const handleSubmit = async (e) => {
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

  return (
    <form onSubmit={handleSubmit} className="max-w-4xl space-y-6">
      {error && (
        <div className="p-4 mb-4 bg-red-500/20 border border-red-500/50 rounded-xl text-red-400">
          {error}
        </div>
      )}

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
            onChange={handleInputChange}
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
            onChange={handleInputChange}
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
            onChange={handleInputChange}
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
              onChange={handleInputChange}
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
              onChange={handleInputChange}
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
              onChange={handleInputChange}
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
            onChange={handleInputChange}
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
          onChange={handleInputChange}
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
          {isSubmitting ? "Starting..." : <><Code className="w-4 h-4" /> Start Code Review</>}
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

export default SastScanForm;
