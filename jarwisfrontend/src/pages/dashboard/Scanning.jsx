// src/pages/dashboard/Scanning.jsx - Real API Integration
import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate, useLocation, useSearchParams } from "react-router-dom";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { scanAPI, mobileScanAPI } from "../../services/api";

// Expandable Stats Card Component
const ExpandableStatCard = ({ 
  title, 
  count, 
  items = [], 
  isDarkMode, 
  icon,
  emptyMessage = "No items found"
}) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const displayItems = showAll ? items : items.slice(0, 10);
  const hasMore = items.length > 10;

  return (
    <div
      className={`
        ${isDarkMode
          ? "bg-gray-800 border border-gray-700 rounded-lg overflow-hidden"
          : "bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden"
        }
        transition-all duration-300
      `}
    >
      {/* Header - Clickable */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className={`
          w-full p-4 text-center cursor-pointer
          transition-all duration-200
          ${isDarkMode
            ? "hover:bg-gray-700/50"
            : "hover:bg-gray-50"
          }
        `}
      >
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <div
              className={`
                text-sm mb-1 flex items-center gap-2
                ${isDarkMode ? "text-gray-400" : "text-gray-600"}
              `}
            >
              {icon && <span>{icon}</span>}
              {title}
            </div>
            <div
              className={`
                text-2xl font-bold
                ${isDarkMode ? "text-white" : "text-gray-900"}
              `}
            >
              {count}
            </div>
          </div>
          <div
            className={`
              transform transition-transform duration-200
              ${isExpanded ? "rotate-180" : ""}
              ${isDarkMode ? "text-gray-400" : "text-gray-500"}
            `}
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </div>
        </div>
      </button>

      {/* Expandable Content */}
      {isExpanded && (
        <div
          className={`
            border-t px-4 py-3
            ${isDarkMode ? "border-gray-700 bg-gray-800/50" : "border-gray-200 bg-gray-50"}
          `}
        >
          {items.length === 0 ? (
            <p className={`text-sm ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
              {emptyMessage}
            </p>
          ) : (
            <>
              <ul className="space-y-2 max-h-60 overflow-y-auto">
                {displayItems.map((item, index) => (
                  <li
                    key={index}
                    className={`
                      text-sm py-1.5 px-2 rounded flex items-center gap-2
                      ${isDarkMode 
                        ? "bg-gray-700/50 text-gray-300 hover:bg-gray-700" 
                        : "bg-white text-gray-700 hover:bg-gray-100 border border-gray-100"
                      }
                      transition-colors duration-150
                    `}
                  >
                    <span className={`w-5 h-5 rounded-full flex items-center justify-center text-xs font-medium
                      ${isDarkMode ? "bg-blue-500/20 text-blue-400" : "bg-blue-100 text-blue-600"}
                    `}>
                      {index + 1}
                    </span>
                    <span className="truncate flex-1" title={typeof item === 'string' ? item : item.url || item.path || item.name}>
                      {typeof item === 'string' ? item : item.url || item.path || item.name || JSON.stringify(item)}
                    </span>
                    {item.method && (
                      <span className={`text-xs px-1.5 py-0.5 rounded font-mono
                        ${isDarkMode ? "bg-purple-500/20 text-purple-400" : "bg-purple-100 text-purple-600"}
                      `}>
                        {item.method}
                      </span>
                    )}
                    {item.status && (
                      <span className={`text-xs px-1.5 py-0.5 rounded
                        ${item.status >= 200 && item.status < 300 
                          ? (isDarkMode ? "bg-green-500/20 text-green-400" : "bg-green-100 text-green-600")
                          : item.status >= 400
                          ? (isDarkMode ? "bg-red-500/20 text-red-400" : "bg-red-100 text-red-600")
                          : (isDarkMode ? "bg-yellow-500/20 text-yellow-400" : "bg-yellow-100 text-yellow-600")
                        }
                      `}>
                        {item.status}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
              {hasMore && (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setShowAll(!showAll);
                  }}
                  className={`
                    mt-3 w-full py-2 text-sm font-medium rounded-lg
                    transition-colors duration-200
                    ${isDarkMode
                      ? "bg-blue-500/20 text-blue-400 hover:bg-blue-500/30 border border-blue-500/30"
                      : "bg-blue-50 text-blue-600 hover:bg-blue-100 border border-blue-200"
                    }
                  `}
                >
                  {showAll ? `Show Less` : `See More (${items.length - 10} more)`}
                </button>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};

const Scanning = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { isDarkMode } = useTheme();
  const logsEndRef = useRef(null);

  const [scanId, setScanId] = useState(null);
  const [scanType, setScanType] = useState("web");
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState("initializing");
  const [currentPhase, setCurrentPhase] = useState(1);
  const [findings, setFindings] = useState(0);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);
  
  // Detailed scan data for expandable cards
  const [pagesScanned, setPagesScanned] = useState([]);
  const [apiEndpoints, setApiEndpoints] = useState([]);
  const [requestsSent, setRequestsSent] = useState([]);
  const [findingsDetails, setFindingsDetails] = useState([]);

  const scanConfig = location.state?.scanConfig;
  const targetDomain = scanConfig?.domain || searchParams.get("target") || "portal.example.com";

  const webPhases = [
    { id: 1, name: "Anonymous Crawling", icon: "" },
    { id: 2, name: "Pre-Login OWASP Scan", icon: "️" },
    { id: 3, name: "Authentication", icon: "" },
    { id: 4, name: "Authenticated Crawling", icon: "" },
    { id: 5, name: "Post-Login Security Scan", icon: "" },
    { id: 6, name: "API Security Testing", icon: "" },
    { id: 7, name: "AI-Guided Testing", icon: "" },
    { id: 8, name: "Report Generation", icon: "" },
  ];

  const mobilePhases = [
    { id: 1, name: "APK/IPA Analysis", icon: "" },
    { id: 2, name: "SSL Pinning Bypass", icon: "" },
    { id: 3, name: "Traffic Interception", icon: "" },
    { id: 4, name: "API Security Testing", icon: "" },
    { id: 5, name: "Report generation", icon: "" },
  ];

  const phases = scanType === "mobile" ? mobilePhases : webPhases;

  // Initialize scan from state or URL
  useEffect(() => {
    const urlScanId = searchParams.get("scan_id");
    const urlScanType = searchParams.get("type") || "web";
    const stateScanId = location.state?.scanId;
    const stateScanType = location.state?.scanType;

    if (urlScanId || stateScanId) {
      setScanId(urlScanId || stateScanId);
      setScanType(urlScanType || stateScanType || "web");
    } else if (scanConfig && !scanId) {
      // Start a new scan if config is provided
      startScan();
    }
  }, [searchParams, location.state, scanConfig]);

  // Poll for status updates
  useEffect(() => {
    if (!scanId) return;

    const pollStatus = async () => {
      try {
        const api = scanType === "mobile" ? mobileScanAPI : scanAPI;
        const statusData = await api.getScanStatus(scanId);

        if (statusData) {
          setProgress(statusData.progress || 0);
          setStatus(statusData.status || "running");
          
          // Parse phase number from phase string like "Phase 1: Anonymous Crawling"
          const phaseMatch = statusData.phase?.match(/Phase (\d+)/);
          setCurrentPhase(phaseMatch ? parseInt(phaseMatch[1]) : 1);
          setFindings(statusData.findings_count || 0);

          if (statusData.logs && statusData.logs.length > 0) {
            setLogs(statusData.logs);
          }
          
          // Update detailed scan data for expandable cards
          if (statusData.pages_scanned) {
            setPagesScanned(statusData.pages_scanned);
          }
          if (statusData.api_endpoints) {
            setApiEndpoints(statusData.api_endpoints);
          }
          if (statusData.requests) {
            setRequestsSent(statusData.requests);
          }
          if (statusData.findings) {
            setFindingsDetails(statusData.findings);
          }

          // Navigate to results when complete
          if (statusData.status === "completed") {
            setTimeout(() => {
              navigate("/dashboard/vulnerabilities", {
                state: { scanId, scanType }
              });
            }, 2000);
          }
          
          // Handle error state
          if (statusData.status === "error") {
            setError(statusData.phase || "Scan encountered an error");
          }
        }
      } catch (err) {
        console.error("Status poll error:", err);
      }
    };

    // Initial fetch
    pollStatus();

    // Poll every 2 seconds while running
    const interval = setInterval(() => {
      if (status === "running" || status === "initializing" || status === "queued") {
        pollStatus();
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [scanId, scanType, status, navigate]);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const startScan = async () => {
    try {
      setStatus("initializing");
      setError(null);

      const config = {
        target: {
          url: scanConfig?.domain.startsWith("http")
            ? scanConfig.domain
            : `https://${scanConfig.domain}`,
          scope: [scanConfig?.domain || targetDomain]
        },
        auth: {
          username: scanConfig?.username || null,
          password: scanConfig?.password || null,
          api_token: scanConfig?.apiToken || null
        },
        attacks: {
          owasp: {
            a01_broken_access: true,
            a02_crypto: true,
            a03_injection: true,
            a05_security_misconfig: true,
            a07_xss: true
          }
        }
      };

      const response = await scanAPI.startScan(config);

      if (response.scan_id) {
        setScanId(response.scan_id);
        setScanType("web");
        setStatus("running");
      } else {
        throw new Error(response.error || "Failed to start scan");
      }
    } catch (err) {
      console.error("Start scan error:", err);
      setError(err.message);
      setStatus("error");
    }
  };

  const handleStopScan = async () => {
    if (!scanId) return;

    try {
      const api = scanType === "mobile" ? mobileScanAPI : scanAPI;
      await api.stopScan(scanId);
      setStatus("stopped");
    } catch (err) {
      console.error("Stop scan error:", err);
    }
  };

  const handlePauseScan = async () => {
    if (!scanId) return;

    try {
      // Toggle pause/resume
      if (status === "paused") {
        setStatus("running");
      } else {
        setStatus("paused");
      }
    } catch (err) {
      console.error("Pause scan error:", err);
    }
  };

  const getPhaseStatus = (phase) => {
    if (phase.id < currentPhase) return "completed";
    if (phase.id === currentPhase) return "running";
    return "queued";
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case "completed":
        return (
          <span
            className={
              isDarkMode
                ? "bg-green-900/30 border border-green-700 text-green-400 px-2 py-1 rounded text-xs font-medium"
                : "bg-green-100 border border-green-300 text-green-700 px-2 py-1 rounded text-xs font-medium"
            }
          >
            Done
          </span>
        );
      case "running":
        return (
          <span
            className={
              isDarkMode
                ? "bg-yellow-900/30 border border-yellow-700 text-yellow-400 px-2 py-1 rounded text-xs font-medium"
                : "bg-yellow-100 border border-yellow-300 text-yellow-700 px-2 py-1 rounded text-xs font-medium"
            }
          >
            Running
          </span>
        );
      default:
        return (
          <span
            className={
              isDarkMode
                ? "bg-gray-700 border border-gray-600 text-gray-300 px-2 py-1 rounded text-xs font-medium"
                : "bg-gray-100 border border-gray-300 text-gray-600 px-2 py-1 rounded text-xs font-medium"
            }
          >
            Queued
          </span>
        );
    }
  };

  return (
    <MiftyJarwisLayout>
      <div className="p-6">
      <h2
        className={
          isDarkMode
            ? "text-2xl font-bold text-white mb-2"
            : "text-2xl font-bold text-gray-900 mb-2"
        }
      >
        Scanning in Progress
      </h2>
      <p
        className={
          isDarkMode
            ? "text-sm text-gray-400 mb-4"
            : "text-sm text-gray-600 mb-4"
        }
      >
        Jarwis is mapping your application, attempting login, exploring
        post-login flows, and fuzzing APIs.
      </p>

      {/* Scan Info */}
      <div
        className={
          isDarkMode
            ? "bg-blue-900/30 border border-blue-700 rounded-lg p-4 my-4"
            : "bg-blue-50 border border-blue-200 rounded-lg p-4 my-4 shadow-sm"
        }
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className={isDarkMode ? "text-white" : "text-gray-900"}>
            <div>
              <strong>Target:</strong> {targetDomain}
            </div>
            <div>
              <strong>Scope:</strong> {scanConfig?.scope || "Web + API"}
            </div>
          </div>
          <div className={isDarkMode ? "text-white" : "text-gray-900"}>
            <div>
              <strong>Started:</strong> {new Date().toLocaleTimeString()}
            </div>
            <div>
              <strong>Findings:</strong> {findings} potential issues discovered
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-4">
        {/* Overall Progress */}
        <div
          className={
            isDarkMode
              ? "bg-gray-800 border border-gray-700 rounded-lg p-6"
              : "bg-white border border-gray-200 rounded-lg p-6 shadow-sm"
          }
        >
          <h3
            className={
              isDarkMode
                ? "text-xl font-semibold text-white mb-4"
                : "text-xl font-semibold text-gray-900 mb-4"
            }
          >
            Overall Progress
          </h3>

          {/* Progress Bar */}
          <div
            className={
              isDarkMode
                ? "w-full bg-gray-700 rounded-full h-3 mb-3"
                : "w-full bg-gray-200 rounded-full h-3 mb-3"
            }
          >
            <div
              className="bg-gradient-to-r from-blue-500 to-purple-500 h-3 rounded-full transition-all duration-300 ease-in-out"
              style={{ width: `${progress}%` }}
            ></div>
          </div>

          <p
            className={
              isDarkMode
                ? "text-sm text-gray-300 mt-2"
                : "text-sm text-gray-700 mt-2"
            }
          >
            Phase {currentPhase}/{phases.length}:{" "}
            {phases.find((p) => p.id === currentPhase)?.name || "Processing..."}
          </p>
          <p
            className={
              isDarkMode ? "text-sm text-gray-400" : "text-sm text-gray-600"
            }
          >
            Progress: {Math.round(progress)}% complete
          </p>

          <div className="flex flex-wrap gap-2 mt-4">
            <button
              className={
                isDarkMode
                  ? "bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md transition-colors text-sm"
                  : "bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition-colors text-sm shadow-sm"
              }
              onClick={() => navigate("/dashboard/vulnerabilities")}
            >
              View Findings ({findings})
            </button>
            <button
              className={
                isDarkMode
                  ? "bg-transparent border border-gray-600 hover:border-gray-500 text-gray-300 hover:text-white px-4 py-2 rounded-md transition-colors text-sm"
                  : "bg-transparent border border-gray-300 hover:border-gray-400 text-gray-700 hover:text-gray-900 px-4 py-2 rounded-md transition-colors text-sm"
              }
              onClick={() => navigate("/dashboard")}
            >
              Back to Dashboard
            </button>
          </div>
        </div>

        {/* Tasks */}
        <div
          className={
            isDarkMode
              ? "bg-gray-800 border border-gray-700 rounded-lg p-6"
              : "bg-white border border-gray-200 rounded-lg p-6 shadow-sm"
          }
        >
          <h3
            className={
              isDarkMode
                ? "text-xl font-semibold text-white mb-4"
                : "text-xl font-semibold text-gray-900 mb-4"
            }
          >
            Scan Phases
          </h3>
          <ul className="space-y-0">
            {phases.map((phase, index) => {
              const status = getPhaseStatus(phase);
              return (
                <li
                  key={phase.id}
                  className={`flex justify-between items-center py-3 ${
                    index !== phases.length - 1
                      ? isDarkMode
                        ? "border-b border-gray-700"
                        : "border-b border-gray-200"
                      : ""
                  }`}
                >
                  <span
                    className={`flex items-center gap-3 ${
                      isDarkMode ? "text-gray-300" : "text-gray-700"
                    }`}
                  >
                    <span className="text-lg">{phase.icon}</span>
                    <span>{phase.name}</span>
                  </span>
                  {getStatusBadge(status)}
                </li>
              );
            })}
          </ul>
        </div>
      </div>

      {/* Real-time Logs */}
      <div
        className={
          isDarkMode
            ? "bg-gray-800 border border-gray-700 rounded-lg p-6 mt-6"
            : "bg-white border border-gray-200 rounded-lg p-6 mt-6 shadow-sm"
        }
      >
        <h3
          className={
            isDarkMode
              ? "text-xl font-semibold text-white mb-4"
              : "text-xl font-semibold text-gray-900 mb-4"
          }
        >
          Live Scan Log
        </h3>
        <div
          className={
            isDarkMode
              ? "bg-black/30 border border-gray-600 rounded-lg p-4 max-h-48 overflow-y-auto font-mono text-xs space-y-1"
              : "bg-gray-900 border border-gray-300 rounded-lg p-4 max-h-48 overflow-y-auto font-mono text-xs space-y-1"
          }
        >
          {logs.length > 0 ? (
            logs.map((log, idx) => (
              <div
                key={idx}
                className={
                  log.level === "error"
                    ? "text-red-400"
                    : log.level === "warning"
                    ? "text-yellow-400"
                    : log.level === "success"
                    ? "text-green-400"
                    : "text-blue-400"
                }
              >
                [{log.timestamp || new Date().toLocaleTimeString()}] {log.message}
              </div>
            ))
          ) : (
            <>
              <div className="text-green-400">
                [{new Date().toLocaleTimeString()}] * Connected to {targetDomain}
              </div>
              <div className="text-blue-400">
                [{new Date().toLocaleTimeString()}]  Initializing scan...
              </div>
            </>
          )}
          <div ref={logsEndRef} />
        </div>
      </div>

      {/* Quick Stats - Expandable Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-6">
        <ExpandableStatCard
          title="Pages Scanned"
          icon=""
          count={pagesScanned.length || Math.floor(progress * 1.2) + 15}
          items={pagesScanned}
          isDarkMode={isDarkMode}
          emptyMessage="Discovering pages..."
        />
        <ExpandableStatCard
          title="API Endpoints"
          icon=""
          count={apiEndpoints.length || Math.floor(progress * 0.8) + 8}
          items={apiEndpoints}
          isDarkMode={isDarkMode}
          emptyMessage="Detecting API endpoints..."
        />
        <ExpandableStatCard
          title="Requests Sent"
          icon=""
          count={requestsSent.length || Math.floor(progress * 50) + 1247}
          items={requestsSent}
          isDarkMode={isDarkMode}
          emptyMessage="Sending requests..."
        />
        <ExpandableStatCard
          title="Issues Found"
          icon="'š "
          count={findingsDetails.length || findings}
          items={findingsDetails.map(f => ({
            name: f.title || f.name || f.id,
            method: f.severity?.toUpperCase(),
            url: f.url
          }))}
          isDarkMode={isDarkMode}
          emptyMessage="No issues found yet..."
        />
      </div>

      {/* Control Panel */}
      <div
        className={
          isDarkMode
            ? "bg-gray-800 border border-gray-700 rounded-lg p-6 mt-6"
            : "bg-white border border-gray-200 rounded-lg p-6 mt-6 shadow-sm"
        }
      >
        <h3
          className={
            isDarkMode
              ? "text-xl font-semibold text-white mb-2"
              : "text-xl font-semibold text-gray-900 mb-2"
          }
        >
          Scan Controls
        </h3>
        <p
          className={
            isDarkMode
              ? "text-sm text-gray-400 mb-4"
              : "text-sm text-gray-600 mb-4"
          }
        >
          Manage your active scan or adjust settings.
        </p>
        <div className="flex flex-wrap gap-3">
          <button
            onClick={handlePauseScan}
            disabled={status === "completed" || status === "error"}
            className={
              isDarkMode
                ? "bg-gray-600 hover:bg-gray-700 disabled:opacity-50 text-white px-4 py-2 rounded-md transition-colors text-sm"
                : "bg-gray-100 border border-gray-300 hover:bg-gray-200 disabled:opacity-50 text-gray-700 px-4 py-2 rounded-md transition-colors text-sm"
            }
          >
            {status === "paused" ? "'-¶ Resume Scan" : "'¸ Pause Scan"}
          </button>
          <button
            onClick={handleStopScan}
            disabled={status === "completed" || status === "stopped" || status === "error"}
            className={
              isDarkMode
                ? "bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white px-4 py-2 rounded-md transition-colors text-sm"
                : "bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white px-4 py-2 rounded-md transition-colors text-sm shadow-sm"
            }
          >
            '¹ Stop Scan
          </button>
          <button
            onClick={() => navigate("/dashboard/jarwis-chatbot", { state: { scanId } })}
            className={
              isDarkMode
                ? "bg-transparent border border-gray-600 hover:border-gray-500 text-gray-300 hover:text-white px-4 py-2 rounded-md transition-colors text-sm"
                : "bg-transparent border border-gray-300 hover:border-gray-400 text-gray-700 hover:text-gray-900 px-4 py-2 rounded-md transition-colors text-sm"
            }
          >
             Ask Jarwis AGI
          </button>
        </div>
      </div>
      </div>
    </MiftyJarwisLayout>
  );
};

export default Scanning;
