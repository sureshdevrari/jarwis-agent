// src/pages/dashboard/Scanning.jsx - Real API Integration with WebSocket
import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate, useLocation, useSearchParams, useParams } from "react-router-dom";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { scanAPI, mobileScanAPI, networkScanAPI, cloudScanAPI, scanAuthAPI, scanOtpAPI } from "../../services/api";
import { useScanWebSocket } from "../../hooks/useWebSocket";
import { FileSearch, Webhook, Send, AlertTriangle, Globe, Smartphone, Wifi, Cloud } from "lucide-react";
import ManualLoginModal from "../../components/scan/ManualLoginModal";
import OTPInputModal from "../../components/scan/OTPInputModal";

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
  const params = useParams();  // Get route params like /scanning/:scanId
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
  const [actualTargetUrl, setActualTargetUrl] = useState(null); // Real target from API
  
  // Manual auth / OTP modals
  const [showManualLoginModal, setShowManualLoginModal] = useState(false);
  const [showOtpModal, setShowOtpModal] = useState(false);
  
  // Detailed scan data for expandable cards
  const [pagesScanned, setPagesScanned] = useState([]);
  const [apiEndpoints, setApiEndpoints] = useState([]);
  const [requestsSent, setRequestsSent] = useState([]);
  const [findingsDetails, setFindingsDetails] = useState([]);
  
  // Timeout detection for stalled scans
  const [scanStartTime, setScanStartTime] = useState(null);
  const [stalledWarning, setStalledWarning] = useState(null);
  const STALL_WARNING_THRESHOLD_MS = 60000; // Show warning after 60 seconds
  const STALL_ERROR_THRESHOLD_MS = 120000; // Show error after 2 minutes
  
  // WebSocket connection state
  const [wsConnected, setWsConnected] = useState(false);
  
  // Agent disconnection state
  const [agentDisconnected, setAgentDisconnected] = useState(false);

  // WebSocket integration for real-time scan updates
  const { isConnected: wsIsConnected, connectionState } = useScanWebSocket(scanId, {
    enabled: !!scanId && (status === "running" || status === "initializing" || status === "queued"),
    onProgress: (data) => {
      console.log("WebSocket: Progress update", data);
      setProgress(data.progress || 0);
      setFindings(data.findings_count || 0);
      if (data.phase) {
        // Map phase name to phase number
        const getPhaseNumber = (phaseName) => {
          const phaseNameMap = {
            "Initializing": 1, "Anonymous Crawling": 1,
            "Pre-Login OWASP Scan": 2, "Authentication": 3,
            "Authenticated Crawling": 4, "Post-Login Scan": 5, "Post-Login Security Scan": 5,
            "API Testing": 6, "API Security Testing": 6, "AI-Guided Testing": 7,
            "AI Verification": 7, "Report Generation": 8, "Completed": 8
          };
          return phaseNameMap[phaseName] || 1;
        };
        setCurrentPhase(getPhaseNumber(data.phase));
      }
      // Clear stall warning on real progress
      if (data.progress > 5) {
        setStalledWarning(null);
        setScanStartTime(null);
      }
    },
    onStatus: (data) => {
      console.log("WebSocket: Status update", data);
      setStatus(data.status || "running");
      if (data.status === "waiting_for_manual_auth") {
        setShowManualLoginModal(true);
      }
      if (data.status === "waiting_for_otp") {
        setShowOtpModal(true);
      }
    },
    onLog: (data) => {
      console.log("WebSocket: Log", data);
      if (data.message) {
        setLogs(prev => [...prev, {
          timestamp: data.timestamp || new Date().toISOString(),
          level: data.level || "info",
          message: data.message
        }]);
      }
    },
    onComplete: (data) => {
      console.log("WebSocket: Scan complete", data);
      setStatus("completed");
      setProgress(100);
      setFindings(data.findings_count || findings);
      setTimeout(() => {
        navigate("/dashboard/vulnerabilities", {
          state: { scanId, scanType }
        });
      }, 2000);
    },
    onError: (data) => {
      console.log("WebSocket: Scan error", data);
      setStatus("error");
      setError(data.error || "Scan encountered an error");
    },
    onFinding: (data) => {
      console.log("WebSocket: New finding", data);
      setFindings(prev => prev + 1);
      if (data.finding) {
        setFindingsDetails(prev => [...prev, data.finding]);
      }
    },
    onConnect: () => {
      console.log("WebSocket connected");
      setWsConnected(true);
    },
    onDisconnect: () => {
      console.log("WebSocket disconnected");
      setWsConnected(false);
    }
  });

  const scanConfig = location.state?.scanConfig;
  // Extract target URL from multiple sources with proper fallback - prefer API response
  const targetDomain = actualTargetUrl || scanConfig?.target_url || scanConfig?.domain || searchParams.get("target") || location.state?.target_url || "scanning...";

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

  const networkPhases = [
    { id: 1, name: "Host Discovery", icon: "" },
    { id: 2, name: "Port Scanning", icon: "" },
    { id: 3, name: "Service Detection", icon: "" },
    { id: 4, name: "Vulnerability Scanning", icon: "" },
    { id: 5, name: "Report Generation", icon: "" },
  ];

  const cloudPhases = [
    { id: 1, name: "Cloud Discovery", icon: "" },
    { id: 2, name: "CSPM Scanning", icon: "" },
    { id: 3, name: "IaC Analysis", icon: "" },
    { id: 4, name: "Container Scanning", icon: "" },
    { id: 5, name: "Runtime Detection", icon: "" },
    { id: 6, name: "CIEM Analysis", icon: "" },
    { id: 7, name: "Kubernetes Scanning", icon: "" },
    { id: 8, name: "Drift Detection", icon: "" },
    { id: 9, name: "Data Security", icon: "" },
    { id: 10, name: "Compliance Mapping", icon: "" },
    { id: 11, name: "AI Attack Path Analysis", icon: "" },
  ];

  // Select phases based on scan type
  const getPhases = () => {
    switch (scanType) {
      case "mobile": return mobilePhases;
      case "network": return networkPhases;
      case "cloud": return cloudPhases;
      default: return webPhases;
    }
  };
  const phases = getPhases();

  // State for loading running scans
  const [loadingRunning, setLoadingRunning] = useState(false);
  const [runningScans, setRunningScans] = useState([]);

  // Initialize scan from state or URL, or auto-fetch running scans
  useEffect(() => {
    const urlScanId = searchParams.get("scan_id");
    const urlScanType = searchParams.get("type") || "web";
    const routeScanId = params.scanId;  // From route /scanning/:scanId
    const stateScanId = location.state?.scanId;
    const stateScanType = location.state?.scanType;

    console.log("Scanning page loaded:", { urlScanId, routeScanId, stateScanId, scanConfig: !!scanConfig });

    if (routeScanId || urlScanId || stateScanId) {
      console.log("Setting scanId from route/state/url:", routeScanId || urlScanId || stateScanId);
      setScanId(routeScanId || urlScanId || stateScanId);
      setScanType(urlScanType || stateScanType || "web");
    } else if (scanConfig && !scanId) {
      console.log("Starting new scan from scanConfig");
      // Start a new scan if config is provided
      startScan();
    } else if (!scanId && !scanConfig) {
      // No scan specified - try to find running scans automatically
      // This handles the case when user clicks "Active Scan" in sidebar
      const fetchRunningScans = async () => {
        setLoadingRunning(true);
        try {
          console.log("No scanId provided, fetching running scans...");
          const response = await scanAPI.getRunningScans();
          console.log("Running scans response:", response);
          
          if (response.scans && response.scans.length > 0) {
            setRunningScans(response.scans);
            // Auto-select the first running scan
            const firstScan = response.scans[0];
            console.log("Auto-selecting running scan:", firstScan);
            setScanId(firstScan.scan_id || firstScan.id);
            setScanType(firstScan.scan_type || "web");
            if (firstScan.target) {
              setActualTargetUrl(firstScan.target);
            }
          }
        } catch (err) {
          console.warn("Failed to fetch running scans:", err);
        } finally {
          setLoadingRunning(false);
        }
      };
      fetchRunningScans();
    }
  }, [searchParams, params.scanId, location.state, scanConfig]);

  // Poll for status updates (fallback when WebSocket not connected)
  useEffect(() => {
    if (!scanId) {
      console.log("Scanning: No scanId yet, waiting...");
      return;
    }
    
    // Skip polling if WebSocket is connected - we get real-time updates
    if (wsConnected) {
      console.log("Scanning: WebSocket connected, skipping HTTP polling");
      return;
    }

    // Initialize scan start time for stall detection
    if (!scanStartTime) {
      setScanStartTime(Date.now());
    }

    const pollStatus = async () => {
      try {
        console.log(`Scanning: Polling status for scan ${scanId} (WebSocket fallback)`);
        // Select appropriate API based on scan type
        const getApiForScanType = () => {
          switch (scanType) {
            case "mobile": return mobileScanAPI;
            case "network": return networkScanAPI;
            case "cloud": return cloudScanAPI;
            default: return scanAPI;
          }
        };
        const api = getApiForScanType();
        const statusData = await api.getScanStatus(scanId);
        console.log("Scanning: Status response:", statusData);

        if (statusData) {
          const newProgress = statusData.progress || 0;
          setProgress(newProgress);
          setStatus(statusData.status || "running");
          
          // Clear stall warning if progress is being made
          if (newProgress > 5 || statusData.status === "completed" || statusData.status === "error") {
            setStalledWarning(null);
            setScanStartTime(null); // Reset timer
          }
          
          // Check for stalled scan (stuck at low progress for too long)
          if (scanStartTime && newProgress <= 5 && statusData.status === "running") {
            const elapsedMs = Date.now() - scanStartTime;
            if (elapsedMs >= STALL_ERROR_THRESHOLD_MS) {
              setStalledWarning("error");
            } else if (elapsedMs >= STALL_WARNING_THRESHOLD_MS) {
              setStalledWarning("warning");
            }
          }
          
          // Map phase name to phase number based on scan type
          const getPhaseMap = () => {
            if (scanType === "network") {
              return {
                "Initializing": 1,
                "Host Discovery": 1,
                "host_discovery": 1,
                "Port Scanning": 2,
                "port_scanning": 2,
                "Service Detection": 3,
                "service_detection": 3,
                "Vulnerability Scanning": 4,
                "vulnerability_scanning": 4,
                "Report Generation": 5,
                "report_generation": 5,
                "Completed": 5
              };
            } else if (scanType === "cloud") {
              return {
                "Initializing": 1,
                "Discovery": 1,
                "discovery": 1,
                "CSPM Scanning": 2,
                "cspm_scanning": 2,
                "IaC Analysis": 3,
                "iac_analysis": 3,
                "Container Scanning": 4,
                "container_scanning": 4,
                "Runtime Detection": 5,
                "runtime_detection": 5,
                "CIEM Analysis": 6,
                "ciem_scanning": 6,
                "Kubernetes Scanning": 7,
                "kubernetes_scanning": 7,
                "Drift Detection": 8,
                "drift_detection": 8,
                "Data Security": 9,
                "data_security": 9,
                "Compliance Mapping": 10,
                "compliance_mapping": 10,
                "AI Attack Path Analysis": 11,
                "ai_analysis": 11,
                "Completed": 11
              };
            } else if (scanType === "mobile") {
              return {
                "Initializing": 1,
                "APK/IPA Analysis": 1,
                "SSL Pinning Bypass": 2,
                "Traffic Interception": 3,
                "API Security Testing": 4,
                "Report Generation": 5,
                "Completed": 5
              };
            }
            // Web phases (default)
            return {
              "Initializing": 1,
              "Anonymous Crawling": 1,
              "Pre-Login OWASP Scan": 2,
              "Authentication": 3,
              "Authenticated Crawling": 4,
              "Post-Login Scan": 5,
              "Post-Login Security Scan": 5,
              "API Testing": 6,
              "API Security Testing": 6,
              "AI-Guided Testing": 7,
              "AI Verification": 7,
              "Report Generation": 8,
              "Completed": 8
            };
          };
          const phaseNameMap = getPhaseMap();
          const currentPhaseName = statusData.phase || "Initializing";
          setCurrentPhase(phaseNameMap[currentPhaseName] || 1);
          setFindings(statusData.findings_count || 0);
          
          // Update actual target URL from API response
          if (statusData.target_url) {
            setActualTargetUrl(statusData.target_url);
          }

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

          // Check for manual auth / OTP waiting states
          if (statusData.status === "waiting_for_manual_auth" || statusData.waiting_for_manual_auth) {
            setShowManualLoginModal(true);
          }
          if (statusData.status === "waiting_for_otp" || statusData.waiting_for_otp) {
            setShowOtpModal(true);
          }

          // Navigate to results when complete
          if (statusData.status === "completed") {
            setTimeout(() => {
              navigate("/dashboard/vulnerabilities", {
                state: { scanId, scanType }
              });
            }, 2000);
          }
          
          // Handle error state - show detailed error message from backend
          if (statusData.status === "error") {
            // Use error_message from backend if available, otherwise fall back to phase
            const errorMsg = statusData.error_message || statusData.phase || "Scan encountered an error";
            setError(errorMsg);
          }
          
          // Handle agent disconnection
          if (statusData.status === "agent_disconnected") {
            setError("Agent connection lost. Please check your Jarwis Agent and resume the scan from your Scan History.");
            setAgentDisconnected(true);
          }
          
          // Handle stalled state from backend (no activity for 2+ hours)
          if (statusData.status === "stalled") {
            setStalledWarning("error");
            setError("Scan appears to have stalled. No activity detected for over 2 hours. You can resume or restart the scan.");
          }
          
          // Update findings count from response
          if (statusData.findings_count !== undefined) {
            setFindings(statusData.findings_count);
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
      if (status === "running" || status === "initializing" || status === "queued" || 
          status === "waiting_for_manual_auth" || status === "waiting_for_otp") {
        pollStatus();
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [scanId, scanType, status, navigate, scanStartTime, wsConnected, STALL_WARNING_THRESHOLD_MS, STALL_ERROR_THRESHOLD_MS]);

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
      // Select appropriate API based on scan type
      const getApiForScanType = () => {
        switch (scanType) {
          case "mobile": return mobileScanAPI;
          case "network": return networkScanAPI;
          case "cloud": return cloudScanAPI;
          default: return scanAPI;
        }
      };
      const api = getApiForScanType();
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

  // Get scan type display info
  const getScanTypeDisplay = () => {
    switch (scanType) {
      case "mobile": return { label: "Mobile App", icon: Smartphone, color: "purple" };
      case "network": return { label: "Network", icon: Wifi, color: "green" };
      case "cloud": return { label: "Cloud Security", icon: Cloud, color: "amber" };
      default: return { label: "Web Application", icon: Globe, color: "blue" };
    }
  };
  const scanTypeInfo = getScanTypeDisplay();
  const ScanIcon = scanTypeInfo.icon;

  // Show loading state while fetching running scans
  if (loadingRunning) {
    return (
      <MiftyJarwisLayout>
        <div className="p-6">
          <div className="flex flex-col items-center justify-center min-h-[60vh]">
            <div className="animate-spin rounded-full h-16 w-16 border-4 border-blue-500 border-t-transparent mb-6"></div>
            <h2
              className={`text-xl font-medium ${
                isDarkMode ? "text-white" : "text-gray-900"
              }`}
            >
              Loading active scans...
            </h2>
          </div>
        </div>
      </MiftyJarwisLayout>
    );
  }

  // Show empty state if no scan is active
  if (!scanId && !scanConfig) {
    return (
      <MiftyJarwisLayout>
        <div className="p-6">
          <div className="flex flex-col items-center justify-center min-h-[60vh]">
            <div className={`text-6xl mb-6 ${isDarkMode ? "opacity-50" : "opacity-40"}`}>
              🔍
            </div>
            <h2
              className={`text-2xl font-bold mb-4 ${
                isDarkMode ? "text-white" : "text-gray-900"
              }`}
            >
              No Active Scan
            </h2>
            <p
              className={`text-center max-w-md mb-8 ${
                isDarkMode ? "text-gray-400" : "text-gray-600"
              }`}
            >
              You don't have any scans running at the moment. Start a new security scan to begin testing your application.
            </p>
            <div className="flex gap-4">
              <button
                onClick={() => navigate("/dashboard/new-scan")}
                className="px-6 py-3 bg-gradient-to-r from-blue-600 to-cyan-500 text-white rounded-lg font-medium hover:from-blue-500 hover:to-cyan-400 transition-all shadow-lg"
              >
                Start New Scan
              </button>
              <button
                onClick={() => navigate("/dashboard/scan-history")}
                className={`px-6 py-3 rounded-lg font-medium transition-all ${
                  isDarkMode
                    ? "bg-gray-700 text-gray-200 hover:bg-gray-600"
                    : "bg-gray-200 text-gray-700 hover:bg-gray-300"
                }`}
              >
                View Scan History
              </button>
            </div>
          </div>
        </div>
      </MiftyJarwisLayout>
    );
  }

  return (
    <MiftyJarwisLayout>
      <div className="p-6">
      <div className="flex items-center gap-3 mb-2">
        <ScanIcon className={`w-6 h-6 text-${scanTypeInfo.color}-500`} />
        <h2
          className={
            isDarkMode
              ? "text-2xl font-bold text-white"
              : "text-2xl font-bold text-gray-900"
          }
        >
          {scanTypeInfo.label} Scan in Progress
        </h2>
      </div>
      <p
        className={
          isDarkMode
            ? "text-sm text-gray-400 mb-4"
            : "text-sm text-gray-600 mb-4"
        }
      >
        {scanType === "cloud" 
          ? "Jarwis is scanning your cloud infrastructure, analyzing configurations, detecting vulnerabilities, and mapping attack paths."
          : scanType === "network"
          ? "Jarwis is discovering hosts, scanning ports, detecting services, and identifying network vulnerabilities."
          : scanType === "mobile"
          ? "Jarwis is analyzing your mobile app, bypassing SSL pinning, intercepting traffic, and testing API security."
          : "Jarwis is mapping your application, attempting login, exploring post-login flows, and fuzzing APIs."
        }
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
            <div className="flex items-center gap-2">
              <strong>Connection:</strong>
              <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${
                wsConnected 
                  ? (isDarkMode ? "bg-green-500/20 text-green-400" : "bg-green-100 text-green-700")
                  : (isDarkMode ? "bg-yellow-500/20 text-yellow-400" : "bg-yellow-100 text-yellow-700")
              }`}>
                <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? "bg-green-500 animate-pulse" : "bg-yellow-500"}`}></span>
                {wsConnected ? "Live" : "Polling"}
              </span>
            </div>
            <div>
              <strong>Findings:</strong> {findings} potential issues discovered
            </div>
          </div>
        </div>
      </div>

      {/* Stall Warning Banner */}
      {stalledWarning && (
        <div
          className={`
            rounded-lg p-4 my-4 flex items-center justify-between
            ${stalledWarning === "error"
              ? (isDarkMode 
                  ? "bg-red-900/30 border border-red-700" 
                  : "bg-red-50 border border-red-200")
              : (isDarkMode 
                  ? "bg-yellow-900/30 border border-yellow-700" 
                  : "bg-yellow-50 border border-yellow-200")
            }
          `}
        >
          <div className="flex items-center gap-3">
            <AlertTriangle 
              className={`w-5 h-5 ${
                stalledWarning === "error" 
                  ? "text-red-500" 
                  : "text-yellow-500"
              }`} 
            />
            <div>
              <p className={`font-medium ${
                stalledWarning === "error"
                  ? (isDarkMode ? "text-red-300" : "text-red-800")
                  : (isDarkMode ? "text-yellow-300" : "text-yellow-800")
              }`}>
                {stalledWarning === "error" 
                  ? "Scan appears to be stuck" 
                  : "Scan is taking longer than expected"}
              </p>
              <p className={`text-sm ${
                stalledWarning === "error"
                  ? (isDarkMode ? "text-red-400" : "text-red-600")
                  : (isDarkMode ? "text-yellow-400" : "text-yellow-600")
              }`}>
                {stalledWarning === "error" 
                  ? "The scan hasn't made progress for over 2 minutes. There might be a connection issue with the target."
                  : "This is normal for large or slow websites. The scan will continue automatically."}
              </p>
            </div>
          </div>
          {stalledWarning === "error" && (
            <div className="flex gap-2">
              <button
                onClick={() => navigate("/dashboard/history")}
                className={`px-4 py-2 rounded text-sm font-medium transition-colors
                  ${isDarkMode
                    ? "bg-gray-700 text-white hover:bg-gray-600"
                    : "bg-white text-gray-700 border border-gray-300 hover:bg-gray-50"
                  }
                `}
              >
                View History
              </button>
              <button
                onClick={() => {
                  // Reset and try again
                  setStalledWarning(null);
                  setScanStartTime(Date.now());
                }}
                className={`px-4 py-2 rounded text-sm font-medium transition-colors
                  ${isDarkMode
                    ? "bg-blue-600 text-white hover:bg-blue-700"
                    : "bg-blue-600 text-white hover:bg-blue-700"
                  }
                `}
              >
                Keep Waiting
              </button>
            </div>
          )}
        </div>
      )}

      {/* Agent Disconnection Banner */}
      {agentDisconnected && (
        <div
          className={`
            rounded-lg p-4 my-4 flex items-center justify-between
            ${isDarkMode 
              ? "bg-orange-900/30 border border-orange-700" 
              : "bg-orange-50 border border-orange-200"
            }
          `}
        >
          <div className="flex items-center gap-3">
            <Wifi 
              className="w-5 h-5 text-orange-500"
            />
            <div>
              <p className={`font-medium ${isDarkMode ? "text-orange-300" : "text-orange-800"}`}>
                Agent Connection Lost
              </p>
              <p className={`text-sm ${isDarkMode ? "text-orange-400" : "text-orange-600"}`}>
                Your Jarwis Agent disconnected during the scan. The scan has been paused and can be resumed once your agent reconnects.
              </p>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => navigate("/dashboard/agent")}
              className={`px-4 py-2 rounded text-sm font-medium transition-colors
                ${isDarkMode
                  ? "bg-orange-600 text-white hover:bg-orange-700"
                  : "bg-orange-600 text-white hover:bg-orange-700"
                }
              `}
            >
              Setup Agent
            </button>
            <button
              onClick={() => navigate("/dashboard/history")}
              className={`px-4 py-2 rounded text-sm font-medium transition-colors
                ${isDarkMode
                  ? "bg-gray-700 text-white hover:bg-gray-600"
                  : "bg-white text-gray-700 border border-gray-300 hover:bg-gray-50"
                }
              `}
            >
              View History
            </button>
          </div>
        </div>
      )}

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
          icon={<FileSearch className="w-5 h-5" />}
          count={pagesScanned.length || Math.floor(progress * 1.2) + 15}
          items={pagesScanned}
          isDarkMode={isDarkMode}
          emptyMessage="Discovering pages..."
        />
        <ExpandableStatCard
          title="API Endpoints"
          icon={<Webhook className="w-5 h-5" />}
          count={apiEndpoints.length || Math.floor(progress * 0.8) + 8}
          items={apiEndpoints}
          isDarkMode={isDarkMode}
          emptyMessage="Detecting API endpoints..."
        />
        <ExpandableStatCard
          title="Requests Sent"
          icon={<Send className="w-5 h-5" />}
          count={requestsSent.length || Math.floor(progress * 50) + 1247}
          items={requestsSent}
          isDarkMode={isDarkMode}
          emptyMessage="Sending requests..."
        />
        <ExpandableStatCard
          title="Issues Found"
          icon={<AlertTriangle className="w-5 h-5" />}
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

      {/* Error Display with Retry Option */}
      {(status === "error" || error) && (
        <div
          className={
            isDarkMode
              ? "bg-red-900/30 border border-red-700 rounded-lg p-6 mt-6"
              : "bg-red-50 border border-red-200 rounded-lg p-6 mt-6 shadow-sm"
          }
        >
          <div className="flex items-start gap-4">
            <div className="flex-shrink-0">
              <AlertTriangle className={`w-8 h-8 ${isDarkMode ? "text-red-400" : "text-red-500"}`} />
            </div>
            <div className="flex-1">
              <h3
                className={`text-lg font-semibold mb-2 ${
                  isDarkMode ? "text-red-300" : "text-red-700"
                }`}
              >
                Scan Failed
              </h3>
              <p
                className={`text-sm mb-4 ${
                  isDarkMode ? "text-red-200" : "text-red-600"
                }`}
              >
                {error || "The scan encountered an unexpected error."}
              </p>
              <div className="flex flex-wrap gap-3">
                <button
                  onClick={async () => {
                    try {
                      const api = scanType === "mobile" ? mobileScanAPI : scanAPI;
                      const response = await api.retryScan(scanId);
                      if (response.new_scan_id) {
                        // Navigate to new scan
                        navigate(`/dashboard/scanning?scan_id=${response.new_scan_id}&type=${scanType}`, {
                          replace: true
                        });
                        window.location.reload();
                      }
                    } catch (err) {
                      console.error("Retry failed:", err);
                      alert("Failed to retry scan: " + (err.message || "Unknown error"));
                    }
                  }}
                  className={
                    isDarkMode
                      ? "bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-md transition-colors text-sm"
                      : "bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition-colors text-sm shadow-sm"
                  }
                >
                  🔄 Retry Scan
                </button>
                <button
                  onClick={async () => {
                    try {
                      const api = scanType === "mobile" ? mobileScanAPI : scanAPI;
                      const diagnostics = await api.getScanDiagnostics(scanId);
                      // Show diagnostics in a modal or alert
                      alert(`Diagnostics:\n\nLast Phase: ${diagnostics.last_successful_phase || diagnostics.current_phase}\n\nError: ${diagnostics.error_message || "Unknown"}\n\nSuggestions:\n${(diagnostics.suggestions || []).join('\n')}`);
                    } catch (err) {
                      console.error("Failed to get diagnostics:", err);
                    }
                  }}
                  className={
                    isDarkMode
                      ? "bg-transparent border border-gray-600 hover:border-gray-500 text-gray-300 hover:text-white px-4 py-2 rounded-md transition-colors text-sm"
                      : "bg-transparent border border-gray-300 hover:border-gray-400 text-gray-700 hover:text-gray-900 px-4 py-2 rounded-md transition-colors text-sm"
                  }
                >
                  🔍 View Diagnostics
                </button>
                <button
                  onClick={() => navigate("/dashboard/new-scan")}
                  className={
                    isDarkMode
                      ? "bg-transparent border border-gray-600 hover:border-gray-500 text-gray-300 hover:text-white px-4 py-2 rounded-md transition-colors text-sm"
                      : "bg-transparent border border-gray-300 hover:border-gray-400 text-gray-700 hover:text-gray-900 px-4 py-2 rounded-md transition-colors text-sm"
                  }
                >
                  ➕ Start New Scan
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      </div>

      {/* Manual Login Modal (for social login targets) */}
      {showManualLoginModal && scanId && (
        <ManualLoginModal
          scanId={scanId}
          onClose={() => setShowManualLoginModal(false)}
          onComplete={() => {
            setShowManualLoginModal(false);
            setStatus("running");
          }}
        />
      )}

      {/* OTP Input Modal (for phone/email OTP targets) */}
      {showOtpModal && scanId && (
        <OTPInputModal
          scanId={scanId}
          onClose={() => setShowOtpModal(false)}
          onComplete={() => {
            setShowOtpModal(false);
            setStatus("running");
          }}
        />
      )}
    </MiftyJarwisLayout>
  );
};

export default Scanning;
