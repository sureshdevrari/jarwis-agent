// src/components/scan/ScanStatus.jsx
// Real-time scan status component with live logs
import { useState, useEffect, useCallback, useRef } from "react";
import { useTheme } from "../../context/ThemeContext";
import { scanAPI, mobileScanAPI } from "../../services/api";

// Helper to detect scan type from scan ID
const getScanType = (scanId) => {
  if (!scanId) return "web";
  if (scanId.startsWith("MOBILE-")) return "mobile";
  if (scanId.startsWith("CLOUD-")) return "cloud";
  return "web";
};

const ScanStatus = ({ scanId, onScanComplete, onNewScan }) => {
  const { isDarkMode } = useTheme();
  const [status, setStatus] = useState(null);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState("connected");
  const [retryCount, setRetryCount] = useState(0);
  const [lastLogTimestamp, setLastLogTimestamp] = useState(null);
  const logsEndRef = useRef(null);
  const pollIntervalRef = useRef(null);
  
  // Stop confirmation dialog state
  const [showStopConfirm, setShowStopConfirm] = useState(false);
  const [stopConfirmMessage, setStopConfirmMessage] = useState("");
  const [stopWarningLevel, setStopWarningLevel] = useState("info");
  const [stopAttempts, setStopAttempts] = useState(0);
  const [refundBlocked, setRefundBlocked] = useState(false);
  const [isStopping, setIsStopping] = useState(false);

  const scanType = getScanType(scanId);

  // Auto-scroll logs to bottom
  const scrollToBottom = () => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [logs]);

  const fetchStatus = useCallback(async () => {
    try {
      const data = scanType === "mobile" 
        ? await mobileScanAPI.getScanStatus(scanId) 
        : await scanAPI.getScanStatus(scanId);
      
      setStatus(data);
      setError(null);
      setConnectionStatus("connected");
      setRetryCount(0);

      if (data.status === "completed" || data.status === "error" || data.status === "stopped") {
        if (onScanComplete) {
          onScanComplete(data);
        }
        if (pollIntervalRef.current) {
          clearInterval(pollIntervalRef.current);
          pollIntervalRef.current = null;
        }
      }
    } catch (err) {
      console.error("Status fetch error:", err);
      setConnectionStatus("disconnected");
      setRetryCount((prev) => prev + 1);
      if (retryCount >= 3) {
        setError("Connection lost. Attempting to reconnect...");
      }
    }
  }, [scanId, scanType, onScanComplete, retryCount]);

  const fetchLogs = useCallback(async () => {
    try {
      const data = scanType === "mobile"
        ? await mobileScanAPI.getScanLogs(scanId, lastLogTimestamp)
        : await scanAPI.getScanLogs(scanId, lastLogTimestamp);
      
      if (data.logs && data.logs.length > 0) {
        setLogs((prevLogs) => {
          const existingTimestamps = new Set(prevLogs.map((l) => l.timestamp));
          const newLogs = data.logs.filter((l) => !existingTimestamps.has(l.timestamp));
          return [...prevLogs, ...newLogs];
        });
        const lastLog = data.logs[data.logs.length - 1];
        setLastLogTimestamp(lastLog.timestamp);
      }
    } catch (err) {
      console.error("Logs fetch error:", err);
    }
  }, [scanId, scanType, lastLogTimestamp]);

  // Main polling effect
  useEffect(() => {
    fetchStatus();
    fetchLogs();

    const pollInterval = connectionStatus === "connected" ? 1500 : 3000;
    pollIntervalRef.current = setInterval(() => {
      const isDone = status?.status === "completed" || status?.status === "error" || status?.status === "stopped";
      if (!isDone) {
        fetchStatus();
        fetchLogs();
      }
    }, pollInterval);

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [scanId, connectionStatus]);

  const handleStop = async (confirmed = false) => {
    try {
      setIsStopping(true);
      const response = scanType === "mobile" 
        ? await mobileScanAPI.stopScan(scanId, confirmed) 
        : await scanAPI.stopScan(scanId, confirmed);
      
      // Check if confirmation is required
      if (response.data?.requires_confirmation && !confirmed) {
        setStopConfirmMessage(response.message);
        setStopWarningLevel(response.data.warning_level || "info");
        setStopAttempts(response.data.stop_attempts || 1);
        setRefundBlocked(response.data.refund_blocked || false);
        setShowStopConfirm(true);
        setIsStopping(false);
        return;
      }
      
      // Scan was stopped
      setShowStopConfirm(false);
      fetchStatus();
    } catch (err) {
      setError("Failed to stop scan");
    } finally {
      setIsStopping(false);
    }
  };
  
  const handleConfirmStop = async () => {
    await handleStop(true);
  };
  
  const handleCancelStop = () => {
    setShowStopConfirm(false);
    setStopConfirmMessage("");
  };

  const getLogIcon = (type) => {
    switch (type) {
      case "info": return "ℹ️";
      case "success": return "✅";
      case "warning": return "⚠️";
      case "error": return "❌";
      case "ai": return "🛡️";
      case "finding": return "🔴";
      case "phase": return "📊";
      default: return "•";
    }
  };

  const getLogColor = (type) => {
    switch (type) {
      case "info": return "text-blue-400";
      case "success": return "text-green-400";
      case "warning": return "text-yellow-400";
      case "error": return "text-red-400";
      case "ai": return "text-purple-400";
      case "finding": return "text-red-500";
      case "phase": return "text-cyan-400";
      default: return isDarkMode ? "text-gray-400" : "text-gray-600";
    }
  };

  // Theme classes
  const cardClass = isDarkMode
    ? "bg-slate-800/50 border border-slate-700/50 rounded-xl p-6"
    : "bg-white border border-gray-200 rounded-xl p-6 shadow-sm";

  if (error && retryCount >= 5) {
    return (
      <div className={`${cardClass} text-center`}>
        <div className="text-4xl mb-4">❌</div>
        <h3 className={isDarkMode ? "text-xl font-semibold text-white mb-2" : "text-xl font-semibold text-gray-900 mb-2"}>
          Connection Error
        </h3>
        <p className={isDarkMode ? "text-gray-400 mb-4" : "text-gray-600 mb-4"}>{error}</p>
        <p className={isDarkMode ? "text-gray-500 text-sm mb-4" : "text-gray-500 text-sm mb-4"}>
          Retry attempts: {retryCount}
        </p>
        <div className="flex justify-center gap-3">
          <button
            onClick={() => { setRetryCount(0); fetchStatus(); }}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
          >
             Retry Connection
          </button>
          {onNewScan && (
            <button
              onClick={onNewScan}
              className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
            >
              Start New Scan
            </button>
          )}
        </div>
      </div>
    );
  }

  if (!status) {
    return (
      <div className={`${cardClass} text-center`}>
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
        <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>Loading scan status...</p>
        {connectionStatus === "disconnected" && (
          <p className="text-yellow-400 text-sm mt-2">Reconnecting... (attempt {retryCount})</p>
        )}
      </div>
    );
  }

  const getStatusIcon = () => {
    switch (status.status) {
      case "running": return "🔄";
      case "completed": return "✅";
      case "error": return "❌";
      case "stopped": return "⏹️";
      case "queued": return "⏳";
      default: return "📊";
    }
  };

  const getProgressPercentage = () => {
    if (status.progress !== undefined) return status.progress;
    if (status.status === "completed") return 100;
    if (status.status === "running") return 50;
    return 0;
  };

  return (
    <div className="space-y-6">
      {/* Connection Status Banner */}
      {connectionStatus === "disconnected" && (
        <div className={`p-3 rounded-lg ${isDarkMode ? "bg-yellow-900/20 border border-yellow-700/30" : "bg-yellow-50 border border-yellow-200"}`}>
          <p className={isDarkMode ? "text-yellow-400 text-sm" : "text-yellow-700 text-sm"}>
            ⚠️ Connection interrupted. Attempting to reconnect... (attempt {retryCount})
          </p>
        </div>
      )}

      {/* Status Overview */}
      <div className={cardClass}>
        <div className="flex items-center justify-between flex-wrap gap-4 mb-6">
          <div className="flex items-center gap-4">
            <div className="text-4xl">{getStatusIcon()}</div>
            <div>
              <h2 className={isDarkMode ? "text-xl font-semibold text-white" : "text-xl font-semibold text-gray-900"}>
                {status.target_url || status.target || "Scan in Progress"}
              </h2>
              <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>
                {scanType.toUpperCase()} Scan * ID: {scanId}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className={`px-4 py-2 rounded-full text-sm font-medium ${
              status.status === "running" 
                ? "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                : status.status === "completed"
                ? "bg-green-500/20 text-green-400 border border-green-500/30"
                : status.status === "error"
                ? "bg-red-500/20 text-red-400 border border-red-500/30"
                : "bg-gray-500/20 text-gray-400 border border-gray-500/30"
            }`}>
              {status.status?.toUpperCase()}
            </span>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="mb-4">
          <div className="flex justify-between mb-2">
            <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
              {status.current_phase || "Scanning..."}
            </span>
            <span className={isDarkMode ? "text-gray-400" : "text-gray-600"}>
              {getProgressPercentage()}%
            </span>
          </div>
          <div className={`w-full h-3 rounded-full ${isDarkMode ? "bg-slate-700" : "bg-gray-200"}`}>
            <div
              className="h-3 rounded-full bg-gradient-to-r from-blue-500 to-purple-500 transition-all duration-500"
              style={{ width: `${getProgressPercentage()}%` }}
            ></div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className={`p-3 rounded-lg ${isDarkMode ? "bg-slate-900/50" : "bg-gray-50"}`}>
            <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>Endpoints</div>
            <div className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              {status.endpoints_found || 0}
            </div>
          </div>
          <div className={`p-3 rounded-lg ${isDarkMode ? "bg-slate-900/50" : "bg-gray-50"}`}>
            <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>Requests</div>
            <div className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              {status.requests_sent || 0}
            </div>
          </div>
          <div className={`p-3 rounded-lg ${isDarkMode ? "bg-slate-900/50" : "bg-gray-50"}`}>
            <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>Findings</div>
            <div className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              {status.findings_count || 0}
            </div>
          </div>
          <div className={`p-3 rounded-lg ${isDarkMode ? "bg-slate-900/50" : "bg-gray-50"}`}>
            <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>Duration</div>
            <div className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              {status.duration || "0:00"}
            </div>
          </div>
        </div>
      </div>

      {/* Severity Summary */}
      {status.results && (
        <div className={cardClass}>
          <h3 className={isDarkMode ? "text-lg font-semibold text-white mb-4" : "text-lg font-semibold text-gray-900 mb-4"}>
            Vulnerability Summary
          </h3>
          <div className="grid grid-cols-5 gap-3">
            {[
              { label: "Critical", count: status.results.critical || 0, color: "bg-red-500" },
              { label: "High", count: status.results.high || 0, color: "bg-orange-500" },
              { label: "Medium", count: status.results.medium || 0, color: "bg-yellow-500" },
              { label: "Low", count: status.results.low || 0, color: "bg-blue-500" },
              { label: "Info", count: status.results.info || 0, color: "bg-gray-500" },
            ].map((sev) => (
              <div key={sev.label} className="text-center">
                <div className={`${sev.color} text-white text-2xl font-bold py-3 rounded-lg`}>
                  {sev.count}
                </div>
                <div className={isDarkMode ? "text-gray-400 text-sm mt-1" : "text-gray-600 text-sm mt-1"}>
                  {sev.label}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Live Logs */}
      <div className={cardClass}>
        <div className="flex items-center justify-between mb-4">
          <h3 className={isDarkMode ? "text-lg font-semibold text-white" : "text-lg font-semibold text-gray-900"}>
            Live Scan Log
          </h3>
          <div className="flex items-center gap-2">
            {status.status === "running" && (
              <span className="flex items-center gap-2 text-green-400 text-sm">
                <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
                Live
              </span>
            )}
          </div>
        </div>
        <div className={`max-h-80 overflow-y-auto font-mono text-sm rounded-lg p-4 ${
          isDarkMode ? "bg-slate-900/50 border border-slate-700/50" : "bg-gray-900 border border-gray-700"
        }`}>
          {logs.length === 0 ? (
            <p className="text-gray-500">Waiting for logs...</p>
          ) : (
            logs.map((log, index) => (
              <div key={index} className={`py-1 ${getLogColor(log.type)}`}>
                <span className="text-gray-500">[{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : "--:--:--"}]</span>
                {" "}{getLogIcon(log.type)} {log.message}
              </div>
            ))
          )}
          <div ref={logsEndRef} />
        </div>
      </div>

      {/* Control Buttons */}
      <div className="flex gap-4">
        {status.status === "running" && (
          <>
            <button
              onClick={() => handleStop(false)}
              disabled={isStopping}
              className={`px-6 py-3 bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors font-medium ${isStopping ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              {isStopping ? '⏳ Stopping...' : '⏹ Stop Scan'}
            </button>
            <button
              className="px-6 py-3 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors font-medium"
            >
              ⏸ Pause Scan
            </button>
          </>
        )}
        {status.status === "completed" && (
          <>
            <a
              href={scanAPI.getReportUrl(scanId)}
              target="_blank"
              rel="noopener noreferrer"
              className="px-6 py-3 bg-green-600 hover:bg-green-500 text-white rounded-lg transition-colors font-medium inline-flex items-center gap-2"
            >
              📄 View Report
            </a>
            {onNewScan && (
              <button
                onClick={onNewScan}
                className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors font-medium"
              >
                🚀 New Scan
              </button>
            )}
          </>
        )}
        {(status.status === "error" || status.status === "stopped") && onNewScan && (
          <button
            onClick={onNewScan}
            className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors font-medium"
          >
            🚀 Start New Scan
          </button>
        )}
      </div>
      
      {/* Stop Confirmation Dialog */}
      {showStopConfirm && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className={`${cardClass} p-6 max-w-md mx-4 shadow-2xl`}>
            <div className="flex items-center gap-3 mb-4">
              {stopWarningLevel === "critical" ? (
                <span className="text-3xl">⚠️</span>
              ) : stopWarningLevel === "warning" ? (
                <span className="text-3xl">⚠️</span>
              ) : (
                <span className="text-3xl">❓</span>
              )}
              <h3 className={`text-lg font-semibold ${
                stopWarningLevel === "critical" ? "text-red-400" :
                stopWarningLevel === "warning" ? "text-yellow-400" :
                isDarkMode ? "text-white" : "text-gray-900"
              }`}>
                {stopWarningLevel === "critical" ? "Abuse Detected!" :
                 stopWarningLevel === "warning" ? "Warning" :
                 "Stop Scan?"}
              </h3>
            </div>
            
            <p className={`mb-4 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
              {stopConfirmMessage}
            </p>
            
            {stopAttempts > 1 && (
              <div className={`mb-4 p-3 rounded-lg ${
                stopWarningLevel === "critical" ? "bg-red-900/30 border border-red-700/50" :
                "bg-yellow-900/30 border border-yellow-700/50"
              }`}>
                <p className={`text-sm ${
                  stopWarningLevel === "critical" ? "text-red-400" : "text-yellow-400"
                }`}>
                  Stop attempts: {stopAttempts}
                  {refundBlocked && " - Credit will NOT be refunded"}
                </p>
              </div>
            )}
            
            <div className="flex gap-3 justify-end">
              <button
                onClick={handleCancelStop}
                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                  isDarkMode 
                    ? "bg-slate-700 hover:bg-slate-600 text-white" 
                    : "bg-gray-200 hover:bg-gray-300 text-gray-900"
                }`}
              >
                Continue Scan
              </button>
              <button
                onClick={handleConfirmStop}
                disabled={isStopping}
                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                  stopWarningLevel === "critical" 
                    ? "bg-red-700 hover:bg-red-600 text-white" 
                    : "bg-red-600 hover:bg-red-500 text-white"
                } ${isStopping ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                {isStopping ? 'Stopping...' : 'Yes, Stop Scan'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanStatus;
