// src/components/scan/ManualLoginModal.jsx
// Modal shown when scan is waiting for user to complete manual login (social/OTP)

import { useState, useEffect, useCallback } from "react";
import { X, ExternalLink, CheckCircle, XCircle, Clock, AlertTriangle, Loader2 } from "lucide-react";
import { useTheme } from "../../context/ThemeContext";
import { scanAuthAPI } from "../../services/api";

const ManualLoginModal = ({ scanId, onClose, onComplete }) => {
  const { isDarkMode } = useTheme();
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState(null);
  const [timeRemaining, setTimeRemaining] = useState(600);

  // Fetch manual auth status
  const fetchStatus = useCallback(async () => {
    try {
      const data = await scanAuthAPI.getStatus(scanId);
      setStatus(data);
      setTimeRemaining(data.time_remaining || 0);
      setLoading(false);
      
      // If no longer waiting, close modal
      if (!data.waiting_for_manual_auth && data.status !== "waiting") {
        onComplete?.(data);
      }
    } catch (err) {
      console.error("Error fetching manual auth status:", err);
      setError(err.response?.data?.detail || "Failed to fetch auth status");
      setLoading(false);
    }
  }, [scanId, onComplete]);

  // Poll for status updates
  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  // Countdown timer
  useEffect(() => {
    if (timeRemaining > 0) {
      const timer = setTimeout(() => {
        setTimeRemaining((t) => Math.max(0, t - 1));
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [timeRemaining]);

  // Handle confirm login
  const handleConfirmLogin = async () => {
    setConfirming(true);
    setError(null);
    try {
      await scanAuthAPI.confirmLogin(scanId);
      onComplete?.({ success: true });
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to confirm login");
      setConfirming(false);
    }
  };

  // Handle cancel
  const handleCancel = async () => {
    setConfirming(true);
    try {
      await scanAuthAPI.cancel(scanId);
      onClose?.();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to cancel");
      setConfirming(false);
    }
  };

  // Format time remaining
  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  // Modal styles
  const overlayClass = "fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50";
  const modalClass = isDarkMode
    ? "bg-slate-800 border border-slate-700 rounded-2xl shadow-2xl max-w-lg w-full mx-4 overflow-hidden"
    : "bg-white border border-gray-200 rounded-2xl shadow-2xl max-w-lg w-full mx-4 overflow-hidden";

  if (loading) {
    return (
      <div className={overlayClass}>
        <div className={modalClass}>
          <div className="p-8 flex flex-col items-center">
            <Loader2 className="w-10 h-10 text-blue-500 animate-spin mb-4" />
            <p className={isDarkMode ? "text-gray-300" : "text-gray-600"}>
              Loading authentication status...
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={overlayClass} onClick={(e) => e.target === e.currentTarget && onClose?.()}>
      <div className={modalClass}>
        {/* Header */}
        <div className={`p-4 border-b ${isDarkMode ? "border-slate-700 bg-slate-900/50" : "border-gray-200 bg-gray-50"}`}>
          <div className="flex items-center justify-between">
            <h2 className={`text-lg font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Manual Login Required
            </h2>
            <button
              onClick={onClose}
              className={`p-1 rounded-lg transition-colors ${
                isDarkMode ? "hover:bg-slate-700 text-gray-400" : "hover:bg-gray-200 text-gray-500"
              }`}
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Timer */}
          <div className="flex items-center justify-center gap-2">
            <Clock className={`w-5 h-5 ${timeRemaining < 60 ? "text-red-500" : "text-blue-500"}`} />
            <span className={`text-2xl font-mono font-bold ${
              timeRemaining < 60 
                ? "text-red-500" 
                : isDarkMode ? "text-white" : "text-gray-900"
            }`}>
              {formatTime(timeRemaining)}
            </span>
          </div>

          {/* Instructions */}
          <div className={`rounded-lg p-4 ${isDarkMode ? "bg-blue-900/20 border border-blue-800/50" : "bg-blue-50 border border-blue-200"}`}>
            <p className={isDarkMode ? "text-blue-300" : "text-blue-700"}>
              {status?.instructions || "Please complete the login in the browser window that opened."}
            </p>
          </div>

          {/* Social Providers */}
          {status?.social_providers?.length > 0 && (
            <div>
              <p className={`text-sm mb-2 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Login using one of these providers:
              </p>
              <div className="flex flex-wrap gap-2">
                {status.social_providers.map((provider) => (
                  <span
                    key={provider}
                    className={`px-3 py-1 rounded-full text-sm font-medium ${
                      isDarkMode ? "bg-slate-700 text-gray-300" : "bg-gray-200 text-gray-700"
                    }`}
                  >
                    {provider.charAt(0).toUpperCase() + provider.slice(1)}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Login URL */}
          {status?.login_url && (
            <a
              href={status.login_url}
              target="_blank"
              rel="noopener noreferrer"
              className={`flex items-center gap-2 text-sm ${
                isDarkMode ? "text-blue-400 hover:text-blue-300" : "text-blue-600 hover:text-blue-500"
              }`}
            >
              <ExternalLink className="w-4 h-4" />
              Open login page in new tab
            </a>
          )}

          {/* Error */}
          {error && (
            <div className={`rounded-lg p-3 ${isDarkMode ? "bg-red-900/20 border border-red-800/50" : "bg-red-50 border border-red-200"}`}>
              <p className={isDarkMode ? "text-red-300 text-sm" : "text-red-700 text-sm"}>
                <AlertTriangle className="w-4 h-4 inline mr-1" />
                {error}
              </p>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className={`p-4 border-t ${isDarkMode ? "border-slate-700 bg-slate-900/30" : "border-gray-200 bg-gray-50"} flex gap-3`}>
          <button
            onClick={handleCancel}
            disabled={confirming}
            className={`flex-1 px-4 py-3 rounded-lg font-medium transition-colors ${
              isDarkMode
                ? "bg-slate-700 hover:bg-slate-600 text-gray-300"
                : "bg-gray-200 hover:bg-gray-300 text-gray-700"
            } disabled:opacity-50`}
          >
            <XCircle className="w-4 h-4 inline mr-2" />
            Skip Authentication
          </button>
          <button
            onClick={handleConfirmLogin}
            disabled={confirming}
            className="flex-1 px-4 py-3 rounded-lg font-medium bg-green-600 hover:bg-green-500 text-white transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {confirming ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <CheckCircle className="w-4 h-4" />
            )}
            I'm Logged In
          </button>
        </div>
      </div>
    </div>
  );
};

export default ManualLoginModal;
