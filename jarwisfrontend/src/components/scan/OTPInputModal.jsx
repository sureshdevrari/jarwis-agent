// src/components/scan/OTPInputModal.jsx
// Modal shown when scan is waiting for user to enter OTP code

import { useState, useEffect, useCallback, useRef } from "react";
import { X, Send, Clock, AlertTriangle, Loader2, RefreshCw, Phone, Mail } from "lucide-react";
import { useTheme } from "../../context/ThemeContext";
import { scanOtpAPI } from "../../services/api";

const OTPInputModal = ({ scanId, onClose, onComplete }) => {
  const { isDarkMode } = useTheme();
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [otpCode, setOtpCode] = useState("");
  const [timeRemaining, setTimeRemaining] = useState(300);
  const inputRef = useRef(null);

  // Fetch OTP status
  const fetchStatus = useCallback(async () => {
    try {
      const data = await scanOtpAPI.getStatus(scanId);
      setStatus(data);
      setTimeRemaining(data.time_remaining || 0);
      setLoading(false);
      
      // If no longer waiting, close modal
      if (!data.waiting_for_otp) {
        onComplete?.(data);
      }
    } catch (err) {
      console.error("Error fetching OTP status:", err);
      setError(err.response?.data?.detail || "Failed to fetch OTP status");
      setLoading(false);
    }
  }, [scanId, onComplete]);

  // Poll for status updates
  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  // Focus input on mount
  useEffect(() => {
    if (!loading && inputRef.current) {
      inputRef.current.focus();
    }
  }, [loading]);

  // Countdown timer
  useEffect(() => {
    if (timeRemaining > 0) {
      const timer = setTimeout(() => {
        setTimeRemaining((t) => Math.max(0, t - 1));
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [timeRemaining]);

  // Handle submit OTP
  const handleSubmit = async (e) => {
    e?.preventDefault();
    if (!otpCode.trim() || otpCode.length < 4) {
      setError("Please enter a valid OTP code");
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      await scanOtpAPI.submitOtp(scanId, otpCode.trim());
      onComplete?.({ success: true });
    } catch (err) {
      setError(err.response?.data?.detail || "Invalid OTP code");
      setSubmitting(false);
    }
  };

  // Handle OTP input with auto-submit
  const handleOtpChange = (e) => {
    const value = e.target.value.replace(/\D/g, "").slice(0, 8);
    setOtpCode(value);
    setError(null);
  };

  // Format time remaining
  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  // Get OTP type icon
  const getOtpIcon = () => {
    if (status?.otp_type === "email") return <Mail className="w-5 h-5" />;
    return <Phone className="w-5 h-5" />;
  };

  // Modal styles
  const overlayClass = "fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50";
  const modalClass = isDarkMode
    ? "bg-slate-800 border border-slate-700 rounded-2xl shadow-2xl max-w-md w-full mx-4 overflow-hidden"
    : "bg-white border border-gray-200 rounded-2xl shadow-2xl max-w-md w-full mx-4 overflow-hidden";

  if (loading) {
    return (
      <div className={overlayClass}>
        <div className={modalClass}>
          <div className="p-8 flex flex-col items-center">
            <Loader2 className="w-10 h-10 text-blue-500 animate-spin mb-4" />
            <p className={isDarkMode ? "text-gray-300" : "text-gray-600"}>
              Loading OTP status...
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
            <div className="flex items-center gap-2">
              {getOtpIcon()}
              <h2 className={`text-lg font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                Enter OTP Code
              </h2>
            </div>
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
        <form onSubmit={handleSubmit} className="p-6 space-y-6">
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

          {/* OTP sent to info */}
          {status?.otp_contact && (
            <div className={`text-center ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              <p className="text-sm">
                OTP sent to: <span className="font-medium">{status.otp_contact}</span>
              </p>
            </div>
          )}

          {/* OTP Input */}
          <div className="space-y-2">
            <input
              ref={inputRef}
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              value={otpCode}
              onChange={handleOtpChange}
              placeholder="Enter OTP code"
              maxLength={8}
              className={`w-full text-center text-3xl font-mono tracking-[0.5em] py-4 px-6 rounded-xl border-2 transition-all ${
                isDarkMode
                  ? "bg-slate-900 border-slate-600 text-white placeholder-gray-500 focus:border-blue-500"
                  : "bg-gray-50 border-gray-300 text-gray-900 placeholder-gray-400 focus:border-blue-500"
              } focus:outline-none focus:ring-2 focus:ring-blue-500/20`}
              disabled={submitting}
            />
            <p className={`text-center text-sm ${isDarkMode ? "text-gray-500" : "text-gray-500"}`}>
              Enter the {status?.otp_type === "email" ? "email" : "SMS"} code you received
            </p>
          </div>

          {/* Attempts info */}
          {status?.attempts > 0 && (
            <div className={`text-center text-sm ${isDarkMode ? "text-gray-500" : "text-gray-500"}`}>
              Attempt {status.attempts} of {status.max_attempts}
            </div>
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

          {/* Submit Button */}
          <button
            type="submit"
            disabled={submitting || otpCode.length < 4}
            className="w-full px-4 py-4 rounded-xl font-medium bg-blue-600 hover:bg-blue-500 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {submitting ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Verifying...
              </>
            ) : (
              <>
                <Send className="w-5 h-5" />
                Submit OTP
              </>
            )}
          </button>
        </form>

        {/* Footer */}
        <div className={`px-6 pb-6 ${isDarkMode ? "text-gray-500" : "text-gray-500"}`}>
          <p className="text-xs text-center">
            Didn't receive the code? Check your {status?.otp_type === "email" ? "email spam folder" : "phone's SMS inbox"}.
          </p>
        </div>
      </div>
    </div>
  );
};

export default OTPInputModal;
