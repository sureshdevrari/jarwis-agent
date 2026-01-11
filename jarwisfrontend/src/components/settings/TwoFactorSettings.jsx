// src/components/settings/TwoFactorSettings.jsx
// Two-Factor Authentication Settings Component
// Uses backend 2FA system with email/SMS channels

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { twoFactorAPI } from "../../services/api";
import { useSubscription } from "../../context/SubscriptionContext";

const TwoFactorSettings = ({ isDarkMode, user }) => {
  const { planId } = useSubscription();
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [showEnrollModal, setShowEnrollModal] = useState(false);
  const [showDisableModal, setShowDisableModal] = useState(false);
  const [showBackupCodesModal, setShowBackupCodesModal] = useState(false);
  
  // Enrollment state
  const [enrollStep, setEnrollStep] = useState("channel"); // channel, phone, verify, backup
  const [selectedChannel, setSelectedChannel] = useState("email");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [backupCodes, setBackupCodes] = useState([]);
  const [recipientMasked, setRecipientMasked] = useState("");
  
  // Disable state
  const [disablePassword, setDisablePassword] = useState("");
  const [disableOtp, setDisableOtp] = useState("");
  
  // Backup codes regeneration state
  const [showRegenPasswordPrompt, setShowRegenPasswordPrompt] = useState(false);
  const [regenPassword, setRegenPassword] = useState("");
  
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Check if 2FA is enforced for this plan
  const is2FAEnforced = planId === "enterprise";
  const is2FAEnabled = status?.enabled || false;

  // Load 2FA status
  const loadStatus = useCallback(async () => {
    try {
      const data = await twoFactorAPI.getStatus();
      setStatus(data);
    } catch (err) {
      console.error("Failed to load 2FA status:", err);
      // Don't show error for initial load failure
    }
  }, []);

  useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  // Handle channel selection and initiate setup
  const handleInitiateSetup = async () => {
    setError("");
    setLoading(true);

    try {
      // For SMS, validate phone first
      if (selectedChannel === "sms") {
        if (!phoneNumber.match(/^\+[1-9]\d{1,14}$/)) {
          setError("Please enter a valid phone number with country code (e.g., +1234567890)");
          setLoading(false);
          return;
        }
      }

      const response = await twoFactorAPI.initiateSetup(
        selectedChannel,
        selectedChannel === "sms" ? phoneNumber : null
      );

      if (response.success) {
        setRecipientMasked(response.recipient_masked);
        setEnrollStep("verify");
        setSuccess(`Verification code sent to ${response.recipient_masked}`);
        setTimeout(() => setSuccess(""), 3000);
      }
    } catch (err) {
      console.error("Setup initiation error:", err);
      const detail = err.response?.data?.detail;
      if (typeof detail === "string") {
        setError(detail);
      } else if (detail?.message) {
        setError(detail.message);
      } else {
        setError("Failed to send verification code. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  // Handle OTP verification to complete setup
  const handleVerifyCode = async () => {
    setError("");
    setLoading(true);

    try {
      const response = await twoFactorAPI.verifySetup(verificationCode);

      if (response.success) {
        // Store backup codes to show
        if (response.backup_codes) {
          setBackupCodes(response.backup_codes);
          setEnrollStep("backup");
        }
        
        // Reload status
        await loadStatus();
        setSuccess("Two-factor authentication enabled successfully!");
      }
    } catch (err) {
      console.error("Verification error:", err);
      const detail = err.response?.data?.detail;
      setError(typeof detail === "string" ? detail : "Invalid verification code. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  // Handle disable 2FA
  const handleDisable2FA = async () => {
    setError("");
    setLoading(true);

    try {
      const response = await twoFactorAPI.disable(disablePassword, disableOtp || null);

      if (response.success) {
        setShowDisableModal(false);
        setDisablePassword("");
        setDisableOtp("");
        await loadStatus();
        setSuccess("Two-factor authentication has been disabled.");
        setTimeout(() => setSuccess(""), 3000);
      }
    } catch (err) {
      console.error("Disable error:", err);
      const detail = err.response?.data?.detail;
      setError(typeof detail === "string" ? detail : "Failed to disable 2FA. Check your password.");
    } finally {
      setLoading(false);
    }
  };

  // Generate new backup codes (requires password)
  const handleGenerateBackupCodes = async () => {
    // Show password prompt first if not during initial 2FA setup
    if (!showRegenPasswordPrompt && is2FAEnabled && backupCodes.length === 0) {
      setShowRegenPasswordPrompt(true);
      return;
    }
    
    setError("");
    setLoading(true);

    try {
      const response = await twoFactorAPI.generateBackupCodes(regenPassword || null);
      if (response.codes) {
        setBackupCodes(response.codes);
        setShowBackupCodesModal(true);
        setShowRegenPasswordPrompt(false);
        setRegenPassword("");
        await loadStatus();
      }
    } catch (err) {
      console.error("Backup codes error:", err);
      const detail = err.response?.data?.detail;
      setError(typeof detail === "string" ? detail : "Failed to generate backup codes. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  // Reset modal state
  const resetModal = () => {
    setShowEnrollModal(false);
    setEnrollStep("channel");
    setSelectedChannel("email");
    setPhoneNumber("");
    setVerificationCode("");
    setRecipientMasked("");
    setError("");
  };

  // Copy backup codes to clipboard
  const copyBackupCodes = () => {
    const codesText = backupCodes.join("\n");
    navigator.clipboard.writeText(codesText);
    setSuccess("Backup codes copied to clipboard!");
    setTimeout(() => setSuccess(""), 3000);
  };

  return (
    <div className={`rounded-xl border p-6 ${isDarkMode ? "bg-slate-800/50 border-slate-700" : "bg-white border-gray-200"}`}>
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h3 className={`text-lg font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
            Two-Factor Authentication (2FA)
          </h3>
          <p className={`text-sm mt-1 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
            Add an extra layer of security to your account via email or SMS
          </p>
        </div>
        
        {/* Status Badge */}
        <div className={`
          px-3 py-1 rounded-full text-xs font-medium
          ${is2FAEnabled 
            ? "bg-green-500/20 text-green-400" 
            : is2FAEnforced 
              ? "bg-red-500/20 text-red-400"
              : isDarkMode 
                ? "bg-slate-700 text-gray-400" 
                : "bg-gray-100 text-gray-600"
          }
        `}>
          {is2FAEnabled ? "Enabled" : is2FAEnforced ? "Required" : "Disabled"}
        </div>
      </div>

      {/* Enforced Warning */}
      {is2FAEnforced && !is2FAEnabled && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className={`mb-6 p-4 rounded-xl ${isDarkMode ? "bg-amber-500/10 border border-amber-500/30" : "bg-amber-50 border border-amber-200"}`}
        >
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-amber-500 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div>
              <p className={`font-medium ${isDarkMode ? "text-amber-400" : "text-amber-700"}`}>
                2FA Required for Enterprise Plan
              </p>
              <p className={`text-sm mt-1 ${isDarkMode ? "text-amber-400/70" : "text-amber-600"}`}>
                Your organization requires two-factor authentication. Please enable it to continue using all features.
              </p>
            </div>
          </div>
        </motion.div>
      )}

      {/* Success/Error Messages */}
      <AnimatePresence>
        {success && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="mb-4 p-4 rounded-xl bg-green-500/10 border border-green-500/30 text-green-400 text-sm"
          >
            {success}
          </motion.div>
        )}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="mb-4 p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm"
          >
            {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Current 2FA Status */}
      {is2FAEnabled && status && (
        <div className="mb-6 space-y-3">
          <h4 className={`text-sm font-medium ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
            Current Configuration
          </h4>
          <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                  status.channel === "sms" 
                    ? isDarkMode ? "bg-purple-500/20" : "bg-purple-100"
                    : isDarkMode ? "bg-cyan-500/20" : "bg-cyan-100"
                }`}>
                  {status.channel === "sms" ? (
                    <svg className={`w-5 h-5 ${isDarkMode ? "text-purple-400" : "text-purple-600"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
                    </svg>
                  ) : (
                    <svg className={`w-5 h-5 ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                    </svg>
                  )}
                </div>
                <div>
                  <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {status.channel === "sms" ? "SMS Verification" : "Email Verification"}
                  </p>
                  <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                    {status.channel === "sms" ? status.phone : status.email}
                  </p>
                </div>
              </div>
              
              <div className="flex items-center gap-2">
                <span className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                  {status.backup_codes_remaining} backup codes
                </span>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-3">
            <button
              onClick={handleGenerateBackupCodes}
              disabled={loading}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                isDarkMode 
                  ? "bg-slate-700 text-gray-300 hover:bg-slate-600" 
                  : "bg-gray-100 text-gray-700 hover:bg-gray-200"
              }`}
            >
              Generate New Backup Codes
            </button>
            <button
              onClick={() => setShowDisableModal(true)}
              disabled={loading}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                isDarkMode 
                  ? "text-red-400 hover:bg-red-500/20" 
                  : "text-red-600 hover:bg-red-50"
              }`}
            >
              Disable 2FA
            </button>
          </div>
        </div>
      )}

      {/* Enable 2FA Button */}
      {!is2FAEnabled && (
        <button
          onClick={() => setShowEnrollModal(true)}
          disabled={loading}
          className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-medium rounded-xl hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 transition-all flex items-center justify-center gap-2"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          Enable Two-Factor Authentication
        </button>
      )}

      {/* Enroll Modal */}
      <AnimatePresence>
        {showEnrollModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={resetModal}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className={`w-full max-w-md rounded-2xl p-6 ${isDarkMode ? "bg-slate-800" : "bg-white"}`}
              onClick={(e) => e.stopPropagation()}
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between mb-6">
                <h3 className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  {enrollStep === "channel" && "Choose Verification Method"}
                  {enrollStep === "phone" && "Enter Phone Number"}
                  {enrollStep === "verify" && "Enter Verification Code"}
                  {enrollStep === "backup" && "Save Backup Codes"}
                </h3>
                <button
                  onClick={resetModal}
                  className={`p-2 rounded-lg transition-colors ${isDarkMode ? "hover:bg-slate-700" : "hover:bg-gray-100"}`}
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              {/* Error */}
              {error && (
                <div className="mb-4 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
                  {error}
                </div>
              )}

              {/* Step: Channel Selection */}
              {enrollStep === "channel" && (
                <div className="space-y-4">
                  <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                    Choose how you want to receive verification codes:
                  </p>

                  {/* Email Option */}
                  <button
                    onClick={() => {
                      setSelectedChannel("email");
                      setError("");
                    }}
                    className={`w-full p-4 rounded-xl border-2 transition-all flex items-center gap-4 ${
                      selectedChannel === "email"
                        ? "border-cyan-500 bg-cyan-500/10"
                        : isDarkMode
                          ? "border-slate-600 hover:border-slate-500"
                          : "border-gray-200 hover:border-gray-300"
                    }`}
                  >
                    <div className={`w-12 h-12 rounded-full flex items-center justify-center ${
                      selectedChannel === "email"
                        ? "bg-cyan-500/20"
                        : isDarkMode ? "bg-slate-700" : "bg-gray-100"
                    }`}>
                      <svg className={`w-6 h-6 ${selectedChannel === "email" ? "text-cyan-400" : isDarkMode ? "text-gray-400" : "text-gray-600"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                      </svg>
                    </div>
                    <div className="text-left flex-1">
                      <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                        Email
                      </p>
                      <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                        Send codes to {status?.email || user?.email}
                      </p>
                    </div>
                    {selectedChannel === "email" && (
                      <svg className="w-6 h-6 text-cyan-500" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                      </svg>
                    )}
                  </button>

                  {/* SMS Option */}
                  <button
                    onClick={() => {
                      setSelectedChannel("sms");
                      setError("");
                    }}
                    className={`w-full p-4 rounded-xl border-2 transition-all flex items-center gap-4 ${
                      selectedChannel === "sms"
                        ? "border-purple-500 bg-purple-500/10"
                        : isDarkMode
                          ? "border-slate-600 hover:border-slate-500"
                          : "border-gray-200 hover:border-gray-300"
                    }`}
                  >
                    <div className={`w-12 h-12 rounded-full flex items-center justify-center ${
                      selectedChannel === "sms"
                        ? "bg-purple-500/20"
                        : isDarkMode ? "bg-slate-700" : "bg-gray-100"
                    }`}>
                      <svg className={`w-6 h-6 ${selectedChannel === "sms" ? "text-purple-400" : isDarkMode ? "text-gray-400" : "text-gray-600"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
                      </svg>
                    </div>
                    <div className="text-left flex-1">
                      <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                        SMS
                      </p>
                      <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                        Send codes to your mobile phone
                      </p>
                    </div>
                    {selectedChannel === "sms" && (
                      <svg className="w-6 h-6 text-purple-500" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                      </svg>
                    )}
                  </button>

                  {/* Phone Input (if SMS selected) */}
                  {selectedChannel === "sms" && (
                    <div className="mt-4">
                      <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                        Phone Number
                      </label>
                      <input
                        type="tel"
                        value={phoneNumber}
                        onChange={(e) => setPhoneNumber(e.target.value)}
                        placeholder="+1234567890"
                        className={`w-full px-4 py-3 rounded-xl border transition-colors ${
                          isDarkMode 
                            ? "bg-slate-700 border-slate-600 text-white placeholder-gray-500" 
                            : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"
                        } focus:outline-none focus:ring-2 focus:ring-purple-500/50`}
                      />
                      <p className={`text-xs mt-1 ${isDarkMode ? "text-gray-500" : "text-gray-500"}`}>
                        Include country code (e.g., +1 for US, +44 for UK)
                      </p>
                    </div>
                  )}

                  <button
                    onClick={handleInitiateSetup}
                    disabled={loading || (selectedChannel === "sms" && !phoneNumber)}
                    className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-medium rounded-xl hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
                  >
                    {loading ? (
                      <>
                        <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                        <span>Sending...</span>
                      </>
                    ) : (
                      "Send Verification Code"
                    )}
                  </button>
                </div>
              )}

              {/* Step: Verify Code */}
              {enrollStep === "verify" && (
                <div className="space-y-4">
                  <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                    Enter the 6-digit code sent to {recipientMasked}
                  </p>

                  <div>
                    <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                      Verification Code
                    </label>
                    <input
                      type="text"
                      value={verificationCode}
                      onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                      placeholder="000000"
                      maxLength={6}
                      autoFocus
                      className={`w-full px-4 py-3 rounded-xl border text-center text-2xl tracking-widest font-mono ${
                        isDarkMode 
                          ? "bg-slate-700 border-slate-600 text-white placeholder-gray-500" 
                          : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"
                      } focus:outline-none focus:ring-2 focus:ring-cyan-500/50`}
                    />
                  </div>

                  <div className="flex gap-3">
                    <button
                      onClick={() => {
                        setEnrollStep("channel");
                        setVerificationCode("");
                        setError("");
                      }}
                      className={`flex-1 py-3 px-4 rounded-xl font-medium transition-colors ${
                        isDarkMode 
                          ? "bg-slate-700 text-gray-300 hover:bg-slate-600" 
                          : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                      }`}
                    >
                      Back
                    </button>
                    <button
                      onClick={handleVerifyCode}
                      disabled={loading || verificationCode.length !== 6}
                      className="flex-1 py-3 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-medium rounded-xl hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
                    >
                      {loading ? (
                        <>
                          <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                          </svg>
                          <span>Verifying...</span>
                        </>
                      ) : (
                        "Verify & Enable"
                      )}
                    </button>
                  </div>

                  <button
                    onClick={handleInitiateSetup}
                    disabled={loading}
                    className={`w-full text-center text-sm ${isDarkMode ? "text-cyan-400 hover:text-cyan-300" : "text-cyan-600 hover:text-cyan-500"}`}
                  >
                    Didn't receive the code? Send again
                  </button>
                </div>
              )}

              {/* Step: Backup Codes */}
              {enrollStep === "backup" && (
                <div className="space-y-4">
                  <div className={`p-4 rounded-xl ${isDarkMode ? "bg-amber-500/10 border border-amber-500/30" : "bg-amber-50 border border-amber-200"}`}>
                    <div className="flex items-start gap-3">
                      <svg className="w-5 h-5 text-amber-500 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                      <div>
                        <p className={`font-medium ${isDarkMode ? "text-amber-400" : "text-amber-700"}`}>
                          Save Your Backup Codes
                        </p>
                        <p className={`text-sm mt-1 ${isDarkMode ? "text-amber-400/70" : "text-amber-600"}`}>
                          These codes can be used to access your account if you lose your phone. Each code can only be used once. Store them securely!
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className={`p-4 rounded-xl font-mono text-sm grid grid-cols-2 gap-2 ${isDarkMode ? "bg-slate-900" : "bg-gray-100"}`}>
                    {backupCodes.map((code, index) => (
                      <div key={index} className={`p-2 rounded ${isDarkMode ? "bg-slate-800" : "bg-white"}`}>
                        {code}
                      </div>
                    ))}
                  </div>

                  <button
                    onClick={copyBackupCodes}
                    className={`w-full py-2 px-4 rounded-xl font-medium transition-colors flex items-center justify-center gap-2 ${
                      isDarkMode 
                        ? "bg-slate-700 text-gray-300 hover:bg-slate-600" 
                        : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                    }`}
                  >
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                    Copy All Codes
                  </button>

                  <button
                    onClick={resetModal}
                    className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-medium rounded-xl hover:from-cyan-400 hover:to-blue-500 transition-all"
                  >
                    I've Saved My Codes
                  </button>
                </div>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Disable 2FA Modal */}
      <AnimatePresence>
        {showDisableModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setShowDisableModal(false)}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className={`w-full max-w-md rounded-2xl p-6 ${isDarkMode ? "bg-slate-800" : "bg-white"}`}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between mb-6">
                <h3 className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  Disable Two-Factor Authentication
                </h3>
                <button
                  onClick={() => setShowDisableModal(false)}
                  className={`p-2 rounded-lg transition-colors ${isDarkMode ? "hover:bg-slate-700" : "hover:bg-gray-100"}`}
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              {error && (
                <div className="mb-4 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
                  {error}
                </div>
              )}

              <div className={`mb-4 p-4 rounded-xl ${isDarkMode ? "bg-red-500/10 border border-red-500/30" : "bg-red-50 border border-red-200"}`}>
                <p className={`text-sm ${isDarkMode ? "text-red-400" : "text-red-600"}`}>
                  Warning: Disabling 2FA will make your account less secure. You'll only need your password to log in.
                </p>
              </div>

              <div className="space-y-4">
                <div>
                  <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Password
                  </label>
                  <input
                    type="password"
                    value={disablePassword}
                    onChange={(e) => setDisablePassword(e.target.value)}
                    placeholder="Enter your password"
                    className={`w-full px-4 py-3 rounded-xl border transition-colors ${
                      isDarkMode 
                        ? "bg-slate-700 border-slate-600 text-white placeholder-gray-500" 
                        : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"
                    } focus:outline-none focus:ring-2 focus:ring-red-500/50`}
                  />
                </div>

                <div>
                  <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Current 2FA Code (Optional)
                  </label>
                  <input
                    type="text"
                    value={disableOtp}
                    onChange={(e) => setDisableOtp(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    placeholder="000000"
                    maxLength={6}
                    className={`w-full px-4 py-3 rounded-xl border transition-colors ${
                      isDarkMode 
                        ? "bg-slate-700 border-slate-600 text-white placeholder-gray-500" 
                        : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"
                    } focus:outline-none focus:ring-2 focus:ring-red-500/50`}
                  />
                </div>

                <div className="flex gap-3">
                  <button
                    onClick={() => {
                      setShowDisableModal(false);
                      setDisablePassword("");
                      setDisableOtp("");
                      setError("");
                    }}
                    className={`flex-1 py-3 px-4 rounded-xl font-medium transition-colors ${
                      isDarkMode 
                        ? "bg-slate-700 text-gray-300 hover:bg-slate-600" 
                        : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                    }`}
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleDisable2FA}
                    disabled={loading || !disablePassword}
                    className="flex-1 py-3 px-4 bg-red-500 text-white font-medium rounded-xl hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
                  >
                    {loading ? (
                      <>
                        <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                        <span>Disabling...</span>
                      </>
                    ) : (
                      "Disable 2FA"
                    )}
                  </button>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Backup Codes Modal (for viewing generated codes) */}
      <AnimatePresence>
        {showBackupCodesModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setShowBackupCodesModal(false)}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className={`w-full max-w-md rounded-2xl p-6 ${isDarkMode ? "bg-slate-800" : "bg-white"}`}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between mb-6">
                <h3 className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  New Backup Codes
                </h3>
                <button
                  onClick={() => setShowBackupCodesModal(false)}
                  className={`p-2 rounded-lg transition-colors ${isDarkMode ? "hover:bg-slate-700" : "hover:bg-gray-100"}`}
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              <div className={`mb-4 p-4 rounded-xl ${isDarkMode ? "bg-amber-500/10 border border-amber-500/30" : "bg-amber-50 border border-amber-200"}`}>
                <p className={`text-sm ${isDarkMode ? "text-amber-400" : "text-amber-600"}`}>
                  Your old backup codes have been invalidated. Save these new codes securely.
                </p>
              </div>

              <div className={`p-4 rounded-xl font-mono text-sm grid grid-cols-2 gap-2 ${isDarkMode ? "bg-slate-900" : "bg-gray-100"}`}>
                {backupCodes.map((code, index) => (
                  <div key={index} className={`p-2 rounded ${isDarkMode ? "bg-slate-800" : "bg-white"}`}>
                    {code}
                  </div>
                ))}
              </div>

              <button
                onClick={copyBackupCodes}
                className={`w-full mt-4 py-2 px-4 rounded-xl font-medium transition-colors flex items-center justify-center gap-2 ${
                  isDarkMode 
                    ? "bg-slate-700 text-gray-300 hover:bg-slate-600" 
                    : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                }`}
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
                Copy All Codes
              </button>

              <button
                onClick={() => setShowBackupCodesModal(false)}
                className="w-full mt-3 py-3 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-medium rounded-xl hover:from-cyan-400 hover:to-blue-500 transition-all"
              >
                Done
              </button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Password Prompt Modal for Regenerating Backup Codes */}
      <AnimatePresence>
        {showRegenPasswordPrompt && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => {
              setShowRegenPasswordPrompt(false);
              setRegenPassword("");
              setError("");
            }}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className={`w-full max-w-md rounded-2xl p-6 ${isDarkMode ? "bg-slate-800" : "bg-white"}`}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between mb-6">
                <h3 className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  Confirm Password
                </h3>
                <button
                  onClick={() => {
                    setShowRegenPasswordPrompt(false);
                    setRegenPassword("");
                    setError("");
                  }}
                  className={`p-2 rounded-lg transition-colors ${isDarkMode ? "hover:bg-slate-700" : "hover:bg-gray-100"}`}
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              {error && (
                <div className={`mb-4 p-4 rounded-xl ${isDarkMode ? "bg-red-500/10 border border-red-500/30" : "bg-red-50 border border-red-200"}`}>
                  <p className={`text-sm ${isDarkMode ? "text-red-400" : "text-red-600"}`}>{error}</p>
                </div>
              )}

              <p className={`mb-4 text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Enter your password to generate new backup codes. This will invalidate all existing backup codes.
              </p>

              <div className="mb-6">
                <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                  Password
                </label>
                <input
                  type="password"
                  value={regenPassword}
                  onChange={(e) => setRegenPassword(e.target.value)}
                  placeholder="Enter your password"
                  className={`w-full px-4 py-3 rounded-xl border transition-colors ${
                    isDarkMode 
                      ? "bg-slate-700 border-slate-600 text-white placeholder-gray-500" 
                      : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"
                  } focus:outline-none focus:ring-2 focus:ring-cyan-500/50`}
                />
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => {
                    setShowRegenPasswordPrompt(false);
                    setRegenPassword("");
                    setError("");
                  }}
                  className={`flex-1 py-3 px-4 rounded-xl font-medium transition-colors ${
                    isDarkMode 
                      ? "bg-slate-700 text-gray-300 hover:bg-slate-600" 
                      : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                  }`}
                >
                  Cancel
                </button>
                <button
                  onClick={handleGenerateBackupCodes}
                  disabled={loading || !regenPassword}
                  className="flex-1 py-3 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-medium rounded-xl hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Generating...
                    </>
                  ) : (
                    "Generate Codes"
                  )}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default TwoFactorSettings;
