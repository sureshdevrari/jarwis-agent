// src/components/settings/TwoFactorSettings.jsx
// Two-Factor Authentication Settings Component

import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { firebaseAuthService } from "../../services/firebaseAuth";
import { useSubscription } from "../../context/SubscriptionContext";

const TwoFactorSettings = ({ isDarkMode, user }) => {
  const { planId } = useSubscription();
  const [loading, setLoading] = useState(false);
  const [enrolledMethods, setEnrolledMethods] = useState([]);
  const [showEnrollModal, setShowEnrollModal] = useState(false);
  const [enrollStep, setEnrollStep] = useState("phone"); // phone, verify
  const [phoneNumber, setPhoneNumber] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [displayName, setDisplayName] = useState("My Phone");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const recaptchaRef = useRef(null);

  // Check if 2FA is enforced for this plan
  const is2FAEnforced = planId === "enterprise";
  const is2FAEnabled = enrolledMethods.length > 0;

  // Load enrolled methods
  useEffect(() => {
    loadEnrolledMethods();
  }, []);

  const loadEnrolledMethods = () => {
    try {
      const methods = firebaseAuthService.getEnrolled2FAMethods();
      setEnrolledMethods(methods);
    } catch (err) {
      console.error("Failed to load 2FA methods:", err);
    }
  };

  // Initialize recaptcha when modal opens
  useEffect(() => {
    if (showEnrollModal && enrollStep === "phone") {
      try {
        firebaseAuthService.initRecaptcha("recaptcha-container");
      } catch (err) {
        console.error("Failed to init recaptcha:", err);
      }
    }
  }, [showEnrollModal, enrollStep]);

  const handleEnrollPhone = async () => {
    setError("");
    setLoading(true);

    try {
      // Validate phone number format
      if (!phoneNumber.match(/^\+[1-9]\d{1,14}$/)) {
        setError("Please enter a valid phone number with country code (e.g., +1234567890)");
        setLoading(false);
        return;
      }

      await firebaseAuthService.enrollPhone2FA(phoneNumber);
      setEnrollStep("verify");
    } catch (err) {
      console.error("Phone enrollment error:", err);
      setError(firebaseAuthService.formatError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyCode = async () => {
    setError("");
    setLoading(true);

    try {
      await firebaseAuthService.completePhone2FAEnrollment(verificationCode, displayName);
      setSuccess("2FA enabled successfully!");
      loadEnrolledMethods();
      
      // Close modal after success
      setTimeout(() => {
        setShowEnrollModal(false);
        setEnrollStep("phone");
        setPhoneNumber("");
        setVerificationCode("");
        setDisplayName("My Phone");
        setSuccess("");
      }, 2000);
    } catch (err) {
      console.error("Verification error:", err);
      setError(firebaseAuthService.formatError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleRemove2FA = async (factor) => {
    if (!window.confirm(`Remove "${factor.displayName || "2FA method"}"? You'll need to set it up again.`)) {
      return;
    }

    setLoading(true);
    try {
      await firebaseAuthService.unenroll2FA(factor);
      loadEnrolledMethods();
      setSuccess("2FA method removed");
      setTimeout(() => setSuccess(""), 3000);
    } catch (err) {
      console.error("Remove 2FA error:", err);
      setError(firebaseAuthService.formatError(err));
    } finally {
      setLoading(false);
    }
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
            Add an extra layer of security to your account
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

      {/* Enrolled Methods */}
      {enrolledMethods.length > 0 && (
        <div className="mb-6 space-y-3">
          <h4 className={`text-sm font-medium ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
            Enrolled Methods
          </h4>
          {enrolledMethods.map((factor, index) => (
            <div
              key={factor.uid || index}
              className={`flex items-center justify-between p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}
            >
              <div className="flex items-center gap-3">
                <div className={`w-10 h-10 rounded-full flex items-center justify-center ${isDarkMode ? "bg-cyan-500/20" : "bg-cyan-100"}`}>
                  <svg className={`w-5 h-5 ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
                  </svg>
                </div>
                <div>
                  <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {factor.displayName || "Phone"}
                  </p>
                  <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                    {factor.phoneNumber ? `****${factor.phoneNumber.slice(-4)}` : "SMS Verification"}
                  </p>
                </div>
              </div>
              <button
                onClick={() => handleRemove2FA(factor)}
                disabled={loading}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  isDarkMode 
                    ? "text-red-400 hover:bg-red-500/20" 
                    : "text-red-600 hover:bg-red-50"
                }`}
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Add 2FA Button */}
      <button
        onClick={() => setShowEnrollModal(true)}
        disabled={loading}
        className={`
          w-full py-3 px-4 rounded-xl font-medium transition-all duration-300 flex items-center justify-center gap-2
          ${is2FAEnabled 
            ? isDarkMode 
              ? "bg-slate-700 text-gray-300 hover:bg-slate-600" 
              : "bg-gray-100 text-gray-700 hover:bg-gray-200"
            : "bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:from-cyan-400 hover:to-blue-500"
          }
        `}
      >
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
        {is2FAEnabled ? "Add Another Method" : "Enable Two-Factor Authentication"}
      </button>

      {/* Enroll Modal */}
      <AnimatePresence>
        {showEnrollModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setShowEnrollModal(false)}
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
                  {enrollStep === "phone" ? "Add Phone Number" : "Verify Code"}
                </h3>
                <button
                  onClick={() => setShowEnrollModal(false)}
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

              {enrollStep === "phone" ? (
                <div className="space-y-4">
                  <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                    Enter your phone number to receive verification codes via SMS.
                  </p>

                  <div>
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
                      } focus:outline-none focus:ring-2 focus:ring-cyan-500/50`}
                    />
                    <p className={`text-xs mt-1 ${isDarkMode ? "text-gray-500" : "text-gray-500"}`}>
                      Include country code (e.g., +1 for US)
                    </p>
                  </div>

                  <div>
                    <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                      Display Name (Optional)
                    </label>
                    <input
                      type="text"
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                      placeholder="My Phone"
                      className={`w-full px-4 py-3 rounded-xl border transition-colors ${
                        isDarkMode 
                          ? "bg-slate-700 border-slate-600 text-white placeholder-gray-500" 
                          : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"
                      } focus:outline-none focus:ring-2 focus:ring-cyan-500/50`}
                    />
                  </div>

                  {/* reCAPTCHA container */}
                  <div id="recaptcha-container" ref={recaptchaRef}></div>

                  <button
                    onClick={handleEnrollPhone}
                    disabled={loading || !phoneNumber}
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
              ) : (
                <div className="space-y-4">
                  <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                    Enter the 6-digit code sent to {phoneNumber}
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
                      className={`w-full px-4 py-3 rounded-xl border text-center text-2xl tracking-widest font-mono ${
                        isDarkMode 
                          ? "bg-slate-700 border-slate-600 text-white placeholder-gray-500" 
                          : "bg-white border-gray-300 text-gray-900 placeholder-gray-400"
                      } focus:outline-none focus:ring-2 focus:ring-cyan-500/50`}
                    />
                  </div>

                  <div className="flex gap-3">
                    <button
                      onClick={() => setEnrollStep("phone")}
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
                </div>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default TwoFactorSettings;
