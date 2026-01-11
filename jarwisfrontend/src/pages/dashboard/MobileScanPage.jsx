// MobileScanPage - Dedicated page for mobile app scanning
import { Smartphone, Lock, Info } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import MobileScanForm from "../../components/scan/MobileScanForm";

// Subscription limit warning banner
const SubscriptionLimitBanner = ({ usage, isDarkMode, onUpgrade }) => {
  const scansLimit = usage?.scans;
  if (!scansLimit || scansLimit.unlimited) return null;
  
  const remaining = scansLimit.remaining;
  const percentage = scansLimit.percentage;
  
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
          <AlertTriangle className="w-6 h-6" />
          <div>
            <p className={`font-semibold ${isAtLimit ? (isDarkMode ? "text-red-400" : "text-red-700") : (isDarkMode ? "text-amber-400" : "text-amber-700")}`}>
              {isAtLimit ? "Monthly Scan Limit Reached" : `${remaining} Scan${remaining !== 1 ? 's' : ''} Remaining`}
            </p>
          </div>
        </div>
        <button onClick={onUpgrade} className="px-4 py-2 rounded-lg font-medium bg-gradient-to-r from-purple-500 to-pink-500 text-white">
          {isAtLimit ? "Upgrade Now" : "View Plans"}
        </button>
      </div>
    </div>
  );
};

const MobileScanPage = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();
  const { getAllUsageStats, canPerformAction } = useSubscription();

  // Check if user has access to mobile scanning
  const hasMobileAccess = canPerformAction("useMobileAppTesting");

  if (!hasMobileAccess) {
    return (
      <MiftyJarwisLayout>
        <div className="p-6">
          <div className={`p-8 rounded-2xl text-center ${isDarkMode ? "bg-slate-800/50 border border-slate-700" : "bg-gray-50 border border-gray-200"}`}>
            <Smartphone className={`w-16 h-16 mx-auto mb-4 ${isDarkMode ? "text-purple-400" : "text-purple-600"}`} />
            <h2 className={`text-2xl font-bold mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Mobile App Testing
            </h2>
            <p className={`mb-6 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              Mobile app security testing requires a Professional or Enterprise plan.
            </p>
            <button
              onClick={() => navigate("/pricing")}
              className="px-6 py-3 bg-gradient-to-r from-purple-600 to-pink-600 text-white rounded-xl font-semibold hover:from-purple-500 hover:to-pink-500 transition-all"
            >
              Upgrade Your Plan
            </button>
          </div>
        </div>
      </MiftyJarwisLayout>
    );
  }

  return (
    <MiftyJarwisLayout>
      <div className="space-y-8 p-6">
        <SubscriptionLimitBanner 
          usage={getAllUsageStats()} 
          isDarkMode={isDarkMode}
          onUpgrade={() => navigate("/pricing")}
        />

        {/* Header */}
        <div>
          <div className="flex items-center gap-3 mb-4">
            <div className={`p-3 rounded-xl ${isDarkMode ? "bg-purple-500/20" : "bg-purple-100"}`}>
              <Smartphone className={`w-8 h-8 ${isDarkMode ? "text-purple-400" : "text-purple-600"}`} />
            </div>
            <div>
              <h1 className={isDarkMode 
                ? "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400"
                : "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-600 to-pink-600"
              }>
                Mobile App Security Scan
              </h1>
              <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>
                Android APK and iOS IPA analysis
              </p>
            </div>
          </div>

          {/* Info Banner */}
          <div className={isDarkMode 
            ? "p-6 bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/20 rounded-2xl backdrop-blur-xl"
            : "p-6 bg-gradient-to-r from-purple-50 to-pink-50 border border-purple-200 rounded-2xl shadow-lg"
          }>
            <p className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
              <strong className={isDarkMode ? "text-purple-300" : "text-purple-700"}>Mobile Scan: </strong>
              Upload your APK/IPA file. Jarwis will analyze the app, bypass SSL pinning with Frida, intercept traffic, and identify security vulnerabilities.
            </p>
          </div>
        </div>

        {/* Form */}
        <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
          <MobileScanForm />
        </div>

        {/* Security Info */}
        <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
          <h3 className={isDarkMode ? "text-xl font-semibold text-white mb-6" : "text-xl font-semibold text-gray-900 mb-6"}>
            Mobile Security Testing Features
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
              <h4 className={isDarkMode ? "font-semibold text-purple-400 mb-2" : "font-semibold text-purple-600 mb-2"}>
                🔐 SSL Pinning Bypass
              </h4>
              <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Automatically bypass certificate pinning using Frida scripts
              </p>
            </div>
            <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
              <h4 className={isDarkMode ? "font-semibold text-purple-400 mb-2" : "font-semibold text-purple-600 mb-2"}>
                🔍 Runtime Analysis
              </h4>
              <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Dynamic instrumentation to detect runtime vulnerabilities
              </p>
            </div>
            <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
              <h4 className={isDarkMode ? "font-semibold text-purple-400 mb-2" : "font-semibold text-purple-600 mb-2"}>
                📡 Traffic Interception
              </h4>
              <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                MITM proxy to capture and analyze API communications
              </p>
            </div>
          </div>
        </div>
      </div>
    </MiftyJarwisLayout>
  );
};

export default MobileScanPage;
