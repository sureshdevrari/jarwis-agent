// SastScanPage - Dedicated page for SAST/Code Review scanning
import { Code, Lock, Info, Shield, FileSearch, Bug } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import SastScanForm from "../../components/scan/SastScanForm";

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
        <button onClick={onUpgrade} className="px-4 py-2 rounded-lg font-medium bg-gradient-to-r from-emerald-500 to-teal-500 text-white">
          {isAtLimit ? "Upgrade Now" : "View Plans"}
        </button>
      </div>
    </div>
  );
};

const SastScanPage = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();
  const { getAllUsageStats, canPerformAction } = useSubscription();

  // Check if user has access to SAST scanning
  const hasSastAccess = canPerformAction("useSASTScanning");

  if (!hasSastAccess) {
    return (
      <MiftyJarwisLayout>
        <div className="p-6">
          <div className={`p-8 rounded-2xl text-center ${isDarkMode ? "bg-slate-800/50 border border-slate-700" : "bg-gray-50 border border-gray-200"}`}>
            <Code className={`w-16 h-16 mx-auto mb-4 ${isDarkMode ? "text-emerald-400" : "text-emerald-600"}`} />
            <h2 className={`text-2xl font-bold mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Secure Code Review (SAST)
            </h2>
            <p className={`mb-6 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              Secure code review requires a Professional or Enterprise plan.
            </p>
            <button
              onClick={() => navigate("/pricing")}
              className="px-6 py-3 bg-gradient-to-r from-emerald-600 to-teal-600 text-white rounded-xl font-semibold hover:from-emerald-500 hover:to-teal-500 transition-all"
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
            <div className={`p-3 rounded-xl ${isDarkMode ? "bg-emerald-500/20" : "bg-emerald-100"}`}>
              <Code className={`w-8 h-8 ${isDarkMode ? "text-emerald-400" : "text-emerald-600"}`} />
            </div>
            <div>
              <h1 className={isDarkMode 
                ? "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-teal-400"
                : "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-emerald-600 to-teal-600"
              }>
                Secure Code Review
              </h1>
              <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>
                Static Application Security Testing (SAST)
              </p>
            </div>
          </div>

          {/* Info Banner */}
          <div className={isDarkMode 
            ? "p-6 bg-gradient-to-r from-emerald-500/10 to-teal-500/10 border border-emerald-500/20 rounded-2xl backdrop-blur-xl"
            : "p-6 bg-gradient-to-r from-emerald-50 to-teal-50 border border-emerald-200 rounded-2xl shadow-lg"
          }>
            <p className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
              <strong className={isDarkMode ? "text-emerald-300" : "text-emerald-700"}>Code Review: </strong>
              Connect your GitHub/GitLab repository. Jarwis will scan for hardcoded secrets, vulnerable dependencies, and security vulnerabilities in your source code.
            </p>
          </div>
        </div>

        {/* Form */}
        <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
          <SastScanForm />
        </div>

        {/* Features */}
        <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
          <h3 className={isDarkMode ? "text-xl font-semibold text-white mb-6" : "text-xl font-semibold text-gray-900 mb-6"}>
            Code Review Features
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
              <Lock className={`w-8 h-8 mb-3 ${isDarkMode ? "text-emerald-400" : "text-emerald-600"}`} />
              <h4 className={isDarkMode ? "font-semibold text-white mb-2" : "font-semibold text-gray-900 mb-2"}>
                Secret Detection
              </h4>
              <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Find hardcoded API keys, passwords, tokens, and credentials in your code
              </p>
            </div>
            <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
              <FileSearch className={`w-8 h-8 mb-3 ${isDarkMode ? "text-emerald-400" : "text-emerald-600"}`} />
              <h4 className={isDarkMode ? "font-semibold text-white mb-2" : "font-semibold text-gray-900 mb-2"}>
                Dependency Scan (SCA)
              </h4>
              <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Check third-party packages for known CVEs and security advisories
              </p>
            </div>
            <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
              <Bug className={`w-8 h-8 mb-3 ${isDarkMode ? "text-emerald-400" : "text-emerald-600"}`} />
              <h4 className={isDarkMode ? "font-semibold text-white mb-2" : "font-semibold text-gray-900 mb-2"}>
                Code Vulnerabilities
              </h4>
              <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Detect SQL injection, XSS, insecure deserialization, and more
              </p>
            </div>
          </div>
        </div>
      </div>
    </MiftyJarwisLayout>
  );
};

export default SastScanPage;
