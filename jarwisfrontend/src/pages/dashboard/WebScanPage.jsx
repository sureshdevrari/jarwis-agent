// WebScanPage - Dedicated page for web scanning with enterprise wizard
import { useSearchParams, useNavigate } from "react-router-dom";
import { Globe, Lock, Info, AlertTriangle } from "lucide-react";
import ScanWizard from "../../components/scan/ScanWizard";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import WebScanForm from "../../components/scan/WebScanForm";

const WebScanPage = () => {
  const [searchParams] = useSearchParams();
  const useClassicForm = searchParams.get("classic") === "true";
  
  // Use the new ScanWizard by default
  // Add ?classic=true to URL to use old form
  if (useClassicForm) {
    // Keep old implementation for backwards compatibility
    return <ClassicWebScanPage />;
  }
  
  return <ScanWizard scanType="web" />;
};

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
            <p className={`font-semibold ${
              isAtLimit 
                ? isDarkMode ? "text-red-400" : "text-red-700"
                : isDarkMode ? "text-amber-400" : "text-amber-700"
            }`}>
              {isAtLimit ? "Monthly Scan Limit Reached" : `${remaining} Scan${remaining !== 1 ? 's' : ''} Remaining`}
            </p>
            <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              {isAtLimit 
                ? "You've used all your scans for this month. Upgrade for more."
                : `You've used ${scansLimit.current} of ${scansLimit.max} scans this month.`}
            </p>
          </div>
        </div>
        <button onClick={onUpgrade} className="px-4 py-2 rounded-lg font-medium bg-gradient-to-r from-blue-500 to-purple-500 text-white">
          {isAtLimit ? "Upgrade Now" : "View Plans"}
        </button>
      </div>
    </div>
  );
};

const ClassicWebScanPage = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();
  const { getAllUsageStats } = useSubscription();

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
            <div className={`p-3 rounded-xl ${isDarkMode ? "bg-blue-500/20" : "bg-blue-100"}`}>
              <Globe className={`w-8 h-8 ${isDarkMode ? "text-blue-400" : "text-blue-600"}`} />
            </div>
            <div>
              <h1 className={isDarkMode 
                ? "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400"
                : "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-cyan-600"
              }>
                Web Security Scan
              </h1>
              <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>
                OWASP Top 10 vulnerability assessment
              </p>
            </div>
          </div>

          {/* Info Banner */}
          <div className={isDarkMode 
            ? "p-6 bg-gradient-to-r from-blue-500/10 to-cyan-500/10 border border-blue-500/20 rounded-2xl backdrop-blur-xl"
            : "p-6 bg-gradient-to-r from-blue-50 to-cyan-50 border border-blue-200 rounded-2xl shadow-lg"
          }>
            <p className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
              <strong className={isDarkMode ? "text-blue-300" : "text-blue-700"}>Web Scan: </strong>
              Provide your target domain, credentials (optional), and scope. Jarwis will perform comprehensive OWASP Top 10 testing including XSS, SQL Injection, CSRF, and more.
            </p>
          </div>
        </div>

        {/* Form */}
        <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
          <WebScanForm />
        </div>

        {/* Security Info */}
        <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
          <h3 className={isDarkMode ? "text-xl font-semibold text-white mb-6" : "text-xl font-semibold text-gray-900 mb-6"}>
            Security & Privacy
          </h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div className="space-y-4">
              <h4 className={isDarkMode ? "flex items-center gap-2 text-blue-400 font-semibold" : "flex items-center gap-2 text-blue-600 font-semibold"}>
                <Lock className="w-5 h-5" /> Data Protection
              </h4>
              <ul className="space-y-2 text-sm">
                <li className="flex items-start gap-2">
                  <span className="text-green-400 mt-1">✓</span>
                  <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>All credentials are encrypted in transit and at rest</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-400 mt-1">✓</span>
                  <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>Scan data is automatically deleted after 90 days</span>
                </li>
              </ul>
            </div>
            <div className="space-y-4">
              <h4 className={isDarkMode ? "flex items-center gap-2 text-blue-400 font-semibold" : "flex items-center gap-2 text-blue-600 font-semibold"}>
                <Info className="w-5 h-5" /> Scan Process
              </h4>
              <ul className="space-y-2 text-sm">
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 mt-1">✓</span>
                  <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>Non-destructive testing methods only</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 mt-1">✓</span>
                  <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>Real-time progress monitoring available</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </MiftyJarwisLayout>
  );
};

export default WebScanPage;
