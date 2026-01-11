// NetworkScanPage - Dedicated page for network security scanning
import { Wifi, Lock, Info, Server, Shield } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import NetworkScanForm from "../../components/scan/NetworkScanForm";

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
        <button onClick={onUpgrade} className="px-4 py-2 rounded-lg font-medium bg-gradient-to-r from-cyan-500 to-blue-500 text-white">
          {isAtLimit ? "Upgrade Now" : "View Plans"}
        </button>
      </div>
    </div>
  );
};

const NetworkScanPage = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();
  const { getAllUsageStats, canPerformAction } = useSubscription();

  // Check if user has access to network scanning
  const hasNetworkAccess = canPerformAction("useNetworkScanning");

  if (!hasNetworkAccess) {
    return (
      <MiftyJarwisLayout>
        <div className="p-6">
          <div className={`p-8 rounded-2xl text-center ${isDarkMode ? "bg-slate-800/50 border border-slate-700" : "bg-gray-50 border border-gray-200"}`}>
            <Wifi className={`w-16 h-16 mx-auto mb-4 ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}`} />
            <h2 className={`text-2xl font-bold mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Network Security Scanning
            </h2>
            <p className={`mb-6 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              Network security scanning requires a Professional or Enterprise plan.
            </p>
            <button
              onClick={() => navigate("/pricing")}
              className="px-6 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-xl font-semibold hover:from-cyan-500 hover:to-blue-500 transition-all"
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
            <div className={`p-3 rounded-xl ${isDarkMode ? "bg-cyan-500/20" : "bg-cyan-100"}`}>
              <Wifi className={`w-8 h-8 ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}`} />
            </div>
            <div>
              <h1 className={isDarkMode 
                ? "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400"
                : "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-600 to-blue-600"
              }>
                Network Security Scan
              </h1>
              <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>
                Host discovery, port scanning, and vulnerability assessment
              </p>
            </div>
          </div>

          {/* Info Banner */}
          <div className={isDarkMode 
            ? "p-6 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/20 rounded-2xl backdrop-blur-xl"
            : "p-6 bg-gradient-to-r from-cyan-50 to-blue-50 border border-cyan-200 rounded-2xl shadow-lg"
          }>
            <p className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
              <strong className={isDarkMode ? "text-cyan-300" : "text-cyan-700"}>Network Scan: </strong>
              Specify target hosts/IPs and port ranges. Jarwis will perform host discovery, port scanning, service detection, and protocol analysis.
            </p>
          </div>
        </div>

        {/* Form */}
        <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
          <NetworkScanForm />
        </div>

        {/* Features */}
        <div className={isDarkMode ? "function-card-dark p-6" : "function-card-light p-6"}>
          <h3 className={isDarkMode ? "text-xl font-semibold text-white mb-6" : "text-xl font-semibold text-gray-900 mb-6"}>
            Network Security Features
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
              <Server className={`w-8 h-8 mb-3 ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}`} />
              <h4 className={isDarkMode ? "font-semibold text-white mb-2" : "font-semibold text-gray-900 mb-2"}>
                Host Discovery
              </h4>
              <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Identify live hosts on your network using ICMP, ARP, and TCP probes
              </p>
            </div>
            <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
              <Wifi className={`w-8 h-8 mb-3 ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}`} />
              <h4 className={isDarkMode ? "font-semibold text-white mb-2" : "font-semibold text-gray-900 mb-2"}>
                Service Detection
              </h4>
              <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Identify running services, versions, and protocols on open ports
              </p>
            </div>
            <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
              <Shield className={`w-8 h-8 mb-3 ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}`} />
              <h4 className={isDarkMode ? "font-semibold text-white mb-2" : "font-semibold text-gray-900 mb-2"}>
                Vulnerability Scan
              </h4>
              <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Check for known CVEs and misconfigurations in detected services
              </p>
            </div>
          </div>
        </div>
      </div>
    </MiftyJarwisLayout>
  );
};

export default NetworkScanPage;
