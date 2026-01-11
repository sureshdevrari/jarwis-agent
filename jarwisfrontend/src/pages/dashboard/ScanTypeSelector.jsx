// ScanTypeSelector - Page to select scan type when visiting /dashboard/new-scan
import { Link } from "react-router-dom";
import { Globe, Smartphone, Wifi, Cloud, Code, Lock, ArrowRight } from "lucide-react";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";

const ScanTypeSelector = () => {
  const { isDarkMode } = useTheme();
  const { canPerformAction } = useSubscription();

  const scanTypes = [
    {
      id: "web",
      path: "/dashboard/scan/web",
      title: "Web Security Scan",
      description: "OWASP Top 10 vulnerability testing for web applications. Includes XSS, SQL Injection, CSRF, and more.",
      icon: Globe,
      color: "blue",
      gradient: "from-blue-500 to-cyan-500",
      feature: null, // Always available
    },
    {
      id: "mobile",
      path: "/dashboard/scan/mobile",
      title: "Mobile App Scan",
      description: "Security testing for Android (APK) and iOS (IPA) applications with SSL pinning bypass and traffic interception.",
      icon: Smartphone,
      color: "purple",
      gradient: "from-purple-500 to-pink-500",
      feature: "useMobileAppTesting",
    },
    {
      id: "network",
      path: "/dashboard/scan/network",
      title: "Network Scan",
      description: "Host discovery, port scanning, service detection, and vulnerability assessment for network infrastructure.",
      icon: Wifi,
      color: "cyan",
      gradient: "from-cyan-500 to-blue-500",
      feature: "useNetworkScanning",
    },
    {
      id: "cloud",
      path: "/dashboard/scan/cloud",
      title: "Cloud Security Scan",
      description: "Security assessment for AWS, Azure, and GCP. Audit IAM, storage, and network configurations.",
      icon: Cloud,
      color: "amber",
      gradient: "from-amber-500 to-orange-500",
      feature: "useCloudScanning",
    },
    {
      id: "sast",
      path: "/dashboard/scan/sast",
      title: "Secure Code Review",
      description: "Static Application Security Testing (SAST). Detect secrets, vulnerable dependencies, and code vulnerabilities.",
      icon: Code,
      color: "emerald",
      gradient: "from-emerald-500 to-teal-500",
      feature: "useSASTScanning",
    },
  ];

  return (
    <MiftyJarwisLayout>
      <div className="p-6 max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-10">
          <h1 className={isDarkMode 
            ? "text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-purple-400 to-pink-400 mb-4"
            : "text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 mb-4"
          }>
            Start a New Security Scan
          </h1>
          <p className={isDarkMode ? "text-gray-400 text-lg" : "text-gray-600 text-lg"}>
            Choose the type of security assessment you want to perform
          </p>
        </div>

        {/* Scan Type Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {scanTypes.map((type) => {
            const Icon = type.icon;
            const isLocked = type.feature && !canPerformAction(type.feature);
            
            return (
              <Link
                key={type.id}
                to={type.path}
                className={`group relative p-6 rounded-2xl transition-all duration-300 ${
                  isLocked
                    ? isDarkMode 
                      ? "bg-slate-800/30 border border-slate-700/50 cursor-not-allowed opacity-60"
                      : "bg-gray-100 border border-gray-200 cursor-not-allowed opacity-60"
                    : isDarkMode
                      ? "bg-slate-800/50 border border-slate-700/50 hover:border-blue-500/50 hover:shadow-lg hover:shadow-blue-500/10"
                      : "bg-white border border-gray-200 hover:border-blue-300 hover:shadow-lg"
                }`}
                onClick={(e) => isLocked && e.preventDefault()}
              >
                {/* Icon */}
                <div className={`inline-flex p-3 rounded-xl mb-4 ${
                  isDarkMode 
                    ? `bg-${type.color}-500/20`
                    : `bg-${type.color}-100`
                }`}>
                  <Icon className={`w-8 h-8 ${isDarkMode ? `text-${type.color}-400` : `text-${type.color}-600`}`} />
                </div>

                {/* Title */}
                <h3 className={`text-xl font-semibold mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  {type.title}
                  {isLocked && (
                    <Lock className="inline-block w-4 h-4 ml-2 text-gray-400" />
                  )}
                </h3>

                {/* Description */}
                <p className={`text-sm mb-4 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                  {type.description}
                </p>

                {/* Action */}
                {isLocked ? (
                  <span className={`text-sm font-medium ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                    Requires upgrade
                  </span>
                ) : (
                  <span className={`inline-flex items-center gap-1 text-sm font-medium bg-gradient-to-r ${type.gradient} bg-clip-text text-transparent group-hover:gap-2 transition-all`}>
                    Start Scan <ArrowRight className={`w-4 h-4 ${isDarkMode ? `text-${type.color}-400` : `text-${type.color}-600`}`} />
                  </span>
                )}

                {/* Locked Overlay */}
                {isLocked && (
                  <div className="absolute inset-0 flex items-center justify-center bg-black/5 rounded-2xl">
                    <Link
                      to="/pricing"
                      onClick={(e) => e.stopPropagation()}
                      className={`px-4 py-2 rounded-lg font-medium text-sm bg-gradient-to-r ${type.gradient} text-white hover:opacity-90 transition-opacity`}
                    >
                      Upgrade Plan
                    </Link>
                  </div>
                )}
              </Link>
            );
          })}
        </div>

        {/* Quick Actions */}
        <div className={`mt-10 p-6 rounded-2xl ${isDarkMode ? "bg-slate-800/30 border border-slate-700/50" : "bg-gray-50 border border-gray-200"}`}>
          <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
            Quick Links
          </h3>
          <div className="flex flex-wrap gap-4">
            <Link
              to="/dashboard/scan-history"
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                isDarkMode 
                  ? "bg-slate-700/50 text-gray-300 hover:bg-slate-700"
                  : "bg-white text-gray-700 border border-gray-200 hover:bg-gray-50"
              }`}
            >
              📜 View Scan History
            </Link>
            <Link
              to="/dashboard/vulnerabilities"
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                isDarkMode 
                  ? "bg-slate-700/50 text-gray-300 hover:bg-slate-700"
                  : "bg-white text-gray-700 border border-gray-200 hover:bg-gray-50"
              }`}
            >
              🚨 View Vulnerabilities
            </Link>
            <Link
              to="/dashboard/reports"
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                isDarkMode 
                  ? "bg-slate-700/50 text-gray-300 hover:bg-slate-700"
                  : "bg-white text-gray-700 border border-gray-200 hover:bg-gray-50"
              }`}
            >
              📄 Generate Reports
            </Link>
          </div>
        </div>
      </div>
    </MiftyJarwisLayout>
  );
};

export default ScanTypeSelector;
