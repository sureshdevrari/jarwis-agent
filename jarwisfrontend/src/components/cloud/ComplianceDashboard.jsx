// src/components/cloud/ComplianceDashboard.jsx - Compliance Framework Scores
import { useState } from "react";
import { useTheme } from "../../context/ThemeContext";
import {
  Shield,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Download,
  TrendingUp,
  TrendingDown,
} from "lucide-react";

// Framework descriptions
const FRAMEWORK_INFO = {
  CIS: {
    name: "CIS Benchmarks",
    fullName: "Center for Internet Security Benchmarks",
    description: "Industry-standard security configurations for cloud infrastructure",
    icon: "🛡️",
  },
  "PCI-DSS": {
    name: "PCI-DSS",
    fullName: "Payment Card Industry Data Security Standard",
    description: "Security standards for organizations handling credit card data",
    icon: "💳",
  },
  HIPAA: {
    name: "HIPAA",
    fullName: "Health Insurance Portability and Accountability Act",
    description: "Security requirements for protected health information (PHI)",
    icon: "🏥",
  },
  SOC2: {
    name: "SOC 2",
    fullName: "Service Organization Control 2",
    description: "Trust service criteria for service organizations",
    icon: "📋",
  },
};

// Score gauge component with animation
const ScoreGauge = ({ score, size = 120, strokeWidth = 10 }) => {
  const { isDarkMode } = useTheme();
  
  const getColor = (score) => {
    if (score >= 90) return { text: "text-green-500", stroke: "#22c55e" };
    if (score >= 70) return { text: "text-yellow-500", stroke: "#eab308" };
    if (score >= 50) return { text: "text-orange-500", stroke: "#f97316" };
    return { text: "text-red-500", stroke: "#ef4444" };
  };

  const { text, stroke } = getColor(score);
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;
  const center = size / 2;

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="transform -rotate-90">
        {/* Background circle */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={isDarkMode ? "#374151" : "#e5e7eb"}
          strokeWidth={strokeWidth}
        />
        {/* Progress circle */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={stroke}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      {/* Center text */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-2xl font-bold ${text}`}>{Math.round(score)}%</span>
        <span className={`text-xs ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
          Score
        </span>
      </div>
    </div>
  );
};

// Framework card component
const FrameworkCard = ({ framework, score, breakdown, onExport }) => {
  const { isDarkMode } = useTheme();
  const [expanded, setExpanded] = useState(false);
  const info = FRAMEWORK_INFO[framework] || { name: framework, description: "", icon: "📄" };

  const getScoreLabel = (score) => {
    if (score >= 90) return { label: "Excellent", color: "text-green-500" };
    if (score >= 70) return { label: "Good", color: "text-yellow-500" };
    if (score >= 50) return { label: "Needs Work", color: "text-orange-500" };
    return { label: "Critical", color: "text-red-500" };
  };

  const { label, color } = getScoreLabel(score);

  return (
    <div
      className={`rounded-xl border overflow-hidden transition-all ${
        isDarkMode ? "bg-gray-800 border-gray-700" : "bg-white border-gray-200"
      }`}
    >
      {/* Header */}
      <div className="p-6">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-4">
            <span className="text-3xl">{info.icon}</span>
            <div>
              <h3 className={`text-lg font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                {info.name}
              </h3>
              <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                {info.fullName}
              </p>
            </div>
          </div>
          <ScoreGauge score={score} size={80} strokeWidth={8} />
        </div>

        {/* Score label */}
        <div className="mt-4 flex items-center justify-between">
          <span className={`text-sm font-medium ${color}`}>{label}</span>
          <button
            onClick={() => setExpanded(!expanded)}
            className={`flex items-center gap-1 text-sm ${
              isDarkMode ? "text-gray-400 hover:text-gray-300" : "text-gray-600 hover:text-gray-800"
            }`}
          >
            {expanded ? "Hide Details" : "Show Details"}
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Expanded breakdown */}
      {expanded && breakdown && (
        <div className={`border-t ${isDarkMode ? "border-gray-700" : "border-gray-200"}`}>
          <div className="p-6 space-y-4">
            {/* Description */}
            <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              {info.description}
            </p>

            {/* Severity breakdown */}
            <div className="grid grid-cols-2 gap-4">
              <div className={`p-3 rounded-lg ${isDarkMode ? "bg-gray-700" : "bg-gray-50"}`}>
                <div className="flex items-center gap-2">
                  <XCircle className="w-4 h-4 text-red-500" />
                  <span className={`text-sm ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Critical: {breakdown.critical || 0}
                  </span>
                </div>
              </div>
              <div className={`p-3 rounded-lg ${isDarkMode ? "bg-gray-700" : "bg-gray-50"}`}>
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-orange-500" />
                  <span className={`text-sm ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    High: {breakdown.high || 0}
                  </span>
                </div>
              </div>
              <div className={`p-3 rounded-lg ${isDarkMode ? "bg-gray-700" : "bg-gray-50"}`}>
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-500" />
                  <span className={`text-sm ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Medium: {breakdown.medium || 0}
                  </span>
                </div>
              </div>
              <div className={`p-3 rounded-lg ${isDarkMode ? "bg-gray-700" : "bg-gray-50"}`}>
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-blue-500" />
                  <span className={`text-sm ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Low: {breakdown.low || 0}
                  </span>
                </div>
              </div>
            </div>

            {/* Total findings */}
            <div className={`flex items-center justify-between pt-3 border-t ${
              isDarkMode ? "border-gray-600" : "border-gray-200"
            }`}>
              <span className={`text-sm font-medium ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                Total Findings: {breakdown.total_findings || 0}
              </span>
              {onExport && (
                <button
                  onClick={() => onExport(framework)}
                  className={`flex items-center gap-1 text-sm px-3 py-1 rounded-lg transition-colors ${
                    isDarkMode
                      ? "bg-gray-600 hover:bg-gray-500 text-white"
                      : "bg-gray-100 hover:bg-gray-200 text-gray-700"
                  }`}
                >
                  <Download className="w-4 h-4" />
                  Export
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Main Compliance Dashboard
const ComplianceDashboard = ({ scores, breakdown, onExport }) => {
  const { isDarkMode } = useTheme();

  // Calculate overall score
  const frameworks = Object.keys(scores || {});
  const overallScore = frameworks.length > 0
    ? frameworks.reduce((sum, f) => sum + (scores[f] || 0), 0) / frameworks.length
    : 0;

  // Get trend indicator (mock - in real app, compare to previous scan)
  const getTrend = (score) => {
    // This would compare to previous scan results
    return score >= 80 ? "up" : score >= 50 ? "stable" : "down";
  };

  if (!scores || Object.keys(scores).length === 0) {
    return (
      <div className={`p-8 rounded-xl text-center ${
        isDarkMode ? "bg-gray-800" : "bg-white"
      } border ${isDarkMode ? "border-gray-700" : "border-gray-200"}`}>
        <Shield className={`w-12 h-12 mx-auto mb-3 ${isDarkMode ? "text-gray-600" : "text-gray-300"}`} />
        <p className={isDarkMode ? "text-gray-500" : "text-gray-400"}>
          No compliance data available
        </p>
        <p className={`text-sm mt-1 ${isDarkMode ? "text-gray-600" : "text-gray-500"}`}>
          Run a cloud scan to generate compliance scores
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Overall Score Header */}
      <div className={`p-6 rounded-xl ${
        isDarkMode ? "bg-gradient-to-r from-gray-800 to-gray-700" : "bg-gradient-to-r from-blue-50 to-indigo-50"
      }`}>
        <div className="flex items-center justify-between">
          <div>
            <h2 className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Compliance Overview
            </h2>
            <p className={`mt-1 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              Security posture across {frameworks.length} compliance frameworks
            </p>
            
            {/* Quick stats */}
            <div className="flex items-center gap-6 mt-4">
              {frameworks.map((f) => (
                <div key={f} className="flex items-center gap-2">
                  <span className="text-lg">{FRAMEWORK_INFO[f]?.icon || "📄"}</span>
                  <span className={`font-medium ${
                    scores[f] >= 70 ? "text-green-500" : scores[f] >= 50 ? "text-yellow-500" : "text-red-500"
                  }`}>
                    {Math.round(scores[f])}%
                  </span>
                </div>
              ))}
            </div>
          </div>
          
          <div className="text-center">
            <ScoreGauge score={overallScore} size={120} strokeWidth={12} />
            <p className={`mt-2 text-sm font-medium ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              Overall Score
            </p>
          </div>
        </div>
      </div>

      {/* Framework Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {frameworks.map((framework) => (
          <FrameworkCard
            key={framework}
            framework={framework}
            score={scores[framework]}
            breakdown={breakdown?.[framework]}
            onExport={onExport}
          />
        ))}
      </div>

      {/* Recommendations */}
      <div className={`p-6 rounded-xl ${
        isDarkMode ? "bg-gray-800" : "bg-white"
      } border ${isDarkMode ? "border-gray-700" : "border-gray-200"}`}>
        <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
          Priority Recommendations
        </h3>
        <div className="space-y-3">
          {overallScore < 70 && (
            <div className={`flex items-start gap-3 p-3 rounded-lg ${
              isDarkMode ? "bg-red-500/10" : "bg-red-50"
            }`}>
              <XCircle className="w-5 h-5 text-red-500 mt-0.5" />
              <div>
                <p className={`font-medium ${isDarkMode ? "text-red-400" : "text-red-700"}`}>
                  Address Critical Findings First
                </p>
                <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                  Focus on critical and high-severity issues to improve your overall compliance posture.
                </p>
              </div>
            </div>
          )}
          {scores.CIS < 80 && (
            <div className={`flex items-start gap-3 p-3 rounded-lg ${
              isDarkMode ? "bg-yellow-500/10" : "bg-yellow-50"
            }`}>
              <AlertTriangle className="w-5 h-5 text-yellow-500 mt-0.5" />
              <div>
                <p className={`font-medium ${isDarkMode ? "text-yellow-400" : "text-yellow-700"}`}>
                  Review CIS Benchmark Failures
                </p>
                <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                  CIS benchmarks form the foundation of cloud security. Address these issues first.
                </p>
              </div>
            </div>
          )}
          {overallScore >= 90 && (
            <div className={`flex items-start gap-3 p-3 rounded-lg ${
              isDarkMode ? "bg-green-500/10" : "bg-green-50"
            }`}>
              <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
              <div>
                <p className={`font-medium ${isDarkMode ? "text-green-400" : "text-green-700"}`}>
                  Excellent Security Posture
                </p>
                <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                  Your cloud infrastructure meets industry best practices. Continue monitoring for changes.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ComplianceDashboard;
