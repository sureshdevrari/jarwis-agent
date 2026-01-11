// src/pages/dashboard/CloudDashboard.jsx - Cloud Security Dashboard
import { useState, useEffect, useCallback } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  Cloud,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  Download,
  ChevronRight,
  Server,
  Database,
  Lock,
  Globe,
  Activity,
  TrendingUp,
  Filter,
  Search,
  Eye,
  FileJson,
  FileText,
} from "lucide-react";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { cloudScanAPI } from "../../services/api";

// Provider logos/icons
const ProviderIcon = ({ provider, size = 24 }) => {
  const icons = {
    aws: "🟠",
    azure: "🔵",
    gcp: "🟢",
  };
  return <span style={{ fontSize: size }}>{icons[provider] || "☁️"}</span>;
};

// Severity badge component
const SeverityBadge = ({ severity, count }) => {
  const colors = {
    critical: "bg-red-500 text-white",
    high: "bg-orange-500 text-white",
    medium: "bg-yellow-500 text-black",
    low: "bg-blue-500 text-white",
    info: "bg-gray-500 text-white",
  };

  return (
    <span className={`px-2 py-1 rounded-full text-xs font-medium ${colors[severity] || colors.info}`}>
      {count} {severity}
    </span>
  );
};

// Compliance gauge component
const ComplianceGauge = ({ score, framework, isDarkMode }) => {
  const getColor = (score) => {
    if (score >= 90) return "text-green-500";
    if (score >= 70) return "text-yellow-500";
    if (score >= 50) return "text-orange-500";
    return "text-red-500";
  };

  const circumference = 2 * Math.PI * 40;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-24 h-24">
        <svg className="w-24 h-24 transform -rotate-90">
          <circle
            cx="48"
            cy="48"
            r="40"
            stroke={isDarkMode ? "#374151" : "#e5e7eb"}
            strokeWidth="8"
            fill="none"
          />
          <circle
            cx="48"
            cy="48"
            r="40"
            stroke="currentColor"
            strokeWidth="8"
            fill="none"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            className={`transition-all duration-1000 ${getColor(score)}`}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-xl font-bold ${getColor(score)}`}>{Math.round(score)}%</span>
        </div>
      </div>
      <span className={`mt-2 text-sm font-medium ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
        {framework}
      </span>
    </div>
  );
};

// Finding card component
const FindingCard = ({ finding, isDarkMode, onClick }) => {
  const severityColors = {
    critical: "border-red-500 bg-red-500/10",
    high: "border-orange-500 bg-orange-500/10",
    medium: "border-yellow-500 bg-yellow-500/10",
    low: "border-blue-500 bg-blue-500/10",
    info: "border-gray-500 bg-gray-500/10",
  };

  return (
    <div
      onClick={onClick}
      className={`p-4 rounded-lg border-l-4 cursor-pointer transition-all hover:scale-[1.01] ${
        severityColors[finding.severity] || severityColors.info
      } ${isDarkMode ? "bg-gray-800/50" : "bg-white"}`}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <ProviderIcon provider={finding.provider} size={16} />
            <span className={`text-xs ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
              {finding.service}
            </span>
          </div>
          <h4 className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
            {finding.title}
          </h4>
          <p className={`text-sm mt-1 line-clamp-2 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
            {finding.description}
          </p>
          <div className="flex items-center gap-2 mt-2">
            <span className={`text-xs px-2 py-0.5 rounded ${isDarkMode ? "bg-gray-700" : "bg-gray-100"}`}>
              {finding.resource_id?.substring(0, 30)}...
            </span>
          </div>
        </div>
        <ChevronRight className={`w-5 h-5 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`} />
      </div>
    </div>
  );
};

// Attack path visualization (simplified)
const AttackPathCard = ({ path, isDarkMode }) => {
  const severityColors = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-yellow-500",
  };

  return (
    <div className={`p-4 rounded-lg border ${isDarkMode ? "border-gray-700 bg-gray-800/50" : "border-gray-200 bg-white"}`}>
      <div className="flex items-center justify-between mb-3">
        <span className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
          Attack Path
        </span>
        <div className="flex items-center gap-2">
          <span className={`text-sm ${severityColors[path.severity] || "text-gray-500"}`}>
            Blast Radius: {path.blast_radius}
          </span>
        </div>
      </div>
      <p className={`text-sm mb-3 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
        {path.description}
      </p>
      <div className="flex items-center gap-2 overflow-x-auto pb-2">
        {path.path?.map((node, idx) => (
          <div key={idx} className="flex items-center">
            <span className={`px-2 py-1 rounded text-xs whitespace-nowrap ${
              isDarkMode ? "bg-gray-700 text-gray-300" : "bg-gray-100 text-gray-700"
            }`}>
              {node}
            </span>
            {idx < path.path.length - 1 && (
              <ChevronRight className={`w-4 h-4 mx-1 ${isDarkMode ? "text-gray-600" : "text-gray-400"}`} />
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

const CloudDashboard = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();

  const [loading, setLoading] = useState(true);
  const [scanStatus, setScanStatus] = useState(null);
  const [findings, setFindings] = useState([]);
  const [attackPaths, setAttackPaths] = useState([]);
  const [complianceScores, setComplianceScores] = useState({});
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState("all");
  const [providerFilter, setProviderFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  // Selected finding for detail view
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Fetch scan data
  const fetchScanData = useCallback(async () => {
    if (!scanId) return;

    try {
      setLoading(true);
      
      // Fetch status
      const status = await cloudScanAPI.getScanStatus(scanId);
      setScanStatus(status);

      // Fetch findings/logs
      const logsData = await cloudScanAPI.getScanLogs(scanId);
      setLogs(logsData.logs || []);

      // If scan is complete, fetch additional data
      if (status.status === "completed") {
        // Fetch attack paths
        try {
          const pathsData = await cloudScanAPI.getAttackPaths(scanId);
          setAttackPaths(pathsData.attack_paths || []);
        } catch (e) {
          console.warn("Attack paths not available:", e);
        }

        // Fetch compliance scores
        try {
          const complianceData = await cloudScanAPI.getComplianceScores(scanId);
          setComplianceScores(complianceData.compliance_scores || {});
          // Extract findings from breakdown if available
          if (complianceData.breakdown) {
            // Findings would come from logs/results
          }
        } catch (e) {
          console.warn("Compliance scores not available:", e);
        }
      }

      setError(null);
    } catch (err) {
      console.error("Failed to fetch scan data:", err);
      setError("Failed to load scan data");
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    fetchScanData();

    // Poll for updates if scan is running
    const interval = setInterval(() => {
      if (scanStatus?.status === "running" || scanStatus?.status === "queued") {
        fetchScanData();
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [fetchScanData, scanStatus?.status]);

  // Export handler
  const handleExport = async (format) => {
    try {
      const data = await cloudScanAPI.exportResults(scanId, format);
      
      if (format === "json") {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `cloud_scan_${scanId}.json`;
        a.click();
      } else {
        // For blob responses (html, pdf, sarif)
        const url = URL.createObjectURL(data);
        const a = document.createElement("a");
        a.href = url;
        a.download = `cloud_scan_${scanId}.${format}`;
        a.click();
      }
    } catch (err) {
      console.error("Export failed:", err);
      alert("Failed to export results");
    }
  };

  // Filter findings
  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== "all" && f.severity !== severityFilter) return false;
    if (providerFilter !== "all" && f.provider !== providerFilter) return false;
    if (searchQuery && !f.title.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !f.description.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  // Summary stats
  const stats = {
    total: findings.length,
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
  };

  if (loading && !scanStatus) {
    return (
      <MiftyJarwisLayout>
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
        </div>
      </MiftyJarwisLayout>
    );
  }

  return (
    <MiftyJarwisLayout>
      <div className="max-w-7xl mx-auto px-4 py-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className={`text-2xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Cloud Security Scan
            </h1>
            <p className={`mt-1 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              Scan ID: {scanId}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={fetchScanData}
              className={`p-2 rounded-lg transition-colors ${
                isDarkMode ? "hover:bg-gray-700" : "hover:bg-gray-100"
              }`}
            >
              <RefreshCw className={`w-5 h-5 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`} />
            </button>
            {scanStatus?.status === "completed" && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleExport("json")}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm ${
                    isDarkMode ? "bg-gray-700 hover:bg-gray-600 text-white" : "bg-gray-100 hover:bg-gray-200 text-gray-700"
                  }`}
                >
                  <FileJson className="w-4 h-4" />
                  JSON
                </button>
                <button
                  onClick={() => handleExport("html")}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm ${
                    isDarkMode ? "bg-gray-700 hover:bg-gray-600 text-white" : "bg-gray-100 hover:bg-gray-200 text-gray-700"
                  }`}
                >
                  <FileText className="w-4 h-4" />
                  Report
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Status Banner */}
        {scanStatus && (
          <div className={`mb-6 p-4 rounded-lg ${
            scanStatus.status === "completed" 
              ? isDarkMode ? "bg-green-500/10 border border-green-500/30" : "bg-green-50 border border-green-200"
              : scanStatus.status === "running"
              ? isDarkMode ? "bg-blue-500/10 border border-blue-500/30" : "bg-blue-50 border border-blue-200"
              : scanStatus.status === "error"
              ? isDarkMode ? "bg-red-500/10 border border-red-500/30" : "bg-red-50 border border-red-200"
              : isDarkMode ? "bg-gray-700" : "bg-gray-100"
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {scanStatus.status === "completed" && <CheckCircle className="w-6 h-6 text-green-500" />}
                {scanStatus.status === "running" && <RefreshCw className="w-6 h-6 text-blue-500 animate-spin" />}
                {scanStatus.status === "error" && <XCircle className="w-6 h-6 text-red-500" />}
                <div>
                  <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {scanStatus.status === "completed" ? "Scan Complete" :
                     scanStatus.status === "running" ? `Scanning: ${scanStatus.phase || "In Progress"}` :
                     scanStatus.status === "error" ? "Scan Failed" : "Queued"}
                  </p>
                  <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                    {scanStatus.findings_count || 0} findings • Provider: {scanStatus.provider?.toUpperCase()}
                  </p>
                </div>
              </div>
              {scanStatus.status === "running" && (
                <div className="w-48">
                  <div className={`h-2 rounded-full overflow-hidden ${isDarkMode ? "bg-gray-600" : "bg-gray-200"}`}>
                    <div 
                      className="h-full bg-blue-500 transition-all"
                      style={{ width: `${scanStatus.progress || 0}%` }}
                    />
                  </div>
                  <p className={`text-xs mt-1 text-right ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                    {scanStatus.progress || 0}%
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          {[
            { label: "Total", value: stats.total, icon: Shield, color: "text-blue-500" },
            { label: "Critical", value: stats.critical, icon: AlertTriangle, color: "text-red-500" },
            { label: "High", value: stats.high, icon: AlertTriangle, color: "text-orange-500" },
            { label: "Medium", value: stats.medium, icon: Activity, color: "text-yellow-500" },
            { label: "Low", value: stats.low, icon: Activity, color: "text-blue-400" },
          ].map((stat) => (
            <div
              key={stat.label}
              className={`p-4 rounded-lg ${isDarkMode ? "bg-gray-800" : "bg-white"} border ${isDarkMode ? "border-gray-700" : "border-gray-200"}`}
            >
              <div className="flex items-center justify-between">
                <stat.icon className={`w-5 h-5 ${stat.color}`} />
                <span className={`text-2xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  {stat.value}
                </span>
              </div>
              <p className={`text-sm mt-1 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                {stat.label}
              </p>
            </div>
          ))}
        </div>

        {/* Compliance Scores */}
        {Object.keys(complianceScores).length > 0 && (
          <div className={`mb-6 p-6 rounded-lg ${isDarkMode ? "bg-gray-800" : "bg-white"} border ${isDarkMode ? "border-gray-700" : "border-gray-200"}`}>
            <h2 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Compliance Scores
            </h2>
            <div className="flex justify-around flex-wrap gap-6">
              {Object.entries(complianceScores).map(([framework, score]) => (
                <ComplianceGauge key={framework} framework={framework} score={score} isDarkMode={isDarkMode} />
              ))}
            </div>
          </div>
        )}

        {/* Attack Paths */}
        {attackPaths.length > 0 && (
          <div className={`mb-6 p-6 rounded-lg ${isDarkMode ? "bg-gray-800" : "bg-white"} border ${isDarkMode ? "border-gray-700" : "border-gray-200"}`}>
            <h2 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Attack Paths ({attackPaths.length})
            </h2>
            <div className="space-y-4">
              {attackPaths.slice(0, 5).map((path, idx) => (
                <AttackPathCard key={idx} path={path} isDarkMode={isDarkMode} />
              ))}
            </div>
          </div>
        )}

        {/* Findings Section */}
        <div className={`p-6 rounded-lg ${isDarkMode ? "bg-gray-800" : "bg-white"} border ${isDarkMode ? "border-gray-700" : "border-gray-200"}`}>
          <div className="flex items-center justify-between mb-4">
            <h2 className={`text-lg font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Findings
            </h2>
            <div className="flex items-center gap-3">
              {/* Search */}
              <div className="relative">
                <Search className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`} />
                <input
                  type="text"
                  placeholder="Search findings..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className={`pl-10 pr-4 py-2 rounded-lg text-sm ${
                    isDarkMode ? "bg-gray-700 text-white" : "bg-gray-100 text-gray-900"
                  }`}
                />
              </div>
              {/* Severity filter */}
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className={`px-3 py-2 rounded-lg text-sm ${
                  isDarkMode ? "bg-gray-700 text-white" : "bg-gray-100 text-gray-900"
                }`}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          {/* Findings list */}
          {filteredFindings.length > 0 ? (
            <div className="space-y-3">
              {filteredFindings.map((finding, idx) => (
                <FindingCard
                  key={finding.id || idx}
                  finding={finding}
                  isDarkMode={isDarkMode}
                  onClick={() => setSelectedFinding(finding)}
                />
              ))}
            </div>
          ) : (
            <div className={`text-center py-12 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
              <Cloud className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>No findings match your filters</p>
            </div>
          )}
        </div>

        {/* Scan Logs */}
        {logs.length > 0 && (
          <div className={`mt-6 p-6 rounded-lg ${isDarkMode ? "bg-gray-800" : "bg-white"} border ${isDarkMode ? "border-gray-700" : "border-gray-200"}`}>
            <h2 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Scan Logs
            </h2>
            <div className={`max-h-64 overflow-y-auto font-mono text-sm ${isDarkMode ? "bg-gray-900" : "bg-gray-50"} p-4 rounded-lg`}>
              {logs.map((log, idx) => (
                <div key={idx} className="flex items-start gap-3 mb-1">
                  <span className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                    {log.timestamp?.substring(11, 19)}
                  </span>
                  <span className={`${
                    log.level === "error" ? "text-red-500" :
                    log.level === "warning" ? "text-yellow-500" :
                    isDarkMode ? "text-gray-300" : "text-gray-700"
                  }`}>
                    {log.message}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Finding Detail Modal */}
        {selectedFinding && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setSelectedFinding(null)}>
            <div
              className={`w-full max-w-2xl max-h-[90vh] overflow-y-auto mx-4 p-6 rounded-lg ${
                isDarkMode ? "bg-gray-800" : "bg-white"
              }`}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <ProviderIcon provider={selectedFinding.provider} />
                    <SeverityBadge severity={selectedFinding.severity} count="" />
                  </div>
                  <h3 className={`text-xl font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {selectedFinding.title}
                  </h3>
                </div>
                <button onClick={() => setSelectedFinding(null)} className="text-gray-500 hover:text-gray-700">
                  <XCircle className="w-6 h-6" />
                </button>
              </div>

              <div className="space-y-4">
                <div>
                  <h4 className={`text-sm font-medium mb-1 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                    Description
                  </h4>
                  <p className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                    {selectedFinding.description}
                  </p>
                </div>

                <div>
                  <h4 className={`text-sm font-medium mb-1 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                    Resource
                  </h4>
                  <code className={`block p-2 rounded text-sm ${isDarkMode ? "bg-gray-900" : "bg-gray-100"}`}>
                    {selectedFinding.resource_arn || selectedFinding.resource_id}
                  </code>
                </div>

                {selectedFinding.remediation && (
                  <div>
                    <h4 className={`text-sm font-medium mb-1 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                      Remediation
                    </h4>
                    <p className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                      {selectedFinding.remediation}
                    </p>
                  </div>
                )}

                {selectedFinding.remediation_cli && (
                  <div>
                    <h4 className={`text-sm font-medium mb-1 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                      CLI Command
                    </h4>
                    <code className={`block p-2 rounded text-sm overflow-x-auto ${isDarkMode ? "bg-gray-900" : "bg-gray-100"}`}>
                      {selectedFinding.remediation_cli}
                    </code>
                  </div>
                )}

                {selectedFinding.cis_benchmark && (
                  <div>
                    <h4 className={`text-sm font-medium mb-1 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                      CIS Benchmark
                    </h4>
                    <span className={`px-2 py-1 rounded text-sm ${isDarkMode ? "bg-gray-700" : "bg-gray-100"}`}>
                      {selectedFinding.cis_benchmark}
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </MiftyJarwisLayout>
  );
};

export default CloudDashboard;
