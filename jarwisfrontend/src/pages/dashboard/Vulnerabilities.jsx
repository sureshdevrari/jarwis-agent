// src/pages/dashboard/Vulnerabilities.jsx - With Real API Integration
import { useState, useEffect, useCallback } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Search, BarChart3, FileText, List, Lock, MessageSquare, RefreshCw } from "lucide-react";
import DashboardPageLayout from "../../components/dashboardTheme/DashboardPageLayout";
import { scanAPI, networkScanAPI, mobileScanAPI, cloudScanAPI } from "../../services/api";
import { useTheme } from "../../context/ThemeContext";

const Vulnerabilities = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { isDarkMode } = useTheme();
  const scanId = location.state?.scanId;
  const scanType = location.state?.scanType || 'web';

  // State for vulnerabilities from API
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 });

  // Fetch vulnerabilities from API - USING CENTRALIZED API CLIENT
  const fetchVulnerabilities = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      let data;
      if (scanId) {
        // Fetch findings for specific scan based on scan type
        if (scanType === 'network') {
          data = await networkScanAPI.getScanFindings(scanId);
        } else if (scanType === 'mobile') {
          data = await mobileScanAPI.getScanFindings(scanId);
        } else if (scanType === 'cloud') {
          data = await cloudScanAPI.getScanFindings(scanId);
        } else {
          // Web scan - use centralized scanAPI
          data = await scanAPI.getScanFindings(scanId);
        }
        
        // Handle findings format
        const findings = data.findings || [];
        setVulnerabilities(findings);
        
        // Use summary from response or calculate from findings
        if (data.summary) {
          setSummary(data.summary);
        } else {
          setSummary({
            total: findings.length,
            critical: findings.filter(f => f.severity === 'critical').length,
            high: findings.filter(f => f.severity === 'high').length,
            medium: findings.filter(f => f.severity === 'medium').length,
            low: findings.filter(f => f.severity === 'low').length,
            info: findings.filter(f => f.severity === 'info').length,
          });
        }
      } else {
        // Fetch all vulnerabilities using centralized API
        data = await scanAPI.getAllVulnerabilities();
        setVulnerabilities(data.vulnerabilities || []);
        setSummary(data.summary || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 });
      }
    } catch (err) {
      console.error('Failed to fetch vulnerabilities:', err);
      setError('Failed to load vulnerabilities');
      setVulnerabilities([]);
    } finally {
      setLoading(false);
    }
  }, [scanId, scanType]);

  useEffect(() => {
    fetchVulnerabilities();
  }, [fetchVulnerabilities]);

  // Initial fetch on mount
  useEffect(() => {
    fetchVulnerabilities();
  }, [fetchVulnerabilities]);

  const [activeFilter, setActiveFilter] = useState("All");

  const filters = ["All", "Critical", "High", "Medium", "Low"];

  const filteredVulnerabilities = vulnerabilities.filter(
    (vuln) => activeFilter === "All" || (vuln.severity || '').toLowerCase() === activeFilter.toLowerCase()
  );

  const getSeverityBadge = (severity) => {
    const baseClasses = "px-2 py-1 rounded text-xs font-medium";
    switch (severity.toLowerCase()) {
      case "critical":
        return (
          <span
            className={
              isDarkMode
                ? `${baseClasses} bg-red-900/30 border border-red-700 text-red-400`
                : `${baseClasses} bg-red-100 border border-red-300 text-red-700`
            }
          >
            {severity}
          </span>
        );
      case "high":
        return (
          <span
            className={
              isDarkMode
                ? `${baseClasses} bg-orange-900/30 border border-orange-700 text-orange-400`
                : `${baseClasses} bg-orange-100 border border-orange-300 text-orange-700`
            }
          >
            {severity}
          </span>
        );
      case "medium":
        return (
          <span
            className={
              isDarkMode
                ? `${baseClasses} bg-yellow-900/30 border border-yellow-700 text-yellow-400`
                : `${baseClasses} bg-yellow-100 border border-yellow-300 text-yellow-700`
            }
          >
            {severity}
          </span>
        );
      case "low":
        return (
          <span
            className={
              isDarkMode
                ? `${baseClasses} bg-blue-900/30 border border-blue-700 text-blue-400`
                : `${baseClasses} bg-blue-100 border border-blue-300 text-blue-700`
            }
          >
            {severity}
          </span>
        );
      default:
        return (
          <span
            className={
              isDarkMode
                ? `${baseClasses} bg-gray-700 border border-gray-600 text-gray-300`
                : `${baseClasses} bg-gray-100 border border-gray-300 text-gray-600`
            }
          >
            {severity}
          </span>
        );
    }
  };

  const getStatusBadge = (status) => {
    const baseClasses = "px-2 py-1 rounded text-xs font-medium";
    return status === "Mitigated" ? (
      <span
        className={
          isDarkMode
            ? `${baseClasses} bg-green-900/30 border border-green-700 text-green-400`
            : `${baseClasses} bg-green-100 border border-green-300 text-green-700`
        }
      >
        {status}
      </span>
    ) : (
      <span
        className={
          isDarkMode
            ? `${baseClasses} bg-yellow-900/30 border border-yellow-700 text-yellow-400`
            : `${baseClasses} bg-yellow-100 border border-yellow-300 text-yellow-700`
        }
      >
        {status}
      </span>
    );
  };

  const getCvssColor = (cvss) => {
    if (cvss >= 7) return isDarkMode ? "text-red-400" : "text-red-600";
    if (cvss >= 4) return isDarkMode ? "text-yellow-400" : "text-yellow-600";
    return isDarkMode ? "text-green-400" : "text-green-600";
  };

  const getSeverityFilterClasses = (severity) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return isDarkMode ? "text-red-400" : "text-red-600";
      case "high":
        return isDarkMode ? "text-orange-400" : "text-orange-600";
      case "medium":
        return isDarkMode ? "text-yellow-400" : "text-yellow-600";
      case "low":
        return isDarkMode ? "text-blue-400" : "text-blue-600";
      default:
        return isDarkMode ? "text-gray-400" : "text-gray-600";
    }
  };

  const getStats = () => {
    const critical = vulnerabilities.filter(
      (v) => (v.severity || '').toLowerCase() === "critical"
    ).length;
    const high = vulnerabilities.filter((v) => (v.severity || '').toLowerCase() === "high").length;
    const medium = vulnerabilities.filter(
      (v) => (v.severity || '').toLowerCase() === "medium"
    ).length;
    const low = vulnerabilities.filter((v) => (v.severity || '').toLowerCase() === "low").length;
    const open = vulnerabilities.filter((v) => (v.status || '').toLowerCase() === "open").length;

    return { critical, high, medium, low, open, total: vulnerabilities.length };
  };

  const stats = getStats();

  // Manual refresh handler
  const handleRefresh = async () => {
    setLoading(true);
    await fetchVulnerabilities();
  };

  return (
    <DashboardPageLayout>
      <div className="p-6">
      {/* Header with Refresh Button */}
      <div className="flex items-center justify-between mb-6">
        <h2
          className={
            isDarkMode
              ? "text-2xl font-bold text-white"
              : "text-2xl font-bold text-gray-900"
          }
        >
          Vulnerabilities
        </h2>
        <button
          onClick={handleRefresh}
          disabled={loading}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-all ${
            isDarkMode
              ? "bg-gray-800 border border-gray-700 text-gray-300 hover:bg-gray-700 disabled:opacity-50"
              : "bg-white border border-gray-200 text-gray-700 hover:bg-gray-50 shadow-sm disabled:opacity-50"
          }`}
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div
          className={
            isDarkMode
              ? "bg-gray-800 border border-gray-700 rounded-lg p-4 text-center"
              : "bg-white border border-gray-200 rounded-lg p-4 text-center shadow-sm"
          }
        >
          <div
            className={
              isDarkMode
                ? "text-sm text-gray-400 mb-1"
                : "text-sm text-gray-600 mb-1"
            }
          >
            Total Issues
          </div>
          <div
            className={
              isDarkMode
                ? "text-2xl font-bold text-white"
                : "text-2xl font-bold text-gray-900"
            }
          >
            {stats.total}
          </div>
        </div>
        <div
          className={
            isDarkMode
              ? "bg-gray-800 border border-gray-700 rounded-lg p-4 text-center"
              : "bg-white border border-gray-200 rounded-lg p-4 text-center shadow-sm"
          }
        >
          <div
            className={
              isDarkMode
                ? "text-sm text-gray-400 mb-1"
                : "text-sm text-gray-600 mb-1"
            }
          >
            Critical & High
          </div>
          <div
            className={
              isDarkMode
                ? "text-2xl font-bold text-white flex items-center justify-center gap-2"
                : "text-2xl font-bold text-gray-900 flex items-center justify-center gap-2"
            }
          >
            {stats.critical + stats.high}
            {stats.critical + stats.high > 0 && (
              <span
                className={
                  isDarkMode
                    ? "bg-red-900/30 border border-red-700 text-red-400 px-2 py-1 rounded text-xs font-medium"
                    : "bg-red-100 border border-red-300 text-red-700 px-2 py-1 rounded text-xs font-medium"
                }
              >
                Urgent
              </span>
            )}
          </div>
        </div>
        <div
          className={
            isDarkMode
              ? "bg-gray-800 border border-gray-700 rounded-lg p-4 text-center"
              : "bg-white border border-gray-200 rounded-lg p-4 text-center shadow-sm"
          }
        >
          <div
            className={
              isDarkMode
                ? "text-sm text-gray-400 mb-1"
                : "text-sm text-gray-600 mb-1"
            }
          >
            Open Issues
          </div>
          <div
            className={
              isDarkMode
                ? "text-2xl font-bold text-white flex items-center justify-center gap-2"
                : "text-2xl font-bold text-gray-900 flex items-center justify-center gap-2"
            }
          >
            {stats.open}
            {stats.open > 0 && (
              <span
                className={
                  isDarkMode
                    ? "bg-yellow-900/30 border border-yellow-700 text-yellow-400 px-2 py-1 rounded text-xs font-medium"
                    : "bg-yellow-100 border border-yellow-300 text-yellow-700 px-2 py-1 rounded text-xs font-medium"
                }
              >
                Action Required
              </span>
            )}
          </div>
        </div>
        <div
          className={
            isDarkMode
              ? "bg-gray-800 border border-gray-700 rounded-lg p-4 text-center"
              : "bg-white border border-gray-200 rounded-lg p-4 text-center shadow-sm"
          }
        >
          <div
            className={
              isDarkMode
                ? "text-sm text-gray-400 mb-1"
                : "text-sm text-gray-600 mb-1"
            }
          >
            Average CVSS
          </div>
          <div
            className={
              isDarkMode
                ? "text-2xl font-bold text-white"
                : "text-2xl font-bold text-gray-900"
            }
          >
            {vulnerabilities.length > 0
              ? (
                  vulnerabilities.reduce((sum, v) => sum + v.cvss, 0) /
                  vulnerabilities.length
                ).toFixed(1)
              : "--"}
          </div>
        </div>
      </div>

      {/* Filters */}
      <div
        className={
          isDarkMode
            ? "bg-gray-800 border border-gray-700 rounded-lg p-4 mb-6"
            : "bg-white border border-gray-200 rounded-lg p-4 mb-6 shadow-sm"
        }
      >
        <div className="flex flex-wrap gap-3 items-center">
          <span
            className={
              isDarkMode
                ? "bg-gray-700 border border-gray-600 text-gray-300 px-2 py-1 rounded text-xs font-medium"
                : "bg-gray-100 border border-gray-300 text-gray-600 px-2 py-1 rounded text-xs font-medium"
            }
          >
            Filter:
          </span>
          {filters.map((filter) => (
            <button
              key={filter}
              onClick={() => setActiveFilter(filter)}
              className={`px-3 py-2 rounded-md transition-colors text-sm font-medium border ${
                activeFilter === filter
                  ? "bg-blue-600 border-blue-500 text-white"
                  : isDarkMode
                  ? "bg-transparent border-gray-600 text-gray-300 hover:border-gray-500 hover:text-white"
                  : "bg-transparent border-gray-300 text-gray-700 hover:border-gray-400 hover:text-gray-900"
              }`}
            >
              <span
                className={
                  filter !== "All" ? getSeverityFilterClasses(filter) : ""
                }
              >
                {filter}
              </span>
              {filter !== "All" && (
                <span
                  className={
                    isDarkMode
                      ? "ml-1 text-xs text-gray-400"
                      : "ml-1 text-xs text-gray-500"
                  }
                >
                  ({vulnerabilities.filter((v) => v.severity === filter).length}
                  )
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Vulnerabilities Table */}
      <div
        className={
          isDarkMode
            ? "bg-gray-800 border border-gray-700 rounded-lg p-6"
            : "bg-white border border-gray-200 rounded-lg p-6 shadow-sm"
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr
                className={
                  isDarkMode
                    ? "border-b border-gray-700"
                    : "border-b border-gray-200"
                }
              >
                <th
                  className={
                    isDarkMode
                      ? "text-left text-gray-300 font-medium pb-3"
                      : "text-left text-gray-700 font-medium pb-3"
                  }
                >
                  Title
                </th>
                <th
                  className={
                    isDarkMode
                      ? "text-left text-gray-300 font-medium pb-3"
                      : "text-left text-gray-700 font-medium pb-3"
                  }
                >
                  Severity
                </th>
                <th
                  className={
                    isDarkMode
                      ? "text-left text-gray-300 font-medium pb-3"
                      : "text-left text-gray-700 font-medium pb-3"
                  }
                >
                  CVSS
                </th>
                <th
                  className={
                    isDarkMode
                      ? "text-left text-gray-300 font-medium pb-3"
                      : "text-left text-gray-700 font-medium pb-3"
                  }
                >
                  Affected
                </th>
                <th
                  className={
                    isDarkMode
                      ? "text-left text-gray-300 font-medium pb-3"
                      : "text-left text-gray-700 font-medium pb-3"
                  }
                >
                  Category
                </th>
                <th
                  className={
                    isDarkMode
                      ? "text-left text-gray-300 font-medium pb-3"
                      : "text-left text-gray-700 font-medium pb-3"
                  }
                >
                  Status
                </th>
                <th
                  className={
                    isDarkMode
                      ? "text-left text-gray-300 font-medium pb-3"
                      : "text-left text-gray-700 font-medium pb-3"
                  }
                >
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredVulnerabilities.map((vuln, index) => (
                <tr
                  key={vuln.id}
                  className={`${
                    index !== filteredVulnerabilities.length - 1
                      ? isDarkMode
                        ? "border-b border-gray-700"
                        : "border-b border-gray-200"
                      : ""
                  } ${
                    isDarkMode ? "hover:bg-gray-700/30" : "hover:bg-gray-50"
                  } transition-colors`}
                >
                  <td className="py-4 pr-4">
                    <div>
                      <div
                        className={
                          isDarkMode
                            ? "font-semibold text-white mb-1"
                            : "font-semibold text-gray-900 mb-1"
                        }
                      >
                        {vuln.title}
                      </div>
                      <div
                        className={
                          isDarkMode
                            ? "text-sm text-gray-400"
                            : "text-sm text-gray-600"
                        }
                      >
                        {vuln.description}
                      </div>
                    </div>
                  </td>
                  <td className="py-4 pr-4">
                    {getSeverityBadge(vuln.severity)}
                  </td>
                  <td className="py-4 pr-4">
                    <span className={`font-medium ${getCvssColor(vuln.cvss)}`}>
                      {vuln.cvss}
                    </span>
                  </td>
                  <td className="py-4 pr-4">
                    <code
                      className={
                        isDarkMode
                          ? "text-xs bg-gray-900 text-green-400 px-2 py-1 rounded"
                          : "text-xs bg-gray-100 border border-gray-300 text-green-700 px-2 py-1 rounded"
                      }
                    >
                      {vuln.affected}
                    </code>
                  </td>
                  <td
                    className={
                      isDarkMode
                        ? "py-4 pr-4 text-gray-300"
                        : "py-4 pr-4 text-gray-700"
                    }
                  >
                    {vuln.category}
                  </td>
                  <td className="py-4 pr-4">{getStatusBadge(vuln.status)}</td>
                  <td className="py-4">
                    <button
                      className={
                        isDarkMode
                          ? "bg-gray-600 hover:bg-gray-700 text-white px-3 py-1 rounded text-sm transition-colors"
                          : "bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm transition-colors shadow-sm"
                      }
                      onClick={() =>
                        navigate(`/dashboard/vulnerability/${vuln.id}`, {
                          state: { vulnerability: vuln },
                        })
                      }
                    >
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredVulnerabilities.length === 0 && (
          <div className="text-center py-10">
            <div className="text-5xl mb-4"><Search className="w-12 h-12 mx-auto text-gray-400" /></div>
            <h3
              className={
                isDarkMode
                  ? "text-gray-400 text-lg font-medium mb-2"
                  : "text-gray-600 text-lg font-medium mb-2"
              }
            >
              No vulnerabilities found
            </h3>
            <p
              className={
                isDarkMode ? "text-sm text-gray-500" : "text-sm text-gray-500"
              }
            >
              No issues match the selected filter "{activeFilter}". Try
              selecting a different severity level.
            </p>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
        <div
          className={
            isDarkMode
              ? "bg-gray-800 border border-gray-700 rounded-lg p-6"
              : "bg-white border border-gray-200 rounded-lg p-6 shadow-sm"
          }
        >
          <h3
            className={
              isDarkMode
                ? "text-xl font-semibold text-white mb-2"
                : "text-xl font-semibold text-gray-900 mb-2"
            }
          >
            Remediation Priority
          </h3>
          <p
            className={
              isDarkMode
                ? "text-sm text-gray-400 mb-4"
                : "text-sm text-gray-600 mb-4"
            }
          >
            Focus on these high-impact vulnerabilities first:
          </p>
          <div className="space-y-0">
            {vulnerabilities
              .filter((v) => v.severity === "Critical" || v.severity === "High")
              .slice(0, 3)
              .map((vuln, index) => (
                <div
                  key={vuln.id}
                  className={`py-3 flex justify-between items-center ${
                    index < 2
                      ? isDarkMode
                        ? "border-b border-gray-700"
                        : "border-b border-gray-200"
                      : ""
                  }`}
                >
                  <div>
                    <div
                      className={
                        isDarkMode
                          ? "text-sm font-semibold text-white"
                          : "text-sm font-semibold text-gray-900"
                      }
                    >
                      {vuln.title}
                    </div>
                    <div
                      className={
                        isDarkMode
                          ? "text-xs text-gray-400"
                          : "text-xs text-gray-600"
                      }
                    >
                      CVSS {vuln.cvss} * {vuln.category}
                    </div>
                  </div>
                  {getSeverityBadge(vuln.severity)}
                </div>
              ))}
          </div>
          <button
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md w-full mt-4 transition-colors shadow-sm"
            onClick={() => navigate("/dashboard/chatbot")}
          >
            <MessageSquare className="w-4 h-4 inline mr-1" /> Get Remediation Help
          </button>
        </div>

        <div
          className={
            isDarkMode
              ? "bg-gray-800 border border-gray-700 rounded-lg p-6"
              : "bg-white border border-gray-200 rounded-lg p-6 shadow-sm"
          }
        >
          <h3
            className={
              isDarkMode
                ? "text-xl font-semibold text-white mb-2"
                : "text-xl font-semibold text-gray-900 mb-2"
            }
          >
            Export & Reports
          </h3>
          <p
            className={
              isDarkMode
                ? "text-sm text-gray-400 mb-4"
                : "text-sm text-gray-600 mb-4"
            }
          >
            Generate reports for your security team or compliance.
          </p>
          <div className="space-y-2">
            <button
              className={
                isDarkMode
                  ? "bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md w-full text-sm transition-colors"
                  : "bg-gray-100 border border-gray-300 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-md w-full text-sm transition-colors"
              }
            >
              <BarChart3 className="w-4 h-4 inline mr-1" /> Executive Summary
            </button>
            <button
              className={
                isDarkMode
                  ? "bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md w-full text-sm transition-colors"
                  : "bg-gray-100 border border-gray-300 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-md w-full text-sm transition-colors"
              }
            >
              <List className="w-4 h-4 inline mr-1" /> Technical Report
            </button>
            <button
              className={
                isDarkMode
                  ? "bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md w-full text-sm transition-colors"
                  : "bg-gray-100 border border-gray-300 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-md w-full text-sm transition-colors"
              }
            >
              <FileText className="w-4 h-4 inline mr-1" /> CSV Export
            </button>
            <button
              className={
                isDarkMode
                  ? "bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-md w-full text-sm transition-colors"
                  : "bg-gray-100 border border-gray-300 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-md w-full text-sm transition-colors"
              }
            >
              <Lock className="w-4 h-4 inline mr-1" /> SARIF Export
            </button>
          </div>
        </div>
      </div>

      {/* Vulnerability Trends */}
      <div
        className={
          isDarkMode
            ? "bg-gray-800 border border-gray-700 rounded-lg p-6 mt-6"
            : "bg-white border border-gray-200 rounded-lg p-6 mt-6 shadow-sm"
        }
      >
        <h3
          className={
            isDarkMode
              ? "text-xl font-semibold text-white mb-4"
              : "text-xl font-semibold text-gray-900 mb-4"
          }
        >
          Vulnerability Trends
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center">
            <div
              className={
                isDarkMode
                  ? "text-2xl font-bold text-red-400 mb-1"
                  : "text-2xl font-bold text-red-600 mb-1"
              }
            >
              +3
            </div>
            <div
              className={
                isDarkMode ? "text-sm text-gray-400" : "text-sm text-gray-600"
              }
            >
              New this week
            </div>
          </div>
          <div className="text-center">
            <div
              className={
                isDarkMode
                  ? "text-2xl font-bold text-green-400 mb-1"
                  : "text-2xl font-bold text-green-600 mb-1"
              }
            >
              -1
            </div>
            <div
              className={
                isDarkMode ? "text-sm text-gray-400" : "text-sm text-gray-600"
              }
            >
              Resolved this week
            </div>
          </div>
          <div className="text-center">
            <div
              className={
                isDarkMode
                  ? "text-2xl font-bold text-yellow-400 mb-1"
                  : "text-2xl font-bold text-yellow-600 mb-1"
              }
            >
              5.2
            </div>
            <div
              className={
                isDarkMode ? "text-sm text-gray-400" : "text-sm text-gray-600"
              }
            >
              Avg. resolution time (days)
            </div>
          </div>
        </div>
      </div>
      </div>
    </DashboardPageLayout>
  );
};

export default Vulnerabilities;
