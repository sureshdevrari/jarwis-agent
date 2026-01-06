// src/components/scan/ScanHistory.jsx
// Scan history component with filtering, sorting, and real-time updates
import { useState, useEffect, useCallback } from "react";
import { useTheme } from "../../context/ThemeContext";
import { scanAPI } from "../../services/api";

const ScanHistory = ({ onViewScan, onResumeScan, onNewScan, currentScanId }) => {
  const { isDarkMode } = useTheme();
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState({ total: 0, web: 0, mobile: 0, cloud: 0, running: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [typeFilter, setTypeFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState("date_desc");

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const data = await scanAPI.listScans({
        type: typeFilter,
        status: statusFilter,
        search: searchQuery,
      });

      if (data.scans) {
        setScans(data.scans);
        setStats(data.stats || { total: 0, web: 0, mobile: 0, cloud: 0, running: 0 });
      } else if (Array.isArray(data)) {
        setScans(data);
      }
    } catch (err) {
      console.error("Failed to load scans:", err);
      setError("Failed to load scan history");
    } finally {
      setLoading(false);
    }
  }, [typeFilter, statusFilter, searchQuery]);

  useEffect(() => {
    fetchScans();
    // Auto-refresh every 30 seconds for running scans (reduced from 5s)
    const interval = setInterval(fetchScans, 30000);
    return () => clearInterval(interval);
  }, [fetchScans]);

  // Sort and paginate scans
  const getAllScans = () => {
    let allScans = [...scans];

    allScans.sort((a, b) => {
      const dateA = new Date(a.started_at || a.start_time || 0);
      const dateB = new Date(b.started_at || b.start_time || 0);

      switch (sortBy) {
        case "date_asc":
          return dateA - dateB;
        case "status":
          return (a.status || "").localeCompare(b.status || "");
        case "severity":
          const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          const aMax = a.findings?.reduce((max, f) => Math.min(max, sevOrder[f.severity] ?? 5), 5) ?? 5;
          const bMax = b.findings?.reduce((max, f) => Math.min(max, sevOrder[f.severity] ?? 5), 5) ?? 5;
          return aMax - bMax;
        case "date_desc":
        default:
          return dateB - dateA;
      }
    });

    return allScans;
  };

  const filteredScans = getAllScans();
  const totalPages = Math.ceil(filteredScans.length / itemsPerPage);
  const paginatedScans = filteredScans.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  const displayStats = {
    total: stats.total || scans.length,
    web: stats.web || 0,
    mobile: stats.mobile || 0,
    cloud: stats.cloud || 0,
    running: stats.running || 0,
    completed: stats.completed || 0,
    failed: stats.error || 0,
  };

  const getScanIcon = (scan) => {
    switch (scan.type || scan.scan_type) {
      case "mobile":
        return "[MOBILE]";
      case "cloud":
        return "";
      case "web":
      default:
        return "[WEB]";
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case "completed":
        return "[OK]";
      case "running":
        return "";
      case "error":
        return "[X]";
      case "stopped":
        return "⏹";
      case "queued":
        return "[WAIT]";
      default:
        return "";
    }
  };

  const getStatusBadge = (status) => {
    const colors = {
      completed: isDarkMode ? "bg-green-900/30 text-green-400 border-green-700" : "bg-green-100 text-green-700 border-green-300",
      running: isDarkMode ? "bg-blue-900/30 text-blue-400 border-blue-700" : "bg-blue-100 text-blue-700 border-blue-300",
      error: isDarkMode ? "bg-red-900/30 text-red-400 border-red-700" : "bg-red-100 text-red-700 border-red-300",
      stopped: isDarkMode ? "bg-gray-700/30 text-gray-400 border-gray-600" : "bg-gray-100 text-gray-600 border-gray-300",
      queued: isDarkMode ? "bg-yellow-900/30 text-yellow-400 border-yellow-700" : "bg-yellow-100 text-yellow-700 border-yellow-300",
    };
    return colors[status] || colors.queued;
  };

  const getSeverityBadges = (scan) => {
    const results = scan.results || {};
    const badges = [];
    if (results.critical > 0) badges.push({ label: "CRITICAL", count: results.critical, color: "bg-red-500/20 text-red-400" });
    if (results.high > 0) badges.push({ label: "HIGH", count: results.high, color: "bg-orange-500/20 text-orange-400" });
    if (results.medium > 0) badges.push({ label: "MEDIUM", count: results.medium, color: "bg-yellow-500/20 text-yellow-400" });
    if (results.low > 0) badges.push({ label: "LOW", count: results.low, color: "bg-blue-500/20 text-blue-400" });
    return badges;
  };

  const formatDuration = (startedAt, completedAt) => {
    if (!startedAt) return "-";
    const start = new Date(startedAt);
    const end = completedAt ? new Date(completedAt) : new Date();
    const diff = Math.floor((end - start) / 1000);
    if (diff < 60) return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
    return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return "-";
    const date = new Date(dateStr);
    return date.toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  };

  // Theme classes
  const cardClass = isDarkMode
    ? "bg-slate-800/50 border border-slate-700/50 rounded-xl"
    : "bg-white border border-gray-200 rounded-xl shadow-sm";

  const inputClass = isDarkMode
    ? "px-4 py-2 bg-slate-800/50 border border-slate-700/50 rounded-lg text-white placeholder-gray-400 focus:border-blue-500/50 focus:ring-2 focus:ring-blue-500/20 outline-none transition-all"
    : "px-4 py-2 bg-white border border-gray-300 rounded-lg text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 outline-none transition-all shadow-sm";

  if (loading && scans.length === 0) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>Loading scan history...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`${cardClass} p-6 text-center`}>
        <p className="text-red-400 mb-4">[X] {error}</p>
        <button
          onClick={fetchScans}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
        >
           Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats Overview */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        {[
          { label: "Total", value: displayStats.total, icon: "[CHART]" },
          { label: "Web", value: displayStats.web, icon: "[WEB]" },
          { label: "Mobile", value: displayStats.mobile, icon: "[MOBILE]" },
          { label: "Cloud", value: displayStats.cloud, icon: "" },
          { label: "Running", value: displayStats.running, icon: "", highlight: true },
          { label: "Completed", value: displayStats.completed, icon: "[OK]" },
          { label: "Failed", value: displayStats.failed, icon: "[X]" },
        ].map((stat) => (
          <div
            key={stat.label}
            className={`${cardClass} p-4 text-center ${stat.highlight && stat.value > 0 ? "border-blue-500/50" : ""}`}
          >
            <div className="text-xl mb-1">{stat.icon}</div>
            <div className={`text-2xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>{stat.value}</div>
            <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className={`${cardClass} p-4`}>
        <div className="flex flex-wrap gap-4">
          <input
            type="text"
            placeholder="Search scans..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className={`${inputClass} flex-1 min-w-[200px]`}
          />
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className={inputClass}>
            <option value="all">All Types</option>
            <option value="web">Web</option>
            <option value="mobile">Mobile</option>
            <option value="cloud">Cloud</option>
          </select>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className={inputClass}>
            <option value="all">All Status</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="error">Error</option>
            <option value="stopped">Stopped</option>
          </select>
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value)} className={inputClass}>
            <option value="date_desc">Newest First</option>
            <option value="date_asc">Oldest First</option>
            <option value="status">By Status</option>
            <option value="severity">By Severity</option>
          </select>
          {onNewScan && (
            <button
              onClick={onNewScan}
              className="px-4 py-2 bg-gradient-to-r from-blue-600 to-blue-500 text-white rounded-lg hover:from-blue-500 hover:to-blue-400 transition-all font-medium"
            >
              + New Scan
            </button>
          )}
        </div>
      </div>

      {/* Scan List */}
      {paginatedScans.length === 0 ? (
        <div className={`${cardClass} p-12 text-center`}>
          <div className="text-4xl mb-4">[SEARCH]</div>
          <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>No scans found</p>
          {onNewScan && (
            <button
              onClick={onNewScan}
              className="mt-4 px-6 py-3 bg-gradient-to-r from-blue-600 to-blue-500 text-white rounded-lg hover:from-blue-500 hover:to-blue-400 transition-all font-medium"
            >
              Start Your First Scan
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {paginatedScans.map((scan) => (
            <div
              key={scan.id || scan.scan_id}
              className={`${cardClass} p-4 hover:border-blue-500/30 transition-all cursor-pointer ${
                currentScanId === (scan.id || scan.scan_id) ? "border-blue-500" : ""
              }`}
              onClick={() => onViewScan && onViewScan(scan)}
            >
              <div className="flex items-center justify-between flex-wrap gap-4">
                <div className="flex items-center gap-4">
                  <div className="text-3xl">{getScanIcon(scan)}</div>
                  <div>
                    <div className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                      {scan.target_url || scan.target || scan.app_name || "Unknown Target"}
                    </div>
                    <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>
                      {scan.type || scan.scan_type || "web"} * {formatDate(scan.started_at || scan.start_time)}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3 flex-wrap">
                  {/* Severity badges */}
                  {getSeverityBadges(scan).map((badge) => (
                    <span key={badge.label} className={`px-2 py-1 rounded text-xs font-medium ${badge.color}`}>
                      {badge.count} {badge.label}
                    </span>
                  ))}

                  {/* Status badge */}
                  <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getStatusBadge(scan.status)}`}>
                    {getStatusIcon(scan.status)} {scan.status || "unknown"}
                  </span>

                  {/* Duration */}
                  <span className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>
                    ⏱ {formatDuration(scan.started_at || scan.start_time, scan.completed_at || scan.end_time)}
                  </span>

                  {/* Actions */}
                  {scan.status === "running" && onViewScan && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onViewScan(scan);
                      }}
                      className="px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm transition-colors"
                    >
                      View Live
                    </button>
                  )}
                  {scan.status === "completed" && (
                    <>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          window.open(scanAPI.getReportUrl(scan.id || scan.scan_id), "_blank");
                        }}
                        className="px-3 py-1 bg-green-600 hover:bg-green-500 text-white rounded text-sm transition-colors"
                      >
                        [DOC] Report
                      </button>
                      <button
                        onClick={async (e) => {
                          e.stopPropagation();
                          try {
                            const pdfUrl = scanAPI.getReportPdfUrl(scan.id || scan.scan_id);
                            window.open(pdfUrl, "_blank");
                          } catch (err) {
                            console.error("PDF download failed:", err);
                            alert("PDF download failed. Please try again.");
                          }
                        }}
                        className="px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm transition-colors"
                        title="Download PDF Report"
                      >
                        [RECEIVE] PDF
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2">
          <button
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className={`px-4 py-2 rounded-lg transition-colors ${
              currentPage === 1
                ? "opacity-50 cursor-not-allowed"
                : isDarkMode
                ? "bg-slate-700 hover:bg-slate-600 text-white"
                : "bg-gray-200 hover:bg-gray-300 text-gray-900"
            }`}
          >
            &larr; Previous
          </button>
          <span className={`px-4 py-2 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
            Page {currentPage} of {totalPages}
          </span>
          <button
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
            className={`px-4 py-2 rounded-lg transition-colors ${
              currentPage === totalPages
                ? "opacity-50 cursor-not-allowed"
                : isDarkMode
                ? "bg-slate-700 hover:bg-slate-600 text-white"
                : "bg-gray-200 hover:bg-gray-300 text-gray-900"
            }`}
          >
            Next &rarr;
          </button>
        </div>
      )}
    </div>
  );
};

export default ScanHistory;
