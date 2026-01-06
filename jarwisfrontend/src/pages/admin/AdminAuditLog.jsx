import { useState } from "react";
import MiftyAdminLayout from "../../components/layout/MiftyAdminLayout";
import { useTheme } from "../../context/ThemeContext";

const AdminAuditLog = () => {
  const { isDarkMode } = useTheme();

  const [filter, setFilter] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [viewMode, setViewMode] = useState("table"); // "table" or "cards"

  // Audit logs will be fetched from API in future implementation
  const auditLogs = [];

  const filteredLogs = auditLogs.filter((log) => {
    const matchesFilter = filter === "all" || log.type === filter;
    const matchesSearch =
      searchTerm === "" ||
      log.actor.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.object.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.details.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const getActionIcon = (action) => {
    switch (action) {
      case "Scan Completed":
      case "Scan Started":
        return "[SEARCH]";
      case "User Approved":
      case "User Rejected":
        return "";
      case "Vuln Pushed":
        return "";
      case "Backup Completed":
        return "";
      default:
        return "[LIST]";
    }
  };

  const getActionColor = (action, isDark) => {
    const colors = {
      "Scan Completed": isDark ? "text-green-400" : "text-green-600",
      "Scan Started": isDark ? "text-blue-400" : "text-blue-600",
      "User Approved": isDark ? "text-green-400" : "text-green-600",
      "User Rejected": isDark ? "text-red-400" : "text-red-600",
      "Vuln Pushed": isDark ? "text-amber-400" : "text-amber-600",
      "Backup Completed": isDark ? "text-purple-400" : "text-purple-600",
    };
    return colors[action] || (isDark ? "text-gray-400" : "text-gray-600");
  };

  const getTypeBadgeColor = (type) => {
    const colors = {
      scan: isDarkMode
        ? "bg-blue-900/30 border-blue-500/30 text-blue-300"
        : "bg-blue-100 border-blue-300 text-blue-800",
      user: isDarkMode
        ? "bg-green-900/30 border-green-500/30 text-green-300"
        : "bg-green-100 border-green-300 text-green-800",
      vulnerability: isDarkMode
        ? "bg-amber-900/30 border-amber-500/30 text-amber-300"
        : "bg-amber-100 border-amber-300 text-amber-800",
      system: isDarkMode
        ? "bg-purple-900/30 border-purple-500/30 text-purple-300"
        : "bg-purple-100 border-purple-300 text-purple-800",
    };
    return colors[type] || (isDarkMode ? "bg-gray-900/30 border-gray-500/30 text-gray-300" : "bg-gray-100 border-gray-300 text-gray-800");
  };

  // Theme-based classes
  const contentThemes = {
    card: isDarkMode
      ? "bg-gradient-to-br from-slate-800/40 to-slate-900/40 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-4 sm:p-6 shadow-2xl"
      : "bg-white/90 backdrop-blur-xl border border-gray-200 rounded-2xl p-4 sm:p-6 shadow-xl",

    filterBar: isDarkMode
      ? "flex flex-col gap-3 sm:gap-4 mb-6 p-3 sm:p-4 bg-slate-800/30 border border-slate-700/50 rounded-xl"
      : "flex flex-col gap-3 sm:gap-4 mb-6 p-3 sm:p-4 bg-gray-50 border border-gray-200 rounded-xl",

    searchInput: isDarkMode
      ? "flex-1 px-3 sm:px-4 py-2 sm:py-3 bg-slate-800/50 border border-slate-700/50 rounded-lg text-sm sm:text-base text-gray-100 placeholder-gray-400 focus:border-blue-500/50 focus:outline-none focus:ring-2 focus:ring-blue-500/20 transition-all duration-200"
      : "flex-1 px-3 sm:px-4 py-2 sm:py-3 bg-white border border-gray-300 rounded-lg text-sm sm:text-base text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20 transition-all duration-200",

    filterSelect: isDarkMode
      ? "px-3 sm:px-4 py-2 sm:py-3 bg-slate-800/50 border border-slate-700/50 rounded-lg text-sm sm:text-base text-gray-100 focus:border-blue-500/50 focus:outline-none focus:ring-2 focus:ring-blue-500/20 transition-all duration-200"
      : "px-3 sm:px-4 py-2 sm:py-3 bg-white border border-gray-300 rounded-lg text-sm sm:text-base text-gray-900 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20 transition-all duration-200",

    table: "w-full border-collapse min-w-full",

    tableHeader: isDarkMode
      ? "border-b border-slate-700/50 pb-2 sm:pb-3 text-left text-xs sm:text-sm font-semibold text-gray-300 uppercase tracking-wider px-2 sm:px-4"
      : "border-b border-gray-200 pb-2 sm:pb-3 text-left text-xs sm:text-sm font-semibold text-gray-700 uppercase tracking-wider px-2 sm:px-4",

    tableRow: isDarkMode
      ? "border-b border-slate-700/30 hover:bg-slate-800/30 transition-colors duration-200"
      : "border-b border-gray-100 hover:bg-gray-50/80 transition-colors duration-200",

    tableCell: isDarkMode
      ? "py-3 sm:py-4 px-2 sm:px-4 text-xs sm:text-sm text-gray-300"
      : "py-3 sm:py-4 px-2 sm:px-4 text-xs sm:text-sm text-gray-700",

    timestampCell: isDarkMode
      ? "py-3 sm:py-4 px-2 sm:px-4 text-xs sm:text-sm text-gray-400 font-mono"
      : "py-3 sm:py-4 px-2 sm:px-4 text-xs sm:text-sm text-gray-500 font-mono",

    actorBadge: isDarkMode
      ? "inline-flex items-center px-2 py-1 text-xs font-medium text-blue-300 bg-blue-900/30 border border-blue-500/30 rounded-full"
      : "inline-flex items-center px-2 py-1 text-xs font-medium text-blue-800 bg-blue-100 border border-blue-300 rounded-full",

    objectCode: isDarkMode
      ? "px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs font-mono break-all"
      : "px-2 py-1 bg-gray-100 border border-gray-300 rounded text-xs font-mono break-all",

    // Card view styles
    logCard: isDarkMode
      ? "bg-gradient-to-br from-slate-800/60 to-slate-900/60 backdrop-blur-xl border border-slate-700/50 rounded-xl p-4 shadow-lg"
      : "bg-white/80 backdrop-blur-xl border border-gray-200 rounded-xl p-4 shadow-md",

    cardLabel: isDarkMode
      ? "text-xs font-medium text-gray-400 uppercase tracking-wider"
      : "text-xs font-medium text-gray-600 uppercase tracking-wider",

    cardValue: isDarkMode
      ? "text-sm font-medium text-gray-200 mt-1"
      : "text-sm font-medium text-gray-800 mt-1",

    viewToggleButton: (isActive) =>
      isDarkMode
        ? `px-3 py-2 text-xs font-medium rounded-lg transition-all duration-200 ${
            isActive
              ? "bg-red-600/20 text-red-300 border border-red-500/30"
              : "text-gray-400 hover:text-gray-300 hover:bg-slate-800/50"
          }`
        : `px-3 py-2 text-xs font-medium rounded-lg transition-all duration-200 ${
            isActive
              ? "bg-red-100 text-red-800 border border-red-300"
              : "text-gray-600 hover:text-gray-800 hover:bg-gray-100"
          }`,

    statCard: isDarkMode
      ? "bg-gradient-to-br from-slate-800/60 to-slate-900/60 backdrop-blur-xl border border-slate-700/50 rounded-xl p-4 text-center"
      : "bg-white/80 backdrop-blur-xl border border-gray-200 rounded-xl p-4 text-center shadow-md",
  };

  // Card component for mobile view
  const LogCard = ({ log }) => (
    <div className={contentThemes.logCard}>
      <div className="space-y-3">
        {/* Header with action and timestamp */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <span className="text-lg">{getActionIcon(log.action)}</span>
            <span className={`font-semibold ${getActionColor(log.action, isDarkMode)}`}>
              {log.action}
            </span>
            <span className={`inline-flex items-center px-2 py-1 text-xs font-medium border rounded-full ${getTypeBadgeColor(log.type)}`}>
              {log.type}
            </span>
          </div>
          <span className={isDarkMode ? "text-xs text-gray-500 font-mono mt-1 sm:mt-0" : "text-xs text-gray-500 font-mono mt-1 sm:mt-0"}>
            {log.timestamp}
          </span>
        </div>

        {/* Details grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <div className={contentThemes.cardLabel}>Actor</div>
            <span className={contentThemes.actorBadge}>{log.actor}</span>
          </div>
          <div>
            <div className={contentThemes.cardLabel}>Object</div>
            <code className={contentThemes.objectCode}>{log.object}</code>
          </div>
        </div>

        {/* Details */}
        <div>
          <div className={contentThemes.cardLabel}>Details</div>
          <div className={contentThemes.cardValue}>{log.details}</div>
        </div>
      </div>
    </div>
  );

  return (
    <MiftyAdminLayout>
      <div className="space-y-6 sm:space-y-8 p-6">
        {/* Page Header */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h1 className={isDarkMode ? "text-2xl sm:text-3xl font-bold text-gray-100" : "text-2xl sm:text-3xl font-bold text-gray-900"}>
              Audit Log
            </h1>
            <p className={isDarkMode ? "text-gray-400 mt-1 sm:mt-2 text-sm sm:text-base" : "text-gray-600 mt-1 sm:mt-2 text-sm sm:text-base"}>
              Track all system activities and administrative actions
            </p>
          </div>

          {/* View Toggle - Only show when there are logs */}
          {filteredLogs.length > 0 && (
            <div className="flex bg-gray-100 dark:bg-slate-800/50 rounded-lg p-1">
              <button
                onClick={() => setViewMode("table")}
                className={contentThemes.viewToggleButton(viewMode === "table")}
              >
                [CHART] Table
              </button>
              <button
                onClick={() => setViewMode("cards")}
                className={contentThemes.viewToggleButton(viewMode === "cards")}
              >
                🃏 Cards
              </button>
            </div>
          )}
        </div>

        {/* Filters */}
        <div className={contentThemes.filterBar}>
          <div className="flex flex-col sm:flex-row gap-3 sm:gap-4">
            <div className="flex-1">
              <input
                type="text"
                placeholder="Search logs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className={contentThemes.searchInput}
              />
            </div>
            <div className="sm:w-48">
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className={contentThemes.filterSelect}
              >
                <option value="all">All Types</option>
                <option value="scan">Scans</option>
                <option value="user">User Actions</option>
                <option value="vulnerability">Vulnerabilities</option>
                <option value="system">System</option>
              </select>
            </div>
          </div>
        </div>

        {/* Audit Content */}
        <div className={contentThemes.card}>
          {filteredLogs.length === 0 ? (
            /* Empty State */
            <div className="text-center py-8 sm:py-12">
              <div className="text-4xl sm:text-6xl mb-4"></div>
              <h3 className={isDarkMode ? "text-lg sm:text-xl font-semibold text-gray-100 mb-2" : "text-lg sm:text-xl font-semibold text-gray-900 mb-2"}>
                No Logs Found
              </h3>
              <p className={isDarkMode ? "text-sm sm:text-base text-gray-400" : "text-sm sm:text-base text-gray-600"}>
                Try adjusting your search or filter criteria
              </p>
            </div>
          ) : viewMode === "cards" ? (
            /* Card View - Better for mobile */
            <div className="space-y-4">
              <div className="flex items-center justify-between mb-4">
                <h3 className={isDarkMode ? "text-lg font-semibold text-gray-100" : "text-lg font-semibold text-gray-900"}>
                  {filteredLogs.length} Log Entr{filteredLogs.length !== 1 ? 'ies' : 'y'}
                </h3>
              </div>
              <div className="space-y-4">
                {filteredLogs.map((log) => (
                  <LogCard key={log.id} log={log} />
                ))}
              </div>
            </div>
          ) : (
            /* Table View */
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className={isDarkMode ? "text-lg font-semibold text-gray-100" : "text-lg font-semibold text-gray-900"}>
                  {filteredLogs.length} Log Entr{filteredLogs.length !== 1 ? 'ies' : 'y'}
                </h3>
              </div>

              {/* Desktop Table */}
              <div className="hidden lg:block overflow-x-auto">
                <table className={contentThemes.table}>
                  <thead>
                    <tr>
                      <th className={contentThemes.tableHeader}>Timestamp</th>
                      <th className={contentThemes.tableHeader}>Actor</th>
                      <th className={contentThemes.tableHeader}>Action</th>
                      <th className={contentThemes.tableHeader}>Object</th>
                      <th className={contentThemes.tableHeader}>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLogs.map((log) => (
                      <tr key={log.id} className={contentThemes.tableRow}>
                        <td className={contentThemes.timestampCell}>
                          {log.timestamp}
                        </td>
                        <td className={contentThemes.tableCell}>
                          <span className={contentThemes.actorBadge}>
                            {log.actor}
                          </span>
                        </td>
                        <td className={contentThemes.tableCell}>
                          <div className="flex items-center gap-2">
                            <span className="text-lg">
                              {getActionIcon(log.action)}
                            </span>
                            <span className={getActionColor(log.action, isDarkMode)}>
                              {log.action}
                            </span>
                          </div>
                        </td>
                        <td className={contentThemes.tableCell}>
                          <code className={contentThemes.objectCode}>
                            {log.object}
                          </code>
                        </td>
                        <td className={contentThemes.tableCell}>{log.details}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Mobile/Tablet Simplified Table */}
              <div className="block lg:hidden overflow-x-auto">
                <table className={contentThemes.table}>
                  <thead>
                    <tr>
                      <th className={contentThemes.tableHeader}>Event</th>
                      <th className={contentThemes.tableHeader}>Details</th>
                      <th className={contentThemes.tableHeader}>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLogs.map((log) => (
                      <tr key={log.id} className={contentThemes.tableRow}>
                        <td className={contentThemes.tableCell}>
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="text-base">{getActionIcon(log.action)}</span>
                              <span className={`font-medium ${getActionColor(log.action, isDarkMode)}`}>
                                {log.action}
                              </span>
                            </div>
                            <span className={contentThemes.actorBadge}>
                              {log.actor}
                            </span>
                          </div>
                        </td>
                        <td className={contentThemes.tableCell}>
                          <div className="space-y-1">
                            <code className={contentThemes.objectCode}>
                              {log.object}
                            </code>
                            <div className="text-xs opacity-75">{log.details}</div>
                          </div>
                        </td>
                        <td className={contentThemes.tableCell}>
                          <div className="text-xs font-mono">
                            {log.timestamp.split(' ')[1]}
                            <br />
                            <span className="opacity-75">
                              {log.timestamp.split(' ')[0]}
                            </span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
          <div className={contentThemes.statCard}>
            <div className={isDarkMode ? "text-xl sm:text-2xl font-bold text-blue-400" : "text-xl sm:text-2xl font-bold text-blue-600"}>
              {auditLogs.filter((log) => log.type === "scan").length}
            </div>
            <div className={isDarkMode ? "text-gray-400 text-xs sm:text-sm mt-1" : "text-gray-600 text-xs sm:text-sm mt-1"}>
              Scan Events
            </div>
          </div>
          <div className={contentThemes.statCard}>
            <div className={isDarkMode ? "text-xl sm:text-2xl font-bold text-green-400" : "text-xl sm:text-2xl font-bold text-green-600"}>
              {auditLogs.filter((log) => log.type === "user").length}
            </div>
            <div className={isDarkMode ? "text-gray-400 text-xs sm:text-sm mt-1" : "text-gray-600 text-xs sm:text-sm mt-1"}>
              User Actions
            </div>
          </div>
          <div className={contentThemes.statCard}>
            <div className={isDarkMode ? "text-xl sm:text-2xl font-bold text-amber-400" : "text-xl sm:text-2xl font-bold text-amber-600"}>
              {auditLogs.filter((log) => log.type === "vulnerability").length}
            </div>
            <div className={isDarkMode ? "text-gray-400 text-xs sm:text-sm mt-1" : "text-gray-600 text-xs sm:text-sm mt-1"}>
              Vuln Events
            </div>
          </div>
          <div className={contentThemes.statCard}>
            <div className={isDarkMode ? "text-xl sm:text-2xl font-bold text-purple-400" : "text-xl sm:text-2xl font-bold text-purple-600"}>
              {auditLogs.filter((log) => log.type === "system").length}
            </div>
            <div className={isDarkMode ? "text-gray-400 text-xs sm:text-sm mt-1" : "text-gray-600 text-xs sm:text-sm mt-1"}>
              System Events
            </div>
          </div>
        </div>
      </div>
    </MiftyAdminLayout>
  );
};

export default AdminAuditLog;