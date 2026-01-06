import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import MiftyAdminLayout from "../../components/layout/MiftyAdminLayout";
import { useTheme } from "../../context/ThemeContext";

const AdminUserDetails = () => {
  const navigate = useNavigate();
  const { userId } = useParams();
  const { isDarkMode } = useTheme();
  const [viewMode, setViewMode] = useState("table"); // "table" or "cards"

  // User data will be fetched from API based on userId in future implementation
  const userData = {
    id: userId,
    name: "",
    email: "",
    company: "",
    domain: "",
    subscription: "",
    totalScans: 0,
    openVulns: 0,
    critical: 0,
    lastScan: "--",
    joinedDate: "--",
    lastLogin: "--",
  };

  // Vulnerabilities will be fetched from API in future implementation
  const vulnerabilities = [];

  const getSeverityBadge = (severity) => {
    const baseClasses =
      "inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full";

    if (isDarkMode) {
      switch (severity) {
        case "Critical":
          return `${baseClasses} text-red-300 bg-red-900/30 border border-red-500/30`;
        case "High":
          return `${baseClasses} text-orange-300 bg-orange-900/30 border border-orange-500/30`;
        case "Medium":
          return `${baseClasses} text-amber-300 bg-amber-900/30 border border-amber-500/30`;
        case "Low":
          return `${baseClasses} text-green-300 bg-green-900/30 border border-green-500/30`;
        default:
          return `${baseClasses} text-gray-300 bg-gray-900/30 border border-gray-500/30`;
      }
    } else {
      switch (severity) {
        case "Critical":
          return `${baseClasses} text-red-800 bg-red-100 border border-red-300`;
        case "High":
          return `${baseClasses} text-orange-800 bg-orange-100 border border-orange-300`;
        case "Medium":
          return `${baseClasses} text-amber-800 bg-amber-100 border border-amber-300`;
        case "Low":
          return `${baseClasses} text-green-800 bg-green-100 border border-green-300`;
        default:
          return `${baseClasses} text-gray-800 bg-gray-100 border border-gray-300`;
      }
    }
  };

  const getStatusBadge = (status) => {
    const baseClasses =
      "inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full";

    if (isDarkMode) {
      switch (status) {
        case "Open":
          return `${baseClasses} text-amber-300 bg-amber-900/30 border border-amber-500/30`;
        case "Mitigated":
          return `${baseClasses} text-green-300 bg-green-900/30 border border-green-500/30`;
        case "In Progress":
          return `${baseClasses} text-blue-300 bg-blue-900/30 border border-blue-500/30`;
        default:
          return `${baseClasses} text-gray-300 bg-gray-900/30 border border-gray-500/30`;
      }
    } else {
      switch (status) {
        case "Open":
          return `${baseClasses} text-amber-800 bg-amber-100 border border-amber-300`;
        case "Mitigated":
          return `${baseClasses} text-green-800 bg-green-100 border border-green-300`;
        case "In Progress":
          return `${baseClasses} text-blue-800 bg-blue-100 border border-blue-300`;
        default:
          return `${baseClasses} text-gray-800 bg-gray-100 border border-gray-300`;
      }
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case "Critical":
        return "[ALERT]";
      case "High":
        return "[!]";
      case "Medium":
        return "[!]";
      case "Low":
        return "ℹ";
      default:
        return "[LIST]";
    }
  };

  const getUserInitials = (name) => {
    return name
      .split(" ")
      .map((n) => n[0])
      .join("");
  };

  // Theme-based classes
  const contentThemes = {
    card: isDarkMode
      ? "bg-gradient-to-br from-slate-800/40 to-slate-900/40 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-4 sm:p-6 shadow-2xl"
      : "bg-white/90 backdrop-blur-xl border border-gray-200 rounded-2xl p-4 sm:p-6 shadow-xl",

    kpiGrid: "grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4",

    kpi: isDarkMode
      ? "bg-gradient-to-br from-slate-800/60 to-slate-900/60 backdrop-blur-xl border border-slate-700/50 rounded-xl p-3 sm:p-4 text-center"
      : "bg-white/80 backdrop-blur-xl border border-gray-200 rounded-xl p-3 sm:p-4 text-center shadow-md",

    kpiLabel: isDarkMode
      ? "text-gray-400 text-xs sm:text-sm font-medium"
      : "text-gray-600 text-xs sm:text-sm font-medium",

    kpiValue: isDarkMode
      ? "text-lg sm:text-2xl font-bold text-gray-100 mt-1 sm:mt-2"
      : "text-lg sm:text-2xl font-bold text-gray-900 mt-1 sm:mt-2",

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

    button: isDarkMode
      ? "inline-flex items-center px-3 sm:px-4 py-2 sm:py-3 text-sm font-medium text-red-300 bg-red-900/30 border border-red-500/30 rounded-lg hover:bg-red-900/50 transition-all duration-200 w-full sm:w-auto justify-center"
      : "inline-flex items-center px-3 sm:px-4 py-2 sm:py-3 text-sm font-medium text-red-800 bg-red-100 border border-red-300 rounded-lg hover:bg-red-200 hover:shadow-md transition-all duration-200 w-full sm:w-auto justify-center",

    buttonSecondary: isDarkMode
      ? "inline-flex items-center px-3 sm:px-4 py-2 sm:py-3 text-sm font-medium text-gray-300 bg-slate-800/50 border border-slate-700/50 rounded-lg hover:bg-slate-700/50 transition-all duration-200 w-full sm:w-auto justify-center"
      : "inline-flex items-center px-3 sm:px-4 py-2 sm:py-3 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 hover:shadow-md transition-all duration-200 w-full sm:w-auto justify-center",

    profileField: isDarkMode
      ? "text-sm sm:text-base text-gray-300 mb-3"
      : "text-sm sm:text-base text-gray-700 mb-3",
    profileLabel: isDarkMode
      ? "font-semibold text-gray-200"
      : "font-semibold text-gray-800",

    // Card view styles for vulnerabilities
    vulnCard: isDarkMode
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

    avatar:
      "w-16 h-16 sm:w-20 sm:h-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center text-white text-lg sm:text-xl font-bold",
  };

  // Vulnerability card component for mobile view
  const VulnerabilityCard = ({ vuln }) => (
    <div className={contentThemes.vulnCard}>
      <div className="space-y-3">
        {/* Header with severity and status */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-lg">{getSeverityIcon(vuln.severity)}</span>
            <h4
              className={
                isDarkMode
                  ? "font-semibold text-gray-100"
                  : "font-semibold text-gray-900"
              }
            >
              {vuln.title}
            </h4>
          </div>
          <div className="flex items-center gap-2">
            <span className={getSeverityBadge(vuln.severity)}>
              {vuln.severity}
            </span>
            <span className={getStatusBadge(vuln.status)}>{vuln.status}</span>
          </div>
        </div>

        {/* Description */}
        <p
          className={
            isDarkMode ? "text-sm text-gray-400" : "text-sm text-gray-600"
          }
        >
          {vuln.description}
        </p>

        {/* Details grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-3 border-t border-gray-200 dark:border-slate-700">
          <div>
            <div className={contentThemes.cardLabel}>Endpoint</div>
            <code
              className={
                isDarkMode
                  ? "px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs mt-1 inline-block"
                  : "px-2 py-1 bg-gray-100 border border-gray-300 rounded text-xs mt-1 inline-block"
              }
            >
              {vuln.endpoint}
            </code>
          </div>
          <div>
            <div className={contentThemes.cardLabel}>Discovered</div>
            <div className={contentThemes.cardValue}>{vuln.discoveredDate}</div>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <MiftyAdminLayout>
      <div className="space-y-6 sm:space-y-8 p-6">
        {/* Page Header */}
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className={contentThemes.avatar}>
              {getUserInitials(userData.name)}
            </div>
            <div>
              <h1
                className={
                  isDarkMode
                    ? "text-2xl sm:text-3xl font-bold text-gray-100"
                    : "text-2xl sm:text-3xl font-bold text-gray-900"
                }
              >
                {userData.company}
              </h1>
              <p
                className={
                  isDarkMode
                    ? "text-gray-400 mt-1 text-sm sm:text-base"
                    : "text-gray-600 mt-1 text-sm sm:text-base"
                }
              >
                Detailed view for {userData.name}
              </p>
            </div>
          </div>

          {/* Action Buttons - Mobile */}
          <div className="flex flex-col sm:flex-row gap-3 sm:gap-4">
            <button
              onClick={() => navigate("/admin/push-vulnerability")}
              className={contentThemes.button}
            >
              <span className="mr-2"></span>
              Push Vulnerability
            </button>
            <button
              onClick={() => navigate("/admin/users")}
              className={contentThemes.buttonSecondary}
            >
              <span className="mr-2">&larr;</span>
              Back to Users
            </button>
          </div>
        </div>

        {/* Profile and Stats Grid */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 sm:gap-8">
          {/* Profile Card */}
          <div className={contentThemes.card}>
            <h3
              className={
                isDarkMode
                  ? "text-lg sm:text-xl font-bold text-gray-100 mb-4 sm:mb-6"
                  : "text-lg sm:text-xl font-bold text-gray-900 mb-4 sm:mb-6"
              }
            >
              Profile Information
            </h3>

            <div className="space-y-3 sm:space-y-4">
              <div className={contentThemes.profileField}>
                <span className={contentThemes.profileLabel}>Owner:</span>{" "}
                {userData.name}
              </div>
              <div className={contentThemes.profileField}>
                <span className={contentThemes.profileLabel}>Email:</span>{" "}
                {userData.email}
              </div>
              <div className={contentThemes.profileField}>
                <span className={contentThemes.profileLabel}>Domain:</span>
                <code
                  className={
                    isDarkMode
                      ? "ml-2 px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs sm:text-sm"
                      : "ml-2 px-2 py-1 bg-gray-100 border border-gray-300 rounded text-xs sm:text-sm"
                  }
                >
                  {userData.domain}
                </code>
              </div>
              <div className={contentThemes.profileField}>
                <span className={contentThemes.profileLabel}>
                  Subscription:
                </span>{" "}
                {userData.subscription}
              </div>
              <div className={contentThemes.profileField}>
                <span className={contentThemes.profileLabel}>Joined:</span>{" "}
                {userData.joinedDate}
              </div>
              <div className={contentThemes.profileField}>
                <span className={contentThemes.profileLabel}>Last Login:</span>{" "}
                {userData.lastLogin}
              </div>
            </div>
          </div>

          {/* Stats Card */}
          <div className={contentThemes.card}>
            <h3
              className={
                isDarkMode
                  ? "text-lg sm:text-xl font-bold text-gray-100 mb-4 sm:mb-6"
                  : "text-lg sm:text-xl font-bold text-gray-900 mb-4 sm:mb-6"
              }
            >
              Security Statistics
            </h3>

            <div className={contentThemes.kpiGrid}>
              <div className={contentThemes.kpi}>
                <div className={contentThemes.kpiLabel}>Total Scans</div>
                <div
                  className={
                    isDarkMode
                      ? "text-lg sm:text-2xl font-bold text-blue-400 mt-1 sm:mt-2"
                      : "text-lg sm:text-2xl font-bold text-blue-600 mt-1 sm:mt-2"
                  }
                >
                  {userData.totalScans}
                </div>
              </div>
              <div className={contentThemes.kpi}>
                <div className={contentThemes.kpiLabel}>Open Vulns</div>
                <div
                  className={
                    isDarkMode
                      ? "text-lg sm:text-2xl font-bold text-amber-400 mt-1 sm:mt-2"
                      : "text-lg sm:text-2xl font-bold text-amber-600 mt-1 sm:mt-2"
                  }
                >
                  {userData.openVulns}
                </div>
              </div>
              <div className={contentThemes.kpi}>
                <div className={contentThemes.kpiLabel}>Critical</div>
                <div
                  className={
                    isDarkMode
                      ? "text-lg sm:text-2xl font-bold text-red-400 mt-1 sm:mt-2"
                      : "text-lg sm:text-2xl font-bold text-red-600 mt-1 sm:mt-2"
                  }
                >
                  {userData.critical}
                </div>
              </div>
              <div className={contentThemes.kpi}>
                <div className={contentThemes.kpiLabel}>Last Scan</div>
                <div className={contentThemes.kpiValue}>
                  {userData.lastScan}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Vulnerabilities Section */}
        <div className={contentThemes.card}>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
            <h3
              className={
                isDarkMode
                  ? "text-lg sm:text-xl font-bold text-gray-100"
                  : "text-lg sm:text-xl font-bold text-gray-900"
              }
            >
              Recent Vulnerabilities ({vulnerabilities.length})
            </h3>

            {/* View Toggle */}
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
          </div>

          {vulnerabilities.length === 0 ? (
            <div className="text-center py-8 sm:py-12">
              <div className="text-4xl sm:text-6xl mb-4">[SHIELD]</div>
              <h4
                className={
                  isDarkMode
                    ? "text-lg font-semibold text-gray-100 mb-2"
                    : "text-lg font-semibold text-gray-900 mb-2"
                }
              >
                No Vulnerabilities Found
              </h4>
              <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>
                This tenant has a clean security record
              </p>
            </div>
          ) : viewMode === "cards" ? (
            /* Card View */
            <div className="space-y-4">
              {vulnerabilities.map((vuln) => (
                <VulnerabilityCard key={vuln.id} vuln={vuln} />
              ))}
            </div>
          ) : (
            /* Table View */
            <div>
              {/* Desktop Table */}
              <div className="hidden lg:block overflow-x-auto">
                <table className={contentThemes.table}>
                  <thead>
                    <tr>
                      <th className={contentThemes.tableHeader}>Title</th>
                      <th className={contentThemes.tableHeader}>Severity</th>
                      <th className={contentThemes.tableHeader}>Endpoint</th>
                      <th className={contentThemes.tableHeader}>Status</th>
                      <th className={contentThemes.tableHeader}>Discovered</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vulnerabilities.map((vuln) => (
                      <tr key={vuln.id} className={contentThemes.tableRow}>
                        <td className={contentThemes.tableCell}>
                          <div className="flex items-center gap-2">
                            <span className="text-base">
                              {getSeverityIcon(vuln.severity)}
                            </span>
                            <div>
                              <div className="font-medium">{vuln.title}</div>
                              <div className="text-xs opacity-75 mt-1">
                                {vuln.description}
                              </div>
                            </div>
                          </div>
                        </td>
                        <td className={contentThemes.tableCell}>
                          <span className={getSeverityBadge(vuln.severity)}>
                            {vuln.severity}
                          </span>
                        </td>
                        <td className={contentThemes.tableCell}>
                          <code
                            className={
                              isDarkMode
                                ? "px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs"
                                : "px-2 py-1 bg-gray-100 border border-gray-300 rounded text-xs"
                            }
                          >
                            {vuln.endpoint}
                          </code>
                        </td>
                        <td className={contentThemes.tableCell}>
                          <span className={getStatusBadge(vuln.status)}>
                            {vuln.status}
                          </span>
                        </td>
                        <td className={contentThemes.tableCell}>
                          {vuln.discoveredDate}
                        </td>
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
                      <th className={contentThemes.tableHeader}>
                        Vulnerability
                      </th>
                      <th className={contentThemes.tableHeader}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vulnerabilities.map((vuln) => (
                      <tr key={vuln.id} className={contentThemes.tableRow}>
                        <td className={contentThemes.tableCell}>
                          <div className="space-y-2">
                            <div className="flex items-center gap-2">
                              <span className="text-base">
                                {getSeverityIcon(vuln.severity)}
                              </span>
                              <span className="font-medium">{vuln.title}</span>
                              <span className={getSeverityBadge(vuln.severity)}>
                                {vuln.severity}
                              </span>
                            </div>
                            <code
                              className={
                                isDarkMode
                                  ? "px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs"
                                  : "px-2 py-1 bg-gray-100 border border-gray-300 rounded text-xs"
                              }
                            >
                              {vuln.endpoint}
                            </code>
                            <div className="text-xs opacity-75">
                              {vuln.discoveredDate}
                            </div>
                          </div>
                        </td>
                        <td className={contentThemes.tableCell}>
                          <span className={getStatusBadge(vuln.status)}>
                            {vuln.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </MiftyAdminLayout>
  );
};

export default AdminUserDetails;
