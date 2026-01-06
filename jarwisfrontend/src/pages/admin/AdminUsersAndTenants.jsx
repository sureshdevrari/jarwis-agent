import { useState } from "react";
import { useNavigate } from "react-router-dom";
import MiftyAdminLayout from "../../components/layout/MiftyAdminLayout";
import { useTheme } from "../../context/ThemeContext";

const AdminUsersAndTenants = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();
  // Removed viewMode - using cards only
  const [searchTerm, setSearchTerm] = useState("");

  // Users will be fetched from API in future implementation
  const users = [];

  const filteredUsers = users.filter(
    (user) =>
      searchTerm === "" ||
      user.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.company.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.domains.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleViewUser = (userId) => {
    navigate(`/admin/users/${userId}`);
  };

  const getUserInitials = (name) => {
    return name
      .split(" ")
      .map((n) => n[0])
      .join("");
  };

  const getRiskLevel = (critical, openVulns) => {
    if (critical > 1) return "high";
    if (critical === 1 || openVulns > 20) return "medium";
    return "low";
  };

  const getRiskColor = (level) => {
    const colors = {
      high: isDarkMode
        ? "text-red-400 bg-red-900/30 border-red-500/30"
        : "text-red-800 bg-red-100 border-red-300",
      medium: isDarkMode
        ? "text-amber-400 bg-amber-900/30 border-amber-500/30"
        : "text-amber-800 bg-amber-100 border-amber-300",
      low: isDarkMode
        ? "text-green-400 bg-green-900/30 border-green-500/30"
        : "text-green-800 bg-green-100 border-green-300",
    };
    return colors[level];
  };

  // Theme-based classes
  const contentThemes = {
    card: isDarkMode
      ? "bg-gradient-to-br from-slate-800/40 to-slate-900/40 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-4 sm:p-6 shadow-2xl"
      : "bg-white/90 backdrop-blur-xl border border-gray-200 rounded-2xl p-4 sm:p-6 shadow-xl",

    searchBar: isDarkMode
      ? "flex flex-col sm:flex-row gap-4 mb-6 p-4 bg-slate-800/30 border border-slate-700/50 rounded-xl"
      : "flex flex-col sm:flex-row gap-4 mb-6 p-4 bg-gray-50 border border-gray-200 rounded-xl",

    searchInput: isDarkMode
      ? "flex-1 px-4 py-3 bg-slate-800/50 border border-slate-700/50 rounded-lg text-gray-100 placeholder-gray-400 focus:border-blue-500/50 focus:outline-none focus:ring-2 focus:ring-blue-500/20 transition-all duration-200"
      : "flex-1 px-4 py-3 bg-white border border-gray-300 rounded-lg text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20 transition-all duration-200",

    // Removed table-related styles since we're only using cards
    viewButton: isDarkMode
      ? "inline-flex items-center px-3 py-2 text-xs font-medium text-blue-300 bg-blue-900/30 border border-blue-500/30 rounded-lg hover:bg-blue-900/50 transition-all duration-200 w-full justify-center"
      : "inline-flex items-center px-3 py-2 text-xs font-medium text-blue-800 bg-blue-100 border border-blue-300 rounded-lg hover:bg-blue-200 hover:shadow-md transition-all duration-200 w-full justify-center",

    criticalBadge: isDarkMode
      ? "inline-flex items-center px-2 py-1 text-xs font-semibold text-red-300 bg-red-900/30 border border-red-500/30 rounded-full"
      : "inline-flex items-center px-2 py-1 text-xs font-semibold text-red-800 bg-red-100 border border-red-300 rounded-full",

    // Card view styles
    userCard: isDarkMode
      ? "bg-gradient-to-br from-slate-800/60 to-slate-900/60 backdrop-blur-xl border border-slate-700/50 rounded-xl p-4 shadow-lg"
      : "bg-white/80 backdrop-blur-xl border border-gray-200 rounded-xl p-4 shadow-md",

    cardLabel: isDarkMode
      ? "text-xs font-medium text-gray-400 uppercase tracking-wider"
      : "text-xs font-medium text-gray-600 uppercase tracking-wider",

    cardValue: isDarkMode
      ? "text-sm font-medium text-gray-200 mt-1"
      : "text-sm font-medium text-gray-800 mt-1",

    avatar:
      "w-10 h-10 sm:w-12 sm:h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center text-white text-sm sm:text-base font-bold",

    statCard: isDarkMode
      ? "bg-gradient-to-br from-slate-800/60 to-slate-900/60 backdrop-blur-xl border border-slate-700/50 rounded-xl p-4 text-center"
      : "bg-white/80 backdrop-blur-xl border border-gray-200 rounded-xl p-4 text-center shadow-md",
  };

  // Card component for mobile view
  const UserCard = ({ user }) => {
    const riskLevel = getRiskLevel(user.critical, user.openVulns);

    return (
      <div className={contentThemes.userCard}>
        <div className="space-y-4">
          {/* Header with avatar and basic info */}
          <div className="flex items-start justify-between">
            <div className="flex items-center space-x-3">
              <div className={contentThemes.avatar}>
                {getUserInitials(user.name)}
              </div>
              <div>
                <h3
                  className={
                    isDarkMode
                      ? "font-semibold text-gray-100"
                      : "font-semibold text-gray-900"
                  }
                >
                  {user.name}
                </h3>
                <p
                  className={
                    isDarkMode
                      ? "text-sm text-gray-400"
                      : "text-sm text-gray-600"
                  }
                >
                  {user.company}
                </p>
              </div>
            </div>
            <span
              className={`inline-flex items-center px-2 py-1 text-xs font-medium border rounded-full ${getRiskColor(
                riskLevel
              )}`}
            >
              {riskLevel} risk
            </span>
          </div>

          {/* Contact and domain info */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <div className={contentThemes.cardLabel}>Email</div>
              <div className={contentThemes.cardValue}>{user.email}</div>
            </div>
            <div>
              <div className={contentThemes.cardLabel}>Domain</div>
              <code
                className={
                  isDarkMode
                    ? "px-2 py-1 bg-slate-800 border border-slate-700 rounded text-xs mt-1 inline-block"
                    : "px-2 py-1 bg-gray-100 border border-gray-300 rounded text-xs mt-1 inline-block"
                }
              >
                {user.domains}
              </code>
            </div>
          </div>

          {/* Stats grid */}
          <div className="grid grid-cols-3 gap-3 py-3 border-t border-gray-200 dark:border-slate-700">
            <div className="text-center">
              <div
                className={
                  isDarkMode
                    ? "text-lg font-bold text-blue-400"
                    : "text-lg font-bold text-blue-600"
                }
              >
                {user.totalScans}
              </div>
              <div className={contentThemes.cardLabel}>Scans</div>
            </div>
            <div className="text-center">
              <div
                className={
                  isDarkMode
                    ? "text-lg font-bold text-amber-400"
                    : "text-lg font-bold text-amber-600"
                }
              >
                {user.openVulns}
              </div>
              <div className={contentThemes.cardLabel}>Open Vulns</div>
            </div>
            <div className="text-center">
              {user.critical > 0 ? (
                <div
                  className={
                    isDarkMode
                      ? "text-lg font-bold text-red-400"
                      : "text-lg font-bold text-red-600"
                  }
                >
                  {user.critical}
                </div>
              ) : (
                <div
                  className={
                    isDarkMode
                      ? "text-lg font-bold text-green-400"
                      : "text-lg font-bold text-green-600"
                  }
                >
                  0
                </div>
              )}
              <div className={contentThemes.cardLabel}>Critical</div>
            </div>
          </div>

          {/* Action button */}
          <button
            onClick={() => handleViewUser(user.id)}
            className={contentThemes.viewButton}
          >
             View Details
          </button>
        </div>
      </div>
    );
  };

  return (
    <MiftyAdminLayout>
      <div className="space-y-6 sm:space-y-8 p-6">
        {/* Page Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1
              className={
                isDarkMode
                  ? "text-2xl sm:text-3xl font-bold text-gray-100"
                  : "text-2xl sm:text-3xl font-bold text-gray-900"
              }
            >
              Users & Tenants
            </h1>
            <p
              className={
                isDarkMode
                  ? "text-gray-400 mt-1 sm:mt-2 text-sm sm:text-base"
                  : "text-gray-600 mt-1 sm:mt-2 text-sm sm:text-base"
              }
            >
              Manage all users and their tenant organizations
            </p>
          </div>
        </div>

        {/* Search Bar */}
        <div className={contentThemes.searchBar}>
          <div className="flex-1">
            <input
              type="text"
              placeholder="Search users, emails, companies, or domains..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className={contentThemes.searchInput}
            />
          </div>
        </div>

        {/* Content */}
        <div className={contentThemes.card}>
          {filteredUsers.length === 0 ? (
            /* Empty State */
            <div className="text-center py-8 sm:py-12">
              <div className="text-4xl sm:text-6xl mb-4"></div>
              <h3
                className={
                  isDarkMode
                    ? "text-lg sm:text-xl font-semibold text-gray-100 mb-2"
                    : "text-lg sm:text-xl font-semibold text-gray-900 mb-2"
                }
              >
                No Users Found
              </h3>
              <p
                className={
                  isDarkMode
                    ? "text-sm sm:text-base text-gray-400"
                    : "text-sm sm:text-base text-gray-600"
                }
              >
                {searchTerm
                  ? "Try adjusting your search criteria"
                  : "No users have been added yet"}
              </p>
            </div>
          ) : (
            /* Card View */
            <div className="space-y-4">
              <div className="flex items-center justify-between mb-4">
                <h3
                  className={
                    isDarkMode
                      ? "text-lg font-semibold text-gray-100"
                      : "text-lg font-semibold text-gray-900"
                  }
                >
                  {filteredUsers.length} User
                  {filteredUsers.length !== 1 ? "s" : ""}
                </h3>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
                {filteredUsers.map((user) => (
                  <UserCard key={user.id} user={user} />
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Stats Summary */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-6">
          <div className={contentThemes.statCard}>
            <div
              className={
                isDarkMode
                  ? "text-2xl sm:text-3xl font-bold text-blue-400"
                  : "text-2xl sm:text-3xl font-bold text-blue-600"
              }
            >
              {users.length}
            </div>
            <div
              className={
                isDarkMode
                  ? "text-gray-400 text-xs sm:text-sm mt-1"
                  : "text-gray-600 text-xs sm:text-sm mt-1"
              }
            >
              Total Tenants
            </div>
          </div>
          <div className={contentThemes.statCard}>
            <div
              className={
                isDarkMode
                  ? "text-2xl sm:text-3xl font-bold text-amber-400"
                  : "text-2xl sm:text-3xl font-bold text-amber-600"
              }
            >
              {users.reduce((sum, user) => sum + user.openVulns, 0)}
            </div>
            <div
              className={
                isDarkMode
                  ? "text-gray-400 text-xs sm:text-sm mt-1"
                  : "text-gray-600 text-xs sm:text-sm mt-1"
              }
            >
              Open Vulnerabilities
            </div>
          </div>
          <div className={contentThemes.statCard}>
            <div
              className={
                isDarkMode
                  ? "text-2xl sm:text-3xl font-bold text-red-400"
                  : "text-2xl sm:text-3xl font-bold text-red-600"
              }
            >
              {users.reduce((sum, user) => sum + user.critical, 0)}
            </div>
            <div
              className={
                isDarkMode
                  ? "text-gray-400 text-xs sm:text-sm mt-1"
                  : "text-gray-600 text-xs sm:text-sm mt-1"
              }
            >
              Critical Issues
            </div>
          </div>
        </div>
      </div>
    </MiftyAdminLayout>
  );
};

export default AdminUsersAndTenants;
