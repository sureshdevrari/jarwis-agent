import { useNavigate } from "react-router-dom";
import { Clock, Unlock, AlertTriangle, AlertCircle, CheckCircle, BarChart3, List, Users, Bug } from "lucide-react";
import { useTheme } from "../../context/ThemeContext";
import MiftyAdminLayout from "../../components/layout/MiftyAdminLayout";
import { useUserManagement } from "../../context/UserManagementContext";
import { useMemo, useState } from "react";
import { MiftyStatCard, MiftyCard, MiftySectionTitle, MiftyDataTable, MiftyButton, MiftyQuickAction, MiftyPageHeader, MiftyBadge } from "../../components/dashboard/MiftyDashboardComponents";

const AdminOverview = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme(); // Get theme from context instead of local state

  // Theme-based classes for content
  const contentThemes = {
    card: isDarkMode
      ? "bg-gradient-to-br from-slate-800/40 to-slate-900/40 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6 shadow-2xl"
      : "bg-white/90 backdrop-blur-xl border border-gray-200 rounded-2xl p-6 shadow-xl",

    kpiGrid: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8",

    kpi: isDarkMode
      ? "bg-gradient-to-br from-slate-800/60 to-slate-900/60 backdrop-blur-xl border border-slate-700/50 rounded-xl p-4"
      : "bg-white/80 backdrop-blur-xl border border-gray-200 rounded-xl p-4 shadow-md",

    kpiLabel: isDarkMode
      ? "text-gray-400 text-sm font-medium"
      : "text-gray-600 text-sm font-medium",

    kpiValue: isDarkMode
      ? "text-2xl font-bold text-gray-100 mt-2"
      : "text-2xl font-bold text-gray-900 mt-2",

    badge: {
      warn: isDarkMode
        ? "inline-flex items-center px-2 py-1 text-xs font-semibold text-amber-300 bg-amber-900/30 border border-amber-500/30 rounded-full ml-2"
        : "inline-flex items-center px-2 py-1 text-xs font-semibold text-amber-800 bg-amber-100 border border-amber-300 rounded-full ml-2",
      danger: isDarkMode
        ? "inline-flex items-center px-2 py-1 text-xs font-semibold text-red-300 bg-red-900/30 border border-red-500/30 rounded-full ml-2"
        : "inline-flex items-center px-2 py-1 text-xs font-semibold text-red-800 bg-red-100 border border-red-300 rounded-full ml-2",
    },

    table: isDarkMode ? "w-full border-collapse" : "w-full border-collapse",

    tableHeader: isDarkMode
      ? "border-b border-slate-700/50 pb-3 text-left text-sm font-semibold text-gray-300 uppercase tracking-wider"
      : "border-b border-gray-200 pb-3 text-left text-sm font-semibold text-gray-700 uppercase tracking-wider",

    tableRow: isDarkMode
      ? "border-b border-slate-700/30 hover:bg-slate-800/30 transition-colors duration-200"
      : "border-b border-gray-100 hover:bg-gray-50/80 transition-colors duration-200",

    tableCell: isDarkMode
      ? "py-4 text-sm text-gray-300"
      : "py-4 text-sm text-gray-700",

    button: isDarkMode
      ? "inline-flex items-center px-4 py-2 text-sm font-medium text-blue-300 bg-blue-900/30 border border-blue-500/30 rounded-lg hover:bg-blue-900/50 transition-all duration-200"
      : "inline-flex items-center px-4 py-2 text-sm font-medium text-blue-800 bg-blue-100 border border-blue-300 rounded-lg hover:bg-blue-200 hover:shadow-md transition-all duration-200",

    buttonSecondary: isDarkMode
      ? "inline-flex items-center px-4 py-2 text-sm font-medium text-gray-300 bg-slate-800/50 border border-slate-700/50 rounded-lg hover:bg-slate-700/50 transition-all duration-200"
      : "inline-flex items-center px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 hover:shadow-md transition-all duration-200",
  };

  // Logic section

  const { allUsers, dashboardStats, pendingUsers, approvedUsers } = useUserManagement();

  // Get statistics from dashboardStats or calculate from users
  const stats = useMemo(() => ({
    total: dashboardStats?.total_users || allUsers.length,
    pending: dashboardStats?.pending_users || pendingUsers.length,
    approved: dashboardStats?.approved_users || approvedUsers.length,
  }), [dashboardStats, allUsers, pendingUsers, approvedUsers]);

  const totalUsers = stats.total;
  const pendingRequests = stats.pending;
  const vulnerabilities = 0;
  const criticalIssues = 0;

  const kpiData = [
    { label: "Total Users", value: totalUsers, icon: "", badge: null },
    {
      label: "Pending Requests",
      value: pendingRequests,
      icon: <Clock className="w-5 h-5" />,
      badge: { type: "warn", text: "Review" },
    },
    {
      label: "Open Vulnerabilities",
      value: vulnerabilities,
      icon: <Unlock className="w-5 h-5" />,
      badge: null,
    },
    {
      label: "Critical Issues",
      value: criticalIssues,
      icon: <AlertTriangle className="w-5 h-5" />,
      badge: { type: "danger", text: "Urgent" },
    },
  ];

  // Recent activity will be fetched from API in future implementation
  const recentActivity = [];

  return (
    <MiftyAdminLayout>
      <div className="space-y-8 p-6">
        {/* Page Header */}
        <MiftyPageHeader
          title="Admin Overview"
          subtitle="Monitor and manage the entire Jarwis platform"
          actions={
            <MiftyButton variant="primary" onClick={() => navigate("/admin/users")}>
              <span className="mr-2"></span>
              Add User
            </MiftyButton>
          }
        />

        {/* KPI Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {kpiData.map((kpi, index) => (
            <MiftyStatCard
              key={index}
              icon={kpi.icon || <BarChart3 className="w-5 h-5" />}
              label={kpi.label}
              value={kpi.value}
              trend={kpi.badge ? kpi.badge.text : null}
              trendUp={kpi.badge ? kpi.badge.type !== 'danger' : true}
              className="mifty-animate-slide-up"
              style={{ animationDelay: `${index * 100}ms` }}
            />
          ))}
        </div>

        {/* Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Recent Activity */}
          <MiftyCard className="mifty-animate-slide-up" style={{ animationDelay: '400ms' }}>
            <MiftySectionTitle title="Recent Activity" icon={<List className="w-5 h-5" />} />
            <div className="overflow-x-auto mt-4">
              <MiftyDataTable
                columns={['Time', 'Event', 'Actor', 'Target']}
                data={recentActivity.map((activity) => ({
                  Time: activity.time,
                  Event: activity.event,
                  Actor: activity.actor,
                  Target: activity.target,
                }))}
                emptyMessage="No recent activity yet"
                emptyIcon={<List className="w-5 h-5" />}
              />
            </div>
          </MiftyCard>

          {/* Quick Actions */}
          <MiftyCard className="mifty-animate-slide-up" style={{ animationDelay: '500ms' }}>
            <MiftySectionTitle title="Quick Actions" icon={<AlertCircle className="w-5 h-5" />} />
            <div className="grid grid-cols-1 gap-4 mt-4">
              <MiftyQuickAction
                icon={<CheckCircle className="w-5 h-5" />}
                title="Review Access Requests"
                description={`${pendingRequests} pending requests`}
                onClick={() => navigate("/admin/requests")}
                color="cyan"
              />
              <MiftyQuickAction
                icon={<Users className="w-5 h-5" />}
                title="Manage Users"
                description={`${totalUsers} total users`}
                onClick={() => navigate("/admin/users")}
                color="purple"
              />
              <MiftyQuickAction
                icon={<Bug className="w-5 h-5" />}
                title="Push Vulnerability"
                description="Add new vulnerability"
                onClick={() => navigate("/admin/push-vulnerability")}
                color="rose"
              />
              <MiftyQuickAction
                icon={<BarChart3 className="w-5 h-5" />}
                title="View Analytics"
                description="Platform insights"
                onClick={() => navigate("/admin/analytics")}
                color="green"
              />
            </div>
          </MiftyCard>
        </div>
      </div>
    </MiftyAdminLayout>
  );
};

export default AdminOverview;
