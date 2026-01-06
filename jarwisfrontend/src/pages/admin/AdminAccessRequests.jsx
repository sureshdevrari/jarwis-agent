import { useState, useMemo, useEffect } from "react";
import { useTheme } from "../../context/ThemeContext";
import { useNavigate } from "react-router-dom";
import { useUserManagement } from "../../context/UserManagementContext";

import MiftyAdminLayout from "../../components/layout/MiftyAdminLayout";
import {
  CheckCircle,
  XCircle,
  Clock,
  User,
  Building,
  Mail,
  Globe,
  MessageSquare,
  Filter,
  Grid3x3,
  List,
  Search,
  AlertCircle,
  CheckCheck,
  X,
  RotateCcw,
  Shield,
  Users,
  UserPlus,
  UserMinus,
  Trash2,
  Crown,
  CreditCard,
} from "lucide-react";

const AdminAccessRequests = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();
  const {
    allUsers,
    loading,
    error,
    approveUser,
    rejectUser,
    resetUserStatus,
    makeAdmin,
    removeAdmin,
    deleteUser,
    isSuperAdmin,
    isAdmin,
    canCreateAdmins,
    canDeleteUsers,
    getFilteredUsers,
    getApprovalStats,
    approveRequest,
    rejectRequest,
    resetUserToPending,
    promoteToAdmin,
    demoteFromAdmin,
    currentUserRole,
    setUserPlan,
    getPlans,
  } = useUserManagement();

  const [viewMode, setViewMode] = useState("grid"); // "grid", "table"
  const [processingIds, setProcessingIds] = useState(new Set());
  const [message, setMessage] = useState({ type: "", text: "" });
  const [searchTerm, setSearchTerm] = useState("");
  const [filterStatus, setFilterStatus] = useState("all"); // "all", "pending", "approved", "rejected", "admin", "super_admin"
  
  // Plan selection modal state
  const [showPlanModal, setShowPlanModal] = useState(false);
  const [selectedUserForApproval, setSelectedUserForApproval] = useState(null);
  const [selectedPlan, setSelectedPlan] = useState("trial");
  const [availablePlans, setAvailablePlans] = useState([
    { id: 'trial', name: 'Trial', description: 'Corporate trial, 14 days access, limited features' },
    { id: 'individual', name: 'Individual', description: '3 websites, 30 days access, API testing' },
    { id: 'professional', name: 'Professional', description: '10 websites, 90 days access, mobile testing' },
    { id: 'enterprise', name: 'Enterprise', description: 'Unlimited, 365 days access, dedicated support' },
  ]);

  // Load available plans on mount
  useEffect(() => {
    const loadPlans = async () => {
      try {
        const plans = await getPlans();
        if (plans && plans.length > 0) {
          setAvailablePlans(plans.map(p => ({
            id: p.id,
            name: p.name,
            description: `${p.features?.max_websites || 1} websites, ${p.features?.dashboard_access_days || 7} days access`
          })));
        }
      } catch (err) {
        console.log("Using default plans");
      }
    };
    loadPlans();
  }, [getPlans]);

  // Get filtered and searched users
  const filteredUsers = useMemo(() => {
    let users = getFilteredUsers(filterStatus);

    if (searchTerm) {
      users = users.filter(
        (user) =>
          user.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
          user.company.toLowerCase().includes(searchTerm.toLowerCase()) ||
          user.domain.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    return users;
  }, [allUsers, filterStatus, searchTerm, getFilteredUsers]);

  // Get statistics
  const stats = useMemo(() => getApprovalStats(), [allUsers, getApprovalStats]);

  // Show message temporarily
  const showMessage = (type, text) => {
    setMessage({ type, text });
    setTimeout(() => setMessage({ type: "", text: "" }), 5000);
  };

  // Open plan selection modal before approving
  const handleApproveClick = (user) => {
    setSelectedUserForApproval(user);
    setSelectedPlan("free");
    setShowPlanModal(true);
  };

  // Confirm approval with selected plan
  const handleConfirmApproval = async () => {
    if (!selectedUserForApproval) return;
    
    const id = selectedUserForApproval.id;
    if (processingIds.has(id)) return;
    
    setProcessingIds((prev) => new Set(prev).add(id));
    setShowPlanModal(false);

    try {
      const result = await approveRequest(id, selectedPlan);
      if (result.success) {
        showMessage("success", result.message);
      } else {
        showMessage("error", result.message);
      }
    } catch (err) {
      showMessage("error", "Failed to approve user");
    } finally {
      setProcessingIds((prev) => {
        const newSet = new Set(prev);
        newSet.delete(id);
        return newSet;
      });
      setSelectedUserForApproval(null);
    }
  };

  // Legacy handleApprove for backward compatibility (approves with free plan)
  const handleApprove = async (id) => {
    if (processingIds.has(id)) return;
    setProcessingIds((prev) => new Set(prev).add(id));

    try {
      const result = await approveRequest(id, 'free');
      if (result.success) {
        showMessage("success", result.message);
      } else {
        showMessage("error", result.message);
      }
    } catch (err) {
      showMessage("error", "Failed to approve user");
    } finally {
      setProcessingIds((prev) => {
        const newSet = new Set(prev);
        newSet.delete(id);
        return newSet;
      });
    }
  };

  // Handle changing plan for existing user
  const handleChangePlan = async (userId, newPlan) => {
    if (processingIds.has(userId)) return;
    setProcessingIds((prev) => new Set(prev).add(userId));

    try {
      await setUserPlan(userId, newPlan);
      showMessage("success", `Plan changed to ${newPlan}`);
    } catch (err) {
      showMessage("error", "Failed to change plan");
    } finally {
      setProcessingIds((prev) => {
        const newSet = new Set(prev);
        newSet.delete(userId);
        return newSet;
      });
    }
  };

  const handleReject = async (id) => {
    if (processingIds.has(id)) return;
    setProcessingIds((prev) => new Set(prev).add(id));

    try {
      const result = await rejectRequest(id);
      if (result.success) {
        showMessage("success", result.message);
      } else {
        showMessage("error", result.message);
      }
    } catch (err) {
      showMessage("error", "Failed to reject user");
    } finally {
      setProcessingIds((prev) => {
        const newSet = new Set(prev);
        newSet.delete(id);
        return newSet;
      });
    }
  };

  const handleReset = async (id) => {
    if (processingIds.has(id)) return;
    setProcessingIds((prev) => new Set(prev).add(id));

    try {
      const result = await resetUserToPending(id);
      if (result.success) {
        showMessage("success", result.message);
      } else {
        showMessage("error", result.message);
      }
    } catch (err) {
      showMessage("error", "Failed to reset user");
    } finally {
      setProcessingIds((prev) => {
        const newSet = new Set(prev);
        newSet.delete(id);
        return newSet;
      });
    }
  };

  const handlePromoteToAdmin = async (id) => {
    if (processingIds.has(id)) return;
    setProcessingIds((prev) => new Set(prev).add(id));

    try {
      const result = await promoteToAdmin(id);
      if (result.success) {
        showMessage("success", result.message);
      } else {
        showMessage("error", result.message);
      }
    } catch (err) {
      showMessage("error", "Failed to promote user to admin");
    } finally {
      setProcessingIds((prev) => {
        const newSet = new Set(prev);
        newSet.delete(id);
        return newSet;
      });
    }
  };

  const handleDemoteFromAdmin = async (id) => {
    if (processingIds.has(id)) return;
    setProcessingIds((prev) => new Set(prev).add(id));

    try {
      const result = await demoteFromAdmin(id);
      if (result.success) {
        showMessage("success", result.message);
      } else {
        showMessage("error", result.message);
      }
    } catch (err) {
      showMessage("error", "Failed to demote admin");
    } finally {
      setProcessingIds((prev) => {
        const newSet = new Set(prev);
        newSet.delete(id);
        return newSet;
      });
    }
  };

  const handleDeleteUser = async (id) => {
    if (processingIds.has(id)) return;

    // Confirmation dialog
    if (
      !window.confirm(
        "Are you sure you want to permanently delete this user? This action cannot be undone."
      )
    ) {
      return;
    }

    setProcessingIds((prev) => new Set(prev).add(id));

    try {
      const result = await deleteUser(id);
      if (result.success) {
        showMessage("success", result.message);
      } else {
        showMessage("error", result.message);
      }
    } catch (err) {
      showMessage("error", "Failed to delete user");
    } finally {
      setProcessingIds((prev) => {
        const newSet = new Set(prev);
        newSet.delete(id);
        return newSet;
      });
    }
  };

  // Status badge component
  const StatusBadge = ({ status }) => {
    const statusConfig = {
      pending: {
        color: isDarkMode
          ? "bg-yellow-900/30 text-yellow-400 border-yellow-600/30"
          : "bg-yellow-50 text-yellow-700 border-yellow-200",
        icon: Clock,
        label: "Pending",
      },
      approved: {
        color: isDarkMode
          ? "bg-green-900/30 text-green-400 border-green-600/30"
          : "bg-green-50 text-green-700 border-green-200",
        icon: CheckCircle,
        label: "Approved",
      },
      rejected: {
        color: isDarkMode
          ? "bg-red-900/30 text-red-400 border-red-600/30"
          : "bg-red-50 text-red-700 border-red-200",
        icon: XCircle,
        label: "Rejected",
      },
      admin: {
        color: isDarkMode
          ? "bg-purple-900/30 text-purple-400 border-purple-600/30"
          : "bg-purple-50 text-purple-700 border-purple-200",
        icon: Shield,
        label: "Admin",
      },
      super_admin: {
        color: isDarkMode
          ? "bg-pink-900/30 text-pink-400 border-pink-600/30"
          : "bg-pink-50 text-pink-700 border-pink-200",
        icon: Crown,
        label: "Super Admin",
      },
    };

    const config = statusConfig[status] || statusConfig.pending;
    const Icon = config.icon;

    return (
      <div
        className={`inline-flex items-center space-x-1 px-2 py-1 text-xs border rounded-full ${config.color}`}
      >
        <Icon className="w-3 h-3" />
        <span>{config.label}</span>
      </div>
    );
  };

  // Modern theme classes
  const styles = {
    card: isDarkMode
      ? "bg-gray-800 border border-gray-700 rounded-xl shadow-lg"
      : "bg-white border border-gray-200 rounded-xl shadow-sm",

    headerCard: isDarkMode
      ? "bg-gradient-to-r from-gray-800 to-gray-900 border border-gray-700"
      : "bg-gradient-to-r from-white to-gray-50 border border-gray-200",

    requestCard: isDarkMode
      ? "bg-gray-800 border border-gray-700 hover:border-gray-600 transition-all duration-200"
      : "bg-white border border-gray-200 hover:border-gray-300 hover:shadow-md transition-all duration-200",

    text: {
      primary: isDarkMode ? "text-gray-100" : "text-gray-900",
      secondary: isDarkMode ? "text-gray-400" : "text-gray-600",
      muted: isDarkMode ? "text-gray-500" : "text-gray-500",
    },

    button: {
      approve: isDarkMode
        ? "bg-green-900/30 text-green-400 border border-green-600/30 hover:bg-green-900/50"
        : "bg-green-50 text-green-700 border border-green-200 hover:bg-green-100",

      reject: isDarkMode
        ? "bg-red-900/30 text-red-400 border border-red-600/30 hover:bg-red-900/50"
        : "bg-red-50 text-red-700 border border-red-200 hover:bg-red-100",

      reset: isDarkMode
        ? "bg-blue-900/30 text-blue-400 border border-blue-600/30 hover:bg-blue-900/50"
        : "bg-blue-50 text-blue-700 border border-blue-200 hover:bg-blue-100",

      promote: isDarkMode
        ? "bg-purple-900/30 text-purple-400 border border-purple-600/30 hover:bg-purple-900/50"
        : "bg-purple-50 text-purple-700 border border-purple-200 hover:bg-purple-100",

      demote: isDarkMode
        ? "bg-orange-900/30 text-orange-400 border border-orange-600/30 hover:bg-orange-900/50"
        : "bg-orange-50 text-orange-700 border border-orange-200 hover:bg-orange-100",

      delete: isDarkMode
        ? "bg-red-900/40 text-red-400 border border-red-600/40 hover:bg-red-900/60"
        : "bg-red-50 text-red-800 border border-red-300 hover:bg-red-100",

      view: (active) =>
        isDarkMode
          ? `${
              active
                ? "bg-blue-900/30 text-blue-400 border-blue-600/30"
                : "bg-gray-700 text-gray-300 border-gray-600"
            } border hover:bg-gray-600`
          : `${
              active
                ? "bg-blue-50 text-blue-700 border-blue-200"
                : "bg-gray-100 text-gray-600 border-gray-300"
            } border hover:bg-gray-200`,
    },

    input: isDarkMode
      ? "bg-gray-700 border border-gray-600 text-gray-100 placeholder-gray-400 focus:border-blue-500"
      : "bg-white border border-gray-300 text-gray-900 placeholder-gray-500 focus:border-blue-500",

    select: isDarkMode
      ? "bg-gray-700 border border-gray-600 text-gray-100 focus:border-blue-500"
      : "bg-white border border-gray-300 text-gray-900 focus:border-blue-500",
  };

  // Loading Component
  const LoadingSpinner = () => (
    <div className="flex items-center justify-center py-16">
      <div className="flex flex-col items-center space-y-4">
        <div
          className={`animate-spin rounded-full h-12 w-12 border-b-2 ${
            isDarkMode ? "border-blue-400" : "border-blue-600"
          }`}
        ></div>
        <p className={styles.text.secondary}>Loading users...</p>
      </div>
    </div>
  );

  // Empty State Component
  const EmptyState = () => (
    <div className="flex flex-col items-center justify-center py-16 px-4">
      <div
        className={`rounded-full p-6 mb-4 ${
          isDarkMode ? "bg-gray-700" : "bg-gray-100"
        }`}
      >
        <Users className={`w-12 h-12 ${styles.text.secondary}`} />
      </div>
      <h3 className={`text-xl font-semibold mb-2 ${styles.text.primary}`}>
        No Users Found
      </h3>
      <p className={styles.text.secondary}>
        {filterStatus === "all"
          ? "No users in the system yet"
          : `No ${filterStatus} users found`}
      </p>
    </div>
  );

  // User Card Component for Grid View
  const UserCard = ({ user }) => {
    const isProcessing = processingIds.has(user.id);

    return (
      <div className={`${styles.requestCard} rounded-xl p-6`}>
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div className="flex-1">
            <h3 className={`font-semibold text-lg mb-1 ${styles.text.primary}`}>
              {user.name}
            </h3>
            <p className={styles.text.secondary}>{user.company}</p>
          </div>
          <div className="flex flex-col items-end space-y-2">
            <div
              className={`text-xs px-3 py-1 rounded-full ${
                isDarkMode
                  ? "bg-blue-900/30 text-blue-400"
                  : "bg-blue-50 text-blue-700"
              }`}
            >
              {user.requestedOn}
            </div>
            <StatusBadge status={user.status} />
          </div>
        </div>

        {/* Details */}
        <div className="space-y-3 mb-6">
          <div className="flex items-center space-x-3">
            <Mail className={`w-4 h-4 ${styles.text.muted}`} />
            <span className={`text-sm ${styles.text.secondary}`}>
              {user.email}
            </span>
          </div>
          <div className="flex items-center space-x-3">
            <Globe className={`w-4 h-4 ${styles.text.muted}`} />
            <code
              className={`text-sm px-2 py-1 rounded ${
                isDarkMode
                  ? "bg-gray-700 text-gray-300"
                  : "bg-gray-100 text-gray-700"
              }`}
            >
              {user.domain}
            </code>
          </div>
          <div className="flex items-start space-x-3">
            <MessageSquare className={`w-4 h-4 mt-0.5 ${styles.text.muted}`} />
            <p className={`text-sm ${styles.text.secondary} leading-relaxed`}>
              {user.reason}
            </p>
          </div>
        </div>

        {/* Actions */}
        <div className="space-y-2">
          {/* Standard Actions */}
          <div className="flex space-x-2">
            {user.status === "pending" && (
              <>
                <button
                  onClick={() => handleApproveClick(user)}
                  disabled={isProcessing}
                  className={`flex-1 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-200 ${
                    styles.button.approve
                  } ${isProcessing ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  {isProcessing ? "..." : "Approve"}
                </button>
                <button
                  onClick={() => handleReject(user.id)}
                  disabled={isProcessing}
                  className={`flex-1 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-200 ${
                    styles.button.reject
                  } ${isProcessing ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  {isProcessing ? "..." : "Reject"}
                </button>
              </>
            )}

            {(user.status === "approved" || user.status === "rejected") && (
              <button
                onClick={() => handleReset(user.id)}
                disabled={isProcessing}
                className={`flex-1 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-200 ${
                  styles.button.reset
                } ${isProcessing ? "opacity-50 cursor-not-allowed" : ""}`}
              >
                {isProcessing ? "..." : "Reset to Pending"}
              </button>
            )}
          </div>

          {/* Super Admin Actions */}
          {isSuperAdmin() && (
            <div className="flex space-x-2">
              {(user.status === "approved" || user.status === "pending") && (
                <button
                  onClick={() => handlePromoteToAdmin(user.id)}
                  disabled={isProcessing}
                  className={`flex-1 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-200 ${
                    styles.button.promote
                  } ${isProcessing ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  <UserPlus className="w-3 h-3 inline mr-1" />
                  {isProcessing ? "..." : "Make Admin"}
                </button>
              )}

              {user.status === "admin" && (
                <button
                  onClick={() => handleDemoteFromAdmin(user.id)}
                  disabled={isProcessing}
                  className={`flex-1 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-200 ${
                    styles.button.demote
                  } ${isProcessing ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  <UserMinus className="w-3 h-3 inline mr-1" />
                  {isProcessing ? "..." : "Remove Admin"}
                </button>
              )}

              {user.status !== "super_admin" && (
                <button
                  onClick={() => handleDeleteUser(user.id)}
                  disabled={isProcessing}
                  className={`px-3 py-2 rounded-lg text-xs font-medium transition-all duration-200 ${
                    styles.button.delete
                  } ${isProcessing ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              )}
            </div>
          )}

          {user.status === "super_admin" && (
            <div
              className={`text-center px-3 py-2 text-xs ${styles.text.muted} border border-pink-600/30 rounded-lg`}
            >
              <Crown className="w-3 h-3 inline mr-1" />
              Super Admin User
            </div>
          )}
        </div>
      </div>
    );
  };

  // Table Row Component
  const TableRow = ({ user }) => {
    const isProcessing = processingIds.has(user.id);

    return (
      <tr
        className={`border-b ${
          isDarkMode
            ? "border-gray-700 hover:bg-gray-700/50"
            : "border-gray-200 hover:bg-gray-50"
        } transition-colors`}
      >
        <td className="px-6 py-4">
          <div>
            <div className={`font-medium ${styles.text.primary}`}>
              {user.name}
            </div>
            <div className={`text-sm ${styles.text.secondary}`}>
              {user.company}
            </div>
          </div>
        </td>
        <td className={`px-6 py-4 text-sm ${styles.text.secondary}`}>
          {user.email}
        </td>
        <td className="px-6 py-4">
          <code
            className={`text-xs px-2 py-1 rounded ${
              isDarkMode
                ? "bg-gray-700 text-gray-300"
                : "bg-gray-100 text-gray-700"
            }`}
          >
            {user.domain}
          </code>
        </td>
        <td className={`px-6 py-4 text-sm ${styles.text.secondary}`}>
          {user.requestedOn}
        </td>
        <td className="px-6 py-4">
          <StatusBadge status={user.status} />
        </td>
        <td className="px-6 py-4">
          <div className="flex space-x-1">
            {user.status === "pending" && (
              <>
                <button
                  onClick={() => handleApproveClick(user)}
                  disabled={isProcessing}
                  className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                    styles.button.approve
                  } ${isProcessing ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  {isProcessing ? "..." : "Approve"}
                </button>
                <button
                  onClick={() => handleReject(user.id)}
                  disabled={isProcessing}
                  className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                    styles.button.reject
                  } ${isProcessing ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  {isProcessing ? "..." : "Reject"}
                </button>
              </>
            )}

            {(user.status === "approved" || user.status === "rejected") && (
              <button
                onClick={() => handleReset(user.id)}
                disabled={isProcessing}
                className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                  styles.button.reset
                } ${isProcessing ? "opacity-50 cursor-not-allowed" : ""}`}
              >
                {isProcessing ? "..." : "Reset"}
              </button>
            )}

            {/* Super Admin Actions */}
            {isSuperAdmin() && (
              <>
                {(user.status === "approved" || user.status === "pending") && (
                  <button
                    onClick={() => handlePromoteToAdmin(user.id)}
                    disabled={isProcessing}
                    className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                      styles.button.promote
                    } ${isProcessing ? "opacity-50 cursor-not-allowed" : ""}`}
                  >
                    <UserPlus className="w-3 h-3" />
                  </button>
                )}

                {user.status === "admin" && (
                  <button
                    onClick={() => handleDemoteFromAdmin(user.id)}
                    disabled={isProcessing}
                    className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                      styles.button.demote
                    } ${isProcessing ? "opacity-50 cursor-not-allowed" : ""}`}
                  >
                    <UserMinus className="w-3 h-3" />
                  </button>
                )}

                {user.status !== "super_admin" && (
                  <button
                    onClick={() => handleDeleteUser(user.id)}
                    disabled={isProcessing}
                    className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                      styles.button.delete
                    } ${isProcessing ? "opacity-50 cursor-not-allowed" : ""}`}
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                )}
              </>
            )}

            {user.status === "super_admin" && (
              <span className={`px-2 py-1 text-xs ${styles.text.muted}`}>
                <Crown className="w-3 h-3" />
              </span>
            )}
          </div>
        </td>
      </tr>
    );
  };

  return (
    <MiftyAdminLayout>
      <div className="space-y-6 p-6">
        {/* Header */}
        <div className={`${styles.headerCard} rounded-xl p-6`}>
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div>
              <h1 className={`text-3xl font-bold ${styles.text.primary} mb-2`}>
                User Management
              </h1>
              <p className={styles.text.secondary}>
                Manage user access and approval status for your platform
              </p>
              <div className="mt-2">
                <span
                  className={`text-sm px-3 py-1 rounded-full ${
                    currentUserRole === "super_admin"
                      ? "bg-pink-900/30 text-pink-400"
                      : "bg-purple-900/30 text-purple-400"
                  }`}
                >
                  {currentUserRole === "super_admin" ? "Super Admin" : "Admin"}{" "}
                  Access
                </span>
              </div>
            </div>

            {/* Stats */}
            <div className="flex flex-wrap gap-4">
              <div
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg ${
                  isDarkMode ? "bg-gray-700" : "bg-gray-100"
                }`}
              >
                <Users className={`w-4 h-4 ${styles.text.muted}`} />
                <span className={`font-semibold ${styles.text.primary}`}>
                  {stats.total}
                </span>
                <span className={styles.text.secondary}>Total</span>
              </div>
              <div
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg ${
                  isDarkMode ? "bg-yellow-900/20" : "bg-yellow-50"
                }`}
              >
                <Clock
                  className={`w-4 h-4 ${
                    isDarkMode ? "text-yellow-400" : "text-yellow-600"
                  }`}
                />
                <span
                  className={`font-semibold ${
                    isDarkMode ? "text-yellow-300" : "text-yellow-700"
                  }`}
                >
                  {stats.pending}
                </span>
                <span
                  className={isDarkMode ? "text-yellow-400" : "text-yellow-600"}
                >
                  Pending
                </span>
              </div>
              <div
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg ${
                  isDarkMode ? "bg-green-900/20" : "bg-green-50"
                }`}
              >
                <CheckCircle
                  className={`w-4 h-4 ${
                    isDarkMode ? "text-green-400" : "text-green-600"
                  }`}
                />
                <span
                  className={`font-semibold ${
                    isDarkMode ? "text-green-300" : "text-green-700"
                  }`}
                >
                  {stats.approved}
                </span>
                <span
                  className={isDarkMode ? "text-green-400" : "text-green-600"}
                >
                  Approved
                </span>
              </div>
              <div
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg ${
                  isDarkMode ? "bg-purple-900/20" : "bg-purple-50"
                }`}
              >
                <Shield
                  className={`w-4 h-4 ${
                    isDarkMode ? "text-purple-400" : "text-purple-600"
                  }`}
                />
                <span
                  className={`font-semibold ${
                    isDarkMode ? "text-purple-300" : "text-purple-700"
                  }`}
                >
                  {stats.admin}
                </span>
                <span
                  className={isDarkMode ? "text-purple-400" : "text-purple-600"}
                >
                  Admins
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Messages */}
        {message.text && (
          <div
            className={`p-4 rounded-lg border ${
              message.type === "success"
                ? isDarkMode
                  ? "bg-green-900/20 border-green-600 text-green-400"
                  : "bg-green-50 border-green-200 text-green-800"
                : isDarkMode
                ? "bg-red-900/20 border-red-600 text-red-400"
                : "bg-red-50 border-red-200 text-red-800"
            }`}
          >
            <div className="flex items-center space-x-2">
              {message.type === "success" ? (
                <CheckCircle className="w-5 h-5" />
              ) : (
                <AlertCircle className="w-5 h-5" />
              )}
              <span>{message.text}</span>
            </div>
          </div>
        )}

        {error && (
          <div
            className={`p-4 rounded-lg border ${
              isDarkMode
                ? "bg-red-900/20 border-red-600 text-red-400"
                : "bg-red-50 border-red-200 text-red-800"
            }`}
          >
            <div className="flex items-center space-x-2">
              <AlertCircle className="w-5 h-5" />
              <span>{error}</span>
            </div>
          </div>
        )}

        {/* Controls */}
        {!loading && (
          <div className={`${styles.card} p-4`}>
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              {/* Left side - Search and Filter */}
              <div className="flex flex-col sm:flex-row gap-4 flex-1">
                {/* Search */}
                <div className="relative flex-1 max-w-md">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search users..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className={`pl-10 pr-4 py-2 w-full rounded-lg text-sm ${styles.input} focus:outline-none focus:ring-2 focus:ring-blue-500/20`}
                  />
                </div>

                {/* Status Filter */}
                <div className="flex items-center space-x-2">
                  <Filter className={`w-4 h-4 ${styles.text.muted}`} />
                  <select
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                    className={`px-3 py-2 rounded-lg text-sm ${styles.select} focus:outline-none focus:ring-2 focus:ring-blue-500/20`}
                  >
                    <option value="all">All Users ({stats.total})</option>
                    <option value="pending">Pending ({stats.pending})</option>
                    <option value="approved">
                      Approved ({stats.approved})
                    </option>
                    <option value="rejected">
                      Rejected ({stats.rejected})
                    </option>
                    <option value="admin">Admins ({stats.admin})</option>
                    {stats.super_admin > 0 && (
                      <option value="super_admin">
                        Super Admins ({stats.super_admin})
                      </option>
                    )}
                  </select>
                </div>
              </div>

              {/* Right side - View Toggle */}
              <div className="flex space-x-1 p-1 bg-gray-100 dark:bg-gray-700 rounded-lg">
                <button
                  onClick={() => setViewMode("grid")}
                  className={`px-3 py-1 rounded text-sm font-medium transition-all ${styles.button.view(
                    viewMode === "grid"
                  )}`}
                >
                  <Grid3x3 className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setViewMode("table")}
                  className={`px-3 py-1 rounded text-sm font-medium transition-all ${styles.button.view(
                    viewMode === "table"
                  )}`}
                >
                  <List className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Content */}
        <div className={styles.card}>
          {loading ? (
            <LoadingSpinner />
          ) : filteredUsers.length === 0 ? (
            <EmptyState />
          ) : viewMode === "grid" ? (
            /* Grid View */
            <div className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                {filteredUsers.map((user) => (
                  <UserCard key={user.id} user={user} />
                ))}
              </div>
            </div>
          ) : (
            /* Table View */
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr
                    className={`border-b ${
                      isDarkMode ? "border-gray-700" : "border-gray-200"
                    }`}
                  >
                    <th
                      className={`px-6 py-3 text-left text-xs font-medium uppercase tracking-wider ${styles.text.secondary}`}
                    >
                      User
                    </th>
                    <th
                      className={`px-6 py-3 text-left text-xs font-medium uppercase tracking-wider ${styles.text.secondary}`}
                    >
                      Email
                    </th>
                    <th
                      className={`px-6 py-3 text-left text-xs font-medium uppercase tracking-wider ${styles.text.secondary}`}
                    >
                      Domain
                    </th>
                    <th
                      className={`px-6 py-3 text-left text-xs font-medium uppercase tracking-wider ${styles.text.secondary}`}
                    >
                      Date
                    </th>
                    <th
                      className={`px-6 py-3 text-left text-xs font-medium uppercase tracking-wider ${styles.text.secondary}`}
                    >
                      Status
                    </th>
                    <th
                      className={`px-6 py-3 text-left text-xs font-medium uppercase tracking-wider ${styles.text.secondary}`}
                    >
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map((user) => (
                    <TableRow key={user.id} user={user} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Plan Selection Modal */}
      {showPlanModal && selectedUserForApproval && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-2xl p-6 w-full max-w-md mx-4 shadow-2xl`}>
            <h3 className={`text-xl font-bold mb-4 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
              Approve User with Plan
            </h3>
            
            <div className={`mb-4 p-3 rounded-lg ${isDarkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
              <p className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                {selectedUserForApproval.name}
              </p>
              <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                {selectedUserForApproval.email}
              </p>
              {selectedUserForApproval.oauth_provider && (
                <p className={`text-xs mt-1 ${isDarkMode ? 'text-cyan-400' : 'text-cyan-600'}`}>
                  via {selectedUserForApproval.oauth_provider.charAt(0).toUpperCase() + selectedUserForApproval.oauth_provider.slice(1)}
                </p>
              )}
            </div>

            <label className={`block text-sm font-medium mb-2 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
              Select Plan
            </label>
            <div className="space-y-2 mb-6">
              {availablePlans.map((plan) => (
                <label
                  key={plan.id}
                  className={`flex items-center p-3 rounded-lg border cursor-pointer transition-all ${
                    selectedPlan === plan.id
                      ? isDarkMode
                        ? 'border-cyan-500 bg-cyan-500/10'
                        : 'border-cyan-500 bg-cyan-50'
                      : isDarkMode
                        ? 'border-gray-600 hover:border-gray-500'
                        : 'border-gray-300 hover:border-gray-400'
                  }`}
                >
                  <input
                    type="radio"
                    name="plan"
                    value={plan.id}
                    checked={selectedPlan === plan.id}
                    onChange={(e) => setSelectedPlan(e.target.value)}
                    className="mr-3"
                  />
                  <div>
                    <p className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                      {plan.name}
                    </p>
                    <p className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                      {plan.description}
                    </p>
                  </div>
                </label>
              ))}
            </div>

            <div className="flex space-x-3">
              <button
                onClick={() => {
                  setShowPlanModal(false);
                  setSelectedUserForApproval(null);
                }}
                className={`flex-1 px-4 py-2 rounded-lg font-medium transition-all ${
                  isDarkMode
                    ? 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                }`}
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmApproval}
                disabled={processingIds.has(selectedUserForApproval?.id)}
                className="flex-1 px-4 py-2 bg-gradient-to-r from-green-500 to-emerald-500 text-white rounded-lg font-medium hover:from-green-600 hover:to-emerald-600 transition-all disabled:opacity-50"
              >
                {processingIds.has(selectedUserForApproval?.id) ? 'Approving...' : 'Approve'}
              </button>
            </div>
          </div>
        </div>
      )}
    </MiftyAdminLayout>
  );
};

export default AdminAccessRequests;
