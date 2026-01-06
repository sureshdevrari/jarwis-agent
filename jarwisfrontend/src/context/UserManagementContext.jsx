// src/context/UserManagementContext.jsx
// User management context for admin panel using FastAPI + PostgreSQL
// Replaces UserApprovalContext.jsx

import { createContext, useContext, useEffect, useState, useCallback } from "react";
import { adminAPI } from "../services/api";
import { useAuth } from "./AuthContext";

const UserManagementContext = createContext();

export const useUserManagement = () => {
  const context = useContext(UserManagementContext);
  if (!context) {
    throw new Error(
      "useUserManagement must be used within a UserManagementProvider"
    );
  }
  return context;
};

// Alias for backward compatibility
export const useUserApprovals = useUserManagement;

export const UserManagementProvider = ({ children }) => {
  const [allUsers, setAllUsers] = useState([]);
  const [dashboardStats, setDashboardStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [pagination, setPagination] = useState({
    page: 1,
    perPage: 20,
    total: 0,
  });

  // Get auth state
  const { user, userDoc, loading: authLoading } = useAuth();

  // Role hierarchy checks
  const isSuperAdmin = useCallback(() => {
    return userDoc?.role === "super_admin" || userDoc?.is_superuser === true;
  }, [userDoc]);

  const isAdmin = useCallback(() => {
    return userDoc?.role === "super_admin" || userDoc?.is_superuser === true;
  }, [userDoc]);

  const canAccessAdminPanel = useCallback(() => {
    return isSuperAdmin() || isAdmin();
  }, [isSuperAdmin, isAdmin]);

  const canManageUsers = useCallback(() => {
    return isSuperAdmin() || isAdmin();
  }, [isSuperAdmin, isAdmin]);

  const canCreateAdmins = useCallback(() => {
    return isSuperAdmin();
  }, [isSuperAdmin]);

  const canDeleteUsers = useCallback(() => {
    return isSuperAdmin();
  }, [isSuperAdmin]);

  // Format date for display
  const formatDate = (timestamp) => {
    if (!timestamp) return "Unknown";

    let date;
    if (typeof timestamp === "string") {
      date = new Date(timestamp);
    } else if (timestamp.toDate) {
      date = timestamp.toDate();
    } else {
      date = new Date(timestamp);
    }

    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays === 1) return "Today";
    if (diffDays === 2) return "Yesterday";
    if (diffDays <= 7) return `${diffDays - 1} days ago`;

    return date.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: date.getFullYear() !== now.getFullYear() ? "numeric" : undefined,
    });
  };

  // Get user status
  const getUserStatus = (userData) => {
    if (userData.role === "super_admin" || userData.is_superuser) return "admin";
    if (userData.approval_status === "approved" || userData.is_verified) return "approved";
    if (userData.approval_status === "disabled" || !userData.is_active) return "rejected";
    return "pending";
  };

  // Fetch dashboard stats
  const fetchDashboardStats = useCallback(async () => {
    if (!canAccessAdminPanel()) return;

    try {
      const stats = await adminAPI.getDashboardStats();
      setDashboardStats(stats);
      return stats;
    } catch (err) {
      console.error("Error fetching dashboard stats:", err);
      throw err;
    }
  }, [canAccessAdminPanel]);

  // Fetch all users
  const fetchUsers = useCallback(async (params = {}) => {
    if (!canAccessAdminPanel()) {
      setAllUsers([]);
      setLoading(false);
      return [];
    }

    setLoading(true);
    setError(null);

    try {
      const response = await adminAPI.getUsers({
        page: params.page || pagination.page,
        per_page: params.perPage || pagination.perPage,
        status_filter: params.statusFilter,
        search: params.search,
      });

      const usersData = response.users.map((userData) => ({
        id: userData.id,
        name: userData.full_name || userData.username,
        email: userData.email,
        company: userData.company || "Not specified",
        domain: userData.email?.split("@")[1] || "Unknown",
        reason: userData.oauth_provider 
          ? `Signed up via ${userData.oauth_provider.charAt(0).toUpperCase() + userData.oauth_provider.slice(1)}` 
          : "User registration via email",
        requestedOn: formatDate(userData.created_at),
        status: getUserStatus(userData),
        lastUpdated: formatDate(userData.last_login),
        scansCount: userData.scans_count || 0,
        oauth_provider: userData.oauth_provider,
        plan: userData.plan || "free",
        ...userData,
      }));

      setAllUsers(usersData);
      setPagination({
        page: response.page,
        perPage: response.per_page,
        total: response.total,
      });
      setLoading(false);

      return usersData;
    } catch (err) {
      console.error("Error fetching users:", err);
      setError(err.response?.data?.detail || "Failed to fetch users");
      setLoading(false);
      throw err;
    }
  }, [canAccessAdminPanel, pagination.page, pagination.perPage]);

  // Approve user
  const approveUser = useCallback(async (userId, plan = 'free') => {
    if (!canManageUsers()) {
      throw new Error("Permission denied");
    }

    try {
      const result = await adminAPI.approveUser(userId, plan);
      await fetchUsers(); // Refresh list
      return result;
    } catch (err) {
      console.error("Error approving user:", err);
      throw new Error(err.response?.data?.detail || "Failed to approve user");
    }
  }, [canManageUsers, fetchUsers]);

  // Set user plan
  const setUserPlan = useCallback(async (userId, plan) => {
    if (!canManageUsers()) {
      throw new Error("Permission denied");
    }

    try {
      const result = await adminAPI.setUserPlan(userId, plan);
      await fetchUsers(); // Refresh list
      return result;
    } catch (err) {
      console.error("Error setting user plan:", err);
      throw new Error(err.response?.data?.detail || "Failed to set user plan");
    }
  }, [canManageUsers, fetchUsers]);

  // Get available plans
  const getPlans = useCallback(async () => {
    try {
      const result = await adminAPI.getPlans();
      return result.plans || [];
    } catch (err) {
      console.error("Error fetching plans:", err);
      return [
        { id: 'free', name: 'Free' },
        { id: 'individual', name: 'Individual' },
        { id: 'professional', name: 'Professional' },
        { id: 'enterprise', name: 'Enterprise' },
      ];
    }
  }, []);

  // Reject user
  const rejectUser = useCallback(async (userId) => {
    if (!canManageUsers()) {
      throw new Error("Permission denied");
    }

    try {
      const result = await adminAPI.rejectUser(userId);
      await fetchUsers(); // Refresh list
      return result;
    } catch (err) {
      console.error("Error rejecting user:", err);
      throw new Error(err.response?.data?.detail || "Failed to reject user");
    }
  }, [canManageUsers, fetchUsers]);

  // Reset user status
  const resetUserStatus = useCallback(async (userId) => {
    if (!canManageUsers()) {
      throw new Error("Permission denied");
    }

    try {
      const result = await adminAPI.resetUserStatus(userId);
      await fetchUsers(); // Refresh list
      return result;
    } catch (err) {
      console.error("Error resetting user status:", err);
      throw new Error(err.response?.data?.detail || "Failed to reset user status");
    }
  }, [canManageUsers, fetchUsers]);

  // Delete user
  const deleteUser = useCallback(async (userId) => {
    if (!canDeleteUsers()) {
      throw new Error("Permission denied - Super admin access required");
    }

    try {
      const result = await adminAPI.deleteUser(userId);
      await fetchUsers(); // Refresh list
      return result;
    } catch (err) {
      console.error("Error deleting user:", err);
      throw new Error(err.response?.data?.detail || "Failed to delete user");
    }
  }, [canDeleteUsers, fetchUsers]);

  // Make user admin
  const makeAdmin = useCallback(async (userId) => {
    if (!canCreateAdmins()) {
      throw new Error("Permission denied - Super admin access required");
    }

    try {
      const result = await adminAPI.makeAdmin(userId);
      await fetchUsers(); // Refresh list
      return result;
    } catch (err) {
      console.error("Error making user admin:", err);
      throw new Error(err.response?.data?.detail || "Failed to make user admin");
    }
  }, [canCreateAdmins, fetchUsers]);

  // Remove admin
  const removeAdmin = useCallback(async (userId) => {
    if (!canCreateAdmins()) {
      throw new Error("Permission denied - Super admin access required");
    }

    try {
      const result = await adminAPI.removeAdmin(userId);
      await fetchUsers(); // Refresh list
      return result;
    } catch (err) {
      console.error("Error removing admin:", err);
      throw new Error(err.response?.data?.detail || "Failed to remove admin");
    }
  }, [canCreateAdmins, fetchUsers]);

  // Get user details
  const getUserDetails = useCallback(async (userId) => {
    if (!canAccessAdminPanel()) {
      throw new Error("Permission denied");
    }

    try {
      return await adminAPI.getUserDetails(userId);
    } catch (err) {
      console.error("Error getting user details:", err);
      throw new Error(err.response?.data?.detail || "Failed to get user details");
    }
  }, [canAccessAdminPanel]);

  // Update user
  const updateUser = useCallback(async (userId, data) => {
    if (!canManageUsers()) {
      throw new Error("Permission denied");
    }

    try {
      const result = await adminAPI.updateUser(userId, data);
      await fetchUsers(); // Refresh list
      return result;
    } catch (err) {
      console.error("Error updating user:", err);
      throw new Error(err.response?.data?.detail || "Failed to update user");
    }
  }, [canManageUsers, fetchUsers]);

  // Initial fetch when user is authenticated and has access
  useEffect(() => {
    if (!authLoading && user && canAccessAdminPanel()) {
      fetchUsers();
      fetchDashboardStats();
    } else if (!authLoading) {
      setLoading(false);
    }
  }, [authLoading, user, canAccessAdminPanel, fetchUsers, fetchDashboardStats]);

  // Filter helpers - check both status and approval_status for compatibility
  const getStatus = (u) => u.status || u.approval_status || "pending";
  const pendingUsers = allUsers.filter((u) => getStatus(u) === "pending");
  const approvedUsers = allUsers.filter((u) => getStatus(u) === "approved");
  const rejectedUsers = allUsers.filter((u) => getStatus(u) === "rejected");
  const adminUsers = allUsers.filter((u) => getStatus(u) === "admin" || u.is_superuser);
  // Users who haven't verified email yet
  const emailUnverifiedUsers = allUsers.filter((u) => getStatus(u) === "email_unverified");

  // Get filtered users by status - for backward compatibility
  const getFilteredUsers = useCallback((status = "all") => {
    switch (status) {
      case "pending":
        return pendingUsers;
      case "approved":
        return approvedUsers;
      case "rejected":
        return rejectedUsers;
      case "admin":
      case "super_admin":
        return adminUsers;
      case "all":
      default:
        return allUsers;
    }
  }, [allUsers, pendingUsers, approvedUsers, rejectedUsers, adminUsers]);

  // Get approval stats - for backward compatibility
  const getApprovalStats = useCallback(() => {
    return {
      total: allUsers.length,
      pending: pendingUsers.length,
      approved: approvedUsers.length,
      rejected: rejectedUsers.length,
      admins: adminUsers.length,
    };
  }, [allUsers.length, pendingUsers.length, approvedUsers.length, rejectedUsers.length, adminUsers.length]);

  // Alias functions for backward compatibility
  const approveRequest = useCallback(async (userId, plan = 'free') => {
    try {
      await approveUser(userId, plan);
      return { success: true, message: `User approved with ${plan} plan` };
    } catch (err) {
      return { success: false, message: err.message };
    }
  }, [approveUser]);

  const rejectRequest = useCallback(async (userId) => {
    try {
      await rejectUser(userId);
      return { success: true, message: "User rejected successfully" };
    } catch (err) {
      return { success: false, message: err.message };
    }
  }, [rejectUser]);

  const resetUserToPending = useCallback(async (userId) => {
    try {
      await resetUserStatus(userId);
      return { success: true, message: "User status reset successfully" };
    } catch (err) {
      return { success: false, message: err.message };
    }
  }, [resetUserStatus]);

  const promoteToAdmin = useCallback(async (userId) => {
    try {
      await makeAdmin(userId);
      return { success: true, message: "User promoted to admin successfully" };
    } catch (err) {
      return { success: false, message: err.message };
    }
  }, [makeAdmin]);

  const demoteFromAdmin = useCallback(async (userId) => {
    try {
      await removeAdmin(userId);
      return { success: true, message: "Admin demoted successfully" };
    } catch (err) {
      return { success: false, message: err.message };
    }
  }, [removeAdmin]);

  // Get current user role - for backward compatibility
  const currentUserRole = userDoc?.role || (userDoc?.is_superuser ? "super_admin" : "user");

  const value = {
    // Data
    allUsers,
    pendingUsers,
    approvedUsers,
    rejectedUsers,
    adminUsers,
    emailUnverifiedUsers,
    dashboardStats,
    loading,
    error,
    pagination,
    currentUserRole,

    // Permission checks
    isSuperAdmin,
    isAdmin,
    canAccessAdminPanel,
    canManageUsers,
    canCreateAdmins,
    canDeleteUsers,

    // Actions
    fetchUsers,
    fetchDashboardStats,
    approveUser,
    rejectUser,
    resetUserStatus,
    deleteUser,
    makeAdmin,
    removeAdmin,
    getUserDetails,
    updateUser,
    setUserPlan,
    getPlans,

    // Backward compatibility aliases
    getFilteredUsers,
    getApprovalStats,
    approveRequest,
    rejectRequest,
    resetUserToPending,
    promoteToAdmin,
    demoteFromAdmin,

    // Helpers
    formatDate,
    getUserStatus,
  };

  return (
    <UserManagementContext.Provider value={value}>
      {children}
    </UserManagementContext.Provider>
  );
};

// Alias for backward compatibility
export const UserApprovalProvider = UserManagementProvider;

export default UserManagementContext;
