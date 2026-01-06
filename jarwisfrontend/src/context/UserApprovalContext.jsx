// src/context/UserApprovalContext.jsx
// Enhanced context with Super Admin and Admin role hierarchy

import { createContext, useContext, useEffect, useState } from "react";
import {
  collection,
  doc,
  getDocs,
  updateDoc,
  deleteDoc,
  onSnapshot,
  query,
  orderBy,
  where,
  serverTimestamp,
} from "firebase/firestore";
import { db } from "../firebase/config";
import { useAuth } from "./FirebaseAuthContext";

const UserApprovalContext = createContext();

export const useUserApprovals = () => {
  const context = useContext(UserApprovalContext);
  if (!context) {
    throw new Error(
      "useUserApprovals must be used within a UserApprovalProvider"
    );
  }
  return context;
};

export const UserApprovalProvider = ({ children }) => {
  const [allUsers, setAllUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Get auth state from FirebaseAuthContext
  const { user, userDoc, loading: authLoading } = useAuth();

  // Collection reference for users
  const usersCollectionRef = collection(db, "users");

  // Role hierarchy checks
  const isSuperAdmin = () => {
    return userDoc?.role === "super_admin";
  };

  const isAdmin = () => {
    return userDoc?.role === "admin";
  };

  const canAccessAdminPanel = () => {
    return isSuperAdmin() || isAdmin();
  };

  const canManageUsers = () => {
    return isSuperAdmin() || isAdmin(); // Both can approve/reject/reset users
  };

  const canCreateAdmins = () => {
    return isSuperAdmin(); // Only super admins can create/demote admins
  };

  const canDeleteUsers = () => {
    return isSuperAdmin(); // Only super admins can delete users
  };

  // Email notification function (placeholder - you'll provide the actual implementation)
  const sendNotificationEmail = async (
    userEmail,
    notificationType,
    additionalData = {}
  ) => {
    try {
      // This is where you'll implement your email service
      console.log(
        `Sending ${notificationType} email to ${userEmail}`,
        additionalData
      );

      // Example structure for your email service:
      // const emailData = {
      //   to: userEmail,
      //   template: notificationType,
      //   data: additionalData
      // };
      // await emailService.send(emailData);

      return { success: true };
    } catch (error) {
      console.error("Error sending email:", error);
      return { success: false, error: error.message };
    }
  };

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
    if (userData.role === "super_admin") return "super_admin";
    if (userData.role === "admin") return "admin";
    if (userData.isApproved === true || userData.approvalStatus === "approved")
      return "approved";
    if (userData.approvalStatus === "rejected") return "rejected";
    return "pending";
  };

  // Real-time listener for all users (excluding current user)
  const setupRealtimeListener = () => {
    if (!user || !canAccessAdminPanel()) {
      setAllUsers([]);
      setLoading(false);
      return null;
    }

    try {
      // Query for all users except current user
      const q = query(usersCollectionRef, orderBy("createdAt", "desc"));

      const unsubscribe = onSnapshot(
        q,
        (querySnapshot) => {
          const usersData = querySnapshot.docs
            .map((doc) => {
              const data = doc.data();

              // Exclude current user from the list
              if (data.uid === user.uid) return null;

              const status = getUserStatus(data);

              return {
                id: doc.id,
                name: data.displayName || data.email,
                email: data.email,
                company: data.company || "Not specified",
                domain: data.email?.split("@")[1] || "Unknown",
                reason: `User registration via ${
                  data.provider || data.authProvider || "email"
                }`,
                requestedOn: formatDate(data.createdAt),
                status: status,
                lastUpdated: formatDate(data.lastUpdated),
                ...data,
              };
            })
            .filter(Boolean); // Remove null entries

          setAllUsers(usersData);
          setLoading(false);
          setError(null);
        },
        (err) => {
          console.error("Error in real-time listener:", err);

          if (err.code === "failed-precondition") {
            setError(
              "Database index not found. Creating indexes may take a few minutes."
            );
          } else if (err.code === "permission-denied") {
            setError("Permission denied. Admin access required.");
          } else {
            setError("Failed to listen for updates");
          }

          setLoading(false);
        }
      );

      return unsubscribe;
    } catch (err) {
      console.error("Error setting up real-time listener:", err);
      setError("Failed to setup real-time updates");
      setLoading(false);
      return null;
    }
  };

  // Approve a user (Both Admin and Super Admin can do this)
  const approveUser = async (userId) => {
    if (!user || !canManageUsers()) {
      return { success: false, message: "Admin access required" };
    }

    try {
      const userRef = doc(db, "users", userId);
      const targetUser = allUsers.find((u) => u.id === userId);

      await updateDoc(userRef, {
        role: "user", // Keep as user but approved
        isApproved: true,
        approvalStatus: "approved",
        approvedAt: serverTimestamp(),
        approvedBy: user.uid,
        approvedByRole: userDoc.role,
        lastUpdated: serverTimestamp(),
      });

      // Send approval email
      if (targetUser?.email) {
        await sendNotificationEmail(targetUser.email, "user_approved", {
          userName: targetUser.name,
          approvedBy: userDoc.displayName || userDoc.email,
          approvedByRole: userDoc.role,
          approvedAt: new Date().toISOString(),
        });
      }

      return { success: true, message: "User approved successfully!" };
    } catch (err) {
      console.error("Error approving user:", err);

      if (err.code === "permission-denied") {
        return {
          success: false,
          message: "Permission denied. Admin access required.",
        };
      }

      return { success: false, message: "Failed to approve user" };
    }
  };

  // Reject a user (Both Admin and Super Admin can do this)
  const rejectUser = async (userId, rejectionReason = "") => {
    if (!user || !canManageUsers()) {
      return { success: false, message: "Admin access required" };
    }

    try {
      const userRef = doc(db, "users", userId);
      const targetUser = allUsers.find((u) => u.id === userId);

      await updateDoc(userRef, {
        isApproved: false,
        approvalStatus: "rejected",
        rejectedAt: serverTimestamp(),
        rejectionReason: rejectionReason,
        rejectedBy: user.uid,
        rejectedByRole: userDoc.role,
        lastUpdated: serverTimestamp(),
      });

      // Send rejection email
      if (targetUser?.email) {
        await sendNotificationEmail(targetUser.email, "user_rejected", {
          userName: targetUser.name,
          rejectionReason: rejectionReason,
          rejectedBy: userDoc.displayName || userDoc.email,
          rejectedByRole: userDoc.role,
          rejectedAt: new Date().toISOString(),
        });
      }

      return { success: true, message: "User rejected successfully!" };
    } catch (err) {
      console.error("Error rejecting user:", err);

      if (err.code === "permission-denied") {
        return {
          success: false,
          message: "Permission denied. Admin access required.",
        };
      }

      return { success: false, message: "Failed to reject user" };
    }
  };

  // Reset approved user back to pending (Both Admin and Super Admin can do this)
  const resetUserToPending = async (userId) => {
    if (!user || !canManageUsers()) {
      return { success: false, message: "Admin access required" };
    }

    try {
      const userRef = doc(db, "users", userId);
      const targetUser = allUsers.find((u) => u.id === userId);

      await updateDoc(userRef, {
        isApproved: false,
        approvalStatus: "pending",
        role: "user",
        resetAt: serverTimestamp(),
        resetBy: user.uid,
        resetByRole: userDoc.role,
        lastUpdated: serverTimestamp(),
        // Clear previous approval/rejection data
        approvedAt: null,
        approvedBy: null,
        rejectedAt: null,
        rejectedBy: null,
        rejectionReason: null,
      });

      // Send reset email
      if (targetUser?.email) {
        await sendNotificationEmail(targetUser.email, "user_reset_to_pending", {
          userName: targetUser.name,
          resetBy: userDoc.displayName || userDoc.email,
          resetByRole: userDoc.role,
          resetAt: new Date().toISOString(),
        });
      }

      return { success: true, message: "User reset to pending successfully!" };
    } catch (err) {
      console.error("Error resetting user:", err);

      if (err.code === "permission-denied") {
        return {
          success: false,
          message: "Permission denied. Admin access required.",
        };
      }

      return { success: false, message: "Failed to reset user" };
    }
  };

  // Promote user to admin (Super Admin only)
  const promoteToAdmin = async (userId) => {
    if (!user || !canCreateAdmins()) {
      return { success: false, message: "Super Admin access required" };
    }

    try {
      const userRef = doc(db, "users", userId);
      const targetUser = allUsers.find((u) => u.id === userId);

      await updateDoc(userRef, {
        role: "admin",
        isApproved: true,
        approvalStatus: "approved",
        promotedToAdminAt: serverTimestamp(),
        promotedBy: user.uid,
        promotedByRole: userDoc.role,
        lastUpdated: serverTimestamp(),
      });

      // Send admin promotion email
      if (targetUser?.email) {
        await sendNotificationEmail(targetUser.email, "promoted_to_admin", {
          userName: targetUser.name,
          promotedBy: userDoc.displayName || userDoc.email,
          promotedAt: new Date().toISOString(),
        });
      }

      return { success: true, message: "User promoted to admin successfully!" };
    } catch (err) {
      console.error("Error promoting user to admin:", err);

      if (err.code === "permission-denied") {
        return {
          success: false,
          message: "Permission denied. Super Admin access required.",
        };
      }

      return { success: false, message: "Failed to promote user to admin" };
    }
  };

  // Demote admin to user (Super Admin only)
  const demoteFromAdmin = async (userId) => {
    if (!user || !canCreateAdmins()) {
      return { success: false, message: "Super Admin access required" };
    }

    try {
      const userRef = doc(db, "users", userId);
      const targetUser = allUsers.find((u) => u.id === userId);

      await updateDoc(userRef, {
        role: "user",
        isApproved: true,
        approvalStatus: "approved",
        demotedFromAdminAt: serverTimestamp(),
        demotedBy: user.uid,
        demotedByRole: userDoc.role,
        lastUpdated: serverTimestamp(),
      });

      // Send demotion email
      if (targetUser?.email) {
        await sendNotificationEmail(targetUser.email, "demoted_from_admin", {
          userName: targetUser.name,
          demotedBy: userDoc.displayName || userDoc.email,
          demotedAt: new Date().toISOString(),
        });
      }

      return { success: true, message: "Admin demoted to user successfully!" };
    } catch (err) {
      console.error("Error demoting admin:", err);

      if (err.code === "permission-denied") {
        return {
          success: false,
          message: "Permission denied. Super Admin access required.",
        };
      }

      return { success: false, message: "Failed to demote admin" };
    }
  };

  // Delete user (Super Admin only)
  const deleteUser = async (userId) => {
    if (!user || !canDeleteUsers()) {
      return { success: false, message: "Super Admin access required" };
    }

    try {
      const userRef = doc(db, "users", userId);
      const targetUser = allUsers.find((u) => u.id === userId);

      // Send deletion notification email before deleting
      if (targetUser?.email) {
        await sendNotificationEmail(targetUser.email, "account_deleted", {
          userName: targetUser.name,
          deletedBy: userDoc.displayName || userDoc.email,
          deletedAt: new Date().toISOString(),
          reason: "Account deleted by administrator",
        });
      }

      await deleteDoc(userRef);

      return { success: true, message: "User deleted successfully!" };
    } catch (err) {
      console.error("Error deleting user:", err);

      if (err.code === "permission-denied") {
        return {
          success: false,
          message: "Permission denied. Super Admin access required.",
        };
      }

      return { success: false, message: "Failed to delete user" };
    }
  };

  // Filter users by status
  const getFilteredUsers = (filterStatus) => {
    // For the "all" filter, we return the list of other users as intended
    if (filterStatus === "all") {
      return allUsers;
    }

    // Start by filtering the list of *other* users
    let filteredList = allUsers.filter((u) => u.status === filterStatus);

    // Now, check if the current user's role matches the active filter
    if (
      userDoc &&
      (filterStatus === "admin" || filterStatus === "super_admin") &&
      userDoc.role === filterStatus
    ) {
      // Double-check that the current user isn't somehow already in the list
      const isCurrentUserInList = filteredList.some(
        (u) => u.id === userDoc.uid
      );

      if (!isCurrentUserInList) {
        // Create a user object for the current admin that matches the data structure
        const currentUserObject = {
          id: userDoc.uid,
          name: `${userDoc.displayName || userDoc.email} (You)`,
          email: userDoc.email,
          company: userDoc.company || "Not specified",
          domain: userDoc.email?.split("@")[1] || "Unknown",
          reason: "Currently logged-in user",
          requestedOn: formatDate(userDoc.createdAt),
          status: userDoc.role,
          ...userDoc,
        };
        // Add the current user to the beginning of the filtered list
        filteredList.unshift(currentUserObject);
      }
    }

    return filteredList;
  };

  // Get approval statistics
  const getApprovalStats = () => {
    const stats = {
      total: allUsers.length,
      pending: 0,
      approved: 0,
      rejected: 0,
      admin: 0,
      super_admin: 0,
    };

    allUsers.forEach((user) => {
      stats[user.status]++;
    });

    if (userDoc) {
      // Increment the total user count to include the current user
      stats.total++;

      // Increment the count for the specific role
      if (userDoc.role === "admin") {
        stats.admin++;
      } else if (userDoc.role === "super_admin") {
        stats.super_admin++;
      }
    }

    return stats;
  };

  // Setup real-time listener when auth state changes
  useEffect(() => {
    if (authLoading) return;

    let unsubscribe = null;

    if (user && canAccessAdminPanel()) {
      unsubscribe = setupRealtimeListener();
    } else {
      setAllUsers([]);
      setLoading(false);
      setError(null);
    }

    return () => {
      if (unsubscribe) {
        unsubscribe();
      }
    };
  }, [user, userDoc, authLoading]);

  const value = {
    // State
    allUsers,
    loading: loading || authLoading,
    error,

    // Role checks
    isSuperAdmin,
    isAdmin,
    canAccessAdminPanel,
    canManageUsers,
    canCreateAdmins,
    canDeleteUsers,

    // User management actions
    approveRequest: approveUser,
    rejectRequest: rejectUser,
    resetUserToPending,
    promoteToAdmin,
    demoteFromAdmin,
    deleteUser,

    // Utility functions
    getFilteredUsers,
    getApprovalStats,

    // Auth state for debugging
    hasPermissions: user && canAccessAdminPanel(),
    currentUserRole: userDoc?.role,
  };

  return (
    <UserApprovalContext.Provider value={value}>
      {children}
    </UserApprovalContext.Provider>
  );
};
