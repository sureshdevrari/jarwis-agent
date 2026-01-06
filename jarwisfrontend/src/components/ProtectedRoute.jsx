// src/components/ProtectedRoute.jsx
// Protected route component using FastAPI + PostgreSQL authentication

import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const ProtectedRoute = ({ children, requireAdmin = false }) => {
  const {
    user,
    userDoc,
    loading,
    canAccessApp,
    canAccessAdmin,
    canAccessDashboard,
    getApprovalStatus,
    isAdmin,
  } = useAuth();
  const location = useLocation();

  // Show loading while auth is being determined
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-300">Loading...</p>
        </div>
      </div>
    );
  }

  // Not authenticated - redirect to login
  if (!user || !userDoc) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check admin access for admin routes
  if (requireAdmin && !canAccessAdmin()) {
    return <Navigate to="/login" replace />;
  }

  // For non-admin routes, check user approval status
  if (!requireAdmin) {
    const status = getApprovalStatus();

    switch (status) {
      case "admin":
        // Admins can access everything
        return children;

      case "approved":
        // Approved users can access dashboard
        return children;

      case "pending":
        // Pending users go to pending page
        if (location.pathname !== "/pending-approval") {
          return <Navigate to="/pending-approval" replace />;
        }
        return children;

      case "rejected":
        // Rejected users go to access denied page
        if (location.pathname !== "/access-denied") {
          return <Navigate to="/access-denied" replace />;
        }
        return children;

      default:
        // Unknown status - treat as pending
        return <Navigate to="/pending-approval" replace />;
    }
  }

  // Default: render children if all checks pass
  return children;
};

// Admin-only route wrapper
export const AdminRoute = ({ children }) => {
  return <ProtectedRoute requireAdmin={true}>{children}</ProtectedRoute>;
};

// Dashboard route wrapper (for approved users only)
export const DashboardRoute = ({ children }) => {
  const { canAccessDashboard } = useAuth();

  return (
    <ProtectedRoute>
      {canAccessDashboard() ? (
        children
      ) : (
        <Navigate to="/pending-approval" replace />
      )}
    </ProtectedRoute>
  );
};

export default ProtectedRoute;
