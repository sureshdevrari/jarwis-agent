import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const UserDashboardRoute = ({ children }) => {
  const {
    user,
    userDoc,
    loading,
    canAccessDashboard,
    getApprovalStatus,
    isAdmin,
  } = useAuth();

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
    return <Navigate to="/login" replace />;
  }

  // Get user approval status
  const status = getApprovalStatus();

  // Handle different user statuses
  switch (status) {
    case "super-admin":
      return children;
    case "admin":
      // Admins should go to admin panel, but can access dashboard if they want
      return children;

    case "approved":
      // Approved users can access dashboard
      return children;

    case "pending":
      // Pending users go to pending approval page
      return <Navigate to="/pending-approval" replace />;

    case "rejected":
      // Rejected users go to access denied page
      return <Navigate to="/access-denied" replace />;

    default:
      // Unknown status - treat as pending
      return <Navigate to="/pending-approval" replace />;
  }
};

export default UserDashboardRoute;
