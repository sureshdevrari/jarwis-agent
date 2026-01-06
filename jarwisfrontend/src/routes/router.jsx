import { createBrowserRouter } from "react-router-dom";
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

// Public Pages
import Home from "../pages/HomeNew";  // Updated to use new Devin-inspired landing page
import About from "../pages/About";
import Header from "../components/Header";
import NotFound from "../pages/NotFound";
import Contact from "../pages/Contact";
import Login from "../pages/auth/Login";
import Signup from "../pages/auth/Signup";
import PricingPlans from "../pages/PricingPlans";
import Privacy from "../pages/Privacy";
import TermsofService from "../pages/TermsofService";
import RefundReturnPolicy from "../pages/RefundReturnPolicy";
import RequestTrialAccess from "../pages/RequestTrialAccess";

// Auth Status Pages
import PendingApproval from "../pages/auth/PendingApproval";
import AccessDenied from "../pages/auth/AccessDenied";
import OAuthCallback from "../pages/auth/OAuthCallback";
import ForgotPassword from "../pages/auth/ForgotPassword";
import ResetPassword from "../pages/auth/ResetPassword";
import VerifyEmail from "../pages/auth/VerifyEmail";
import FirebaseAction from "../pages/auth/FirebaseAction";

// Payment Pages
import PaymentSuccess from "../pages/PaymentSuccess";

// Route Protection Components
import ProtectedRoute from "../components/ProtectedRoute";
import AdminRoute from "../routes/AdminRoute";
import UserDashboardRoute from "../routes/UserDashboardRoute";
import ScrollToTop from "../components/ScrollToTop";

// Jarwis Dashboard Components
import JarwisDashboard from "../pages/dashboard/JarwisDashboard";
import NewScan from "../pages/dashboard/NewScan";
import VerifyDomain from "../pages/dashboard/VerifyDomain";
import Scanning from "../pages/dashboard/Scanning";
import Vulnerabilities from "../pages/dashboard/Vulnerabilities";
import VulnerabilityDetails from "../pages/dashboard/VulnerabilityDetails";
import JarwisChatbot from "../pages/dashboard/JarwisChatbot";
import ScanHistory from "../pages/dashboard/ScanHistory";
import Billing from "../pages/dashboard/Billing";
import Reports from "../pages/dashboard/Reports";

// Admin Pages
import AdminOverview from "../pages/admin/AdminOverview";
import AdminAccessRequests from "../pages/admin/AdminAccessRequests";
import AdminUsersAndTenants from "../pages/admin/AdminUsersAndTenants";
import AdminUserDetails from "../pages/admin/AdminUserDetails";
import AdminPushVulnerability from "../pages/admin/AdminPushVulnerability";
import AdminAuditLog from "../pages/admin/AdminAuditLog";
import AdminContactSubmissions from "../pages/admin/AdminContactSubmissions";

// Component to handle role-based redirects
const RoleBasedRedirect = () => {
  const { user, userDoc, loading, getApprovalStatus } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!loading && user && userDoc) {
      const status = getApprovalStatus();

      // Redirect based on user status
      switch (status) {
        case "admin":
          navigate("/admin", { replace: true });
          break;
        case "approved":
          navigate("/dashboard", { replace: true });
          break;
        case "pending":
          navigate("/pending-approval", { replace: true });
          break;
        case "rejected":
          navigate("/access-denied", { replace: true });
          break;
        default:
          navigate("/pending-approval", { replace: true });
          break;
      }
    } else if (!loading && !user) {
      // If not authenticated, redirect to home
      navigate("/", { replace: true });
    }
  }, [user, userDoc, loading, navigate, getApprovalStatus]);

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

  return null;
};

// Root layout component for public pages
const PublicLayout = () => {
  return (
    <>
      <ScrollToTop />
      <Header />
    </>
  );
};

const router = createBrowserRouter([
  // Public Routes with Header
  {
    path: "/",
    element: <PublicLayout />,
    children: [
      {
        index: true, // This makes it the default route for "/"
        element: <Home />,
      },
      {
        path: "about",
        element: <About />,
      },
      {
        path: "contact",
        element: <Contact />,
      },
      {
        path: "pricing",
        element: <PricingPlans />,
      },
      {
        path: "privacy",
        element: <Privacy />,
      },
      {
        path: "terms",
        element: <TermsofService />,
      },
      {
        path: "refund&return",
        element: <RefundReturnPolicy />,
      },
      {
        path: "request-trial",
        element: <RequestTrialAccess />,
      },
      // Payment Routes
      {
        path: "payment-success",
        element: <PaymentSuccess />,
      },
      // Authentication Routes
      {
        path: "/login",
        element: <Login />,
      },
      {
        path: "/signup",
        element: <Signup />,
      },
      {
        path: "/oauth/callback",
        element: <OAuthCallback />,
      },
      {
        path: "/forgot-password",
        element: <ForgotPassword />,
      },
      {
        path: "/reset-password",
        element: <ResetPassword />,
      },
      {
        path: "/verify-email",
        element: <VerifyEmail />,
      },
      {
        path: "/__/auth/action",
        element: <FirebaseAction />,
      },
    ],
  },

  // Authentication Status Routes (protected but accessible to specific states)
  {
    path: "/pending-approval",
    element: (
      <ProtectedRoute>
        <PendingApproval />
      </ProtectedRoute>
    ),
  },
  {
    path: "/access-denied",
    element: (
      <ProtectedRoute>
        <AccessDenied />
      </ProtectedRoute>
    ),
  },

  // User Dashboard Routes (Approved Users Only)
  {
    path: "/dashboard",
    element: (
      <UserDashboardRoute>
        <JarwisDashboard />
      </UserDashboardRoute>
    ),
  },
  {
    path: "/dashboard/new-scan",
    element: (
      <UserDashboardRoute>
        <NewScan />
      </UserDashboardRoute>
    ),
  },
  {
    path: "/dashboard/verify-domain",
    element: (
      <UserDashboardRoute>
        <VerifyDomain />
      </UserDashboardRoute>
    ),
  },
  {
    path: "/dashboard/scanning",
    element: (
      <UserDashboardRoute>
        <Scanning />
      </UserDashboardRoute>
    ),
  },
  {
    path: "/dashboard/vulnerabilities",
    element: (
      <UserDashboardRoute>
        <Vulnerabilities />
      </UserDashboardRoute>
    ),
  },
  {
    path: "/dashboard/vulnerability/:id",
    element: (
      <UserDashboardRoute>
        <VulnerabilityDetails />
      </UserDashboardRoute>
    ),
  },
  {
    path: "/dashboard/chatbot",
    element: (
      <UserDashboardRoute>
        <JarwisChatbot />
      </UserDashboardRoute>
    ),
  },
  {
    path: "/dashboard/jarwis-chatbot",
    element: (
      <UserDashboardRoute>
        <JarwisChatbot />
      </UserDashboardRoute>
    ),
  },
  {
    path: "/dashboard/scan-history",
    element: (
      <UserDashboardRoute>
        <ScanHistory />
      </UserDashboardRoute>
    ),
  },
  {
    path: "/dashboard/billing",
    element: (
      <UserDashboardRoute>
        <Billing />
      </UserDashboardRoute>
    ),
  },
  {
    path: "/dashboard/reports",
    element: (
      <UserDashboardRoute>
        <Reports />
      </UserDashboardRoute>
    ),
  },

  // Admin Routes (Admin Only)
  {
    path: "/admin",
    element: (
      <AdminRoute>
        <AdminOverview />
      </AdminRoute>
    ),
  },
  {
    path: "/admin/requests",
    element: (
      <AdminRoute>
        <AdminAccessRequests />
      </AdminRoute>
    ),
  },
  {
    path: "/admin/users",
    element: (
      <AdminRoute>
        <AdminUsersAndTenants />
      </AdminRoute>
    ),
  },
  {
    path: "/admin/users/:userId",
    element: (
      <AdminRoute>
        <AdminUserDetails />
      </AdminRoute>
    ),
  },
  {
    path: "/admin/push-vulnerability",
    element: (
      <AdminRoute>
        <AdminPushVulnerability />
      </AdminRoute>
    ),
  },
  {
    path: "/admin/audit-log",
    element: (
      <AdminRoute>
        <AdminAuditLog />
      </AdminRoute>
    ),
  },
  {
    path: "/admin/submissions",
    element: (
      <AdminRoute>
        <AdminContactSubmissions />
      </AdminRoute>
    ),
  },

  // Role-based redirect route
  {
    path: "/app",
    element: (
      <ProtectedRoute>
        <RoleBasedRedirect />
      </ProtectedRoute>
    ),
  },

  // Payment Routes (for future implementation)
  {
    path: "/pay/:plan",
    element: (
      <UserDashboardRoute>
        <NotFound />
      </UserDashboardRoute>
    ),
  },

  // Catch all - 404
  {
    path: "*",
    element: (
      <>
        <ScrollToTop />
        <NotFound />
      </>
    ),
  },
]);

export default router;
