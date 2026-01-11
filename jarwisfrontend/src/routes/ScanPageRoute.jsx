/**
 * ScanPageRoute - Route guard for scan pages
 * 
 * Blocks personal email users who haven't verified any domains.
 * Redirects them to Settings with domain verification tab.
 */

import { useState, useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { domainVerificationAPI } from '../services/api';

// List of personal/free email providers - must verify domains
const FREE_EMAIL_PROVIDERS = [
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.in', 'yahoo.co.uk',
  'hotmail.com', 'outlook.com', 'live.com', 'msn.com', 'aol.com',
  'icloud.com', 'me.com', 'mac.com', 'protonmail.com', 'proton.me',
  'zoho.com', 'mail.com', 'yandex.com', 'gmx.com', 'gmx.net',
  'rediffmail.com', 'tutanota.com', 'fastmail.com',
];

const isPersonalEmail = (email) => {
  if (!email || !email.includes('@')) return true;
  const domain = email.split('@')[1]?.toLowerCase();
  return FREE_EMAIL_PROVIDERS.includes(domain);
};

const ScanPageRoute = ({ children }) => {
  const { user, userDoc, loading, getApprovalStatus } = useAuth();
  const [checkingDomains, setCheckingDomains] = useState(true);
  const [canScan, setCanScan] = useState(true);
  const location = useLocation();

  useEffect(() => {
    const checkDomainAccess = async () => {
      // Skip check for non-personal emails (corporate users)
      if (!isPersonalEmail(user?.email)) {
        setCanScan(true);
        setCheckingDomains(false);
        return;
      }

      try {
        const result = await domainVerificationAPI.hasVerifiedDomains();
        setCanScan(result.can_scan);
      } catch (error) {
        console.error("Failed to check domain access:", error);
        // On error, block access for personal emails (safe default)
        setCanScan(false);
      } finally {
        setCheckingDomains(false);
      }
    };

    if (user?.email && !loading) {
      checkDomainAccess();
    } else if (!loading && (!user || !userDoc)) {
      setCheckingDomains(false);
    }
  }, [user?.email, loading, user, userDoc]);

  // Show loading while auth or domain check is in progress
  if (loading || checkingDomains) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500 mx-auto mb-4"></div>
          <p className="text-gray-300">
            {loading ? 'Loading...' : 'Checking access...'}
          </p>
        </div>
      </div>
    );
  }

  // Not authenticated - redirect to login
  if (!user || !userDoc) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Get user approval status
  const status = getApprovalStatus();

  // Handle non-approved users
  if (status === 'pending') {
    return <Navigate to="/pending-approval" replace />;
  }
  if (status === 'rejected') {
    return <Navigate to="/access-denied" replace />;
  }

  // Personal email user without verified domains - redirect to settings
  if (!canScan) {
    return (
      <Navigate
        to="/dashboard/settings?tab=domains&reason=verification_required"
        state={{ 
          from: location, 
          requireVerification: true,
          message: 'Please verify at least one domain before starting scans.'
        }}
        replace
      />
    );
  }

  // All checks passed - render children
  return children;
};

export default ScanPageRoute;
