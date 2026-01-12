// src/components/scan/ScanWizard.jsx - Enterprise Scan Wizard with Animated Steps
import { useState, useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import { useAuth } from "../../context/AuthContext";
import { scanAPI, domainAPI, domainVerificationAPI } from "../../services/api";
import {
  Check,
  CheckCircle,
  Lock,
  Shield,
  Zap,
  Smartphone,
  MessageSquare,
  Rocket,
  AlertTriangle,
  Lightbulb,
  Plug,
  Key,
  Link,
  Cookie
} from "lucide-react";

// Step configurations for each scan type
const SCAN_TYPE_STEPS = {
  web: [
    { id: "target", title: "Target", description: "Enter target URL" },
    { id: "config", title: "Configuration", description: "Scan options" },
    { id: "auth", title: "Authentication", description: "Login credentials (optional)" },
    { id: "review", title: "Review", description: "Confirm and start" },
  ],
  mobile: [
    { id: "upload", title: "Upload", description: "Upload APK/IPA file" },
    { id: "config", title: "Configuration", description: "Analysis options" },
    { id: "review", title: "Review", description: "Confirm and start" },
  ],
  network: [
    { id: "target", title: "Targets", description: "IP addresses or ranges" },
    { id: "config", title: "Configuration", description: "Scan profile" },
    { id: "review", title: "Review", description: "Confirm and start" },
  ],
  cloud: [
    { id: "provider", title: "Provider", description: "Select cloud platform" },
    { id: "credentials", title: "Credentials", description: "Connect account" },
    { id: "config", title: "Scope", description: "Select resources" },
    { id: "review", title: "Review", description: "Confirm and start" },
  ],
};

// Progress indicator component
const StepIndicator = ({ steps, currentStep, isDarkMode }) => {
  return (
    <div className="relative px-4 py-6">
      {/* Progress line background */}
      <div className={`absolute top-1/2 left-8 right-8 h-1 -translate-y-1/2 rounded-full ${isDarkMode ? "bg-gray-700" : "bg-gray-200"}`} />
      
      {/* Animated progress line */}
      <motion.div
        className="absolute top-1/2 left-8 h-1 -translate-y-1/2 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500"
        initial={{ width: "0%" }}
        animate={{ width: `${(currentStep / (steps.length - 1)) * 100}%` }}
        transition={{ duration: 0.4, ease: "easeOut" }}
        style={{ maxWidth: "calc(100% - 4rem)" }}
      />
      
      {/* Step circles */}
      <div className="relative flex justify-between">
        {steps.map((step, index) => {
          const isCompleted = index < currentStep;
          const isCurrent = index === currentStep;
          const isUpcoming = index > currentStep;
          
          return (
            <div key={step.id} className="flex flex-col items-center">
              <motion.div
                className={`
                  w-10 h-10 rounded-full flex items-center justify-center font-semibold text-sm
                  transition-all duration-300 border-2
                  ${isCompleted 
                    ? "bg-gradient-to-br from-cyan-500 to-blue-500 border-transparent text-white shadow-lg shadow-cyan-500/30" 
                    : isCurrent 
                      ? isDarkMode 
                        ? "bg-gray-800 border-cyan-500 text-cyan-400 shadow-lg shadow-cyan-500/20" 
                        : "bg-white border-cyan-500 text-cyan-600 shadow-lg shadow-cyan-500/20"
                      : isDarkMode
                        ? "bg-gray-800 border-gray-600 text-gray-500"
                        : "bg-gray-100 border-gray-300 text-gray-400"
                  }
                `}
                initial={{ scale: 0.8 }}
                animate={{ 
                  scale: isCurrent ? 1.1 : 1,
                }}
                transition={{ duration: 0.3 }}
              >
                {isCompleted ? (
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                  </svg>
                ) : (
                  index + 1
                )}
              </motion.div>
              
              <div className="mt-2 text-center">
                <p className={`text-sm font-medium ${
                  isCurrent 
                    ? isDarkMode ? "text-white" : "text-gray-900"
                    : isCompleted
                      ? isDarkMode ? "text-cyan-400" : "text-cyan-600"
                      : isDarkMode ? "text-gray-500" : "text-gray-400"
                }`}>
                  {step.title}
                </p>
                <p className={`text-xs hidden sm:block ${isDarkMode ? "text-gray-600" : "text-gray-400"}`}>
                  {step.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

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

// Normalize URL to ensure it has https:// protocol
const normalizeUrl = (url) => {
  if (!url || typeof url !== 'string') return url;
  const trimmed = url.trim();
  if (!trimmed) return trimmed;
  
  // Already has protocol
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return trimmed;
  }
  
  // Add https:// by default
  return `https://${trimmed}`;
};

// Check if URL needs protocol prefix (for display hint)
const urlNeedsProtocol = (url) => {
  if (!url || typeof url !== 'string') return false;
  const trimmed = url.trim();
  if (!trimmed) return false;
  return !trimmed.startsWith('http://') && !trimmed.startsWith('https://');
};

// Web scan target step with DYNAMIC domain verification
const WebTargetStep = ({ formData, setFormData, isDarkMode, verifiedDomains }) => {
  const { user } = useAuth();
  const [domainStatus, setDomainStatus] = useState(null);
  const [checkingDomain, setCheckingDomain] = useState(false);
  const [authorizationResult, setAuthorizationResult] = useState(null);
  
  const userHasPersonalEmail = isPersonalEmail(user?.email);
  const userEmailDomain = user?.email?.split('@')[1]?.toLowerCase();
  
  // Dynamic domain check with debounce
  const checkDomain = useCallback(async (url) => {
    if (!url) {
      setDomainStatus(null);
      setAuthorizationResult(null);
      return;
    }
    
    // Validate URL first
    let domain;
    try {
      domain = new URL(url.startsWith("http") ? url : `https://${url}`).hostname;
    } catch {
      setDomainStatus("invalid");
      setAuthorizationResult(null);
      return;
    }
    
    setCheckingDomain(true);
    
    try {
      // Call the API to check authorization
      const result = await domainVerificationAPI.checkAuthorization(url);
      setAuthorizationResult(result);
      
      if (result.authorized) {
        setDomainStatus("verified");
        // Store in formData for canProceed check
        setFormData(prev => ({ ...prev, domain_authorized: true, domain_check_reason: result.reason }));
      } else {
        setDomainStatus("unverified");
        setFormData(prev => ({ ...prev, domain_authorized: false, domain_check_reason: result.reason }));
      }
    } catch (error) {
      console.error("Domain check failed:", error);
      // Fallback to local check
      const isVerified = verifiedDomains.some(d => d.domain === domain && d.verified);
      setDomainStatus(isVerified ? "verified" : "unverified");
      setAuthorizationResult(null);
      setFormData(prev => ({ ...prev, domain_authorized: isVerified, domain_check_reason: null }));
    } finally {
      setCheckingDomain(false);
    }
  }, [verifiedDomains, setFormData]);
  
  // Debounced domain check
  useEffect(() => {
    const timer = setTimeout(() => {
      checkDomain(formData.target_url);
    }, 500); // 500ms debounce
    
    return () => clearTimeout(timer);
  }, [formData.target_url, checkDomain]);

  // Get status display info
  const getStatusDisplay = () => {
    if (checkingDomain) {
      return {
        icon: "⏳",
        text: "Checking...",
        color: isDarkMode ? "bg-gray-600/50 text-gray-400" : "bg-gray-100 text-gray-600"
      };
    }
    
    if (domainStatus === "verified") {
      const reason = authorizationResult?.reason;
      let text = "✓ Verified";
      if (reason === "corporate_email_match" || reason === "corporate_subdomain_match") {
        text = "✓ Corporate Email";
      } else if (reason === "dns_txt_verified" || reason === "root_domain_verified") {
        text = "✓ DNS Verified";
      }
      return {
        icon: "✓",
        text,
        color: isDarkMode ? "bg-green-500/20 text-green-400" : "bg-green-100 text-green-700"
      };
    }
    
    if (domainStatus === "unverified") {
      return {
        icon: "⚠",
        text: userHasPersonalEmail ? "⚠ Verification Required" : "⚠ Not Verified",
        color: isDarkMode ? "bg-amber-500/20 text-amber-400" : "bg-amber-100 text-amber-700"
      };
    }
    
    if (domainStatus === "invalid") {
      return {
        icon: "✕",
        text: "✕ Invalid URL",
        color: isDarkMode ? "bg-red-500/20 text-red-400" : "bg-red-100 text-red-700"
      };
    }
    
    return null;
  };
  
  const statusDisplay = getStatusDisplay();

  return (
    <div className="space-y-6">
      {/* Personal Email Warning Banner */}
      {userHasPersonalEmail && (
        <div className={`p-4 rounded-xl ${isDarkMode ? "bg-amber-900/20 border border-amber-700/30" : "bg-amber-50 border border-amber-200"}`}>
          <div className="flex gap-3">
            <span className="text-2xl">📧</span>
            <div>
              <h4 className={`font-medium ${isDarkMode ? "text-amber-400" : "text-amber-700"}`}>
                Personal Email Account
              </h4>
              <p className={`text-sm mt-1 ${isDarkMode ? "text-amber-300/70" : "text-amber-600"}`}>
                You're using a personal email ({user?.email}). You must verify domain ownership before scanning.
                Go to <strong>Settings → Verified Domains</strong> to add DNS verification.
              </p>
            </div>
          </div>
        </div>
      )}
      
      <div>
        <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
          Target URL
        </label>
        <div className="relative">
          <input
            type="url"
            value={formData.target_url || ""}
            onChange={(e) => setFormData({ ...formData, target_url: e.target.value })}
            placeholder="https://example.com"
            className={`w-full px-4 py-3 pr-40 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
              isDarkMode 
                ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
                : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
            }`}
          />
          {statusDisplay && (
            <div className={`absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-medium ${statusDisplay.color}`}>
              {checkingDomain && (
                <div className="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin mr-1" />
              )}
              {statusDisplay.text}
            </div>
          )}
        </div>
        
        {/* Dynamic status message */}
        {domainStatus === "unverified" && !checkingDomain && (
          <div className={`mt-3 p-3 rounded-lg ${isDarkMode ? "bg-amber-900/30 border border-amber-700/50" : "bg-amber-50 border border-amber-200"}`}>
            <p className={`text-sm ${isDarkMode ? "text-amber-400" : "text-amber-700"}`}>
              {userHasPersonalEmail ? (
                <>
                  <strong>Domain verification required.</strong> Personal email users must verify domain ownership via DNS TXT record.
                  <br />
                  <span className={isDarkMode ? "text-amber-300/70" : "text-amber-600"}>
                    Go to Settings → Verified Domains to add your domain.
                  </span>
                </>
              ) : (
                <>
                  <strong>Domain not verified.</strong> You can scan your corporate domain ({userEmailDomain}) without verification.
                  For other domains, add DNS verification in Settings.
                </>
              )}
            </p>
          </div>
        )}
        
        {domainStatus === "verified" && authorizationResult?.reason && !checkingDomain && (
          <p className={`mt-2 text-sm ${isDarkMode ? "text-green-400" : "text-green-600"}`}>
            {authorizationResult.reason === "corporate_email_match" && (
              <>✓ You can scan this domain because your email ({user?.email}) matches.</>
            )}
            {authorizationResult.reason === "corporate_subdomain_match" && (
              <>✓ You can scan this subdomain of your corporate domain.</>
            )}
            {authorizationResult.reason === "dns_txt_verified" && (
              <>✓ Domain verified via DNS TXT record.</>
            )}
            {authorizationResult.reason === "root_domain_verified" && (
              <>✓ Parent domain verified - subdomains allowed.</>
            )}
          </p>
        )}
        
        {/* Show normalized URL hint when protocol is missing */}
        {formData.target_url && urlNeedsProtocol(formData.target_url) && domainStatus !== "invalid" && (
          <div className={`mt-3 p-3 rounded-lg flex items-center gap-2 ${isDarkMode ? "bg-cyan-900/30 border border-cyan-700/50" : "bg-cyan-50 border border-cyan-200"}`}>
            <Lock className="w-4 h-4 text-cyan-500" />
            <p className={`text-sm ${isDarkMode ? "text-cyan-400" : "text-cyan-700"}`}>
              <strong>Will scan as:</strong>{" "}
              <code className={`px-2 py-0.5 rounded ${isDarkMode ? "bg-gray-800 text-cyan-300" : "bg-white text-cyan-600"}`}>
                https://{formData.target_url.trim()}
              </code>
            </p>
          </div>
        )}
      </div>
      
      <div>
        <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
          Scan Name (Optional)
        </label>
        <input
          type="text"
          value={formData.scan_name || ""}
          onChange={(e) => setFormData({ ...formData, scan_name: e.target.value })}
          placeholder="My Web Security Scan"
          className={`w-full px-4 py-3 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
            isDarkMode 
              ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
              : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
          }`}
        />
      </div>
      
      {/* Scope Configuration */}
      <div>
        <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
          Scan Scope (Optional)
        </label>
        <input
          type="text"
          value={formData.scope || ""}
          onChange={(e) => setFormData({ ...formData, scope: e.target.value })}
          placeholder="/api/*, /admin/* (leave empty for full site)"
          className={`w-full px-4 py-3 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
            isDarkMode 
              ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
              : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
          }`}
        />
        <p className={`text-xs mt-1 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
          Limit scanning to specific paths. Use comma-separated patterns with wildcards.
        </p>
      </div>
    </div>
  );
};

// Web scan configuration step
const WebConfigStep = ({ formData, setFormData, isDarkMode }) => {
  const scanProfiles = [
    { id: "full", name: "Full OWASP Top 10", description: "Comprehensive security assessment", duration: "30-60 min", icon: Shield },
    { id: "quick", name: "Quick Scan", description: "Fast vulnerability check", duration: "5-10 min", icon: Zap },
    { id: "api", name: "API Security", description: "REST/GraphQL endpoint testing", duration: "15-30 min", icon: Plug },
    { id: "authenticated", name: "Authenticated Scan", description: "Deep scan with login", duration: "45-90 min", icon: Lock },
  ];

  return (
    <div className="space-y-6">
      <div>
        <label className={`block text-sm font-medium mb-3 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
          Scan Profile
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {scanProfiles.map((profile) => (
            <motion.button
              key={profile.id}
              type="button"
              onClick={() => setFormData({ ...formData, scan_type: profile.id })}
              className={`p-4 rounded-xl border-2 text-left transition-all ${
                formData.scan_type === profile.id
                  ? isDarkMode
                    ? "border-cyan-500 bg-cyan-500/10"
                    : "border-cyan-500 bg-cyan-50"
                  : isDarkMode
                    ? "border-gray-700 bg-gray-800/50 hover:border-gray-600"
                    : "border-gray-200 bg-white hover:border-gray-300"
              }`}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <div className="flex items-start gap-3">
                <span className="text-cyan-400">
                  {typeof profile.icon === 'string' ? profile.icon : <profile.icon className="w-6 h-6" />}
                </span>
                <div className="flex-1">
                  <p className={`font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {profile.name}
                  </p>
                  <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                    {profile.description}
                  </p>
                  <p className={`text-xs mt-1 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                    Est. {profile.duration}
                  </p>
                </div>
                {formData.scan_type === profile.id && (
                  <div className="flex-shrink-0 w-5 h-5 rounded-full bg-cyan-500 flex items-center justify-center">
                    <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                )}
              </div>
            </motion.button>
          ))}
        </div>
      </div>
      
      <div>
        <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
          Rate Limit (requests/second)
        </label>
        <div className="flex items-center gap-4">
          <input
            type="range"
            min="1"
            max="50"
            value={formData.rate_limit || 10}
            onChange={(e) => setFormData({ ...formData, rate_limit: parseInt(e.target.value) })}
            className="flex-1 h-2 rounded-lg appearance-none cursor-pointer accent-cyan-500"
            style={{
              background: `linear-gradient(to right, rgb(6, 182, 212) 0%, rgb(6, 182, 212) ${((formData.rate_limit || 10) / 50) * 100}%, ${isDarkMode ? '#374151' : '#e5e7eb'} ${((formData.rate_limit || 10) / 50) * 100}%, ${isDarkMode ? '#374151' : '#e5e7eb'} 100%)`
            }}
          />
          <span className={`w-12 text-center font-mono text-lg ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}`}>
            {formData.rate_limit || 10}
          </span>
        </div>
        <p className={`text-xs mt-1 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
          Higher values = faster scan, but may trigger rate limiting on target
        </p>
      </div>
    </div>
  );
};

// Web scan authentication step
const WebAuthStep = ({ formData, setFormData, isDarkMode }) => {
  const [showPassword, setShowPassword] = useState(false);
  const [authEnabled, setAuthEnabled] = useState(!!formData.auth_enabled);
  const [verificationStatus, setVerificationStatus] = useState(null);
  const [checkingVerification, setCheckingVerification] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const { user } = useAuth();
  
  // Auth method options
  const authMethods = [
    { id: 'username_password', name: 'Username & Password', icon: Key, description: 'Standard form login' },
    { id: 'phone_otp', name: 'Phone OTP', icon: Smartphone, description: 'SMS verification code' },
    { id: 'social_login', name: 'Social Login', icon: Link, description: 'Google, Facebook, etc.' },
    { id: 'manual_session', name: 'Manual Session', icon: Cookie, description: 'Provide cookies/tokens' },
  ];
  
  // Social providers
  const socialProviders = [
    { id: 'google', name: 'Google', icon: '🔴' },
    { id: 'facebook', name: 'Facebook', icon: '🔵' },
    { id: 'linkedin', name: 'LinkedIn', icon: '💼' },
    { id: 'apple', name: 'Apple', icon: '🍎' },
    { id: 'github', name: 'GitHub', icon: '⚫' },
  ];
  
  // Check domain verification status when auth is enabled and target URL changes
  useEffect(() => {
    const checkVerification = async () => {
      if (!authEnabled || !formData.target_url) {
        setVerificationStatus(null);
        return;
      }
      
      setCheckingVerification(true);
      try {
        const result = await domainVerificationAPI.checkAuthorization(formData.target_url);
        setVerificationStatus(result);
      } catch (error) {
        console.error('Failed to check verification:', error);
        setVerificationStatus({ authorized: false, reason: 'error', message: 'Failed to check verification status' });
      } finally {
        setCheckingVerification(false);
      }
    };
    
    // Debounce the check
    const timer = setTimeout(checkVerification, 500);
    return () => clearTimeout(timer);
  }, [authEnabled, formData.target_url]);
  
  const selectedAuthMethod = formData.auth_method || 'username_password';
  
  return (
    <div className="space-y-6">
      <div className={`p-4 rounded-xl ${isDarkMode ? "bg-gray-800/50 border border-gray-700" : "bg-gray-50 border border-gray-200"}`}>
        <div className="flex items-center justify-between">
          <div>
            <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Enable Authenticated Scanning
            </p>
            <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
              Test protected areas behind login
            </p>
          </div>
          <button
            type="button"
            onClick={() => {
              setAuthEnabled(!authEnabled);
              setFormData({ ...formData, auth_enabled: !authEnabled });
            }}
            className={`relative w-14 h-7 rounded-full transition-colors ${
              authEnabled 
                ? "bg-cyan-500" 
                : isDarkMode ? "bg-gray-600" : "bg-gray-300"
            }`}
          >
            <motion.div
              className="absolute top-1 w-5 h-5 rounded-full bg-white shadow-md"
              animate={{ left: authEnabled ? "calc(100% - 1.5rem)" : "0.25rem" }}
              transition={{ duration: 0.2 }}
            />
          </button>
        </div>
      </div>
      
      <AnimatePresence>
        {authEnabled && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3 }}
            className="space-y-4 overflow-hidden"
          >
            {/* Auth Method Selector */}
            <div>
              <label className={`block text-sm font-medium mb-3 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                Authentication Method
              </label>
              <div className="grid grid-cols-2 gap-3">
                {authMethods.map((method) => (
                  <button
                    key={method.id}
                    type="button"
                    onClick={() => setFormData({ ...formData, auth_method: method.id })}
                    className={`p-3 rounded-xl border-2 text-left transition-all ${
                      selectedAuthMethod === method.id
                        ? "border-cyan-500 bg-cyan-500/10"
                        : isDarkMode
                          ? "border-gray-700 bg-gray-800 hover:border-gray-600"
                          : "border-gray-200 bg-white hover:border-gray-300"
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-cyan-400">
                        {typeof method.icon === 'string' ? method.icon : <method.icon className="w-5 h-5" />}
                      </span>
                      <div>
                        <p className={`font-medium text-sm ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                          {method.name}
                        </p>
                        <p className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                          {method.description}
                        </p>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>
            
            {/* Domain Verification Status */}
            {formData.target_url && (
              <div className={`p-4 rounded-xl border-2 ${
                checkingVerification 
                  ? isDarkMode ? "bg-gray-800/30 border-gray-700" : "bg-gray-50 border-gray-200"
                  : verificationStatus?.authorized
                    ? isDarkMode ? "bg-green-900/20 border-green-700" : "bg-green-50 border-green-200"
                    : isDarkMode ? "bg-amber-900/20 border-amber-700" : "bg-amber-50 border-amber-200"
              }`}>
                {checkingVerification ? (
                  <div className="flex items-center gap-3">
                    <div className="w-5 h-5 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                    <span className={isDarkMode ? "text-gray-400" : "text-gray-600"}>Checking domain authorization...</span>
                  </div>
                ) : verificationStatus?.authorized ? (
                  <div className="flex items-center gap-3">
                    <CheckCircle className="w-6 h-6 text-green-400" />
                    <div>
                      <p className={`font-medium ${isDarkMode ? "text-green-400" : "text-green-700"}`}>
                        Domain Authorized
                      </p>
                      <p className={`text-sm ${isDarkMode ? "text-green-300/70" : "text-green-600"}`}>
                        {verificationStatus.reason === 'corporate_email_match' 
                          ? `Your email domain (${user?.email?.split('@')[1]}) matches the target.`
                          : verificationStatus.reason === 'corporate_subdomain_match'
                            ? `Subdomain of your corporate domain.`
                            : 'Domain verified via DNS TXT record.'}
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div className="flex items-center gap-3">
                      <AlertTriangle className="w-6 h-6 text-amber-400" />
                      <div>
                        <p className={`font-medium ${isDarkMode ? "text-amber-400" : "text-amber-700"}`}>
                          Domain Verification Required
                        </p>
                        <p className={`text-sm ${isDarkMode ? "text-amber-300/70" : "text-amber-600"}`}>
                          {verificationStatus?.message || 'You need to verify ownership of this domain to use credentials.'}
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
            
            {/* Username/Password Fields */}
            {selectedAuthMethod === 'username_password' && (
              <>
                <div>
                  <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Login URL
                  </label>
                  <input
                    type="url"
                    value={formData.login_url || ""}
                    onChange={(e) => setFormData({ ...formData, login_url: e.target.value })}
                    placeholder="https://example.com/login"
                    className={`w-full px-4 py-3 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
                      isDarkMode 
                        ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
                        : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
                    }`}
                  />
                </div>
                
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                      Username / Email
                    </label>
                    <input
                      type="text"
                      value={formData.auth_username || ""}
                      onChange={(e) => setFormData({ ...formData, auth_username: e.target.value })}
                      placeholder="user@example.com"
                      className={`w-full px-4 py-3 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
                        isDarkMode 
                          ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
                          : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
                      }`}
                    />
                  </div>
                  
                  <div>
                    <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                      Password
                    </label>
                    <div className="relative">
                      <input
                        type={showPassword ? "text" : "password"}
                        value={formData.auth_password || ""}
                        onChange={(e) => setFormData({ ...formData, auth_password: e.target.value })}
                        placeholder="••••••••"
                        className={`w-full px-4 py-3 pr-12 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
                          isDarkMode 
                            ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
                            : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
                        }`}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className={`absolute right-3 top-1/2 -translate-y-1/2 p-1 rounded ${isDarkMode ? "text-gray-400 hover:text-gray-300" : "text-gray-500 hover:text-gray-600"}`}
                      >
                        {showPassword ? "🙈" : "👁️"}
                      </button>
                    </div>
                  </div>
                </div>
              </>
            )}
            
            {/* Phone OTP Fields */}
            {selectedAuthMethod === 'phone_otp' && (
              <>
                <div>
                  <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Login URL
                  </label>
                  <input
                    type="url"
                    value={formData.login_url || ""}
                    onChange={(e) => setFormData({ ...formData, login_url: e.target.value })}
                    placeholder="https://example.com/login"
                    className={`w-full px-4 py-3 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
                      isDarkMode 
                        ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
                        : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
                    }`}
                  />
                </div>
                <div>
                  <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Phone Number (for receiving OTP)
                  </label>
                  <input
                    type="tel"
                    value={formData.phone_number || ""}
                    onChange={(e) => setFormData({ ...formData, phone_number: e.target.value })}
                    placeholder="+1 (555) 123-4567"
                    className={`w-full px-4 py-3 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
                      isDarkMode 
                        ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
                        : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
                    }`}
                  />
                  <p className={`text-xs mt-1 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                    We'll prompt you to enter the OTP code during the scan.
                  </p>
                </div>
              </>
            )}
            
            {/* Social Login Fields */}
            {selectedAuthMethod === 'social_login' && (
              <>
                <div>
                  <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Login URL
                  </label>
                  <input
                    type="url"
                    value={formData.login_url || ""}
                    onChange={(e) => setFormData({ ...formData, login_url: e.target.value })}
                    placeholder="https://example.com/login"
                    className={`w-full px-4 py-3 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
                      isDarkMode 
                        ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
                        : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
                    }`}
                  />
                </div>
                <div>
                  <label className={`block text-sm font-medium mb-3 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Social Login Providers Available on Target
                  </label>
                  <div className="flex flex-wrap gap-2">
                    {socialProviders.map((provider) => {
                      const isSelected = (formData.social_providers || []).includes(provider.id);
                      return (
                        <button
                          key={provider.id}
                          type="button"
                          onClick={() => {
                            const current = formData.social_providers || [];
                            const updated = isSelected
                              ? current.filter(p => p !== provider.id)
                              : [...current, provider.id];
                            setFormData({ ...formData, social_providers: updated });
                          }}
                          className={`px-4 py-2 rounded-lg border-2 flex items-center gap-2 transition-all ${
                            isSelected
                              ? "border-cyan-500 bg-cyan-500/10"
                              : isDarkMode
                                ? "border-gray-700 bg-gray-800 hover:border-gray-600"
                                : "border-gray-200 bg-white hover:border-gray-300"
                          }`}
                        >
                          <span>{provider.icon}</span>
                          <span className={`text-sm ${isDarkMode ? "text-white" : "text-gray-900"}`}>{provider.name}</span>
                        </button>
                      );
                    })}
                  </div>
                  <p className={`text-xs mt-2 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                    We'll pause the scan for you to complete social login manually.
                  </p>
                </div>
              </>
            )}
            
            {/* Manual Session Fields */}
            {selectedAuthMethod === 'manual_session' && (
              <div className="space-y-4">
                <div className={`p-3 rounded-lg ${isDarkMode ? "bg-blue-900/20 border border-blue-700" : "bg-blue-50 border border-blue-200"}`}>
                  <p className={`text-sm flex items-start gap-2 ${isDarkMode ? "text-blue-400" : "text-blue-700"}`}>
                    <Lightbulb className="w-4 h-4 flex-shrink-0 mt-0.5" /> <span><strong>Tip:</strong> Log in to your target site in a browser, then copy the session cookie or auth token from developer tools.</span>
                  </p>
                </div>
                <div>
                  <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Session Cookie
                  </label>
                  <textarea
                    value={formData.session_cookie || ""}
                    onChange={(e) => setFormData({ ...formData, session_cookie: e.target.value })}
                    placeholder="PHPSESSID=abc123...; connect.sid=xyz789..."
                    rows={2}
                    className={`w-full px-4 py-3 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
                      isDarkMode 
                        ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
                        : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
                    }`}
                  />
                </div>
                <div>
                  <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Authorization Token (Optional)
                  </label>
                  <input
                    type="text"
                    value={formData.session_token || ""}
                    onChange={(e) => setFormData({ ...formData, session_token: e.target.value })}
                    placeholder="Bearer eyJhbGciOiJIUzI1NiIs..."
                    className={`w-full px-4 py-3 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
                      isDarkMode 
                        ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
                        : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
                    }`}
                  />
                </div>
              </div>
            )}
            
            {/* 2FA Configuration */}
            <div className={`p-4 rounded-xl ${isDarkMode ? "bg-gray-800/50 border border-gray-700" : "bg-gray-50 border border-gray-200"}`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    Target Site Uses 2FA
                  </p>
                  <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                    Enable if the target requires two-factor authentication
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setFormData({ 
                    ...formData, 
                    two_factor_enabled: !formData.two_factor_enabled 
                  })}
                  className={`relative w-14 h-7 rounded-full transition-colors ${
                    formData.two_factor_enabled 
                      ? "bg-cyan-500" 
                      : isDarkMode ? "bg-gray-600" : "bg-gray-300"
                  }`}
                >
                  <motion.div
                    className="absolute top-1 w-5 h-5 rounded-full bg-white shadow-md"
                    animate={{ left: formData.two_factor_enabled ? "calc(100% - 1.5rem)" : "0.25rem" }}
                    transition={{ duration: 0.2 }}
                  />
                </button>
              </div>
              
              <AnimatePresence>
                {formData.two_factor_enabled && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    className="mt-4 space-y-4"
                  >
                    <div>
                      <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                        2FA Type
                      </label>
                      <div className="grid grid-cols-3 gap-2">
                        {[
                          { id: 'email', name: 'Email OTP', icon: '📧' },
                          { id: 'sms', name: 'SMS OTP', icon: MessageSquare },
                          { id: 'authenticator', name: 'Authenticator', icon: '🔐' },
                        ].map((type) => (
                          <button
                            key={type.id}
                            type="button"
                            onClick={() => setFormData({ ...formData, two_factor_type: type.id })}
                            className={`p-2 rounded-lg border-2 text-center transition-all ${
                              formData.two_factor_type === type.id
                                ? "border-cyan-500 bg-cyan-500/10"
                                : isDarkMode
                                  ? "border-gray-700 bg-gray-800 hover:border-gray-600"
                                  : "border-gray-200 bg-white hover:border-gray-300"
                            }`}
                          >
                            <span className="text-lg">{type.icon}</span>
                            <p className={`text-xs mt-1 ${isDarkMode ? "text-white" : "text-gray-900"}`}>{type.name}</p>
                          </button>
                        ))}
                      </div>
                    </div>
                    
                    {formData.two_factor_type === 'email' && (
                      <div>
                        <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                          Email for 2FA Code
                        </label>
                        <input
                          type="email"
                          value={formData.two_factor_email || ""}
                          onChange={(e) => setFormData({ ...formData, two_factor_email: e.target.value })}
                          placeholder="your@email.com"
                          className={`w-full px-4 py-3 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
                            isDarkMode 
                              ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
                              : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
                          }`}
                        />
                      </div>
                    )}
                    
                    {formData.two_factor_type === 'sms' && (
                      <div>
                        <label className={`block text-sm font-medium mb-2 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                          Phone for 2FA Code
                        </label>
                        <input
                          type="tel"
                          value={formData.two_factor_phone || ""}
                          onChange={(e) => setFormData({ ...formData, two_factor_phone: e.target.value })}
                          placeholder="+1 (555) 123-4567"
                          className={`w-full px-4 py-3 rounded-xl border-2 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/50 ${
                            isDarkMode 
                              ? "bg-gray-800 border-gray-700 text-white placeholder-gray-500 focus:border-cyan-500" 
                              : "bg-white border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500"
                          }`}
                        />
                      </div>
                    )}
                    
                    {formData.two_factor_type === 'authenticator' && (
                      <div className={`p-3 rounded-lg ${isDarkMode ? "bg-gray-900/50" : "bg-white"}`}>
                        <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                          🔐 We'll pause during login and ask you to enter the code from your authenticator app.
                        </p>
                      </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
            
            <p className={`text-sm flex items-center gap-2 ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
              <Lock className="w-4 h-4 text-cyan-500" />
              Credentials are encrypted and never stored permanently
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// Review step (shared across scan types)
const ReviewStep = ({ formData, scanType, isDarkMode, onStartScan, isSubmitting }) => {
  const configItems = [];
  
  if (scanType === "web") {
    configItems.push(
      { label: "Target URL", value: formData.target_url },
      { label: "Scan Type", value: formData.scan_type || "full" },
      { label: "Rate Limit", value: `${formData.rate_limit || 10} req/s` },
      { label: "Authentication", value: formData.auth_enabled ? "Enabled" : "Disabled" },
    );
    if (formData.auth_enabled) {
      configItems.push({ label: "Login URL", value: formData.login_url });
    }
  }

  return (
    <div className="space-y-6">
      <div className={`p-6 rounded-xl ${isDarkMode ? "bg-gray-800/50 border border-gray-700" : "bg-gray-50 border border-gray-200"}`}>
        <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
          Scan Configuration
        </h3>
        <div className="space-y-3">
          {configItems.map((item, index) => (
            <div key={index} className="flex items-center justify-between py-2 border-b last:border-0 ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}">
              <span className={isDarkMode ? "text-gray-400" : "text-gray-500"}>{item.label}</span>
              <span className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                {item.value || "—"}
              </span>
            </div>
          ))}
        </div>
      </div>
      
      <div className={`p-4 rounded-xl ${isDarkMode ? "bg-cyan-500/10 border border-cyan-500/30" : "bg-cyan-50 border border-cyan-200"}`}>
        <div className="flex items-start gap-3">
          <Rocket className="w-6 h-6 text-cyan-400" />
          <div>
            <p className={`font-medium ${isDarkMode ? "text-cyan-400" : "text-cyan-700"}`}>
              Ready to Start
            </p>
            <p className={`text-sm ${isDarkMode ? "text-cyan-400/70" : "text-cyan-600"}`}>
              The scan will begin immediately. You can monitor progress in real-time.
            </p>
          </div>
        </div>
      </div>
      
      <motion.button
        type="button"
        onClick={onStartScan}
        disabled={isSubmitting}
        className={`
          w-full py-4 px-6 rounded-xl font-bold text-lg text-white
          bg-gradient-to-r from-cyan-500 to-blue-500
          hover:from-cyan-400 hover:to-blue-400
          shadow-lg shadow-cyan-500/30
          transition-all duration-300
          disabled:opacity-50 disabled:cursor-not-allowed
          flex items-center justify-center gap-3
        `}
        whileHover={{ scale: isSubmitting ? 1 : 1.02 }}
        whileTap={{ scale: isSubmitting ? 1 : 0.98 }}
      >
        {isSubmitting ? (
          <>
            <div className="w-6 h-6 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            Starting Scan...
          </>
        ) : (
          <>
            <Rocket className="w-5 h-5" />
            Start Security Scan
          </>
        )}
      </motion.button>
    </div>
  );
};

// Main ScanWizard component
export default function ScanWizard({ scanType = "web" }) {
  const { isDarkMode } = useTheme();
  const { user } = useAuth();
  const { currentPlan } = useSubscription();
  const navigate = useNavigate();
  
  const [currentStep, setCurrentStep] = useState(0);
  const [formData, setFormData] = useState({
    scan_type: "full",
    rate_limit: 10,
  });
  const [verifiedDomains, setVerifiedDomains] = useState([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);
  
  const steps = SCAN_TYPE_STEPS[scanType] || SCAN_TYPE_STEPS.web;
  
  // Fetch verified domains on mount
  useEffect(() => {
    const fetchDomains = async () => {
      try {
        const domains = await domainAPI.getAll();
        setVerifiedDomains(domains || []);
      } catch (err) {
        console.error("Failed to fetch domains:", err);
      }
    };
    fetchDomains();
  }, []);
  
  // Check if current user has personal email
  const userHasPersonalEmail = isPersonalEmail(user?.email);
  
  const canProceed = useCallback(() => {
    if (scanType === "web") {
      if (currentStep === 0) {
        // Must have URL
        if (!formData.target_url) return false;
        
        // Personal email users MUST have domain authorized
        if (userHasPersonalEmail && formData.domain_authorized === false) {
          return false;
        }
        
        return true;
      }
      if (currentStep === 1) {
        return !!formData.scan_type;
      }
    }
    return true;
  }, [currentStep, formData, scanType, userHasPersonalEmail]);
  
  const handleNext = () => {
    if (currentStep < steps.length - 1 && canProceed()) {
      // Normalize URL when leaving step 0 (target step) for web scans
      if (scanType === "web" && currentStep === 0 && formData.target_url) {
        const normalizedUrl = normalizeUrl(formData.target_url);
        if (normalizedUrl !== formData.target_url) {
          setFormData(prev => ({ ...prev, target_url: normalizedUrl }));
        }
      }
      setCurrentStep(currentStep + 1);
    }
  };
  
  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };
  
  const handleStartScan = async () => {
    setIsSubmitting(true);
    setError(null);
    
    try {
      // Ensure URL is normalized with protocol before sending to backend
      const normalizedTargetUrl = normalizeUrl(formData.target_url);
      
      const scanConfig = {
        target_url: normalizedTargetUrl,
        scan_type: formData.scan_type || "full",
        scan_name: formData.scan_name || `${scanType.toUpperCase()} Scan - ${new Date().toLocaleDateString()}`,
        rate_limit: formData.rate_limit || 10,
        scope: formData.scope || null,
      };
      
      // Check authorization for credential-based scans
      if (formData.auth_enabled && formData.target_url) {
        const authCheck = await domainVerificationAPI.checkAuthorization(formData.target_url);
        
        if (!authCheck.authorized) {
          // Provide helpful message about verification
          const verifyUrl = authCheck.verification_url || '/dashboard/verify-domain';
          setError(
            `Domain verification required for credential-based scanning. ` +
            `${authCheck.message || 'Please verify domain ownership first.'} ` +
            `Go to Settings > Verified Domains to add verification.`
          );
          setIsSubmitting(false);
          return;
        }
        
        // Build auth config based on selected method
        const authMethod = formData.auth_method || 'username_password';
        
        scanConfig.auth = {
          method: authMethod,
          login_url: formData.login_url,
          username: formData.auth_username,
          password: formData.auth_password,
        };
        
        // Add phone OTP fields
        if (authMethod === 'phone_otp') {
          scanConfig.phone_number = formData.phone_number;
        }
        
        // Add social login fields
        if (authMethod === 'social_login') {
          scanConfig.social_providers = formData.social_providers || [];
        }
        
        // Add manual session fields
        if (authMethod === 'manual_session') {
          scanConfig.session_cookie = formData.session_cookie;
          scanConfig.session_token = formData.session_token;
        }
        
        // Add 2FA config if enabled
        if (formData.two_factor_enabled) {
          scanConfig.two_factor = {
            enabled: true,
            type: formData.two_factor_type || 'email',
            email: formData.two_factor_email,
            phone: formData.two_factor_phone,
          };
        }
      }
      
      const result = await scanAPI.startScan(scanConfig);
      
      if (result.scan_id) {
        navigate(`/dashboard/scanning/${result.scan_id}`, { state: { scanId: result.scan_id, scanType } });
      } else {
        throw new Error("No scan ID returned");
      }
    } catch (err) {
      console.error("Failed to start scan:", err);
      setError(err.message || "Failed to start scan. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };
  
  const handleClose = () => {
    navigate("/dashboard");
  };
  
  const renderStep = () => {
    if (scanType === "web") {
      switch (steps[currentStep]?.id) {
        case "target":
          return <WebTargetStep formData={formData} setFormData={setFormData} isDarkMode={isDarkMode} verifiedDomains={verifiedDomains} />;
        case "config":
          return <WebConfigStep formData={formData} setFormData={setFormData} isDarkMode={isDarkMode} />;
        case "auth":
          return <WebAuthStep formData={formData} setFormData={setFormData} isDarkMode={isDarkMode} />;
        case "review":
          return <ReviewStep formData={formData} scanType={scanType} isDarkMode={isDarkMode} onStartScan={handleStartScan} isSubmitting={isSubmitting} />;
        default:
          return null;
      }
    }
    return null;
  };

  return (
    <div className={`min-h-screen ${isDarkMode ? "bg-gray-900" : "bg-gray-50"}`}>
      {/* Header */}
      <div className={`sticky top-0 z-20 px-4 py-4 border-b backdrop-blur-lg ${isDarkMode ? "bg-gray-900/90 border-gray-800" : "bg-white/90 border-gray-200"}`}>
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <button
            onClick={currentStep === 0 ? handleClose : handleBack}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-colors ${
              isDarkMode ? "text-gray-400 hover:text-white hover:bg-gray-800" : "text-gray-500 hover:text-gray-900 hover:bg-gray-100"
            }`}
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            {currentStep === 0 ? "Cancel" : "Back"}
          </button>
          
          <div className="text-center">
            <h1 className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              {scanType === "web" ? "Web Application Scan" : `${scanType.charAt(0).toUpperCase() + scanType.slice(1)} Scan`}
            </h1>
            <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
              Step {currentStep + 1} of {steps.length}
            </p>
          </div>
          
          <button
            onClick={handleClose}
            className={`p-2 rounded-lg transition-colors ${
              isDarkMode ? "text-gray-400 hover:text-white hover:bg-gray-800" : "text-gray-500 hover:text-gray-900 hover:bg-gray-100"
            }`}
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      </div>
      
      {/* Step Indicator */}
      <div className="max-w-4xl mx-auto pt-6">
        <StepIndicator steps={steps} currentStep={currentStep} isDarkMode={isDarkMode} />
      </div>
      
      {/* Content */}
      <div className="max-w-2xl mx-auto px-4 py-8">
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className={`mb-6 p-4 rounded-xl ${isDarkMode ? "bg-red-500/20 border border-red-500/30 text-red-400" : "bg-red-50 border border-red-200 text-red-700"}`}
          >
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5" />
              <p>{error}</p>
            </div>
          </motion.div>
        )}
        
        <AnimatePresence mode="wait">
          <motion.div
            key={currentStep}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.3, ease: "easeInOut" }}
          >
            {renderStep()}
          </motion.div>
        </AnimatePresence>
      </div>
      
      {/* Footer Navigation */}
      {currentStep < steps.length - 1 && (
        <div className={`fixed bottom-0 left-0 right-0 px-4 py-4 border-t backdrop-blur-lg ${isDarkMode ? "bg-gray-900/90 border-gray-800" : "bg-white/90 border-gray-200"}`}>
          <div className="max-w-2xl mx-auto flex items-center justify-between">
            <button
              onClick={handleBack}
              disabled={currentStep === 0}
              className={`px-6 py-3 rounded-xl font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed ${
                isDarkMode 
                  ? "text-gray-300 hover:bg-gray-800 disabled:hover:bg-transparent" 
                  : "text-gray-600 hover:bg-gray-100 disabled:hover:bg-transparent"
              }`}
            >
              Previous
            </button>
            
            <motion.button
              onClick={handleNext}
              disabled={!canProceed()}
              className={`
                px-8 py-3 rounded-xl font-semibold
                bg-gradient-to-r from-cyan-500 to-blue-500
                text-white shadow-lg shadow-cyan-500/30
                hover:from-cyan-400 hover:to-blue-400
                disabled:opacity-50 disabled:cursor-not-allowed
                transition-all duration-300
              `}
              whileHover={{ scale: canProceed() ? 1.02 : 1 }}
              whileTap={{ scale: canProceed() ? 0.98 : 1 }}
            >
              Next →
            </motion.button>
          </div>
        </div>
      )}
    </div>
  );
}
