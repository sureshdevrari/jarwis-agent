// src/components/settings/VerifiedDomainsSettings.jsx
// Verified Domains Management for Credential-based Scanning

import { useState, useEffect, useCallback } from "react";
import { useAuth } from "../../context/AuthContext";
import { domainVerificationAPI } from "../../services/api";

const VerifiedDomainsSettings = ({ isDarkMode }) => {
  const { user } = useAuth();
  const [verifiedDomains, setVerifiedDomains] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  
  // Add new domain state
  const [newDomain, setNewDomain] = useState("");
  const [addingDomain, setAddingDomain] = useState(false);
  const [verificationCode, setVerificationCode] = useState(null);
  const [verificationInstructions, setVerificationInstructions] = useState(null);
  
  // Checking verification state
  const [checkingDomain, setCheckingDomain] = useState(null);
  
  // Theme classes
  const themeClasses = {
    card: isDarkMode
      ? "p-4 sm:p-5 bg-gray-800/50 border border-gray-700 rounded-xl mb-4"
      : "p-4 sm:p-5 bg-gray-50 border border-gray-200 rounded-xl mb-4 shadow-sm",
    cardTitle: isDarkMode
      ? "text-base sm:text-lg font-semibold text-white mb-3 sm:mb-4"
      : "text-base sm:text-lg font-semibold text-gray-900 mb-3 sm:mb-4",
    label: isDarkMode
      ? "block text-xs sm:text-sm font-medium text-gray-400 mb-1.5 sm:mb-2"
      : "block text-xs sm:text-sm font-medium text-gray-600 mb-1.5 sm:mb-2",
    input: isDarkMode
      ? "w-full px-3 sm:px-4 py-2.5 bg-gray-700 border border-gray-600 rounded-lg text-white text-base placeholder-gray-400 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-colors min-h-[48px]"
      : "w-full px-3 sm:px-4 py-2.5 bg-white border border-gray-300 rounded-lg text-gray-900 text-base placeholder-gray-400 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-colors min-h-[48px]",
    btnPrimary: isDarkMode
      ? "px-4 py-2.5 sm:py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors min-h-[44px] active:scale-95"
      : "px-4 py-2.5 sm:py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors shadow-sm min-h-[44px] active:scale-95",
    btnSecondary: isDarkMode
      ? "px-4 py-2.5 sm:py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg font-medium transition-colors border border-gray-600 min-h-[44px] active:scale-95"
      : "px-4 py-2.5 sm:py-2 bg-white hover:bg-gray-50 text-gray-700 rounded-lg font-medium transition-colors border border-gray-300 shadow-sm min-h-[44px] active:scale-95",
    btnDanger: isDarkMode
      ? "px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg font-medium transition-colors border border-red-600/30"
      : "px-4 py-2 bg-red-50 hover:bg-red-100 text-red-600 rounded-lg font-medium transition-colors border border-red-200",
    text: isDarkMode ? "text-gray-300" : "text-gray-700",
    textMuted: isDarkMode ? "text-gray-500" : "text-gray-400",
  };

  // Fetch verified domains
  const fetchDomains = useCallback(async () => {
    try {
      setLoading(true);
      const result = await domainVerificationAPI.listVerifiedDomains();
      setVerifiedDomains(result.domains || []);
    } catch (err) {
      console.error("Failed to fetch domains:", err);
      setError("Failed to load verified domains");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDomains();
  }, [fetchDomains]);

  // Generate verification code for new domain
  const handleGenerateCode = async () => {
    if (!newDomain.trim()) return;
    
    setAddingDomain(true);
    setError(null);
    setSuccess(null);
    
    try {
      const result = await domainVerificationAPI.generateVerificationCode(newDomain.trim());
      
      if (result.already_verified) {
        setSuccess(`Domain ${result.domain} is already verified!`);
        setNewDomain("");
        fetchDomains();
      } else {
        setVerificationCode(result.verification_code);
        setVerificationInstructions({
          domain: result.domain,
          txtHost: result.txt_record_host || "_jarwis-verify",
          txtValue: result.verification_code,
          instructions: result.instructions,
          expiresIn: result.expires_in
        });
      }
    } catch (err) {
      console.error("Failed to generate code:", err);
      setError(err.response?.data?.detail || "Failed to generate verification code");
    } finally {
      setAddingDomain(false);
    }
  };

  // Check if TXT record is configured
  const handleCheckVerification = async (domain) => {
    setCheckingDomain(domain);
    setError(null);
    setSuccess(null);
    
    try {
      const result = await domainVerificationAPI.checkTxtRecord(domain);
      
      if (result.verified) {
        setSuccess(`Domain ${domain} verified successfully!`);
        setVerificationCode(null);
        setVerificationInstructions(null);
        setNewDomain("");
        fetchDomains();
      } else {
        setError(result.error || "Verification failed. Make sure the TXT record is properly configured.");
      }
    } catch (err) {
      console.error("Verification check failed:", err);
      setError(err.response?.data?.detail || "Failed to check verification");
    } finally {
      setCheckingDomain(null);
    }
  };

  // Remove verified domain
  const handleRemoveDomain = async (domain) => {
    if (!window.confirm(`Are you sure you want to remove ${domain}? You will need to re-verify to scan with credentials.`)) {
      return;
    }
    
    try {
      await domainVerificationAPI.removeVerifiedDomain(domain);
      setSuccess(`Domain ${domain} removed successfully`);
      fetchDomains();
    } catch (err) {
      console.error("Failed to remove domain:", err);
      setError(err.response?.data?.detail || "Failed to remove domain");
    }
  };

  // Cancel adding new domain
  const handleCancelAdd = () => {
    setVerificationCode(null);
    setVerificationInstructions(null);
    setNewDomain("");
    setError(null);
  };

  // Get email domain for display
  const emailDomain = user?.email ? user.email.split('@')[1] : null;

  return (
    <div className="space-y-6">
      {/* Success/Error Messages */}
      {success && (
        <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-green-500/20 border-green-500/30 text-green-400" : "bg-green-50 border-green-200 text-green-700"}`}>
          <div className="flex items-center gap-3">
            <span>✓</span>
            <p>{success}</p>
          </div>
        </div>
      )}
      {error && (
        <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-red-500/20 border-red-500/30 text-red-400" : "bg-red-50 border-red-200 text-red-700"}`}>
          <div className="flex items-center gap-3">
            <span>✕</span>
            <p>{error}</p>
          </div>
        </div>
      )}

      {/* Info Card */}
      <div className={`p-4 rounded-xl ${isDarkMode ? "bg-blue-900/20 border border-blue-700/30" : "bg-blue-50 border border-blue-200"}`}>
        <div className="flex gap-3">
          <span className="text-2xl">🔐</span>
          <div>
            <h4 className={`font-medium ${isDarkMode ? "text-blue-400" : "text-blue-700"}`}>
              Domain Verification for Credential-Based Scans
            </h4>
            <p className={`text-sm mt-1 ${isDarkMode ? "text-blue-300/70" : "text-blue-600"}`}>
              When scanning with login credentials, you must prove domain ownership to prevent unauthorized testing.
              Verification is done via DNS TXT record or corporate email matching.
            </p>
          </div>
        </div>
      </div>

      {/* Corporate Email Domain (Auto-verified) */}
      {emailDomain && (
        <div className={themeClasses.card}>
          <h3 className={themeClasses.cardTitle}>🏢 Corporate Email Domain</h3>
          <div className={`flex items-center justify-between p-3 rounded-lg ${isDarkMode ? "bg-gray-700/50" : "bg-white border border-gray-200"}`}>
            <div className="flex items-center gap-3">
              <span className="text-2xl">✅</span>
              <div>
                <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  {emailDomain}
                </p>
                <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                  Auto-verified via your email ({user?.email})
                </p>
              </div>
            </div>
            <span className="px-3 py-1 text-xs font-medium bg-green-500/20 text-green-500 rounded-full">
              Auto-Verified
            </span>
          </div>
          <p className={`text-sm mt-3 ${themeClasses.textMuted}`}>
            You can scan {emailDomain} and its subdomains with credentials without additional verification.
          </p>
        </div>
      )}

      {/* Verified Domains List */}
      <div className={themeClasses.card}>
        <h3 className={themeClasses.cardTitle}>🌐 DNS-Verified Domains</h3>
        
        {loading ? (
          <div className="flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
          </div>
        ) : (
          <div className="space-y-3">
            {verifiedDomains.filter(d => d.method !== "corporate_email" && !d.auto_verified).length > 0 ? (
              verifiedDomains
                .filter(d => d.method !== "corporate_email" && !d.auto_verified)
                .map((domain, idx) => (
                  <div 
                    key={idx} 
                    className={`flex items-center justify-between p-3 rounded-lg ${isDarkMode ? "bg-gray-700/50" : "bg-white border border-gray-200"}`}
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-2xl">🔒</span>
                      <div>
                        <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                          {domain.domain}
                        </p>
                        <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                          Verified {domain.verified_at ? new Date(domain.verified_at).toLocaleDateString() : "via DNS TXT"}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="px-3 py-1 text-xs font-medium bg-cyan-500/20 text-cyan-500 rounded-full">
                        DNS Verified
                      </span>
                      <button
                        onClick={() => handleRemoveDomain(domain.domain)}
                        className={`p-2 rounded-lg transition-colors ${isDarkMode ? "hover:bg-red-500/20 text-red-400" : "hover:bg-red-50 text-red-500"}`}
                        title="Remove domain"
                      >
                        🗑️
                      </button>
                    </div>
                  </div>
                ))
            ) : (
              <div className={`text-center py-6 ${themeClasses.textMuted}`}>
                <p>No DNS-verified domains yet.</p>
                <p className="text-sm mt-1">Add a domain below to verify via DNS TXT record.</p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Add New Domain */}
      <div className={themeClasses.card}>
        <h3 className={themeClasses.cardTitle}>➕ Add New Domain</h3>
        
        {!verificationInstructions ? (
          <div className="space-y-4">
            <div>
              <label className={themeClasses.label}>Domain Name</label>
              <input
                type="text"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                placeholder="example.com"
                className={themeClasses.input}
              />
            </div>
            <button
              onClick={handleGenerateCode}
              disabled={addingDomain || !newDomain.trim()}
              className={`${themeClasses.btnPrimary} disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              {addingDomain ? "Generating..." : "Generate Verification Code"}
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Verification Instructions */}
            <div className={`p-4 rounded-lg ${isDarkMode ? "bg-amber-900/20 border border-amber-700/30" : "bg-amber-50 border border-amber-200"}`}>
              <h4 className={`font-medium mb-3 ${isDarkMode ? "text-amber-400" : "text-amber-700"}`}>
                📋 DNS TXT Record Instructions
              </h4>
              <p className={`text-sm mb-4 ${isDarkMode ? "text-amber-300/80" : "text-amber-600"}`}>
                Add this TXT record to your DNS settings for <strong>{verificationInstructions.domain}</strong>:
              </p>
              
              <div className={`p-3 rounded-lg font-mono text-sm ${isDarkMode ? "bg-gray-900/50" : "bg-white"}`}>
                <div className="grid grid-cols-2 gap-2 mb-2">
                  <div>
                    <span className={themeClasses.textMuted}>Name/Host:</span>
                    <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                      {verificationInstructions.txtHost}
                    </p>
                  </div>
                  <div>
                    <span className={themeClasses.textMuted}>Type:</span>
                    <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>TXT</p>
                  </div>
                </div>
                <div>
                  <span className={themeClasses.textMuted}>Value:</span>
                  <div className="flex items-center gap-2 mt-1">
                    <code className={`flex-1 p-2 rounded ${isDarkMode ? "bg-gray-800 text-cyan-400" : "bg-gray-100 text-cyan-600"}`}>
                      {verificationInstructions.txtValue}
                    </code>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(verificationInstructions.txtValue);
                        setSuccess("Verification code copied to clipboard!");
                        setTimeout(() => setSuccess(null), 2000);
                      }}
                      className={themeClasses.btnSecondary}
                      title="Copy to clipboard"
                    >
                      📋
                    </button>
                  </div>
                </div>
              </div>
              
              <p className={`text-xs mt-3 ${themeClasses.textMuted}`}>
                DNS changes can take 5-30 minutes to propagate. Code expires in {verificationInstructions.expiresIn || "24 hours"}.
              </p>
            </div>
            
            <div className="flex gap-3">
              <button
                onClick={() => handleCheckVerification(verificationInstructions.domain)}
                disabled={checkingDomain === verificationInstructions.domain}
                className={`flex-1 ${themeClasses.btnPrimary} disabled:opacity-50`}
              >
                {checkingDomain === verificationInstructions.domain ? (
                  <span className="flex items-center justify-center gap-2">
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    Checking...
                  </span>
                ) : (
                  "Verify TXT Record"
                )}
              </button>
              <button
                onClick={handleCancelAdd}
                className={themeClasses.btnSecondary}
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Help Section */}
      <div className={themeClasses.card}>
        <h3 className={themeClasses.cardTitle}>❓ How Domain Verification Works</h3>
        <div className={`space-y-3 text-sm ${themeClasses.text}`}>
          <div className="flex gap-3">
            <span className="text-lg">1️⃣</span>
            <p><strong>Corporate Email:</strong> If your email is user@company.com, you can automatically scan company.com and its subdomains.</p>
          </div>
          <div className="flex gap-3">
            <span className="text-lg">2️⃣</span>
            <p><strong>DNS TXT Record:</strong> For other domains, add a TXT record to prove ownership. This is a standard verification method.</p>
          </div>
          <div className="flex gap-3">
            <span className="text-lg">3️⃣</span>
            <p><strong>Subdomains:</strong> Verifying a root domain (e.g., example.com) allows scanning all subdomains (e.g., api.example.com).</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default VerifiedDomainsSettings;
