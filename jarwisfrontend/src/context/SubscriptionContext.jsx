// src/context/SubscriptionContext.jsx
// Subscription management context with plan enforcement
import { createContext, useContext, useCallback, useMemo, useState, useEffect } from "react";
import { useAuth } from "./AuthContext";
import { 
  PLAN_LIMITS, 
  getPlanById, 
  hasFeature, 
  isWithinLimit, 
  getRemainingQuota,
  getUsagePercentage,
  isPlanHigher
} from "../config/planLimits";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

const SubscriptionContext = createContext();

export const useSubscription = () => {
  const context = useContext(SubscriptionContext);
  if (!context) {
    throw new Error("useSubscription must be used within a SubscriptionProvider");
  }
  return context;
};

export const SubscriptionProvider = ({ children }) => {
  const { userDoc, token } = useAuth();
  const [serverUsage, setServerUsage] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Fetch subscription data from server
  const fetchSubscriptionData = useCallback(async () => {
    if (!token) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${API_URL}/api/users/me/subscription`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      
      if (response.ok) {
        const data = await response.json();
        setServerUsage(data);
      } else {
        console.warn("Failed to fetch subscription data");
      }
    } catch (err) {
      console.error("Error fetching subscription:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  // Fetch on mount and when token changes
  useEffect(() => {
    fetchSubscriptionData();
  }, [fetchSubscriptionData]);

  // Check if user can perform an action (server-side check)
  const checkActionAllowed = useCallback(async (action) => {
    if (!token) return { allowed: false, message: "Not authenticated" };
    
    try {
      const response = await fetch(`${API_URL}/api/users/me/subscription/check/${action}`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      
      return await response.json();
    } catch (err) {
      console.error("Error checking action:", err);
      return { allowed: false, message: "Failed to check permissions" };
    }
  }, [token]);

  // Get current plan details
  const currentPlan = useMemo(() => {
    const planId = userDoc?.plan || "trial";
    return getPlanById(planId);
  }, [userDoc?.plan]);

  // Get current usage from server or userDoc
  const usage = useMemo(() => {
    // Prefer server data if available
    if (serverUsage?.usage) {
      return {
        scansThisMonth: serverUsage.usage.scans?.used || 0,
        websitesThisMonth: serverUsage.usage.websites?.used || 0,
        teamMembers: serverUsage.usage.team_members?.used || 1,
        chatbotQuestionsToday: userDoc?.chatbot_questions_today || 0,
      };
    }
    
    // Fallback to userDoc
    return {
      scansThisMonth: userDoc?.scans_this_month || 0,
      websitesThisMonth: userDoc?.websites_this_month || 0,
      teamMembers: userDoc?.team_members_count || 1,
      chatbotQuestionsToday: userDoc?.chatbot_questions_today || 0,
    };
  }, [userDoc, serverUsage]);

  // Check if user can perform an action
  const canPerformAction = useCallback((action) => {
    const planId = userDoc?.plan || "trial";
    const plan = getPlanById(planId);

    switch (action) {
      case "startScan":
        return isWithinLimit(planId, "maxScansPerMonth", usage.scansThisMonth);
      
      case "addWebsite":
        return isWithinLimit(planId, "maxWebsitesPerMonth", usage.websitesThisMonth);
      
      case "addTeamMember":
        return isWithinLimit(planId, "maxTeamMembers", usage.teamMembers);
      
      case "useApiTesting":
        return plan.features.apiTesting;
      
      case "useCredentialScanning":
        return plan.features.credentialScanning;
      
      case "useMobileAppTesting":
        return plan.features.mobileAppTesting;
      
      case "useCloudScanning":
        return plan.features.cloudScanning || plan.features.mobileAppTesting; // Cloud requires same tier as mobile
      
      case "useChatbot":
        return plan.features.chatbotAccess;
      
      case "useApiAccess":
        return plan.features.apiAccess;
      
      case "useScheduledScans":
        return plan.features.scheduledScans;
      
      case "useWebhooks":
        return plan.features.webhooks;
      
      case "useSlackIntegration":
        return plan.features.slackIntegration;
      
      case "useJiraIntegration":
        return plan.features.jiraIntegration;
        
      case "useComplianceReports":
        return plan.features.complianceReports;
      
      default:
        return true;
    }
  }, [userDoc?.plan, usage]);

  // Get action limit details
  const getActionLimit = useCallback((action) => {
    const planId = userDoc?.plan || "trial";
    const plan = getPlanById(planId);

    const limits = {
      scans: {
        current: usage.scansThisMonth,
        max: plan.maxScansPerMonth,
        remaining: getRemainingQuota(planId, "maxScansPerMonth", usage.scansThisMonth),
        percentage: getUsagePercentage(planId, "maxScansPerMonth", usage.scansThisMonth),
        label: "Scans this month",
        unlimited: plan.maxScansPerMonth === -1,
      },
      websites: {
        current: usage.websitesThisMonth,
        max: plan.maxWebsitesPerMonth,
        remaining: getRemainingQuota(planId, "maxWebsitesPerMonth", usage.websitesThisMonth),
        percentage: getUsagePercentage(planId, "maxWebsitesPerMonth", usage.websitesThisMonth),
        label: "Websites this month",
        unlimited: plan.maxWebsitesPerMonth === -1,
      },
      teamMembers: {
        current: usage.teamMembers,
        max: plan.maxTeamMembers,
        remaining: getRemainingQuota(planId, "maxTeamMembers", usage.teamMembers),
        percentage: getUsagePercentage(planId, "maxTeamMembers", usage.teamMembers),
        label: "Team members",
        unlimited: plan.maxTeamMembers === -1,
      },
      pagesPerScan: {
        max: plan.maxPagesPerScan,
        label: "Pages per scan",
        unlimited: plan.maxPagesPerScan === -1,
      },
      dashboardAccess: {
        max: plan.dashboardAccessDays,
        label: "Dashboard access",
        unlimited: plan.dashboardAccessDays === -1,
        unit: "days",
      },
      reportRetention: {
        max: plan.reportRetentionDays,
        label: "Report retention",
        unlimited: plan.reportRetentionDays === -1,
        unit: "days",
      },
    };

    return limits[action] || null;
  }, [userDoc?.plan, usage]);

  // Get all usage stats for display
  const getAllUsageStats = useCallback(() => {
    return {
      scans: getActionLimit("scans"),
      websites: getActionLimit("websites"),
      teamMembers: getActionLimit("teamMembers"),
      pagesPerScan: getActionLimit("pagesPerScan"),
      dashboardAccess: getActionLimit("dashboardAccess"),
      reportRetention: getActionLimit("reportRetention"),
    };
  }, [getActionLimit]);

  // Check if feature is available
  const checkFeature = useCallback((featureName) => {
    const planId = userDoc?.plan || "trial";
    return hasFeature(planId, featureName);
  }, [userDoc?.plan]);

  // Get upgrade message for a blocked feature
  const getUpgradeMessage = useCallback((feature) => {
    const planId = userDoc?.plan || "trial";
    
    // Find which plan unlocks this feature
    const plansWithFeature = Object.values(PLAN_LIMITS).filter(
      plan => plan.features[feature]
    );
    
    if (plansWithFeature.length === 0) {
      return {
        message: "This feature is not available",
        upgradeToPlans: [],
      };
    }

    const lowestPlan = plansWithFeature.reduce((lowest, plan) => {
      if (plan.priceMonthly === -1) return lowest;
      if (lowest.priceMonthly === -1) return plan;
      return plan.priceMonthly < lowest.priceMonthly ? plan : lowest;
    });

    return {
      message: `Upgrade to ${lowestPlan.name} to unlock this feature`,
      upgradeToPlans: plansWithFeature.map(p => p.id),
      minimumPlan: lowestPlan.id,
      minimumPlanName: lowestPlan.name,
    };
  }, [userDoc?.plan]);

  // Get all features with their availability status
  const getAllFeatures = useCallback(() => {
    const planId = userDoc?.plan || "trial";
    const plan = getPlanById(planId);
    
    const featureDescriptions = {
      basicDAST: { name: "Basic DAST Scanning", icon: "Icon", category: "scanning" },
      owaspTop10: { name: "OWASP Top 10 Detection", icon: "Icon", category: "scanning" },
      sansTop25: { name: "SANS Top 25 Detection", icon: "Icon", category: "scanning" },
      apiTesting: { name: "API Security Testing", icon: "Icon", category: "scanning" },
      credentialScanning: { name: "Credential-based Scanning", icon: "Icon", category: "scanning" },
      authenticatedScanning: { name: "Authenticated Scanning", icon: "Icon", category: "scanning" },
      mobileAppTesting: { name: "Mobile App Penetration Testing", icon: "Icon", category: "scanning" },
      chatbotAccess: { name: "Jarwis AGI Chatbot", icon: "", category: "ai" },
      complianceReports: { name: "Compliance & Audit Reports", icon: "Icon", category: "reporting" },
      ciCdIntegration: { name: "CI/CD Integration", icon: "Icon", category: "integration" },
      webhooks: { name: "Webhooks", icon: "Icon", category: "integration" },
      apiAccess: { name: "API Access", icon: "Icon", category: "integration" },
      customBranding: { name: "Custom Branding", icon: "Icon", category: "enterprise" },
      ssoIntegration: { name: "SSO Integration", icon: "", category: "enterprise" },
      dedicatedSupport: { name: "Dedicated Support", icon: "Icon", category: "support" },
      slackIntegration: { name: "Slack Integration", icon: "Icon", category: "integration" },
      jiraIntegration: { name: "Jira Integration", icon: "Icon", category: "integration" },
      priorityScanning: { name: "Priority Scanning", icon: "Icon", category: "scanning" },
      advancedReporting: { name: "Advanced Reporting", icon: "Icon", category: "reporting" },
      scheduledScans: { name: "Scheduled Scans", icon: "Icon", category: "scanning" },
      realTimeAlerts: { name: "Real-time Alerts", icon: "Icon", category: "notifications" },
    };

    return Object.entries(plan.features).map(([key, enabled]) => ({
      id: key,
      enabled,
      ...featureDescriptions[key],
      upgradeInfo: !enabled ? getUpgradeMessage(key) : null,
    }));
  }, [userDoc?.plan, getUpgradeMessage]);

  // Check subscription status
  const subscriptionStatus = useMemo(() => {
    if (!userDoc?.subscription_end) {
      return { 
        isActive: userDoc?.plan === "trial" || userDoc?.plan === "free", 
        daysRemaining: null,
        expiresAt: null,
      };
    }

    const expiresAt = new Date(userDoc.subscription_end);
    const now = new Date();
    const daysRemaining = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));
    
    return {
      isActive: daysRemaining > 0,
      daysRemaining: Math.max(0, daysRemaining),
      expiresAt,
      isExpiringSoon: daysRemaining > 0 && daysRemaining <= 7,
    };
  }, [userDoc?.subscription_end, userDoc?.plan]);

  // Compare plans
  const comparePlans = useCallback(() => {
    return Object.values(PLAN_LIMITS);
  }, []);

  // Check if can upgrade to a plan
  const canUpgradeTo = useCallback((targetPlanId) => {
    const currentPlanId = userDoc?.plan || "trial";
    return isPlanHigher(targetPlanId, currentPlanId);
  }, [userDoc?.plan]);

  const value = {
    // Current plan info
    currentPlan,
    planId: userDoc?.plan || "trial",
    
    // Usage tracking
    usage,
    getAllUsageStats,
    getActionLimit,
    serverUsage, // Raw server data
    
    // Feature checking
    canPerformAction,
    checkFeature,
    getAllFeatures,
    hasFeature: checkFeature,
    hasFeatureAccess: checkFeature, // Alias for backwards compatibility
    
    // Server-side checks
    checkActionAllowed, // Async server check
    refreshSubscription: fetchSubscriptionData,
    
    // Upgrade helpers
    getUpgradeMessage,
    canUpgradeTo,
    comparePlans,
    
    // Subscription status
    subscriptionStatus,
    loading,
    error,
    
    // Plan limits reference
    PLAN_LIMITS,
  };

  return (
    <SubscriptionContext.Provider value={value}>
      {children}
    </SubscriptionContext.Provider>
  );
};

export default SubscriptionContext;
