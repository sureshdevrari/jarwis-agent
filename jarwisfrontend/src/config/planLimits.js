// src/config/planLimits.js
// Centralized subscription plan configuration
// This defines all features and limits for each plan

export const PLAN_LIMITS = {
  trial: {
    id: "trial",
    name: "Trial",
    badge: "",
    price: "Free",
    priceMonthly: 0,
    color: "cyan",
    gradientFrom: "from-cyan-500",
    gradientTo: "to-blue-600",
    
    // Scan Limits
    maxWebsitesPerMonth: 1,
    maxScansPerMonth: 3,
    maxPagesPerScan: 50,
    maxTeamMembers: 1, // Only the owner
    
    // Time Limits
    dashboardAccessDays: 14,
    reportRetentionDays: 14,
    
    // Requirements
    requiresCorporateEmail: true, // Must have corporate email to request,
    
    // Feature Access
    features: {
      basicDAST: true,
      owaspTop10: true,
      sansTop25: true,
      apiTesting: false,
      credentialScanning: false,
      authenticatedScanning: false,
      mobileAppTesting: false,
      cloudScanning: false,  // No cloud for free
      chatbotAccess: false,
      chatbotQuestionsPerDay: 0,
      complianceReports: false,
      ciCdIntegration: false,
      webhooks: false,
      apiAccess: false,
      customBranding: false,
      ssoIntegration: false,
      dedicatedSupport: false,
      slackIntegration: false,
      jiraIntegration: false,
      priorityScanning: false,
      advancedReporting: false,
      exportFormats: ["html"],
      scheduledScans: false,
      realTimeAlerts: false,
    },
    
    // Support
    supportLevel: "community",
    supportResponseTime: "72 hours",
    
    // Display
    displayFeatures: [
      "1 Website scan",
      "3 Scans per month",
      "Basic OWASP Top 10 detection",
      "14-day report access",
      "Corporate email required",
    ],
    limitations: [
      "Corporate email required",
      "Limited to public-facing pages only",
      "No API testing",
      "No credential-based scanning",
      "No chatbot access",
    ],
  },
  
  individual: {
    id: "individual",
    name: "Individual",
    badge: "[STAR]",
    price: "$20/scan",
    priceMonthly: 20,
    color: "blue",
    gradientFrom: "from-blue-500",
    gradientTo: "to-cyan-500",
    
    // Scan Limits - Individual can only scan 1 website, 1 scan per month
    maxWebsitesPerMonth: 1,
    maxScansPerMonth: 1,
    maxPagesPerScan: 100,
    maxTeamMembers: 1,
    
    // Time Limits
    dashboardAccessDays: 7,
    reportRetentionDays: 30,
    
    // Feature Access - Limited features for Individual
    features: {
      basicDAST: true,
      owaspTop10: true,
      sansTop25: true,
      apiTesting: false,  // No API testing
      credentialScanning: false,
      authenticatedScanning: false,
      mobileAppTesting: false,  // No mobile
      cloudScanning: false,  // No cloud
      chatbotAccess: false,
      chatbotQuestionsPerDay: 0,
      complianceReports: false,
      ciCdIntegration: false,
      webhooks: false,
      apiAccess: false,
      customBranding: false,
      ssoIntegration: false,
      dedicatedSupport: false,
      slackIntegration: false,
      jiraIntegration: false,
      priorityScanning: false,
      advancedReporting: false,
      exportFormats: ["html", "json"],
      scheduledScans: false,
      realTimeAlerts: false,
    },
    
    // Support
    supportLevel: "email",
    supportResponseTime: "48 hours",
    
    // Display
    displayFeatures: [
      "1 Website per month",
      "1 Scan per month",
      "OWASP Top 10 & SANS Top 25",
      "Public-facing DAST only",
      "7-day dashboard access",
      "Email support",
    ],
    limitations: [
      "No API testing",
      "No mobile/iOS scanning",
      "No cloud scanning",
      "No Jarwis AGI chatbot",
      "Single user only",
    ],
  },
  
  professional: {
    id: "professional",
    name: "Professional",
    badge: "",
    price: "$999/month",
    priceMonthly: 999,
    color: "purple",
    gradientFrom: "from-purple-500",
    gradientTo: "to-pink-500",
    isPopular: true,
    
    // Scan Limits
    maxWebsitesPerMonth: 10,
    maxScansPerMonth: 10,
    maxPagesPerScan: 500,
    maxTeamMembers: 3,
    
    // Time Limits
    dashboardAccessDays: 365, // While plan is active
    reportRetentionDays: 365,
    
    // Feature Access
    features: {
      basicDAST: true,
      owaspTop10: true,
      sansTop25: true,
      apiTesting: true,
      credentialScanning: true,
      authenticatedScanning: true,
      mobileAppTesting: true,  // Pro includes mobile
      cloudScanning: true,  // Pro includes cloud
      chatbotAccess: true,
      chatbotQuestionsPerDay: -1, // Unlimited
      complianceReports: false,
      ciCdIntegration: true,
      webhooks: true,
      apiAccess: true,
      customBranding: false,
      ssoIntegration: false,
      dedicatedSupport: false,
      slackIntegration: true,
      jiraIntegration: true,
      priorityScanning: true,
      advancedReporting: true,
      exportFormats: ["html", "json", "pdf", "sarif"],
      scheduledScans: true,
      realTimeAlerts: true,
    },
    
    // Support
    supportLevel: "priority",
    supportResponseTime: "24 hours",
    
    // Display
    displayFeatures: [
      "10 Scans per month (Web, Mobile, Cloud, API)",
      "Up to 3 team members",
      "Full DAST with credentials",
      "API security testing",
      "Mobile app testing",
      "Cloud security scanning",
      "Jarwis AGI - Suru 1.1 (500K tokens/month)",
      "CI/CD integration",
      "Slack & Jira integration",
      "Priority support (24hr)",
    ],
    limitations: [
      "No Savi 3.1 Thinking model",
      "No compliance audits",
      "No dedicated pentester",
    ],
  },
  
  enterprise: {
    id: "enterprise",
    name: "Enterprise",
    badge: "",
    price: "Custom",
    priceMonthly: -1, // Custom pricing
    color: "amber",
    gradientFrom: "from-amber-500",
    gradientTo: "to-yellow-500",
    
    // Scan Limits
    maxWebsitesPerMonth: -1, // Unlimited
    maxScansPerMonth: -1, // Unlimited
    maxPagesPerScan: -1, // Unlimited
    maxTeamMembers: -1, // Unlimited
    
    // Time Limits
    dashboardAccessDays: 365,
    reportRetentionDays: -1, // Unlimited
    
    // Feature Access
    features: {
      basicDAST: true,
      owaspTop10: true,
      sansTop25: true,
      apiTesting: true,
      credentialScanning: true,
      authenticatedScanning: true,
      mobileAppTesting: true,
      cloudScanning: true,  // Enterprise includes cloud
      chatbotAccess: true,
      chatbotQuestionsPerDay: -1, // Unlimited
      complianceReports: true,
      ciCdIntegration: true,
      webhooks: true,
      apiAccess: true,
      customBranding: true,
      ssoIntegration: true,
      dedicatedSupport: true,
      slackIntegration: true,
      jiraIntegration: true,
      priorityScanning: true,
      advancedReporting: true,
      exportFormats: ["html", "json", "pdf", "sarif", "xml", "csv"],
      scheduledScans: true,
      realTimeAlerts: true,
    },
    
    // Support
    supportLevel: "dedicated",
    supportResponseTime: "1 hour",
    hasDedicatedPentester: true,
    hasDedicatedAuditor: true,
    has24x7Support: true,
    
    // Display
    displayFeatures: [
      "Unlimited scans (Web, Mobile, Cloud, API)",
      "Unlimited team members",
      "Jarwis AGI - Savi 3.1 Thinking (5M tokens/month)",
      "Best AI model for cybersecurity",
      "Mobile app penetration testing",
      "Compliance & audit reports",
      "Dedicated pentester",
      "Dedicated auditor",
      "24/7 call & chat support",
      "Custom integrations",
      "SSO integration",
    ],
    limitations: [],
  },
};

// Helper function to get plan by ID
export const getPlanById = (planId) => {
  return PLAN_LIMITS[planId] || PLAN_LIMITS.trial;
};

// Helper function to check if a feature is available for a plan
export const hasFeature = (planId, featureName) => {
  const plan = getPlanById(planId);
  return plan.features[featureName] || false;
};

// Helper function to check if user has reached their limit
export const isWithinLimit = (planId, limitName, currentValue) => {
  const plan = getPlanById(planId);
  const limit = plan[limitName];
  if (limit === -1) return true; // Unlimited
  return currentValue < limit;
};

// Helper function to get remaining quota
export const getRemainingQuota = (planId, limitName, currentValue) => {
  const plan = getPlanById(planId);
  const limit = plan[limitName];
  if (limit === -1) return "Unlimited";
  return Math.max(0, limit - currentValue);
};

// Helper function to get usage percentage
export const getUsagePercentage = (planId, limitName, currentValue) => {
  const plan = getPlanById(planId);
  const limit = plan[limitName];
  if (limit === -1) return 0; // Show 0% for unlimited
  return Math.min(100, Math.round((currentValue / limit) * 100));
};

// Export all plan IDs
export const PLAN_IDS = Object.keys(PLAN_LIMITS);

// Get plans sorted by price for comparison
export const getSortedPlans = () => {
  return Object.values(PLAN_LIMITS).sort((a, b) => {
    if (a.priceMonthly === -1) return 1;
    if (b.priceMonthly === -1) return -1;
    return a.priceMonthly - b.priceMonthly;
  });
};

// Check if plan A is higher than plan B
export const isPlanHigher = (planA, planB) => {
  const order = ["trial", "free", "individual", "professional", "enterprise"];
  return order.indexOf(planA) > order.indexOf(planB);
};

export default PLAN_LIMITS;
