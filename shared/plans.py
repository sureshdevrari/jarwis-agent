"""
Centralized Plan Configuration - Single Source of Truth
========================================================
All subscription plans, limits, and features are defined here.
Both backend and frontend should derive their configuration from this file.

To change plan limits/features:
1. Update the PLANS dictionary below
2. Run `python shared/generate_frontend_plans.py` to update frontend config
3. Restart the backend server

Usage:
    from shared.plans import PlanManager, PlanId
    
    # Get plan config
    plan = PlanManager.get_plan("professional")
    
    # Check feature access
    has_mobile = PlanManager.has_feature("professional", "mobile_pentest")
    
    # Get limit
    max_scans = PlanManager.get_limit("professional", "max_scans_per_month")
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime


class PlanId(str, Enum):
    """Available subscription plan identifiers"""
    FREE = "free"
    TRIAL = "trial"
    INDIVIDUAL = "individual"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    DEVELOPER = "developer"  # Internal testing plan


class FeatureId(str, Enum):
    """Feature identifiers for subscription checks"""
    API_TESTING = "api_testing"
    CREDENTIAL_SCANNING = "credential_scanning"
    MOBILE_PENTEST = "mobile_pentest"
    NETWORK_SCAN = "network_scan"
    CLOUD_SCANNING = "cloud_scanning"
    SAST_SCANNING = "sast_scanning"
    CHATBOT_ACCESS = "chatbot_access"
    COMPLIANCE_AUDITS = "compliance_audits"
    ADVANCED_REPORTING = "advanced_reporting"
    PRIORITY_SUPPORT = "priority_support"
    DEDICATED_SUPPORT = "dedicated_support"
    API_KEY_ACCESS = "api_key_access"
    CI_CD_INTEGRATION = "ci_cd_integration"
    WEBHOOKS = "webhooks"
    SLACK_INTEGRATION = "slack_integration"
    JIRA_INTEGRATION = "jira_integration"
    SSO = "sso"
    CUSTOM_INTEGRATIONS = "custom_integrations"
    SCHEDULED_SCANS = "scheduled_scans"


class LimitId(str, Enum):
    """Limit identifiers for quota checks"""
    MAX_SCANS_PER_MONTH = "max_scans_per_month"
    MAX_WEBSITES_PER_MONTH = "max_websites_per_month"
    MAX_PAGES_PER_SCAN = "max_pages_per_scan"
    MAX_TEAM_MEMBERS = "max_team_members"
    DASHBOARD_ACCESS_DAYS = "dashboard_access_days"
    REPORT_RETENTION_DAYS = "report_retention_days"
    CHATBOT_TOKENS_PER_MONTH = "chatbot_tokens_per_month"


# Use -1 for unlimited values
UNLIMITED = -1


@dataclass
class PlanLimits:
    """Numerical limits for a plan"""
    max_scans_per_month: int = 0
    max_websites_per_month: int = 1
    max_pages_per_scan: int = 50
    max_team_members: int = 1
    dashboard_access_days: int = 7  # 0 = while plan active
    report_retention_days: int = 30
    chatbot_tokens_per_month: int = 0
    
    def get(self, limit_id: str) -> int:
        """Get limit by string ID"""
        return getattr(self, limit_id, 0)


@dataclass
class PlanFeatures:
    """Boolean feature flags for a plan"""
    api_testing: bool = False
    credential_scanning: bool = False
    mobile_pentest: bool = False
    network_scan: bool = False
    cloud_scanning: bool = False
    sast_scanning: bool = False
    chatbot_access: bool = False
    compliance_audits: bool = False
    advanced_reporting: bool = False
    priority_support: bool = False
    dedicated_support: bool = False
    api_key_access: bool = False
    ci_cd_integration: bool = False
    webhooks: bool = False
    slack_integration: bool = False
    jira_integration: bool = False
    sso: bool = False
    custom_integrations: bool = False
    scheduled_scans: bool = False
    
    def has(self, feature_id: str) -> bool:
        """Check if feature is enabled by string ID"""
        return getattr(self, feature_id, False)


@dataclass
class Plan:
    """Complete plan definition"""
    id: str
    name: str
    display_name: str
    description: str
    
    # Pricing
    price_monthly: Optional[int] = None  # In cents/paise, None for custom
    price_per_scan: Optional[int] = None  # For pay-per-scan plans
    currency: str = "INR"
    
    # Visual
    badge: str = ""
    color: str = "slate"
    gradient_from: str = "from-slate-500"
    gradient_to: str = "to-gray-600"
    is_popular: bool = False
    
    # Limits and Features
    limits: PlanLimits = field(default_factory=PlanLimits)
    features: PlanFeatures = field(default_factory=PlanFeatures)
    
    # Display text for marketing
    display_features: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    
    # Support
    support_level: str = "community"
    support_response_time: str = "72 hours"
    
    # Requirements
    requires_corporate_email: bool = False
    requires_approval: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            "id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "price_monthly": self.price_monthly,
            "price_per_scan": self.price_per_scan,
            "currency": self.currency,
            "badge": self.badge,
            "color": self.color,
            "is_popular": self.is_popular,
            "limits": {
                "max_scans_per_month": self.limits.max_scans_per_month,
                "max_websites_per_month": self.limits.max_websites_per_month,
                "max_pages_per_scan": self.limits.max_pages_per_scan,
                "max_team_members": self.limits.max_team_members,
                "dashboard_access_days": self.limits.dashboard_access_days,
                "report_retention_days": self.limits.report_retention_days,
                "chatbot_tokens_per_month": self.limits.chatbot_tokens_per_month,
            },
            "features": {
                "api_testing": self.features.api_testing,
                "credential_scanning": self.features.credential_scanning,
                "mobile_pentest": self.features.mobile_pentest,
                "network_scan": self.features.network_scan,
                "cloud_scanning": self.features.cloud_scanning,
                "sast_scanning": self.features.sast_scanning,
                "chatbot_access": self.features.chatbot_access,
                "compliance_audits": self.features.compliance_audits,
                "advanced_reporting": self.features.advanced_reporting,
                "priority_support": self.features.priority_support,
                "dedicated_support": self.features.dedicated_support,
                "api_key_access": self.features.api_key_access,
                "ci_cd_integration": self.features.ci_cd_integration,
                "webhooks": self.features.webhooks,
                "slack_integration": self.features.slack_integration,
                "jira_integration": self.features.jira_integration,
                "sso": self.features.sso,
                "custom_integrations": self.features.custom_integrations,
                "scheduled_scans": self.features.scheduled_scans,
            },
            "display_features": self.display_features,
            "limitations": self.limitations,
            "support_level": self.support_level,
            "support_response_time": self.support_response_time,
        }


# =============================================================================
# PLAN DEFINITIONS - THE SINGLE SOURCE OF TRUTH
# =============================================================================
# To add a new plan or modify limits:
# 1. Update this dictionary
# 2. Run generate_frontend_plans.py
# 3. Restart the backend
# =============================================================================

PLANS: Dict[str, Plan] = {
    PlanId.FREE.value: Plan(
        id="free",
        name="Free",
        display_name="Free (Corporate)",
        description="Basic access for corporate email holders",
        price_monthly=0,
        currency="INR",
        badge="",
        color="slate",
        gradient_from="from-slate-500",
        gradient_to="to-gray-600",
        limits=PlanLimits(
            max_scans_per_month=0,  # Admin assigns quota
            max_websites_per_month=0,
            max_pages_per_scan=50,
            max_team_members=1,
            dashboard_access_days=7,
            report_retention_days=14,
            chatbot_tokens_per_month=0,
        ),
        features=PlanFeatures(
            api_testing=False,
            credential_scanning=False,
            mobile_pentest=False,
            network_scan=False,
            cloud_scanning=False,
            sast_scanning=False,
            chatbot_access=False,
        ),
        display_features=[
            "Admin-assigned scan quota",
            "Basic OWASP Top 10 detection",
            "7-day report access",
            "Corporate email required",
        ],
        limitations=[
            "Requires admin approval",
            "No API testing",
            "No credential-based scanning",
            "No chatbot access",
        ],
        support_level="community",
        support_response_time="72 hours",
        requires_corporate_email=True,
        requires_approval=True,
    ),
    
    PlanId.TRIAL.value: Plan(
        id="trial",
        name="Trial",
        display_name="Trial",
        description="14-day trial for evaluation",
        price_monthly=0,
        currency="INR",
        badge="🎯",
        color="cyan",
        gradient_from="from-cyan-500",
        gradient_to="to-blue-600",
        limits=PlanLimits(
            max_scans_per_month=3,
            max_websites_per_month=1,
            max_pages_per_scan=50,
            max_team_members=1,
            dashboard_access_days=14,
            report_retention_days=14,
            chatbot_tokens_per_month=0,
        ),
        features=PlanFeatures(
            api_testing=False,
            credential_scanning=False,
            mobile_pentest=False,
            network_scan=False,
            cloud_scanning=False,
            sast_scanning=False,
            chatbot_access=False,
        ),
        display_features=[
            "1 Website scan",
            "3 Scans per month",
            "Basic OWASP Top 10 detection",
            "14-day report access",
            "Corporate email required",
        ],
        limitations=[
            "Corporate email required",
            "Limited to public-facing pages",
            "No API testing",
            "No credential-based scanning",
        ],
        support_level="community",
        support_response_time="72 hours",
        requires_corporate_email=True,
    ),
    
    PlanId.INDIVIDUAL.value: Plan(
        id="individual",
        name="Individual",
        display_name="Individual",
        description="Pay-per-scan for individual security researchers",
        price_per_scan=10000,  # ₹100 per scan in paise
        currency="INR",
        badge="⭐",
        color="blue",
        gradient_from="from-blue-500",
        gradient_to="to-cyan-500",
        limits=PlanLimits(
            max_scans_per_month=1,  # 1 scan per purchase
            max_websites_per_month=1,
            max_pages_per_scan=100,
            max_team_members=1,
            dashboard_access_days=7,
            report_retention_days=30,
            chatbot_tokens_per_month=0,
        ),
        features=PlanFeatures(
            api_testing=False,
            credential_scanning=False,
            mobile_pentest=False,
            network_scan=False,
            cloud_scanning=False,
            sast_scanning=False,
            chatbot_access=False,
        ),
        display_features=[
            "1 Website per month",
            "1 Scan per purchase",
            "OWASP Top 10 & SANS Top 25",
            "Public-facing DAST only",
            "7-day dashboard access",
            "Email support",
        ],
        limitations=[
            "No API testing",
            "No mobile/iOS scanning",
            "No cloud scanning",
            "No Jarwis AGI chatbot",
            "Single user only",
        ],
        support_level="email",
        support_response_time="48 hours",
    ),
    
    PlanId.PROFESSIONAL.value: Plan(
        id="professional",
        name="Professional",
        display_name="Professional",
        description="Full-featured plan for professional security teams",
        price_monthly=99900,  # ₹999/month in paise
        currency="INR",
        badge="🚀",
        color="purple",
        gradient_from="from-purple-500",
        gradient_to="to-pink-500",
        is_popular=True,
        limits=PlanLimits(
            max_scans_per_month=10,
            max_websites_per_month=10,
            max_pages_per_scan=500,
            max_team_members=3,
            dashboard_access_days=0,  # While plan active
            report_retention_days=365,
            chatbot_tokens_per_month=500000,  # 500K tokens
        ),
        features=PlanFeatures(
            api_testing=True,
            credential_scanning=True,
            mobile_pentest=True,
            network_scan=True,
            cloud_scanning=True,
            sast_scanning=True,
            chatbot_access=True,
            compliance_audits=True,
            advanced_reporting=True,
            api_key_access=True,
            ci_cd_integration=True,
            webhooks=True,
            slack_integration=True,
            jira_integration=True,
            scheduled_scans=True,
        ),
        display_features=[
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
        limitations=[
            "No Savi 3.1 Thinking model",
            "No dedicated pentester",
        ],
        support_level="priority",
        support_response_time="24 hours",
    ),
    
    PlanId.ENTERPRISE.value: Plan(
        id="enterprise",
        name="Enterprise",
        display_name="Enterprise",
        description="Custom solutions for large organizations",
        price_monthly=None,  # Custom pricing
        currency="INR",
        badge="👑",
        color="amber",
        gradient_from="from-amber-500",
        gradient_to="to-yellow-500",
        limits=PlanLimits(
            max_scans_per_month=UNLIMITED,
            max_websites_per_month=UNLIMITED,
            max_pages_per_scan=10000,
            max_team_members=UNLIMITED,
            dashboard_access_days=0,  # While plan active
            report_retention_days=UNLIMITED,
            chatbot_tokens_per_month=5000000,  # 5M tokens
        ),
        features=PlanFeatures(
            api_testing=True,
            credential_scanning=True,
            mobile_pentest=True,
            network_scan=True,
            cloud_scanning=True,
            sast_scanning=True,
            chatbot_access=True,
            compliance_audits=True,
            advanced_reporting=True,
            priority_support=True,
            dedicated_support=True,
            api_key_access=True,
            ci_cd_integration=True,
            webhooks=True,
            slack_integration=True,
            jira_integration=True,
            sso=True,
            custom_integrations=True,
            scheduled_scans=True,
        ),
        display_features=[
            "Unlimited scans",
            "Unlimited team members",
            "All scanning types",
            "Jarwis AGI - Savi 3.1 Thinking (5M tokens)",
            "Dedicated pentester available",
            "24/7 priority support",
            "Custom integrations",
            "SSO/SAML integration",
            "On-premise deployment option",
        ],
        limitations=[],
        support_level="dedicated",
        support_response_time="4 hours",
    ),
    
    PlanId.DEVELOPER.value: Plan(
        id="developer",
        name="Developer",
        display_name="Developer (Internal)",
        description="Internal testing plan with all features enabled",
        price_monthly=0,
        currency="INR",
        badge="🔧",
        color="green",
        gradient_from="from-green-500",
        gradient_to="to-emerald-500",
        limits=PlanLimits(
            max_scans_per_month=UNLIMITED,
            max_websites_per_month=UNLIMITED,
            max_pages_per_scan=UNLIMITED,
            max_team_members=UNLIMITED,
            dashboard_access_days=0,
            report_retention_days=UNLIMITED,
            chatbot_tokens_per_month=UNLIMITED,
        ),
        features=PlanFeatures(
            api_testing=True,
            credential_scanning=True,
            mobile_pentest=True,
            network_scan=True,
            cloud_scanning=True,
            sast_scanning=True,
            chatbot_access=True,
            compliance_audits=True,
            advanced_reporting=True,
            priority_support=True,
            dedicated_support=True,
            api_key_access=True,
            ci_cd_integration=True,
            webhooks=True,
            slack_integration=True,
            jira_integration=True,
            sso=True,
            custom_integrations=True,
            scheduled_scans=True,
        ),
        display_features=["All features enabled for testing"],
        limitations=[],
        support_level="internal",
        support_response_time="N/A",
    ),
}


# =============================================================================
# PLAN MANAGER - API FOR ACCESSING PLAN CONFIGURATION
# =============================================================================

class PlanManager:
    """
    Centralized API for accessing plan configuration.
    Use this class instead of directly accessing PLANS dictionary.
    """
    
    @staticmethod
    def get_plan(plan_id: str) -> Plan:
        """Get plan configuration by ID. Returns free plan if not found."""
        return PLANS.get(plan_id, PLANS[PlanId.FREE.value])
    
    @staticmethod
    def get_all_plans() -> Dict[str, Plan]:
        """Get all available plans"""
        return PLANS
    
    @staticmethod
    def get_public_plans() -> List[Plan]:
        """Get plans available for public signup (excludes developer)"""
        return [p for p in PLANS.values() if p.id != PlanId.DEVELOPER.value]
    
    @staticmethod
    def has_feature(plan_id: str, feature_id: str) -> bool:
        """Check if a plan has a specific feature enabled"""
        plan = PlanManager.get_plan(plan_id)
        return plan.features.has(feature_id)
    
    @staticmethod
    def get_limit(plan_id: str, limit_id: str) -> int:
        """Get a specific limit value for a plan"""
        plan = PlanManager.get_plan(plan_id)
        return plan.limits.get(limit_id)
    
    @staticmethod
    def is_unlimited(plan_id: str, limit_id: str) -> bool:
        """Check if a limit is unlimited (-1)"""
        return PlanManager.get_limit(plan_id, limit_id) == UNLIMITED
    
    @staticmethod
    def get_plan_hierarchy() -> List[str]:
        """Get plans in order from lowest to highest tier"""
        return [
            PlanId.FREE.value,
            PlanId.TRIAL.value,
            PlanId.INDIVIDUAL.value,
            PlanId.PROFESSIONAL.value,
            PlanId.ENTERPRISE.value,
        ]
    
    @staticmethod
    def is_plan_higher(plan_a: str, plan_b: str) -> bool:
        """Check if plan_a is a higher tier than plan_b"""
        hierarchy = PlanManager.get_plan_hierarchy()
        try:
            return hierarchy.index(plan_a) > hierarchy.index(plan_b)
        except ValueError:
            return False
    
    @staticmethod
    def get_upgrade_options(current_plan: str) -> List[Plan]:
        """Get available upgrade options for current plan"""
        hierarchy = PlanManager.get_plan_hierarchy()
        try:
            current_index = hierarchy.index(current_plan)
            upgrade_ids = hierarchy[current_index + 1:]
            return [PLANS[pid] for pid in upgrade_ids if pid in PLANS]
        except ValueError:
            return []
    
    @staticmethod
    def to_frontend_config() -> Dict[str, Any]:
        """Export configuration for frontend consumption"""
        return {
            plan_id: plan.to_dict() 
            for plan_id, plan in PLANS.items()
        }


# =============================================================================
# BACKWARD COMPATIBILITY - Aliases for existing code
# =============================================================================
# These provide backward compatibility with existing database/subscription.py

def get_plan_config(plan: str) -> Dict[str, Any]:
    """Get configuration for a specific plan (legacy compatibility)"""
    plan_obj = PlanManager.get_plan(plan)
    return {
        "display_name": plan_obj.display_name,
        "price_monthly": plan_obj.price_monthly,
        "price_per_scan": plan_obj.price_per_scan,
        "limits": {
            "max_websites_per_month": plan_obj.limits.max_websites_per_month,
            "max_scans_per_month": plan_obj.limits.max_scans_per_month,
            "max_pages_per_scan": plan_obj.limits.max_pages_per_scan,
            "max_team_members": plan_obj.limits.max_team_members,
            "dashboard_access_days": plan_obj.limits.dashboard_access_days,
        },
        "features": {
            "api_testing": plan_obj.features.api_testing,
            "credential_scanning": plan_obj.features.credential_scanning,
            "mobile_pentest": plan_obj.features.mobile_pentest,
            "network_scan": plan_obj.features.network_scan,
            "cloud_scanning": plan_obj.features.cloud_scanning,
            "chatbot_access": plan_obj.features.chatbot_access,
            "compliance_audits": plan_obj.features.compliance_audits,
            "advanced_reporting": plan_obj.features.advanced_reporting,
            "priority_support": plan_obj.features.priority_support,
            "dedicated_support": plan_obj.features.dedicated_support,
            "api_key_access": plan_obj.features.api_key_access,
            "custom_integrations": plan_obj.features.custom_integrations,
            "sso": plan_obj.features.sso,
        }
    }


def get_plan_limit(plan: str, limit_key: str) -> int:
    """Get a specific limit value for a plan (legacy compatibility)"""
    return PlanManager.get_limit(plan, limit_key)


def has_feature(plan: str, feature_key: str) -> bool:
    """Check if a plan has a specific feature (legacy compatibility)"""
    return PlanManager.has_feature(plan, feature_key)
