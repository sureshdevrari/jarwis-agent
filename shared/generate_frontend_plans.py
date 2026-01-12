#!/usr/bin/env python3
"""
Generate Frontend Plan Configuration
=====================================
This script generates the frontend planLimits.js from the centralized 
shared/plans.py configuration.

Usage:
    python shared/generate_frontend_plans.py

This ensures the frontend always has up-to-date plan definitions
without manual synchronization.
"""

import os
import sys
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from shared.plans import PlanManager, PLANS, UNLIMITED


def generate_frontend_config() -> str:
    """Generate JavaScript configuration from Python plans"""
    
    js_lines = [
        "// src/config/planLimits.js",
        "// AUTO-GENERATED from shared/plans.py - DO NOT EDIT DIRECTLY",
        "// Run: python shared/generate_frontend_plans.py",
        f"// Generated at: {__import__('datetime').datetime.now().isoformat()}",
        "",
        "export const PLAN_LIMITS = {",
    ]
    
    for plan_id, plan in PLANS.items():
        js_lines.append(f'  {plan_id}: {{')
        js_lines.append(f'    id: "{plan.id}",')
        js_lines.append(f'    name: "{plan.name}",')
        js_lines.append(f'    badge: "{plan.badge}",')
        
        # Price formatting
        if plan.price_monthly is None:
            js_lines.append('    price: "Custom",')
            js_lines.append('    priceMonthly: -1,')
        elif plan.price_per_scan:
            price_display = f"₹{plan.price_per_scan // 100}/scan"
            js_lines.append(f'    price: "{price_display}",')
            js_lines.append(f'    priceMonthly: {plan.price_per_scan // 100},')
        else:
            price_display = "Free" if plan.price_monthly == 0 else f"₹{plan.price_monthly // 100}/month"
            js_lines.append(f'    price: "{price_display}",')
            js_lines.append(f'    priceMonthly: {plan.price_monthly // 100},')
        
        js_lines.append(f'    color: "{plan.color}",')
        js_lines.append(f'    gradientFrom: "{plan.gradient_from}",')
        js_lines.append(f'    gradientTo: "{plan.gradient_to}",')
        
        if plan.is_popular:
            js_lines.append('    isPopular: true,')
        
        js_lines.append('')
        js_lines.append('    // Scan Limits')
        
        # Limits - convert -1 to JavaScript Infinity representation
        max_scans = plan.limits.max_scans_per_month
        max_websites = plan.limits.max_websites_per_month
        max_pages = plan.limits.max_pages_per_scan
        max_team = plan.limits.max_team_members
        
        js_lines.append(f'    maxWebsitesPerMonth: {"-1" if max_websites == UNLIMITED else max_websites},')
        js_lines.append(f'    maxScansPerMonth: {"-1" if max_scans == UNLIMITED else max_scans},')
        js_lines.append(f'    maxPagesPerScan: {"-1" if max_pages == UNLIMITED else max_pages},')
        js_lines.append(f'    maxTeamMembers: {"-1" if max_team == UNLIMITED else max_team},')
        
        js_lines.append('')
        js_lines.append('    // Time Limits')
        js_lines.append(f'    dashboardAccessDays: {plan.limits.dashboard_access_days},')
        js_lines.append(f'    reportRetentionDays: {plan.limits.report_retention_days},')
        
        js_lines.append('')
        js_lines.append('    // Feature Access')
        js_lines.append('    features: {')
        js_lines.append('      basicDAST: true,')
        js_lines.append('      owaspTop10: true,')
        js_lines.append('      sansTop25: true,')
        js_lines.append(f'      apiTesting: {str(plan.features.api_testing).lower()},')
        js_lines.append(f'      credentialScanning: {str(plan.features.credential_scanning).lower()},')
        js_lines.append(f'      authenticatedScanning: {str(plan.features.credential_scanning).lower()},')
        js_lines.append(f'      mobileAppTesting: {str(plan.features.mobile_pentest).lower()},')
        js_lines.append(f'      cloudScanning: {str(plan.features.cloud_scanning).lower()},')
        js_lines.append(f'      sastScanning: {str(plan.features.sast_scanning).lower()},')
        js_lines.append(f'      chatbotAccess: {str(plan.features.chatbot_access).lower()},')
        js_lines.append(f'      complianceReports: {str(plan.features.compliance_audits).lower()},')
        js_lines.append(f'      ciCdIntegration: {str(plan.features.ci_cd_integration).lower()},')
        js_lines.append(f'      webhooks: {str(plan.features.webhooks).lower()},')
        js_lines.append(f'      apiAccess: {str(plan.features.api_key_access).lower()},')
        js_lines.append(f'      customBranding: false,')
        js_lines.append(f'      ssoIntegration: {str(plan.features.sso).lower()},')
        js_lines.append(f'      dedicatedSupport: {str(plan.features.dedicated_support).lower()},')
        js_lines.append(f'      slackIntegration: {str(plan.features.slack_integration).lower()},')
        js_lines.append(f'      jiraIntegration: {str(plan.features.jira_integration).lower()},')
        js_lines.append(f'      priorityScanning: {str(plan.features.priority_support).lower()},')
        js_lines.append(f'      advancedReporting: {str(plan.features.advanced_reporting).lower()},')
        js_lines.append(f'      scheduledScans: {str(plan.features.scheduled_scans).lower()},')
        js_lines.append('      realTimeAlerts: true,')
        js_lines.append('    },')
        
        js_lines.append('')
        js_lines.append('    // Support')
        js_lines.append(f'    supportLevel: "{plan.support_level}",')
        js_lines.append(f'    supportResponseTime: "{plan.support_response_time}",')
        
        js_lines.append('')
        js_lines.append('    // Display')
        js_lines.append(f'    displayFeatures: {json.dumps(plan.display_features)},')
        js_lines.append(f'    limitations: {json.dumps(plan.limitations)},')
        
        js_lines.append('  },')
        js_lines.append('')
    
    js_lines.append('};')
    js_lines.append('')
    
    # Add helper functions
    js_lines.extend([
        '',
        '// Helper functions',
        'export const getPlanById = (planId) => PLAN_LIMITS[planId] || PLAN_LIMITS.free;',
        '',
        'export const hasFeature = (planId, featureKey) => {',
        '  const plan = getPlanById(planId);',
        '  return plan?.features?.[featureKey] ?? false;',
        '};',
        '',
        'export const isWithinLimit = (planId, limitKey, currentUsage) => {',
        '  const plan = getPlanById(planId);',
        '  const limit = plan?.[limitKey] ?? 0;',
        '  if (limit === -1) return true; // Unlimited',
        '  return currentUsage < limit;',
        '};',
        '',
        'export const getRemainingQuota = (planId, limitKey, currentUsage) => {',
        '  const plan = getPlanById(planId);',
        '  const limit = plan?.[limitKey] ?? 0;',
        '  if (limit === -1) return Infinity;',
        '  return Math.max(0, limit - currentUsage);',
        '};',
        '',
        'export const getUsagePercentage = (planId, limitKey, currentUsage) => {',
        '  const plan = getPlanById(planId);',
        '  const limit = plan?.[limitKey] ?? 0;',
        '  if (limit === -1 || limit === 0) return 0;',
        '  return Math.min(100, (currentUsage / limit) * 100);',
        '};',
        '',
        'export const isPlanHigher = (planA, planB) => {',
        '  const hierarchy = ["free", "trial", "individual", "professional", "enterprise"];',
        '  return hierarchy.indexOf(planA) > hierarchy.indexOf(planB);',
        '};',
        '',
        'export default PLAN_LIMITS;',
    ])
    
    return '\n'.join(js_lines)


def main():
    """Generate and optionally write the frontend config"""
    
    js_content = generate_frontend_config()
    
    # Output file path
    output_path = project_root / "jarwisfrontend" / "src" / "config" / "planLimits.generated.js"
    
    # Check if we should write to file
    if len(sys.argv) > 1 and sys.argv[1] == "--write":
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(js_content)
        print(f"✅ Generated: {output_path}")
        print(f"   Plans: {', '.join(PLANS.keys())}")
    else:
        print("Generated JavaScript config:")
        print("-" * 60)
        print(js_content)
        print("-" * 60)
        print(f"\nTo write to {output_path}:")
        print(f"  python {__file__} --write")


if __name__ == "__main__":
    main()
