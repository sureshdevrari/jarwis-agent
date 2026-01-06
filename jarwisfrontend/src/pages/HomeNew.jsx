// src/pages/HomeNew.jsx
// New Devin.ai-inspired landing page for Jarwis

import {
  HeroSection,
  WorkflowSteps,
  FeaturesGrid,
  StatsSection,
  CTASection,
  TrustedBy,
  FooterNew
} from "../components/landing";

const HomeNew = () => {
  return (
    <div className="min-h-screen bg-gray-950">
      {/* Hero Section */}
      <HeroSection />

      {/* Trusted By / Integrations Marquee */}
      <TrustedBy />

      {/* How It Works - Workflow Steps */}
      <WorkflowSteps />

      {/* Stats Section */}
      <StatsSection />

      {/* Features Grid */}
      <FeaturesGrid />

      {/* Final CTA */}
      <CTASection />

      {/* Footer */}
      <FooterNew />
    </div>
  );
};

export default HomeNew;
