// src/pages/HomeNew.jsx
// New Devin.ai-inspired landing page for Jarwis

import {
  HeroSection,
  WorkflowSteps,
  FeaturesGrid,
  StatsSection,
  CTASection,
  TrustedBy,
  FooterNew,
  UseCasesSlider,
  PrivacyClaim
} from "../components/landing";

const HomeNew = () => {
  return (
    <div className="min-h-screen bg-gray-950">
      {/* Hero Section */}
      <HeroSection />

      {/* Trusted By / Integrations Marquee */}
      <TrustedBy />

      {/* Use Cases - Web, Mobile, Network, Cloud, AI */}
      <UseCasesSlider />

      {/* How It Works - Workflow Steps */}
      <WorkflowSteps />

      {/* Stats Section */}
      <StatsSection />

      {/* Features Grid */}
      <FeaturesGrid />

      {/* Final CTA */}
      <CTASection />

      {/* Privacy Claim */}
      <PrivacyClaim />

      {/* Footer */}
      <FooterNew />
    </div>
  );
};

export default HomeNew;
