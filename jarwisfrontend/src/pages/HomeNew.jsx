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
import AIEngineSection from "../components/solutions/AIEngineSection";
import { ScrollProgressBar, RevealOnScroll } from "../components/ui";

const HomeNew = () => {
  return (
    <div className="min-h-screen bg-gray-950">
      {/* Scroll Progress Bar - Palo Alto style */}
      <ScrollProgressBar />

      {/* Hero Section */}
      <HeroSection />

      {/* Trusted By / Integrations Marquee */}
      <RevealOnScroll animation="fadeUp" delay={0.1}>
        <TrustedBy />
      </RevealOnScroll>

      {/* Use Cases - Web, Mobile, Network, Cloud, AI */}
      <RevealOnScroll animation="fadeUp">
        <UseCasesSlider />
      </RevealOnScroll>

      {/* How It Works - Workflow Steps */}
      <RevealOnScroll animation="fadeUp">
        <WorkflowSteps />
      </RevealOnScroll>

      {/* AI Engine Section - Built by BKD Labs, No LLMs */}
      <RevealOnScroll animation="zoomIn">
        <AIEngineSection scanType="web" showInteractiveDemo={true} />
      </RevealOnScroll>

      {/* Stats Section */}
      <RevealOnScroll animation="fadeUp">
        <StatsSection />
      </RevealOnScroll>

      {/* Features Grid */}
      <RevealOnScroll animation="fadeUp">
        <FeaturesGrid />
      </RevealOnScroll>

      {/* Final CTA */}
      <RevealOnScroll animation="spring">
        <CTASection />
      </RevealOnScroll>

      {/* Privacy Claim */}
      <RevealOnScroll animation="fade">
        <PrivacyClaim />
      </RevealOnScroll>

      {/* Footer */}
      <FooterNew />
    </div>
  );
};

export default HomeNew;
