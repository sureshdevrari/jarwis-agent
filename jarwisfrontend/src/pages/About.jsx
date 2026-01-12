import { Link } from "react-router-dom";
import Footer from "../components/Footer";
import AIFlowAnimation from "../components/AIFlowAnimation";
import AnimatedTypingHeading from "../components/AnimatedTypingHeading";
import { Globe, Smartphone, Wifi, Cloud, MessageSquare, Shield } from "lucide-react";
import { ScrollProgressBar, RevealOnScroll, StaggerContainer, StaggerItem } from "../components/ui";

const About = () => {
  // What we offer - comprehensive security services
  const services = [
    {
      icon: Globe,
      title: "Web Application Security",
      description: "Complete OWASP Top 10 and SANS Top 25 vulnerability detection for web applications, APIs, and business logic flaws.",
      image: "/gridphoto/web.png",
    },
    {
      icon: Smartphone,
      title: "Mobile App Security",
      description: "Deep analysis of Android (APK) and iOS (IPA) applications for security vulnerabilities, data leakage, and insecure storage.",
      image: "/gridphoto/mobile.png",
    },
    {
      icon: Wifi,
      title: "Network Security",
      description: "Infrastructure penetration testing covering port scanning, service enumeration, and network vulnerability assessment.",
      image: "/gridphoto/network.png",
    },
    {
      icon: Cloud,
      title: "Cloud Security",
      description: "Multi-cloud security audits for AWS, Azure, and GCP with compliance checks against CIS benchmarks and best practices.",
      image: "/gridphoto/cloud.png",
    },
    {
      icon: MessageSquare,
      title: "AI Security Assistant",
      description: "24/7 AI chatbot powered by advanced LLMs to answer security questions, explain vulnerabilities, and guide remediation.",
      image: "/gridphoto/chatbot1.png",
    },
    {
      icon: Shield,
      title: "Automated Remediation",
      description: "Get actionable fix recommendations, code snippets, and step-by-step guides to resolve vulnerabilities quickly.",
      image: "/gridphoto/chatbot2.png",
    },
  ];

  const bottomBoxes = [
    {
      title: "Multi-Agent Reasoning",
      points: [
        "Jarwis orchestrates specialised AI agents - recon, exploit, remediation, and compliance - each powered by large-language-model reasoning and real-time context sharing.",
      ],
    },
    {
      title: "Self-Updating Knowledge Graph",
      points: [
        "Every scan enriches Jarwis's internal security graph, allowing the platform to predict emerging attack paths and suggest preventive hardening before threats materialise.",
      ],
    },
    {
      title: "Zero-Trust by Design",
      points: [
        "Credentials provided for testing are stored ephemerally and deleted automatically once the scan is complete, ensuring no sensitive keys linger on our servers.",
      ],
    },
    {
      title: "Instant Remediation Blueprints",
      points: [
        "Beyond finding vulnerabilities, Jarwis generates merge-ready pull-requests, Terraform patches, and CI/CD guardrails so teams can fix issues the same day they're found.",
      ],
    },
  ];

  return (
    <div>
      {/* Scroll Progress Bar */}
      <ScrollProgressBar />

      <div className="text-white relative overflow-hidden">
        {/* Background Pattern/Lines */}
        <div className="absolute inset-0 opacity-10">
          {/* Top left curved line */}
          <svg
            className="absolute top-0 left-0 w-96 h-96"
            viewBox="0 0 400 400"
            fill="none"
          >
            <path
              d="M0 200 Q200 0 400 200"
              stroke="url(#gradient1)"
              strokeWidth="2"
              fill="none"
            />
            <defs>
              <linearGradient id="gradient1" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#3B82F6" />
                <stop offset="100%" stopColor="#06B6D4" />
              </linearGradient>
            </defs>
          </svg>

          {/* Bottom right curved line */}
          <svg
            className="absolute bottom-0 right-0 w-96 h-96"
            viewBox="0 0 400 400"
            fill="none"
          >
            <path
              d="M400 200 Q200 400 0 200"
              stroke="url(#gradient2)"
              strokeWidth="2"
              fill="none"
            />
            <defs>
              <linearGradient id="gradient2" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#3B82F6" />
                <stop offset="100%" stopColor="#06B6D4" />
              </linearGradient>
            </defs>
          </svg>

          {/* Additional subtle lines */}
          <div className="absolute top-1/4 left-1/4 w-px h-32 bg-gradient-to-b from-blue-500/20 to-transparent"></div>
          <div className="absolute top-3/4 right-1/3 w-px h-24 bg-gradient-to-b from-cyan-500/20 to-transparent"></div>
          <div className="absolute top-1/2 left-1/2 w-16 h-px bg-gradient-to-r from-blue-500/20 to-transparent"></div>
        </div>

        {/* Main Content */}
        <div className="relative z-10 flex flex-col items-center justify-center px-4 sm:px-6 lg:px-8 py-12 sm:py-16 lg:py-20">
          <div className="text-center max-w-4xl mx-auto space-y-6">
            {/* Enterprise Label */}
            <div className="mb-4">
              <span className="text-gray-400 text-sm font-medium tracking-wider uppercase">
                About Jarwis AGI
              </span>
            </div>

            <AnimatedTypingHeading />

            {/* Description */}
            <div className="space-y-4">
              <h2 className="text-xl sm:text-2xl font-semibold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
                Engineered by BKD Labs
              </h2>
              <p className="text-gray-300 text-base sm:text-lg lg:text-xl leading-relaxed max-w-3xl mx-auto">
                Jarwis is the world's first Domain-AGI Security Engineer - an autonomous AI that thinks, reasons, and protects like a senior security expert across Web, Mobile, Network, Cloud, and API security.
              </p>
              <p className="text-gray-500 text-sm sm:text-base font-medium">
                Made in India 🇮🇳
              </p>
            </div>

            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center pt-4">
              <Link
                to="/contact"
                className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium text-sm sm:text-base w-full sm:w-auto text-center"
              >
                Contact us
              </Link>

              <Link
                to={"/pricing"}
                className="bg-gray-800 text-white border border-gray-600 px-6 py-3 rounded-lg hover:bg-gray-700 hover:border-gray-500 transition-all duration-200 font-medium text-sm sm:text-base w-full sm:w-auto text-center"
              >
                View Pricing
              </Link>
            </div>
          </div>
        </div>

        <div className="absolute top-1/4 left-1/4 w-64 h-64 bg-blue-500/5 rounded-full blur-3xl"></div>
        <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl"></div>
      </div>

      {/* What We Do Section - Photo Grid */}
      <div className="px-4 sm:px-6 lg:px-8 py-12 sm:py-16 lg:py-20 bg-gradient-to-b from-transparent to-gray-900/50">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl xl:text-6xl font-bold mb-4">
              What{" "}
              <span className="bg-gradient-to-r from-blue-500 to-cyan-400 bg-clip-text text-transparent">
                We Do
              </span>
            </h2>
            <p className="text-gray-400 text-base sm:text-lg lg:text-xl max-w-3xl mx-auto">
              Comprehensive AI-powered security testing across your entire digital infrastructure
            </p>
          </div>

          {/* Photo Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {services.map((service, index) => (
              <div
                key={index}
                className="group relative bg-gradient-to-br from-gray-800/80 to-gray-900/80 rounded-2xl overflow-hidden border border-gray-700/50 hover:border-cyan-500/50 transition-all duration-300 hover:shadow-xl hover:shadow-cyan-500/10"
              >
                {/* Image */}
                <div className="relative h-48 overflow-hidden">
                  <img
                    src={service.image}
                    alt={service.title}
                    className="w-full h-full object-cover transform group-hover:scale-110 transition-transform duration-500"
                  />
                  <div className="absolute inset-0 bg-gradient-to-t from-gray-900 via-gray-900/50 to-transparent"></div>
                  <div className="absolute top-4 left-4 p-3 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-xl shadow-lg">
                    <service.icon className="w-5 h-5 text-white" />
                  </div>
                </div>

                {/* Content */}
                <div className="p-5">
                  <h3 className="text-lg font-semibold text-white mb-2">
                    {service.title}
                  </h3>
                  <p className="text-gray-400 text-sm leading-relaxed">
                    {service.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* What is Jarvis Section */}
      <div className="px-4 sm:px-6 relative lg:px-8 py-12 sm:py-16 lg:py-20">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-8 lg:gap-12 xl:gap-16">
            {/* Left Content */}
            <div className="flex-1 max-w-full xl:max-w-2xl">
              <h2 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl xl:text-6xl font-bold mb-6 leading-tight">
                What Is{" "}
                <span className="bg-gradient-to-r from-blue-500 to-cyan-400 bg-clip-text text-transparent">
                  Jarwis AGI?
                </span>
              </h2>

              <p className="text-gray-200 text-base sm:text-lg lg:text-xl mb-4 leading-relaxed">
                Jarwis is the world's first Domain-AGI Security Engineer - a revolutionary platform that combines autonomous AI with comprehensive security testing across all attack surfaces.
              </p>
              <p className="text-gray-200 text-base sm:text-lg lg:text-xl mb-4 leading-relaxed">
                Unlike traditional scanners, Jarwis understands business logic, chains vulnerabilities together, and provides actionable remediation - just like a senior penetration tester would.
              </p>
              <p className="text-gray-400 text-base sm:text-lg lg:text-xl mb-8 leading-relaxed">
                Supporting <span className="text-cyan-400 font-medium">Web Apps, Mobile Apps (APK/IPA), Network Infrastructure, Cloud (AWS/Azure/GCP)</span>, and <span className="text-cyan-400 font-medium">API Security</span> - all powered by advanced LLM reasoning.
              </p>

              <Link
                to={"/pricing"}
                className="bg-blue-600 text-white px-4 py-2 sm:px-6 sm:py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium text-sm sm:text-base"
              >
                Get Started
              </Link>
            </div>

            {/* Right Content - AI Flow Animation */}
            <div className="flex-1 flex items-center justify-center">
              <AIFlowAnimation />
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto mt-16 sm:mt-20">
          <h2 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl xl:text-6xl font-bold mb-8 leading-tight text-center">
            Why Is{" "}
            <span className="bg-gradient-to-r from-blue-500 to-cyan-400 bg-clip-text text-transparent">
              Jarwis AGI
            </span>{" "}
            So Advanced?
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mt-10">
            {bottomBoxes.map((box, index) => (
              <div
                key={index}
                className="bg-gradient-to-br from-gray-800/80 to-gray-900/80 border border-gray-700/50 rounded-2xl p-6 hover:border-cyan-500/50 transition-all duration-300 hover:shadow-xl hover:shadow-cyan-500/10"
              >
                <h4 className="text-lg font-semibold mb-4 text-white">
                  {box.title}
                </h4>
                <ul className="space-y-3 text-gray-400 text-sm">
                  {box.points.map((point, i) => (
                    <li key={i} className="flex items-start gap-3">
                      <span className="w-2 h-2 bg-cyan-500 rounded-full mt-1.5 flex-shrink-0"></span>
                      <span className="leading-relaxed">{point}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* CTA Section */}
      <div className="px-4 sm:px-6 relative lg:px-8 py-16 sm:py-20 lg:py-24">
        <div className="max-w-4xl mx-auto text-center space-y-6">
          <h2 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl xl:text-6xl font-bold leading-tight">
            Ready to Experience{" "}
            <span className="bg-gradient-to-r from-blue-500 to-cyan-400 bg-clip-text text-transparent">
              AI-Powered Security?
            </span>
          </h2>
          <p className="text-gray-300 text-base sm:text-lg lg:text-xl leading-relaxed max-w-3xl mx-auto">
            Join thousands of security teams who trust Jarwis for comprehensive vulnerability assessment.
          </p>
          <div className="pt-4">
            <Link
              to={"/pricing"}
              className="bg-blue-600 text-white px-4 py-2 sm:px-6 sm:py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium text-sm sm:text-base"
            >
              Hire Jarwis
            </Link>
          </div>
        </div>
        <div className="mt-16">
          <Footer />
        </div>
      </div>
    </div>
  );
};

export default About;
