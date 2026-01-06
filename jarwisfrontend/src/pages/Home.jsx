import { useNavigate } from "react-router-dom";
import BuildMore from "../components/BuildMore";
import Footer from "../components/Footer";
import WhyJarwis from "../components/WhyJarwis";
import ImageToggleInterface from "../components/ImageToggleInterface";

const Home = () => {
  const navigate = useNavigate();

  return (
    <div>
      {/* Hero Section */}
      <div className="px-4 sm:px-6 relative lg:px-8 py-6 sm:py-8 lg:py-10 xl:py-10">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-8 lg:gap-12 xl:gap-16">
            {/* Left Content */}
            <div className="flex-1 max-w-full xl:max-w-2xl">
              <h1 className="text-4xl sm:text-4xl md:text-5xl lg:text-6xl xl:text-6xl font-bold mb-6 sm:mb-8 leading-tight">
                Meet{" "}
                <span className="bg-gradient-to-r from-blue-500 to-cyan-400 bg-clip-text text-transparent">
                  Jarwis:{" "}
                </span>
                Your
                <br />
                <span className="block">Domain-AGI Security Engineer</span>
              </h1>

              <button
                onClick={() => navigate("/pricing")}
                className="bg-blue-600 text-white px-4 py-2 sm:px-6 sm:py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium mb-8 sm:mb-12 text-sm sm:text-base"
              >
                Hire Jarwis
              </button>

              <p className="text-gray-400 text-base sm:text-lg lg:text-xl mb-4 max-w-md leading-relaxed">
                The World's First Human-Like AI Security Engineer
              </p>
              <p className="text-gray-200 text-base sm:text-lg lg:text-xl mb-4 max-w-md leading-relaxed">
                Revolutionary AI that thinks, reasons, and protects like a
                senior security expert. Jarwis automatically discovers and
                provide hand-holding support fixing OWASP Top 10 and SANS Top 25
                vulnerabilities across your entire digital infrastructure with
                just simple prompts.
              </p>
            </div>

            {/* Right Content - Slack/Linear Interface Mockup */}
            <ImageToggleInterface
              imageOne={"/imageOne.jpg"}
              imageTwo={"/imageTwo.jpg"}
            />
          </div>
        </div>
      </div>

      <div className="relative">
        <WhyJarwis />
        <BuildMore />
        <Footer />
      </div>
    </div>
  );
};

export default Home;
