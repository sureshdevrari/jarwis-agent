import { Link } from "react-router-dom";
import ContactForm from "../components/ContactForm";
import ContactCards from "../components/ContactCards";
import Footer from "../components/Footer";

const Contact = () => {
  return (
    <div className="min-h-screen">
      <div className="text-white relative overflow-hidden">
        {/* Background Pattern/Lines */}
        <div className="absolute inset-0 opacity-10 pointer-events-none">
          {/* Top left curved line */}
          <svg
            className="absolute top-0 left-0 w-96 h-96 pointer-events-none"
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
            className="absolute bottom-0 right-0 w-96 h-96 pointer-events-none"
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
        <div className="relative z-10 flex flex-col items-center justify-center px-4 sm:px-6 lg:px-8 py-8 sm:py-10 lg:py-10">
          <div className="text-center max-w-4xl mx-auto space-y-6 sm:space-y-8 lg:space-y-10">
            {/* Enterprise Label */}
            <div className="mb-8">
              <span className="text-gray-400 text-sm sm:text-base lg:text-lg font-medium tracking-wide">
                Contact Us
              </span>
            </div>

            {/* Main Heading */}
            <h1 className="text-3xl sm:text-4xl  md:text-5xl lg:text-6xl xl:text-7xl font-bold leading-tight">
              <span className="text-white"> Hire </span>
              <span className="bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
                Jarwis
              </span>
            </h1>

            {/* Description */}
            <p className="text-gray-300 text-sm sm:text-base md:text-lg lg:text-xl xl:text-2xl leading-relaxed max-w-3xl mx-auto">
              Have questions? Get in touch with us at{" "}
              <a
                href="/"
                className="bg-gradient-to-r border-b-2 border-blue-600 pb-1 border-dotted from-blue-400 to-cyan-400 bg-clip-text text-transparent"
              >
                jarwis.ai
              </a>
            </p>

            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row gap-4 sm:gap-6 justify-center items-center">
              <Link
                to={"/pricing"}
                className="bg-gray-800 text-white border border-gray-600 px-8 py-3 rounded-2xl hover:bg-gray-700 hover:border-gray-500 transition-all duration-200 font-medium text-sm sm:text-base lg:text-lg shadow-lg hover:shadow-xl transform hover:scale-105 w-full sm:w-auto"
              >
                Request Early Access
              </Link>
            </div>
          </div>
        </div>

        {/* Subtle Glow Effects */}
        <div className="absolute top-1/4 left-1/4 w-64 h-64 bg-blue-500/5 rounded-full blur-3xl"></div>
        <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl"></div>
      </div>

      {/* contact form */}
      <ContactForm />

      {/* Socoal link and email */}
      <ContactCards />

      {/* Footer */}
      <Footer />
    </div>
  );
};

export default Contact;
