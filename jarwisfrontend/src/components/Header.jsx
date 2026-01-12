import { useState, useRef, useEffect } from "react";
import { Link, Outlet, useNavigate, useLocation } from "react-router-dom";
import { Globe, Smartphone, Server, Cloud, Code2 } from "lucide-react";

// import { useAuth } from "../context/AuthContext";
import { useAuth } from "../context/AuthContext";

import { CgProfile } from "react-icons/cg";

const Header = () => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const navigate = useNavigate();
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) {
      return;
    }

    const ctx = canvas.getContext("2d");
    if (!ctx) {
      return;
    }

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const waves = [
      {
        y: height * 0.5,
        length: 0.015,
        amplitude: 80,
        frequency: 0.01,
        color: "rgba(0, 255, 255, 0.2)",
      },
      {
        y: height * 0.6,
        length: 0.02,
        amplitude: 60,
        frequency: 0.02,
        color: "rgba(0, 180, 255, 0.15)",
      },
      {
        y: height * 0.4,
        length: 0.025,
        amplitude: 50,
        frequency: 0.018,
        color: "rgba(0, 140, 255, 0.1)",
      },
    ];

    let increment = 0;

    let animationId;

    const animate = () => {
      ctx.clearRect(0, 0, width, height);

      waves.forEach((wave) => {
        ctx.beginPath();
        ctx.moveTo(0, height / 2);

        for (let x = 0; x < width; x++) {
          const y =
            wave.y +
            Math.sin(x * wave.length + increment) *
              wave.amplitude *
              Math.sin(increment);
          ctx.lineTo(x, y);
        }

        ctx.strokeStyle = wave.color;
        ctx.lineWidth = 2;
        ctx.stroke();
      });

      increment += 0.02;
      animationId = requestAnimationFrame(animate);
    };

    animate();

    const resize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener("resize", resize);

    return () => {
      window.removeEventListener("resize", resize);
      if (animationId) {
        cancelAnimationFrame(animationId);
      }
    };
  }, []);

  // auth
  const { user, userDoc } = useAuth();

  const location = useLocation();

  // Helper function to check if link is active
  const isActiveLink = (path) => {
    if (path === "/") {
      return location.pathname === "/";
    }
    return location.pathname.startsWith(path);
  };

  return (
    <div className="relative bg-gray-900">
      {/* Header */}
      <header className="px-4 sm:px-6 lg:px-8 py-3 sm:py-4 border-b border-gray-700 sticky top-0 z-50 bg-black/50 backdrop-blur-md">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          {/* Logo */}
          <div className="flex items-center space-x-4 lg:space-x-8">
            <div
              onClick={() => navigate("/")}
              className="flex justify-center items-center cursor-pointer"
            >
              <img
                src="/logo/jarwis-logo-transparent.svg"
                alt="Jarwis Logo"
                className="object-contain w-[44px]"
              />
              {/* <h1 className="text-xl font-bold bg-gradient-to-r from-blue-500 to-cyan-400 bg-clip-text text-transparent">
                JARWIS
              </h1> */}
            </div>

            {/* Desktop Navigation */}
            <nav className="hidden md:flex items-center space-x-6">
              <Link
                to="/"
                className={`relative text-sm font-medium transition-all duration-200 ${
                  isActiveLink("/")
                    ? "text-white"
                    : "text-cyan-300 hover:text-gray-300"
                }`}
              >
                Home
                {isActiveLink("/") && (
                  <>
                    <div className="absolute -bottom-1 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-400 to-blue-400 rounded-full"></div>
                    <div className="absolute -bottom-2 left-1/2 transform -translate-x-1/2 w-1 h-1 bg-cyan-400 rounded-full animate-pulse"></div>
                  </>
                )}
              </Link>

              {/* Solutions Dropdown */}
              <div className="relative group">
                <button
                  className={`relative text-sm font-medium transition-all duration-200 flex items-center gap-1 ${
                    isActiveLink("/solutions")
                      ? "text-white"
                      : "text-cyan-300 hover:text-white"
                  }`}
                >
                  Solutions
                  <svg
                    className="w-4 h-4 transition-transform group-hover:rotate-180"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                  {isActiveLink("/solutions") && (
                    <>
                      <div className="absolute -bottom-1 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-400 to-blue-400 rounded-full"></div>
                      <div className="absolute -bottom-2 left-1/2 transform -translate-x-1/2 w-1 h-1 bg-cyan-400 rounded-full animate-pulse"></div>
                    </>
                  )}
                </button>

                {/* Dropdown Menu */}
                <div className="absolute top-full left-0 pt-2 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50">
                  <div className="bg-gray-900/95 backdrop-blur-xl border border-gray-700 rounded-xl shadow-2xl overflow-hidden min-w-[280px]">
                    <div className="p-2">
                      <Link
                        to="/solutions/web-security"
                        className="flex items-center gap-3 p-3 rounded-lg hover:bg-cyan-500/10 transition-colors group/item"
                      >
                        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                          <Globe className="w-5 h-5 text-white" />
                        </div>
                        <div>
                          <div className="text-sm font-medium text-white group-hover/item:text-cyan-300 transition-colors">Web Security</div>
                          <div className="text-xs text-gray-500">OWASP Top 10, API Security</div>
                        </div>
                      </Link>

                      <Link
                        to="/solutions/mobile-security"
                        className="flex items-center gap-3 p-3 rounded-lg hover:bg-purple-500/10 transition-colors group/item"
                      >
                        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center">
                          <Smartphone className="w-5 h-5 text-white" />
                        </div>
                        <div>
                          <div className="text-sm font-medium text-white group-hover/item:text-purple-300 transition-colors">Mobile Security</div>
                          <div className="text-xs text-gray-500">APK/IPA Analysis, MASTG</div>
                        </div>
                      </Link>

                      <Link
                        to="/solutions/network-security"
                        className="flex items-center gap-3 p-3 rounded-lg hover:bg-green-500/10 transition-colors group/item"
                      >
                        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-green-500 to-emerald-600 flex items-center justify-center">
                          <Server className="w-5 h-5 text-white" />
                        </div>
                        <div>
                          <div className="text-sm font-medium text-white group-hover/item:text-green-300 transition-colors">Network Security</div>
                          <div className="text-xs text-gray-500">Port Scanning, CVE Detection</div>
                        </div>
                      </Link>

                      <Link
                        to="/solutions/cloud-security"
                        className="flex items-center gap-3 p-3 rounded-lg hover:bg-orange-500/10 transition-colors group/item"
                      >
                        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-orange-500 to-amber-600 flex items-center justify-center">
                          <Cloud className="w-5 h-5 text-white" />
                        </div>
                        <div>
                          <div className="text-sm font-medium text-white group-hover/item:text-orange-300 transition-colors">Cloud Security</div>
                          <div className="text-xs text-gray-500">CNAPP, AWS/Azure/GCP</div>
                        </div>
                      </Link>

                      <Link
                        to="/solutions/sast-security"
                        className="flex items-center gap-3 p-3 rounded-lg hover:bg-red-500/10 transition-colors group/item"
                      >
                        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-red-500 to-rose-600 flex items-center justify-center">
                          <Code2 className="w-5 h-5 text-white" />
                        </div>
                        <div>
                          <div className="text-sm font-medium text-white group-hover/item:text-red-300 transition-colors">Code Security</div>
                          <div className="text-xs text-gray-500">SAST, Secret Scanning, SCA</div>
                        </div>
                      </Link>
                    </div>

                    {/* Bottom Section */}
                    <div className="border-t border-gray-700 p-3 bg-gray-800/50">
                      <div className="flex items-center gap-2 text-xs text-gray-400">
                        <span className="relative flex h-2 w-2">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                          <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
                        </span>
                        Powered by JARWIS AI Engine
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <Link
                to="/about"
                className={`relative text-sm font-medium transition-all duration-200 ${
                  isActiveLink("/about")
                    ? "text-white"
                    : "text-cyan-300 hover:text-white"
                }`}
              >
                About
                {isActiveLink("/about") && (
                  <>
                    <div className="absolute -bottom-1 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-400 to-blue-400 rounded-full"></div>
                    <div className="absolute -bottom-2 left-1/2 transform -translate-x-1/2 w-1 h-1 bg-cyan-400 rounded-full animate-pulse"></div>
                  </>
                )}
              </Link>

              <Link
                to="/pricing"
                className={`relative text-sm font-medium transition-all duration-200 ${
                  isActiveLink("/pricing")
                    ? "text-white"
                    : "text-cyan-300 hover:text-white"
                }`}
              >
                Pricing
                {isActiveLink("/pricing") && (
                  <>
                    <div className="absolute -bottom-1 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-400 to-blue-400 rounded-full"></div>
                    <div className="absolute -bottom-2 left-1/2 transform -translate-x-1/2 w-1 h-1 bg-cyan-400 rounded-full animate-pulse"></div>
                  </>
                )}
              </Link>

              <Link
                to="/request-trial"
                className={`relative text-sm font-medium transition-all duration-200 ${
                  isActiveLink("/request-trial")
                    ? "text-white"
                    : "text-cyan-300 hover:text-white"
                }`}
              >
                Request Trial
                {isActiveLink("/request-trial") && (
                  <>
                    <div className="absolute -bottom-1 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-400 to-blue-400 rounded-full"></div>
                    <div className="absolute -bottom-2 left-1/2 transform -translate-x-1/2 w-1 h-1 bg-cyan-400 rounded-full animate-pulse"></div>
                  </>
                )}
              </Link>
            </nav>
          </div>

          {/* Right Side */}
          <div className="flex items-center justify-center space-x-4">
            {!user ? (
              <>
                <Link
                  to="/login"
                  className={`hidden sm:block relative text-sm font-medium transition-all duration-200 ${
                    isActiveLink("/login")
                      ? "text-white"
                      : "text-cyan-300 hover:text-white"
                  }`}
                >
                  <span className="flex items-center gap-1">Login ↗</span>
                  {isActiveLink("/login") && (
                    <>
                      <div className="absolute -bottom-1 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-400 to-blue-400 rounded-full"></div>
                      <div className="absolute -bottom-2 left-1/2 transform -translate-x-1/2 w-1 h-1 bg-cyan-400 rounded-full animate-pulse"></div>
                    </>
                  )}
                </Link>

                <Link
                  to="/pricing"
                  className={`hidden sm:block px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 transform hover:scale-105 ${
                    isActiveLink("/pricing")
                      ? "bg-blue-200 text-blue-800 shadow-lg shadow-blue-200/50 ring-2 ring-blue-300/50"
                      : "bg-blue-100 text-blue-900 hover:bg-blue-200"
                  }`}
                >
                  <span className="flex items-center gap-2">
                    {isActiveLink("/pricing") && (
                      <div className="w-2 h-2 bg-blue-600 rounded-full animate-pulse"></div>
                    )}
                    Hire Jarwis
                  </span>
                </Link>
              </>
            ) : (
              <>
                <Link
                  to="/dashboard"
                  className={`hidden sm:block relative font-medium text-sm transition-all duration-200 ${
                    isActiveLink("/dashboard")
                      ? "text-white"
                      : "text-white/80 hover:text-white"
                  }`}
                >
                  <span className="flex items-center gap-2">
                    {isActiveLink("/dashboard") && (
                      <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></div>
                    )}
                    Hi, {userDoc?.displayName}
                  </span>
                  {isActiveLink("/dashboard") && (
                    <>
                      <div className="absolute -bottom-1 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-400 to-blue-400 rounded-full"></div>
                      <div className="absolute -bottom-2 left-1/2 transform -translate-x-1/2 w-1 h-1 bg-cyan-400 rounded-full animate-pulse"></div>
                    </>
                  )}
                </Link>

                <Link
                  to="/dashboard"
                  className={`pt-1 p-2 rounded-full transition-all duration-200 ${
                    isActiveLink("/dashboard")
                      ? "bg-cyan-600/20 ring-2 ring-cyan-400/30 shadow-lg shadow-cyan-400/20"
                      : "hover:bg-gray-800/50"
                  }`}
                >
                  <CgProfile
                    color={isActiveLink("/dashboard") ? "#22d3ee" : "white"}
                    size={25}
                  />
                  {isActiveLink("/dashboard") && (
                    <div className="absolute -bottom-1 left-1/2 transform -translate-x-1/2 w-1 h-1 bg-cyan-400 rounded-full animate-pulse"></div>
                  )}
                </Link>
              </>
            )}

            {/* Mobile Menu Button */}
            <button
              className="md:hidden p-2 min-w-[44px] min-h-[44px] flex items-center justify-center text-gray-400 hover:text-white active:scale-95 transition-transform"
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              aria-label={isMobileMenuOpen ? "Close menu" : "Open menu"}
            >
              {isMobileMenuOpen ? (
                <svg className="w-6 h-6" fill="none" stroke="currentColor">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              ) : (
                <svg className="w-6 h-6" fill="none" stroke="currentColor">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M4 6h16M4 12h16M4 18h16"
                  />
                </svg>
              )}
            </button>
          </div>
        </div>

        {isMobileMenuOpen && (
          <nav className="md:hidden fixed top-[68px] sm:top-[76px] right-0 bg-gradient-to-br from-gray-900 to-black border border-gray-700 rounded-bl-2xl shadow-2xl backdrop-blur-sm z-50 min-w-fit overflow-hidden">
            {/* Navigation Links Container */}
            <div className="px-6 py-6 space-y-1">
              <Link
                to="/"
                onClick={() => setIsMobileMenuOpen(false)}
                className={`flex items-center justify-between group px-4 py-3 rounded-lg transition-all duration-200 text-base font-medium ${
                  isActiveLink("/")
                    ? "text-white bg-cyan-600/20 border border-cyan-500/30 shadow-lg shadow-cyan-500/10"
                    : "text-gray-300 hover:text-white hover:bg-gray-800/50"
                }`}
              >
                <span className="flex items-center gap-2">
                  {isActiveLink("/") && (
                    <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></div>
                  )}
                  Home
                </span>
                <svg
                  className={`w-4 h-4 transition-all ${
                    isActiveLink("/")
                      ? "opacity-100 text-cyan-400"
                      : "opacity-0 group-hover:opacity-100"
                  }`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 5l7 7-7 7"
                  />
                </svg>
              </Link>

              {/* Solutions Section - Mobile */}
              <div className="py-2">
                <div className="px-4 py-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                  Solutions
                </div>
                <Link
                  to="/solutions/web-security"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-gray-800/50 transition-colors"
                >
                  <span className="text-lg">🌐</span>
                  <span className="text-sm text-gray-300">Web Security</span>
                </Link>
                <Link
                  to="/solutions/mobile-security"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-gray-800/50 transition-colors"
                >
                  <span className="text-lg">📱</span>
                  <span className="text-sm text-gray-300">Mobile Security</span>
                </Link>
                <Link
                  to="/solutions/network-security"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-gray-800/50 transition-colors"
                >
                  <span className="text-lg">🖧</span>
                  <span className="text-sm text-gray-300">Network Security</span>
                </Link>
                <Link
                  to="/solutions/cloud-security"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-gray-800/50 transition-colors"
                >
                  <span className="text-lg">☁️</span>
                  <span className="text-sm text-gray-300">Cloud Security</span>
                </Link>
                <Link
                  to="/solutions/sast-security"
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-gray-800/50 transition-colors"
                >
                  <span className="text-lg">📝</span>
                  <span className="text-sm text-gray-300">Code Security</span>
                </Link>
              </div>

              <Link
                to="/about"
                onClick={() => setIsMobileMenuOpen(false)}
                className={`flex items-center justify-between group px-4 py-3 rounded-lg transition-all duration-200 text-base font-medium ${
                  isActiveLink("/about")
                    ? "text-white bg-cyan-600/20 border border-cyan-500/30 shadow-lg shadow-cyan-500/10"
                    : "text-gray-300 hover:text-white hover:bg-gray-800/50"
                }`}
              >
                <span className="flex items-center gap-2">
                  {isActiveLink("/about") && (
                    <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></div>
                  )}
                  About
                </span>
                <svg
                  className={`w-4 h-4 transition-all ${
                    isActiveLink("/about")
                      ? "opacity-100 text-cyan-400"
                      : "opacity-0 group-hover:opacity-100"
                  }`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 5l7 7-7 7"
                  />
                </svg>
              </Link>

              <Link
                to="/pricing"
                onClick={() => setIsMobileMenuOpen(false)}
                className={`flex items-center justify-between group px-4 py-3 rounded-lg transition-all duration-200 text-base font-medium ${
                  isActiveLink("/pricing")
                    ? "text-white bg-cyan-600/20 border border-cyan-500/30 shadow-lg shadow-cyan-500/10"
                    : "text-gray-300 hover:text-white hover:bg-gray-800/50"
                }`}
              >
                <span className="flex items-center gap-2">
                  {isActiveLink("/pricing") && (
                    <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></div>
                  )}
                  Pricing
                </span>
                <svg
                  className={`w-4 h-4 transition-all ${
                    isActiveLink("/pricing")
                      ? "opacity-100 text-cyan-400"
                      : "opacity-0 group-hover:opacity-100"
                  }`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 5l7 7-7 7"
                  />
                </svg>
              </Link>

              <Link
                to="/request-trial"
                onClick={() => setIsMobileMenuOpen(false)}
                className={`flex items-center justify-between group px-4 py-3 rounded-lg transition-all duration-200 text-base font-medium ${
                  isActiveLink("/request-trial")
                    ? "text-white bg-cyan-600/20 border border-cyan-500/30 shadow-lg shadow-cyan-500/10"
                    : "text-gray-300 hover:text-white hover:bg-gray-800/50"
                }`}
              >
                <span className="flex items-center gap-2">
                  {isActiveLink("/request-trial") && (
                    <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></div>
                  )}
                  Request Trial
                </span>
                <svg
                  className={`w-4 h-4 transition-all ${
                    isActiveLink("/request-trial")
                      ? "opacity-100 text-cyan-400"
                      : "opacity-0 group-hover:opacity-100"
                  }`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 5l7 7-7 7"
                  />
                </svg>
              </Link>

              <Link
                to="/contact"
                onClick={() => setIsMobileMenuOpen(false)}
                className={`flex items-center justify-between group px-4 py-3 rounded-lg transition-all duration-200 text-base font-medium ${
                  isActiveLink("/contact")
                    ? "text-white bg-cyan-600/20 border border-cyan-500/30 shadow-lg shadow-cyan-500/10"
                    : "text-gray-300 hover:text-white hover:bg-gray-800/50"
                }`}
              >
                <span className="flex items-center gap-2">
                  {isActiveLink("/contact") && (
                    <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></div>
                  )}
                  Contact
                </span>
                <svg
                  className={`w-4 h-4 transition-all ${
                    isActiveLink("/contact")
                      ? "opacity-100 text-cyan-400"
                      : "opacity-0 group-hover:opacity-100"
                  }`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 5l7 7-7 7"
                  />
                </svg>
              </Link>

              {!user && (
                <>
                  {/* Divider */}
                  <div className="border-t sm:border-0 border-gray-700 my-4"></div>

                  <Link
                    to="/login"
                    onClick={() => setIsMobileMenuOpen(false)}
                    className={`flex sm:hidden items-center justify-between group px-4 py-3 rounded-lg transition-all duration-200 text-base font-medium ${
                      isActiveLink("/login")
                        ? "text-cyan-200 bg-cyan-600/20 border border-cyan-500/30 shadow-lg shadow-cyan-500/10"
                        : "text-cyan-300 hover:text-cyan-200 hover:bg-cyan-900/20"
                    }`}
                  >
                    <span className="flex items-center gap-2">
                      {isActiveLink("/login") && (
                        <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse"></div>
                      )}
                      Login
                    </span>
                    <svg
                      className={`w-4 h-4 transition-all ${
                        isActiveLink("/login")
                          ? "opacity-100 text-cyan-400 translate-x-1"
                          : "opacity-60 group-hover:opacity-100 group-hover:translate-x-1"
                      }`}
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M10 6H6a2 2 0 00-2 2v7a2 2 0 002 2h4m1 0h2a2 2 0 002-2V8a2 2 0 00-2-2h-2m1 0V4a2 2 0 10-2 0v2m1 0V4a2 2 0 10-2 0v2"
                      />
                    </svg>
                  </Link>
                </>
              )}
            </div>

            {/* Bottom accent */}
            <div className="h-1 bg-gradient-to-r from-cyan-500 to-blue-500"></div>
          </nav>
        )}
      </header>

      <div className="relative bg-gray-900 overflow-hidden">
        {/* Animated Canvas */}
        <canvas ref={canvasRef} className="absolute inset-0 z-0" />

        {/* Floating glowing orbs */}
        <div className="absolute inset-0 z-1">
          <div className="absolute top-1/4 left-1/4 w-32 h-32 bg-blue-500/10 rounded-full blur-xl animate-pulse"></div>
          <div className="absolute top-3/4 right-1/4 w-24 h-24 bg-cyan-500/10 rounded-full blur-xl animate-pulse delay-1000"></div>
          <div className="absolute top-1/2 left-3/4 w-40 h-40 bg-indigo-500/8 rounded-full blur-2xl animate-pulse delay-2000"></div>
          <div className="absolute inset-0 bg-gradient-to-br from-blue-900/5 via-transparent to-cyan-900/5"></div>
          <div
            className="absolute inset-0 opacity-5"
            style={{
              backgroundImage: `
              linear-gradient(rgba(59, 130, 246, 0.1) 1px, transparent 1px),
              linear-gradient(90deg, rgba(59, 130, 246, 0.1) 1px, transparent 1px)
            `,
              backgroundSize: "50px 50px",
            }}
          ></div>
        </div>

        <main className="text-white">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default Header;
