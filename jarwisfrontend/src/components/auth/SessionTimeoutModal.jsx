// SessionTimeoutModal.jsx - Security modal for session timeout
// Blurs screen and shows timeout message before redirecting to login

import { useEffect, useState } from "react";

const SessionTimeoutModal = ({ isOpen, reason = "inactive", onClose }) => {
  const [countdown, setCountdown] = useState(5);

  useEffect(() => {
    if (!isOpen) return;

    // Reset countdown when modal opens
    setCountdown(5);

    // Countdown timer
    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          // Use window.location.href since we're outside Router context
          window.location.href = `/login?reason=${reason}`;
          if (onClose) onClose();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [isOpen, reason, onClose]);

  const handleLoginNow = () => {
    window.location.href = `/login?reason=${reason}`;
    if (onClose) onClose();
  };

  if (!isOpen) return null;

  const messages = {
    inactive: {
      title: "Session Timed Out",
      subtitle: "You've been inactive for too long",
      description: "For your security, your session has been terminated due to inactivity.",
      icon: (
        <svg className="w-16 h-16 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
    session_expired: {
      title: "Session Expired",
      subtitle: "Your session has ended",
      description: "Your authentication token has expired. Please log in again to continue.",
      icon: (
        <svg className="w-16 h-16 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
        </svg>
      ),
    },
    logged_out: {
      title: "Logged Out",
      subtitle: "You have been logged out",
      description: "Your session was terminated. This may be due to a login from another device.",
      icon: (
        <svg className="w-16 h-16 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15M12 9l-3 3m0 0l3 3m-3-3h12.75" />
        </svg>
      ),
    },
  };

  const content = messages[reason] || messages.inactive;

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center">
      {/* Blurred backdrop */}
      <div 
        className="absolute inset-0 bg-black/60 backdrop-blur-md"
        style={{ backdropFilter: "blur(8px)" }}
      />
      
      {/* Modal content */}
      <div className="relative z-10 w-full max-w-md mx-4">
        <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-2xl overflow-hidden animate-pulse-slow">
          {/* Security warning bar */}
          <div className="bg-gradient-to-r from-red-500 to-orange-500 px-6 py-3">
            <div className="flex items-center gap-2 text-white">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <span className="font-semibold text-sm uppercase tracking-wide">Security Alert</span>
            </div>
          </div>

          {/* Content */}
          <div className="p-8 text-center">
            {/* Icon */}
            <div className="flex justify-center mb-6">
              <div className="p-4 bg-gray-100 dark:bg-slate-700 rounded-full">
                {content.icon}
              </div>
            </div>

            {/* Title */}
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
              {content.title}
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-300 mb-4">
              {content.subtitle}
            </p>

            {/* Description */}
            <p className="text-gray-500 dark:text-gray-400 mb-6">
              {content.description}
            </p>

            {/* Countdown */}
            <div className="mb-6">
              <div className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-slate-700 rounded-full">
                <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                <span className="text-sm text-gray-600 dark:text-gray-300">
                  Redirecting in <span className="font-bold text-red-500">{countdown}</span> seconds
                </span>
              </div>
            </div>

            {/* Login button */}
            <button
              onClick={handleLoginNow}
              className="w-full py-3 px-6 bg-gradient-to-r from-purple-600 to-cyan-500 text-white font-semibold rounded-xl 
                         hover:from-purple-700 hover:to-cyan-600 transform hover:scale-[1.02] transition-all duration-200
                         shadow-lg hover:shadow-xl"
            >
              Login Now
            </button>

            {/* Security note */}
            <p className="mt-4 text-xs text-gray-400 dark:text-gray-500">
              🔒 Your data remains secure. No unauthorized access occurred.
            </p>
          </div>
        </div>
      </div>

      {/* Floating lock icons for visual effect */}
      <div className="absolute top-10 left-10 text-white/20 animate-bounce" style={{ animationDelay: "0s" }}>
        <svg className="w-8 h-8" fill="currentColor" viewBox="0 0 24 24">
          <path d="M12 1C8.676 1 6 3.676 6 7v2H4v14h16V9h-2V7c0-3.324-2.676-6-6-6zm0 2c2.276 0 4 1.724 4 4v2H8V7c0-2.276 1.724-4 4-4z"/>
        </svg>
      </div>
      <div className="absolute bottom-10 right-10 text-white/20 animate-bounce" style={{ animationDelay: "0.5s" }}>
        <svg className="w-8 h-8" fill="currentColor" viewBox="0 0 24 24">
          <path d="M12 1C8.676 1 6 3.676 6 7v2H4v14h16V9h-2V7c0-3.324-2.676-6-6-6zm0 2c2.276 0 4 1.724 4 4v2H8V7c0-2.276 1.724-4 4-4z"/>
        </svg>
      </div>
    </div>
  );
};

export default SessionTimeoutModal;
