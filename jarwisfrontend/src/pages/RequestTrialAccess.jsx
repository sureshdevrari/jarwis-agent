// src/pages/RequestTrialAccess.jsx
// Request Trial Access page for companies with corporate email validation

import { useState } from "react";
import { Link } from "react-router-dom";
import Footer from "../components/Footer";
import { useContactForm } from "../context/ContactFormContext";
import { Building, Mail, Globe, User, AlertCircle, CheckCircle, Sparkles } from "lucide-react";

// List of free email providers that are NOT allowed for trial requests
const FREE_EMAIL_PROVIDERS = [
  'gmail.com',
  'yahoo.com',
  'yahoo.co.in',
  'yahoo.co.uk',
  'hotmail.com',
  'outlook.com',
  'live.com',
  'msn.com',
  'aol.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'protonmail.com',
  'proton.me',
  'zoho.com',
  'mail.com',
  'yandex.com',
  'gmx.com',
  'gmx.net',
  'rediffmail.com',
  'inbox.com',
  'fastmail.com',
  'tutanota.com',
  'mailinator.com',
  'guerrillamail.com',
  'tempmail.com',
  'throwaway.email',
  '10minutemail.com',
];

const RequestTrialAccess = () => {
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    workEmail: "",
    companyName: "",
    companyWebsite: "",
    jobTitle: "",
    employeeCount: "",
    useCase: "",
    plan: "Trial", // Fixed as Trial
  });

  const {
    loading,
    error: submissionError,
    success,
    addSubmission,
  } = useContactForm();

  const [formErrors, setFormErrors] = useState({});
  const [emailWarning, setEmailWarning] = useState("");

  // Validate if email is a corporate email (not from free providers)
  const isCorporateEmail = (email) => {
    if (!email) return false;
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return false;
    return !FREE_EMAIL_PROVIDERS.includes(domain);
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));

    // Clear specific error when user starts typing
    if (formErrors[name]) {
      setFormErrors((prev) => ({ ...prev, [name]: null }));
    }

    // Check email as user types
    if (name === "workEmail" && value.includes("@")) {
      if (!isCorporateEmail(value)) {
        setEmailWarning("Trial access is only available for corporate email addresses. Personal email providers like Gmail, Yahoo, etc. are not accepted.");
      } else {
        setEmailWarning("");
      }
    }
  };

  const validateForm = () => {
    const errors = {};

    if (!formData.firstName.trim()) {
      errors.firstName = "First name is required";
    }

    if (!formData.workEmail.trim()) {
      errors.workEmail = "Corporate email is required";
    } else if (!formData.workEmail.includes("@")) {
      errors.workEmail = "Please enter a valid email address";
    } else if (!isCorporateEmail(formData.workEmail)) {
      errors.workEmail = "Trial access requires a corporate email address. Personal email providers (Gmail, Yahoo, Outlook, etc.) are not accepted.";
    }

    if (!formData.companyName.trim()) {
      errors.companyName = "Company name is required";
    }

    if (formData.companyWebsite && !formData.companyWebsite.includes(".")) {
      errors.companyWebsite = "Please enter a valid URL (e.g., example.com)";
    }

    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormErrors({});
    setEmailWarning("");

    if (!validateForm()) {
      return;
    }

    const submissionData = {
      ...formData,
      requestType: "trial_access",
      submittedAt: new Date().toISOString(),
    };

    const result = await addSubmission(submissionData);
    if (result.success) {
      setFormData({
        firstName: "",
        lastName: "",
        workEmail: "",
        companyName: "",
        companyWebsite: "",
        jobTitle: "",
        employeeCount: "",
        useCase: "",
        plan: "Trial",
      });
    }
  };

  return (
    <div className="min-h-screen">
      <div className="text-white relative overflow-hidden">
        {/* Background Pattern */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-1/4 left-1/4 w-[600px] h-[600px] bg-cyan-500/10 rounded-full blur-[120px] animate-pulse" />
          <div className="absolute bottom-1/4 right-1/4 w-[500px] h-[500px] bg-blue-500/10 rounded-full blur-[100px] animate-pulse delay-1000" />
        </div>

        {/* Main Content */}
        <div className="relative z-10 flex flex-col items-center justify-center px-4 sm:px-6 lg:px-8 py-8 sm:py-10 lg:py-12">
          <div className="text-center max-w-4xl mx-auto space-y-6 mb-8">
            {/* Badge */}
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-white/5 border border-white/10">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <span className="text-sm text-gray-300">Corporate Trial Program</span>
            </div>

            {/* Main Heading */}
            <h1 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl font-bold leading-tight">
              <span className="text-white">Request </span>
              <span className="bg-gradient-to-r from-cyan-400 via-blue-500 to-violet-500 bg-clip-text text-transparent">
                Trial Access
              </span>
            </h1>

            {/* Description */}
            <p className="text-gray-400 text-base sm:text-lg lg:text-xl leading-relaxed max-w-2xl mx-auto">
              Experience the power of AI-driven security testing with a free trial for your organization.
              <span className="block mt-2 text-cyan-400 font-medium">
                Corporate email required for trial access.
              </span>
            </p>
          </div>

          {/* Form Container */}
          <div className="w-full max-w-2xl mx-auto">
            <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-2xl p-6 sm:p-8">
              {success ? (
                <div className="text-center py-8">
                  <div className="inline-flex items-center justify-center w-16 h-16 bg-green-500/20 rounded-full mb-4">
                    <CheckCircle className="w-8 h-8 text-green-400" />
                  </div>
                  <h3 className="text-2xl font-bold text-white mb-2">Request Submitted!</h3>
                  <p className="text-gray-400 mb-6">
                    Thank you for your interest in Jarwis. Our team will review your request and contact you within 1-2 business days.
                  </p>
                  <Link
                    to="/"
                    className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-medium rounded-xl hover:from-cyan-400 hover:to-blue-500 transition-all"
                  >
                    Back to Home
                  </Link>
                </div>
              ) : (
                <form onSubmit={handleSubmit} className="space-y-5">
                  {/* Corporate Email Notice */}
                  <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4 mb-6">
                    <div className="flex items-start gap-3">
                      <Building className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
                      <div>
                        <p className="text-blue-300 text-sm font-medium">Corporate Email Required</p>
                        <p className="text-gray-400 text-xs mt-1">
                          Trial access is exclusively available for organizations. Please use your corporate email address (e.g., you@yourcompany.com).
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Name Row */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {/* First Name */}
                    <div>
                      <label htmlFor="firstName" className="block text-sm font-medium text-gray-300 mb-2">
                        First Name <span className="text-red-400">*</span>
                      </label>
                      <div className="relative">
                        <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                        <input
                          type="text"
                          name="firstName"
                          id="firstName"
                          required
                          value={formData.firstName}
                          onChange={handleInputChange}
                          className={`w-full pl-10 pr-4 py-3 bg-gray-900/50 border ${formErrors.firstName ? 'border-red-500' : 'border-gray-600'} rounded-xl text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors`}
                          placeholder="John"
                        />
                      </div>
                      {formErrors.firstName && (
                        <p className="text-red-400 text-xs mt-1">{formErrors.firstName}</p>
                      )}
                    </div>

                    {/* Last Name */}
                    <div>
                      <label htmlFor="lastName" className="block text-sm font-medium text-gray-300 mb-2">
                        Last Name
                      </label>
                      <input
                        type="text"
                        name="lastName"
                        id="lastName"
                        value={formData.lastName}
                        onChange={handleInputChange}
                        className="w-full px-4 py-3 bg-gray-900/50 border border-gray-600 rounded-xl text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors"
                        placeholder="Doe"
                      />
                    </div>
                  </div>

                  {/* Corporate Email */}
                  <div>
                    <label htmlFor="workEmail" className="block text-sm font-medium text-gray-300 mb-2">
                      Corporate Email <span className="text-red-400">*</span>
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                      <input
                        type="email"
                        name="workEmail"
                        id="workEmail"
                        required
                        value={formData.workEmail}
                        onChange={handleInputChange}
                        className={`w-full pl-10 pr-4 py-3 bg-gray-900/50 border ${formErrors.workEmail || emailWarning ? 'border-red-500' : 'border-gray-600'} rounded-xl text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors`}
                        placeholder="you@yourcompany.com"
                      />
                    </div>
                    {emailWarning && (
                      <div className="flex items-start gap-2 mt-2">
                        <AlertCircle className="w-4 h-4 text-amber-400 mt-0.5 flex-shrink-0" />
                        <p className="text-amber-400 text-xs">{emailWarning}</p>
                      </div>
                    )}
                    {formErrors.workEmail && (
                      <p className="text-red-400 text-xs mt-1">{formErrors.workEmail}</p>
                    )}
                  </div>

                  {/* Company Name */}
                  <div>
                    <label htmlFor="companyName" className="block text-sm font-medium text-gray-300 mb-2">
                      Company Name <span className="text-red-400">*</span>
                    </label>
                    <div className="relative">
                      <Building className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                      <input
                        type="text"
                        name="companyName"
                        id="companyName"
                        required
                        value={formData.companyName}
                        onChange={handleInputChange}
                        className={`w-full pl-10 pr-4 py-3 bg-gray-900/50 border ${formErrors.companyName ? 'border-red-500' : 'border-gray-600'} rounded-xl text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors`}
                        placeholder="Acme Corporation"
                      />
                    </div>
                    {formErrors.companyName && (
                      <p className="text-red-400 text-xs mt-1">{formErrors.companyName}</p>
                    )}
                  </div>

                  {/* Company Website */}
                  <div>
                    <label htmlFor="companyWebsite" className="block text-sm font-medium text-gray-300 mb-2">
                      Company Website
                    </label>
                    <div className="relative">
                      <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                      <input
                        type="text"
                        name="companyWebsite"
                        id="companyWebsite"
                        value={formData.companyWebsite}
                        onChange={handleInputChange}
                        className={`w-full pl-10 pr-4 py-3 bg-gray-900/50 border ${formErrors.companyWebsite ? 'border-red-500' : 'border-gray-600'} rounded-xl text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors`}
                        placeholder="https://yourcompany.com"
                      />
                    </div>
                    {formErrors.companyWebsite && (
                      <p className="text-red-400 text-xs mt-1">{formErrors.companyWebsite}</p>
                    )}
                  </div>

                  {/* Job Title and Employee Count Row */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {/* Job Title */}
                    <div>
                      <label htmlFor="jobTitle" className="block text-sm font-medium text-gray-300 mb-2">
                        Job Title
                      </label>
                      <input
                        type="text"
                        name="jobTitle"
                        id="jobTitle"
                        value={formData.jobTitle}
                        onChange={handleInputChange}
                        className="w-full px-4 py-3 bg-gray-900/50 border border-gray-600 rounded-xl text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors"
                        placeholder="Security Engineer"
                      />
                    </div>

                    {/* Employee Count */}
                    <div>
                      <label htmlFor="employeeCount" className="block text-sm font-medium text-gray-300 mb-2">
                        Company Size
                      </label>
                      <select
                        name="employeeCount"
                        id="employeeCount"
                        value={formData.employeeCount}
                        onChange={handleInputChange}
                        className="w-full px-4 py-3 bg-gray-900/50 border border-gray-600 rounded-xl text-white focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors appearance-none cursor-pointer"
                      >
                        <option value="" className="bg-gray-800">Select size</option>
                        <option value="1-10" className="bg-gray-800">1-10 employees</option>
                        <option value="11-50" className="bg-gray-800">11-50 employees</option>
                        <option value="51-200" className="bg-gray-800">51-200 employees</option>
                        <option value="201-500" className="bg-gray-800">201-500 employees</option>
                        <option value="501-1000" className="bg-gray-800">501-1000 employees</option>
                        <option value="1000+" className="bg-gray-800">1000+ employees</option>
                      </select>
                    </div>
                  </div>

                  {/* Use Case */}
                  <div>
                    <label htmlFor="useCase" className="block text-sm font-medium text-gray-300 mb-2">
                      How do you plan to use Jarwis?
                    </label>
                    <textarea
                      name="useCase"
                      id="useCase"
                      rows={3}
                      value={formData.useCase}
                      onChange={handleInputChange}
                      className="w-full px-4 py-3 bg-gray-900/50 border border-gray-600 rounded-xl text-white placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors resize-none"
                      placeholder="Tell us about your security testing needs..."
                    />
                  </div>

                  {/* Error Message */}
                  {submissionError && (
                    <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
                      <p className="text-red-400 text-sm">{submissionError}</p>
                    </div>
                  )}

                  {/* Submit Button */}
                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full py-4 px-6 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold rounded-xl hover:from-cyan-400 hover:to-blue-500 transition-all duration-300 shadow-lg shadow-cyan-500/25 hover:shadow-cyan-500/40 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  >
                    {loading ? (
                      <>
                        <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        Submitting...
                      </>
                    ) : (
                      "Request Trial Access"
                    )}
                  </button>

                  {/* Terms */}
                  <p className="text-gray-500 text-xs text-center">
                    By submitting this form, you agree to our{" "}
                    <Link to="/terms" className="text-cyan-400 hover:underline">Terms of Service</Link>
                    {" "}and{" "}
                    <Link to="/privacy" className="text-cyan-400 hover:underline">Privacy Policy</Link>.
                  </p>
                </form>
              )}
            </div>

            {/* Already have an account? */}
            <div className="text-center mt-6">
              <p className="text-gray-400">
                Already have an account?{" "}
                <Link to="/login" className="text-cyan-400 hover:underline font-medium">
                  Sign in
                </Link>
              </p>
            </div>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
};

export default RequestTrialAccess;
