// src/components/ContactForm.jsx
import React, { useState } from "react";
// import ReCAPTCHA from "react-google-recaptcha"; // TODO: Re-enable CAPTCHA later
import { useContactForm } from "../context/ContactFormContext";

const ContactForm = () => {
  // State for the form fields
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    workEmail: "",
    companyName: "",
    companyWebsite: "",
    plan: "",
  });

  // State from our new context
  const {
    loading,
    error: submissionError,
    success,
    addSubmission,
  } = useContactForm();

  const [formErrors, setFormErrors] = useState(null);
  // const [captchaValue, setCaptchaValue] = useState(null); // TODO: Re-enable CAPTCHA later

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const validateForm = () => {
    const newErrors = {};
    if (formData.companyWebsite && !formData.companyWebsite.includes(".")) {
      newErrors.companyWebsite =
        "Please enter a valid URL (e.g., example.com).";
    }
    // TODO: Re-enable CAPTCHA validation later
    // if (!captchaValue) {
    //   newErrors.captcha = "Please verify that you are not a robot.";
    // }
    setFormErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormErrors(null);

    if (!validateForm()) {
      return;
    }

    // Include captcha token in form data
    const submissionData = {
      ...formData,
      // captchaToken: captchaValue // TODO: Re-enable CAPTCHA later
    };

    const result = await addSubmission(submissionData);
    if (result.success) {
      // Reset form on success
      setFormData({
        firstName: "",
        lastName: "",
        workEmail: "",
        companyName: "",
        companyWebsite: "",
        plan: "",
      });
      // setCaptchaValue(null);  // TODO: Re-enable CAPTCHA later
    }
  };

  return (
    <div className="flex items-center justify-center p-3 sm:p-4 relative">
      <div className="bg-black/20 rounded-lg shadow-lg p-4 sm:p-6 md:p-8 w-full max-w-4xl">
        <form onSubmit={handleSubmit} className="space-y-5 sm:space-y-6">
          {/* Your form inputs remain exactly the same... */}
          {/* First Name */}
          <div className="relative">
            <input
              type="text"
              name="firstName"
              required
              value={formData.firstName}
              onChange={handleInputChange}
              className="w-full px-3 sm:px-4 py-3 bg-gray-800 text-base sm:text-lg border-2 border-gray-500 rounded-md focus:border-blue-500 focus:outline-none peer placeholder-transparent min-h-[48px]"
              placeholder="First Name"
              id="firstName"
              autoComplete="given-name"
            />
            <label
              htmlFor="firstName"
              className="absolute left-3 sm:left-4 -top-3 bg-gray-900 px-1 text-xs sm:text-sm font-medium text-gray-400 transition-all peer-placeholder-shown:text-sm sm:peer-placeholder-shown:text-base peer-placeholder-shown:text-gray-400 peer-placeholder-shown:top-3.5 peer-placeholder-shown:bg-gray-800 peer-focus:-top-3 peer-focus:text-xs sm:peer-focus:text-sm peer-focus:text-blue-500 peer-focus:bg-gray-900"
            >
              FIRST NAME
            </label>
          </div>

          {/* Last Name */}
          <div className="relative">
            <input
              type="text"
              name="lastName"
              value={formData.lastName}
              onChange={handleInputChange}
              className="w-full px-3 sm:px-4 py-3 bg-gray-800 text-base sm:text-lg border-2 border-gray-500 rounded-md focus:border-blue-500 focus:outline-none peer placeholder-transparent min-h-[48px]"
              placeholder="Last Name"
              id="lastName"
              autoComplete="family-name"
            />
            <label
              htmlFor="lastName"
              className="absolute left-3 sm:left-4 -top-3 bg-gray-900 px-1 text-xs sm:text-sm font-medium text-gray-400 transition-all peer-placeholder-shown:text-sm sm:peer-placeholder-shown:text-base peer-placeholder-shown:text-gray-400 peer-placeholder-shown:top-3.5 peer-placeholder-shown:bg-gray-800 peer-focus:-top-3 peer-focus:text-xs sm:peer-focus:text-sm peer-focus:text-blue-500 peer-focus:bg-gray-900"
            >
              LAST NAME
            </label>
          </div>

          {/* Work Email */}
          <div className="relative">
            <input
              type="email"
              name="workEmail"
              required
              value={formData.workEmail}
              onChange={handleInputChange}
              className="w-full px-3 sm:px-4 py-3 bg-gray-800 text-base sm:text-lg border-2 border-gray-500 rounded-md focus:border-blue-500 focus:outline-none peer placeholder-transparent min-h-[48px]"
              placeholder="Work Email"
              id="workEmail"
              autoComplete="email"
            />
            <label
              htmlFor="workEmail"
              className="absolute left-3 sm:left-4 -top-3 bg-gray-900 px-1 text-xs sm:text-sm font-medium text-gray-400 transition-all peer-placeholder-shown:text-sm sm:peer-placeholder-shown:text-base peer-placeholder-shown:text-gray-400 peer-placeholder-shown:top-3.5 peer-placeholder-shown:bg-gray-800 peer-focus:-top-3 peer-focus:text-xs sm:peer-focus:text-sm peer-focus:text-blue-500 peer-focus:bg-gray-900"
            >
              WORK EMAIL
            </label>
          </div>

          {/* Company Name */}
          <div className="relative">
            <input
              type="text"
              name="companyName"
              value={formData.companyName}
              onChange={handleInputChange}
              className="w-full px-3 sm:px-4 py-3 bg-gray-800 text-base sm:text-lg border-2 border-gray-500 rounded-md focus:border-blue-500 focus:outline-none peer placeholder-transparent min-h-[48px]"
              placeholder="Company Name"
              id="companyName"
              autoComplete="organization"
            />
            <label
              htmlFor="companyName"
              className="absolute left-3 sm:left-4 -top-3 bg-gray-900 px-1 text-xs sm:text-sm font-medium text-gray-400 transition-all peer-placeholder-shown:text-sm sm:peer-placeholder-shown:text-base peer-placeholder-shown:text-gray-400 peer-placeholder-shown:top-3.5 peer-placeholder-shown:bg-gray-800 peer-focus:-top-3 peer-focus:text-xs sm:peer-focus:text-sm peer-focus:text-blue-500 peer-focus:bg-gray-900"
            >
              COMPANY NAME
            </label>
          </div>

          {/* Company Website */}
          <div className="relative">
            <input
              type="text"
              name="companyWebsite"
              value={formData.companyWebsite}
              onChange={handleInputChange}
              className="w-full px-3 sm:px-4 py-3 bg-gray-800 text-base sm:text-lg border-2 border-gray-500 rounded-md focus:border-blue-500 focus:outline-none peer placeholder-transparent min-h-[48px]"
              placeholder="Company Website"
              id="companyWebsite"
              autoComplete="url"
            />
            <label
              htmlFor="companyWebsite"
              className="absolute left-3 sm:left-4 -top-3 bg-gray-900 px-1 text-xs sm:text-sm font-medium text-gray-400 transition-all peer-placeholder-shown:text-sm sm:peer-placeholder-shown:text-base peer-placeholder-shown:text-gray-400 peer-placeholder-shown:top-3.5 peer-placeholder-shown:bg-gray-800 peer-focus:-top-3 peer-focus:text-xs sm:peer-focus:text-sm peer-focus:text-blue-500 peer-focus:bg-gray-900"
            >
              COMPANY WEBSITE
            </label>
          </div>

          {/* Plan Dropdown */}
          <div className="relative">
            <select
              name="plan"
              required
              value={formData.plan}
              onChange={handleInputChange}
              id="plan"
              className={`w-full px-3 sm:px-4 py-3 bg-transparent text-base sm:text-lg border-2 border-gray-500 rounded-md focus:border-blue-500 focus:outline-none peer appearance-none min-h-[48px] ${
                formData.plan ? "text-white" : "text-gray-400"
              }`}
            >
              <option value="" disabled className="bg-gray-800 text-gray-500">
                Select a Plan
              </option>
              <option value="Trial" className="bg-gray-800 text-white">
                Trial (Corporate Only)
              </option>
              <option value="Individuals" className="bg-gray-800 text-white">
                Individuals
              </option>
              <option value="Professional" className="bg-gray-800 text-white">
                Professional
              </option>
              <option value="Enterprise" className="bg-gray-800 text-white">
                Enterprise
              </option>
            </select>
            <label
              htmlFor="plan"
              className="absolute left-3 sm:left-4 -top-3 bg-gray-900 px-1 text-xs sm:text-sm font-medium text-blue-500"
            >
              PLAN
            </label>
            {/* Custom dropdown arrow */}
            <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-gray-400">
              <svg
                className="fill-current h-5 w-5"
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 20 20"
              >
                <path d="M9.293 12.95l.707.707L15.657 8l-1.414-1.414L10 10.828 5.757 6.586 4.343 8z" />
              </svg>
            </div>
          </div>

          {/* reCAPTCHA - TODO: Re-enable later */}
          {/* <div className="pt-3 sm:pt-4 flex justify-center sm:justify-start overflow-x-auto">
            <ReCAPTCHA
              sitekey={process.env.REACT_APP_CAPTCHA_SITE_KEY}
              onChange={(value) => setCaptchaValue(value)}
            />
            {formErrors?.captcha && (
              <p className="text-red-500 text-sm mt-2">{formErrors.captcha}</p>
            )}
          </div> */}

          {/* Feedback Messages */}
          {formErrors?.companyWebsite && (
            <p className="text-red-500 text-sm">{formErrors.companyWebsite}</p>
          )}
          {submissionError && (
            <p className="text-red-500 text-sm">{submissionError}</p>
          )}
          {success && <p className="text-green-500 text-sm">{success}</p>}

          {/* Submit Button */}
          <div className="pt-3 sm:pt-4">
            <button
              type="submit"
              disabled={loading}
              className="bg-gray-800 text-white border border-gray-600 px-6 sm:px-8 py-3 rounded-xl sm:rounded-2xl hover:bg-gray-700 hover:border-gray-500 transition-all duration-200 font-medium text-sm sm:text-base lg:text-lg shadow-lg hover:shadow-xl transform hover:scale-105 w-full sm:w-auto disabled:opacity-50 disabled:cursor-not-allowed min-h-[48px] touch-target active:scale-[0.98]"
            >
              {loading ? "SENDING..." : "SUBMIT"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ContactForm;
