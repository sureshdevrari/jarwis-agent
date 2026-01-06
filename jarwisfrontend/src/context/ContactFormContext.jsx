// src/context/ContactFormContext.jsx
// Contact form context using FastAPI + PostgreSQL backend
// Replaces Firebase Firestore implementation

import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import { contactAPI, adminAPI } from "../services/api";
import { useAuth } from "./AuthContext";

const ContactFormContext = createContext();

export const useContactForm = () => {
  return useContext(ContactFormContext);
};

export const ContactFormProvider = ({ children }) => {
  const { userDoc } = useAuth();
  const [submissions, setSubmissions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // Submit a contact form (public)
  const addSubmission = async (formData) => {
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      await contactAPI.submit(formData);
      setSuccess(
        "Your message has been sent successfully! We'll be in touch soon."
      );
      setLoading(false);
      return { success: true };
    } catch (err) {
      console.error("Error submitting contact form:", err);
      const errorMessage = err.response?.data?.detail || "Failed to send message. Please try again later.";
      setError(errorMessage);
      setLoading(false);
      return { success: false, error: err };
    }
  };

  // Delete a submission (admin only)
  const deleteSubmission = async (submissionId) => {
    try {
      await adminAPI.deleteContactSubmission(submissionId);
      // Remove from local state
      setSubmissions(prev => prev.filter(sub => sub.id !== submissionId));
      return { success: true, message: "Submission deleted successfully." };
    } catch (err) {
      console.error("Error deleting submission:", err);
      return { success: false, message: "Failed to delete submission." };
    }
  };

  // Fetch submissions for admins
  const fetchSubmissions = useCallback(async () => {
    const isAdmin =
      userDoc?.role === "admin" || userDoc?.role === "super_admin" || userDoc?.is_superuser;

    if (isAdmin) {
      setLoading(true);
      try {
        const response = await adminAPI.getContactSubmissions();
        // Backend returns { submissions: [], total: number }
        const submissionsList = response?.submissions || response || [];
        setSubmissions(Array.isArray(submissionsList) ? submissionsList : []);
        setLoading(false);
      } catch (err) {
        console.error("Error fetching submissions:", err);
        setError("Could not load submissions.");
        setLoading(false);
      }
    } else {
      setSubmissions([]);
    }
  }, [userDoc]);

  useEffect(() => {
    fetchSubmissions();
  }, [fetchSubmissions]);

  const value = {
    submissions,
    loading,
    error,
    success,
    addSubmission,
    deleteSubmission,
    refreshSubmissions: fetchSubmissions,
  };

  return (
    <ContactFormContext.Provider value={value}>
      {children}
    </ContactFormContext.Provider>
  );
};
