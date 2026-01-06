// src/pages/admin/AdminContactSubmissions.jsx
import React, { useState } from "react";
import MiftyAdminLayout from "../../components/layout/MiftyAdminLayout";
import { useContactForm } from "../../context/ContactFormContext";
import { Mail, Building, Clock, Trash2, X, AlertTriangle } from "lucide-react";

const AdminContactSubmissions = () => {
  const { submissions, loading, error, deleteSubmission } = useContactForm();
  const [isDeleting, setIsDeleting] = useState(null); // Tracks which submission is being deleted
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [submissionToDelete, setSubmissionToDelete] = useState(null);

  const formatDate = (timestamp) => {
    if (!timestamp) return "N/A";
    // Handle both ISO string and Date object
    try {
      const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp;
      return date.toLocaleString();
    } catch (e) {
      return timestamp;
    }
  };

  // Open confirmation modal
  const handleDeleteClick = (submission) => {
    setSubmissionToDelete(submission);
    setShowConfirmModal(true);
  };

  // Confirm and execute deletion
  const confirmDelete = async () => {
    if (!submissionToDelete) return;

    setIsDeleting(submissionToDelete.id);
    await deleteSubmission(submissionToDelete.id);
    setIsDeleting(null);
    setShowConfirmModal(false);
    setSubmissionToDelete(null);
  };

  // Confirmation Modal Component
  const ConfirmationModal = () => (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-gray-800 border border-gray-700 rounded-lg shadow-xl p-6 w-full max-w-md">
        <div className="flex items-center">
          <div className="bg-red-900/50 p-2 rounded-full mr-4">
            <AlertTriangle className="text-red-400" size={24} />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Delete Submission</h2>
            <p className="text-gray-400 mt-1">
              Are you sure you want to permanently delete this message?
            </p>
          </div>
        </div>
        <div className="mt-6 flex justify-end space-x-3">
          <button
            onClick={() => setShowConfirmModal(false)}
            className="px-4 py-2 rounded-md text-sm font-medium bg-gray-700 text-gray-200 hover:bg-gray-600"
          >
            Cancel
          </button>
          <button
            onClick={confirmDelete}
            className="px-4 py-2 rounded-md text-sm font-medium bg-red-600 text-white hover:bg-red-700"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <MiftyAdminLayout>
      {showConfirmModal && <ConfirmationModal />}
      <div className="space-y-6 p-6">
        {/* Header */}
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6">
          <h1 className="text-3xl font-bold text-gray-100 mb-2">
            Contact Form Submissions
          </h1>
          <p className="text-gray-400">
            Messages sent through the public contact form are displayed here.
          </p>
        </div>

        {/* Content */}
        {loading && (
          <p className="text-center text-gray-400">Loading submissions...</p>
        )}
        {error && <p className="text-center text-red-400">{error}</p>}

        {!loading && !error && (
          <div className="space-y-4">
            {submissions.length === 0 ? (
              <p className="text-center text-gray-500 py-12">
                No submissions yet.
              </p>
            ) : (
              submissions.map((sub) => (
                <div
                  key={sub.id}
                  className="bg-gray-800 border border-gray-700 rounded-lg p-5"
                >
                  <div className="flex justify-between items-start">
                    <div>
                      <h3 className="font-semibold text-lg text-white">
                        {sub.firstName} {sub.lastName}
                      </h3>
                      <p className="text-sm text-blue-400">{sub.plan} Plan</p>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className="text-xs text-gray-500 flex items-center gap-1.5">
                        <Clock size={12} /> {formatDate(sub.submitted_at || sub.submittedAt)}
                      </span>
                      <button
                        onClick={() => handleDeleteClick(sub)}
                        disabled={isDeleting === sub.id}
                        className="p-2 text-gray-500 hover:text-red-400 hover:bg-red-900/50 rounded-full transition-colors disabled:opacity-50"
                        aria-label="Delete submission"
                      >
                        {isDeleting === sub.id ? (
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-red-400"></div>
                        ) : (
                          <Trash2 size={16} />
                        )}
                      </button>
                    </div>
                  </div>
                  <div className="mt-4 border-t border-gray-700 pt-4 space-y-2 text-sm">
                    <p className="flex items-center gap-2 text-gray-300">
                      <Mail size={14} className="text-gray-500" />{" "}
                      {sub.workEmail}
                    </p>
                    <p className="flex items-center gap-2 text-gray-300">
                      <Building size={14} className="text-gray-500" />{" "}
                      {sub.companyName} ({sub.companyWebsite})
                    </p>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </MiftyAdminLayout>
  );
};

export default AdminContactSubmissions;
