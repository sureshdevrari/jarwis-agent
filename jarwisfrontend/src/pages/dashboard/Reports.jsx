// src/pages/dashboard/Reports.jsx - Reports Page with PDF Download
import { useState, useEffect, useCallback } from "react";
import DashboardPageLayout from "../../components/dashboardTheme/DashboardPageLayout";
import { useTheme } from "../../context/ThemeContext";
import { scanAPI } from "../../services/api";

const Reports = () => {
  const { isDarkMode } = useTheme();
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [downloadingPdf, setDownloadingPdf] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState("date_desc");

  const fetchReports = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await scanAPI.listReports();
      setReports(data.reports || []);
    } catch (err) {
      console.error("Failed to load reports:", err);
      setError("Failed to load reports");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const handleDownloadPdf = async (report) => {
    setDownloadingPdf(report.name);
    try {
      await scanAPI.downloadReportPdf(report);
    } catch (err) {
      console.error("PDF download failed:", err);
      alert("PDF download failed. Please ensure the server has PDF generation capabilities installed.");
    } finally {
      setDownloadingPdf(null);
    }
  };

  const handleViewReport = (report) => {
    const url = scanAPI.getFullReportUrl(report);
    window.open(url, "_blank");
  };

  // Filter and sort reports
  const getFilteredReports = () => {
    let filtered = reports.filter((report) =>
      report.name.toLowerCase().includes(searchQuery.toLowerCase())
    );

    filtered.sort((a, b) => {
      switch (sortBy) {
        case "date_asc":
          return a.modified - b.modified;
        case "name":
          return a.name.localeCompare(b.name);
        case "size":
          return b.size - a.size;
        case "date_desc":
        default:
          return b.modified - a.modified;
      }
    });

    return filtered;
  };

  const formatDate = (timestamp) => {
    if (!timestamp) return "-";
    const date = new Date(timestamp * 1000);
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const extractTargetName = (filename) => {
    // Extract target name from report filename
    // Format: report_targetname_timestamp.html
    const match = filename.match(/report_(.+?)_\d{8}_\d{6}\.html/);
    if (match) {
      return match[1].replace(/_/g, " ");
    }
    return filename.replace(/report_|\.html/g, "").replace(/_/g, " ");
  };

  // Theme classes
  const cardClass = isDarkMode
    ? "bg-slate-800/50 border border-slate-700/50 rounded-xl"
    : "bg-white border border-gray-200 rounded-xl shadow-sm";

  const inputClass = isDarkMode
    ? "px-4 py-2 bg-slate-800/50 border border-slate-700/50 rounded-lg text-white placeholder-gray-400 focus:border-blue-500/50 focus:ring-2 focus:ring-blue-500/20 outline-none transition-all"
    : "px-4 py-2 bg-white border border-gray-300 rounded-lg text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 outline-none transition-all shadow-sm";

  const filteredReports = getFilteredReports();

  if (loading) {
    return (
      <DashboardPageLayout>
        <div className="flex items-center justify-center py-16">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
            <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>Loading reports...</p>
          </div>
        </div>
      </DashboardPageLayout>
    );
  }

  return (
    <DashboardPageLayout>
      <div className="space-y-6 p-6">
        {/* Header */}
        <div className="flex justify-between items-center flex-wrap gap-4">
          <div>
            <h1
              className={
                isDarkMode
                  ? "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400 mb-2"
                  : "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-cyan-600 mb-2"
              }
            >
              Security Reports
            </h1>
            <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>
              View, download, and manage your security assessment reports.
            </p>
          </div>
          <button
            onClick={fetchReports}
            className="px-4 py-2 bg-gradient-to-r from-blue-600 to-blue-500 text-white rounded-lg hover:from-blue-500 hover:to-blue-400 transition-all font-medium"
          >
            Refresh Reports
          </button>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className={`${cardClass} p-4 text-center`}>
            <div className={`text-2xl mb-1 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              {reports.length}
            </div>
            <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>
              Total Reports
            </div>
          </div>
          <div className={`${cardClass} p-4 text-center`}>
            <div className={`text-2xl mb-1 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              PDF
            </div>
            <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>
              Download Format
            </div>
          </div>
          <div className={`${cardClass} p-4 text-center`}>
            <div className={`text-2xl mb-1 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              HTML
            </div>
            <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>
              View Format
            </div>
          </div>
          <div className={`${cardClass} p-4 text-center`}>
            <div className={`text-2xl mb-1 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              *
            </div>
            <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>
              AI Verified
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className={`${cardClass} p-4`}>
          <div className="flex flex-wrap gap-4">
            <input
              type="text"
              placeholder="Search reports..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className={`${inputClass} flex-1 min-w-[200px]`}
            />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className={inputClass}
            >
              <option value="date_desc">Newest First</option>
              <option value="date_asc">Oldest First</option>
              <option value="name">By Name</option>
              <option value="size">By Size</option>
            </select>
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div className={`${cardClass} p-6 text-center border-red-500`}>
            <p className="text-red-400 mb-4">{error}</p>
            <button
              onClick={fetchReports}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
            >
              Retry
            </button>
          </div>
        )}

        {/* No Reports */}
        {!loading && !error && reports.length === 0 ? (
          <div className={`${cardClass} p-12 text-center`}>
            <div className="text-5xl mb-4"></div>
            <h3 className={`text-xl font-semibold mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              No Reports Found
            </h3>
            <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>
              {searchQuery
                ? "No reports match your search criteria."
                : "Complete a security scan to generate your first report."}
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {filteredReports.map((report, index) => (
              <div
                key={report.name + index}
                className={`${cardClass} p-5 hover:border-blue-500/30 transition-all`}
              >
                <div className="flex items-center justify-between flex-wrap gap-4">
                  {/* Report Info */}
                  <div className="flex items-center gap-4 flex-1 min-w-[300px]">
                    <div className="text-4xl"></div>
                    <div>
                      <h3 className={`font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                        {extractTargetName(report.name)}
                      </h3>
                      <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                        {report.name}
                      </p>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-3">
                    {/* View HTML */}
                    <button
                      onClick={() => handleViewReport(report)}
                      className={`px-4 py-2 rounded-lg font-medium transition-all flex items-center gap-2 ${
                        isDarkMode
                          ? "bg-slate-700 hover:bg-slate-600 text-white"
                          : "bg-gray-100 hover:bg-gray-200 text-gray-900"
                      }`}
                    >
                      View
                    </button>
                    <button
                      onClick={() => handleDownloadPdf(report)}
                      disabled={downloadingPdf === report.name}
                      className={`px-4 py-2 rounded-lg font-medium transition-all flex items-center gap-2 ${
                        downloadingPdf === report.name
                          ? "bg-gray-500 cursor-not-allowed"
                          : "bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400"
                      } text-white`}
                    >
                      {downloadingPdf === report.name ? (
                        <>
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                          <span>Downloading...</span>
                        </>
                      ) : (
                        <>
                          <span></span>
                          <span>PDF</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

      {/* Report Standards Info */}
      <div className={cardClass}>
        <div className="p-6">
          <h4 className={`font-medium mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
            Professional Report Standards
          </h4>
          <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
            All reports follow professional penetration testing standards with executive summaries,
            detailed findings, and remediation guidance.
          </p>
        </div>
      </div>

      </div>
    </DashboardPageLayout>
  );
};

export default Reports;
