// src/pages/dashboard/VerifyDomain.jsx - With Theme Support
import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";

const VerifyDomain = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { isDarkMode } = useTheme();

  const [verificationStatus, setVerificationStatus] = useState({
    dns: false,
    html: false,
    checking: false,
  });

  // Get scan config from previous page if available
  const scanConfig = location.state?.scanConfig;
  const targetDomain = scanConfig?.domain || "yourdomain.com";

  // Generate verification codes (in real app, these would come from backend)
  const verificationCode = "7b1f-ACME-9x2";
  const htmlVerificationCode = "9x2-ACME";

  const checkVerification = async (method) => {
    setVerificationStatus((prev) => ({ ...prev, checking: true }));

    // Simulate verification check
    setTimeout(() => {
      // In a real app, you'd make an API call here
      const isVerified = Math.random() > 0.5; // Random for demo

      setVerificationStatus((prev) => ({
        ...prev,
        [method]: isVerified,
        checking: false,
      }));

      if (isVerified) {
        // Navigate to scanning page after successful verification
        setTimeout(() => {
          navigate("/dashboard/scanning", {
            state: { scanConfig, verificationMethod: method },
          });
        }, 1500);
      }
    }, 2000);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // You could show a toast notification here
  };

  return (
    <MiftyJarwisLayout>
      <div className="p-6">
      <h2
        className={
          isDarkMode
            ? "text-2xl font-bold text-white mb-2"
            : "text-2xl font-bold text-gray-900 mb-2"
        }
      >
        Verify Domain Ownership
      </h2>
      <p
        className={
          isDarkMode
            ? "text-sm text-gray-400 mb-4"
            : "text-sm text-gray-600 mb-4"
        }
      >
        Pick one method to prove you control the target. This protects against
        unauthorized testing.
      </p>

      {scanConfig && (
        <div
          className={
            isDarkMode
              ? "bg-blue-900/30 border border-blue-700 rounded-lg p-4 my-4"
              : "bg-blue-50 border border-blue-200 rounded-lg p-4 my-4 shadow-sm"
          }
        >
          <div className={isDarkMode ? "text-white" : "text-gray-900"}>
            <strong>Target Domain:</strong> {targetDomain}
          </div>
          <div className={isDarkMode ? "text-white" : "text-gray-900"}>
            <strong>Scan Type:</strong> {scanConfig.scope}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
        {/* DNS TXT Method */}
        <div
          className={
            isDarkMode
              ? "bg-gray-800 border border-gray-700 rounded-lg p-6"
              : "bg-white border border-gray-200 rounded-lg p-6 shadow-sm"
          }
        >
          <h3
            className={
              isDarkMode
                ? "text-xl font-semibold text-white mb-3"
                : "text-xl font-semibold text-gray-900 mb-3"
            }
          >
            DNS TXT Method
          </h3>
          <p
            className={isDarkMode ? "text-gray-300 mb-4" : "text-gray-700 mb-4"}
          >
            Add a TXT record to your DNS:
          </p>

          <div className="space-y-3 my-4">
            <div
              className={
                isDarkMode
                  ? "bg-gray-700 rounded-md px-3 py-2 flex items-center justify-between"
                  : "bg-gray-50 border border-gray-200 rounded-md px-3 py-2 flex items-center justify-between"
              }
            >
              <div>
                <strong className={isDarkMode ? "text-white" : "text-gray-900"}>
                  Host:
                </strong>{" "}
                <code
                  className={
                    isDarkMode
                      ? "bg-gray-900 px-2 py-1 rounded text-green-400 ml-1"
                      : "bg-gray-100 border border-gray-300 px-2 py-1 rounded text-green-700 ml-1"
                  }
                >
                  _jarwis-verification
                </code>
              </div>
              <button
                onClick={() => copyToClipboard("_jarwis-verification")}
                className={
                  isDarkMode
                    ? "ml-2 bg-transparent border-none text-blue-400 cursor-pointer hover:text-blue-300 transition-colors"
                    : "ml-2 bg-transparent border-none text-blue-600 cursor-pointer hover:text-blue-500 transition-colors"
                }
              >
                [LIST]
              </button>
            </div>
            <div
              className={
                isDarkMode
                  ? "bg-gray-700 rounded-md px-3 py-2 flex items-center justify-between"
                  : "bg-gray-50 border border-gray-200 rounded-md px-3 py-2 flex items-center justify-between"
              }
            >
              <div>
                <strong className={isDarkMode ? "text-white" : "text-gray-900"}>
                  Value:
                </strong>{" "}
                <code
                  className={
                    isDarkMode
                      ? "bg-gray-900 px-2 py-1 rounded text-green-400 ml-1"
                      : "bg-gray-100 border border-gray-300 px-2 py-1 rounded text-green-700 ml-1"
                  }
                >
                  jarwis={verificationCode}
                </code>
              </div>
              <button
                onClick={() => copyToClipboard(`jarwis=${verificationCode}`)}
                className={
                  isDarkMode
                    ? "ml-2 bg-transparent border-none text-blue-400 cursor-pointer hover:text-blue-300 transition-colors"
                    : "ml-2 bg-transparent border-none text-blue-600 cursor-pointer hover:text-blue-500 transition-colors"
                }
              >
                [LIST]
              </button>
            </div>
          </div>

          <p
            className={
              isDarkMode
                ? "text-sm text-gray-400 mb-4"
                : "text-sm text-gray-600 mb-4"
            }
          >
            Propagation may take up to 10 minutes.
          </p>

          {verificationStatus.dns ? (
            <div
              className={
                isDarkMode
                  ? "bg-green-900/30 border border-green-700 text-green-400 px-4 py-2 rounded-md mb-4"
                  : "bg-green-50 border border-green-200 text-green-700 px-4 py-2 rounded-md mb-4"
              }
            >
              [OK] DNS Verification Successful!
            </div>
          ) : (
            <button
              className={
                isDarkMode
                  ? "bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white px-4 py-2 rounded-md transition-colors"
                  : "bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white px-4 py-2 rounded-md transition-colors shadow-sm"
              }
              onClick={() => checkVerification("dns")}
              disabled={verificationStatus.checking}
            >
              {verificationStatus.checking
                ? " Checking..."
                : "Check DNS Verification"}
            </button>
          )}
        </div>

        {/* HTML File Method */}
        <div
          className={
            isDarkMode
              ? "bg-gray-800 border border-gray-700 rounded-lg p-6"
              : "bg-white border border-gray-200 rounded-lg p-6 shadow-sm"
          }
        >
          <h3
            className={
              isDarkMode
                ? "text-xl font-semibold text-white mb-3"
                : "text-xl font-semibold text-gray-900 mb-3"
            }
          >
            HTML File Upload
          </h3>
          <p
            className={isDarkMode ? "text-gray-300 mb-4" : "text-gray-700 mb-4"}
          >
            Upload a file at the root of your site:
          </p>

          <div className="space-y-3 my-4">
            <div
              className={
                isDarkMode
                  ? "bg-gray-700 rounded-md px-3 py-2 flex items-center justify-between"
                  : "bg-gray-50 border border-gray-200 rounded-md px-3 py-2 flex items-center justify-between"
              }
            >
              <div>
                <strong className={isDarkMode ? "text-white" : "text-gray-900"}>
                  Filename:
                </strong>{" "}
                <code
                  className={
                    isDarkMode
                      ? "bg-gray-900 px-2 py-1 rounded text-green-400 ml-1 break-all"
                      : "bg-gray-100 border border-gray-300 px-2 py-1 rounded text-green-700 ml-1 break-all"
                  }
                >
                  jarwis-verify-{htmlVerificationCode}.html
                </code>
              </div>
              <button
                onClick={() =>
                  copyToClipboard(`jarwis-verify-${htmlVerificationCode}.html`)
                }
                className={
                  isDarkMode
                    ? "ml-2 bg-transparent border-none text-blue-400 cursor-pointer hover:text-blue-300 transition-colors flex-shrink-0"
                    : "ml-2 bg-transparent border-none text-blue-600 cursor-pointer hover:text-blue-500 transition-colors flex-shrink-0"
                }
              >
                [LIST]
              </button>
            </div>
            <div
              className={
                isDarkMode
                  ? "bg-gray-700 rounded-md px-3 py-2 flex items-center justify-between"
                  : "bg-gray-50 border border-gray-200 rounded-md px-3 py-2 flex items-center justify-between"
              }
            >
              <div>
                <strong className={isDarkMode ? "text-white" : "text-gray-900"}>
                  Contents:
                </strong>{" "}
                <code
                  className={
                    isDarkMode
                      ? "bg-gray-900 px-2 py-1 rounded text-green-400 ml-1 break-all"
                      : "bg-gray-100 border border-gray-300 px-2 py-1 rounded text-green-700 ml-1 break-all"
                  }
                >
                  jarwis-site-verification: {htmlVerificationCode}
                </code>
              </div>
              <button
                onClick={() =>
                  copyToClipboard(
                    `jarwis-site-verification: ${htmlVerificationCode}`
                  )
                }
                className={
                  isDarkMode
                    ? "ml-2 bg-transparent border-none text-blue-400 cursor-pointer hover:text-blue-300 transition-colors flex-shrink-0"
                    : "ml-2 bg-transparent border-none text-blue-600 cursor-pointer hover:text-blue-500 transition-colors flex-shrink-0"
                }
              >
                [LIST]
              </button>
            </div>
          </div>

          <p
            className={
              isDarkMode
                ? "text-sm text-gray-400 mb-4"
                : "text-sm text-gray-600 mb-4"
            }
          >
            Accessible at{" "}
            <code
              className={
                isDarkMode
                  ? "bg-gray-900 px-2 py-1 rounded text-green-400 break-all"
                  : "bg-gray-100 border border-gray-300 px-2 py-1 rounded text-green-700 break-all"
              }
            >
              https://{targetDomain}/jarwis-verify-{htmlVerificationCode}.html
            </code>
          </p>

          {verificationStatus.html ? (
            <div
              className={
                isDarkMode
                  ? "bg-green-900/30 border border-green-700 text-green-400 px-4 py-2 rounded-md mb-4"
                  : "bg-green-50 border border-green-200 text-green-700 px-4 py-2 rounded-md mb-4"
              }
            >
              [OK] HTML Verification Successful!
            </div>
          ) : (
            <button
              className={
                isDarkMode
                  ? "bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white px-4 py-2 rounded-md transition-colors"
                  : "bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white px-4 py-2 rounded-md transition-colors shadow-sm"
              }
              onClick={() => checkVerification("html")}
              disabled={verificationStatus.checking}
            >
              {verificationStatus.checking
                ? " Checking..."
                : "Check HTML Verification"}
            </button>
          )}
        </div>
      </div>

      {/* Instructions */}
      <div
        className={
          isDarkMode
            ? "bg-gray-800 border border-gray-700 rounded-lg p-6 mt-6"
            : "bg-white border border-gray-200 rounded-lg p-6 mt-6 shadow-sm"
        }
      >
        <h3
          className={
            isDarkMode
              ? "text-xl font-semibold text-white mb-4"
              : "text-xl font-semibold text-gray-900 mb-4"
          }
        >
          Need Help?
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4
              className={
                isDarkMode
                  ? "text-blue-400 font-medium mb-2"
                  : "text-blue-600 font-medium mb-2"
              }
            >
              DNS Method Steps:
            </h4>
            <ol
              className={
                isDarkMode
                  ? "list-decimal list-inside space-y-1 text-gray-400"
                  : "list-decimal list-inside space-y-1 text-gray-700"
              }
            >
              <li>Log into your DNS provider (Cloudflare, Route53, etc.)</li>
              <li>Add a new TXT record with the host and value above</li>
              <li>Wait 5-10 minutes for DNS propagation</li>
              <li>Click "Check DNS Verification"</li>
            </ol>
          </div>
          <div>
            <h4
              className={
                isDarkMode
                  ? "text-blue-400 font-medium mb-2"
                  : "text-blue-600 font-medium mb-2"
              }
            >
              HTML Method Steps:
            </h4>
            <ol
              className={
                isDarkMode
                  ? "list-decimal list-inside space-y-1 text-gray-400"
                  : "list-decimal list-inside space-y-1 text-gray-700"
              }
            >
              <li>Create the HTML file with the exact filename and contents</li>
              <li>Upload to your website's root directory</li>
              <li>Ensure the file is publicly accessible</li>
              <li>Click "Check HTML Verification"</li>
            </ol>
          </div>
        </div>

        <div className="mt-6 text-center">
          <button
            className={
              isDarkMode
                ? "bg-gray-600 hover:bg-gray-700 text-white px-6 py-2 rounded-md transition-colors"
                : "bg-gray-100 border border-gray-300 hover:bg-gray-200 text-gray-700 px-6 py-2 rounded-md transition-colors shadow-sm"
            }
            onClick={() => navigate("/dashboard/new-scan")}
          >
            &larr; Back to Scan Setup
          </button>
        </div>
      </div>
      </div>
    </MiftyJarwisLayout>
  );
};

export default VerifyDomain;
