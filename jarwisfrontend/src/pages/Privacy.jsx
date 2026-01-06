import Footer from "../components/Footer";

const Privacy = () => {
  return (
    <div className="min-h-screen relative py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto">
        <div className="space-y-8">
          {/* Header */}
          <div className="border-b border-gray-400 pb-6">
            <h1 className="text-3xl sm:text-4xl font-bold text-white mb-2">
              Privacy Policy
            </h1>
            <p className="text-gray-200">
              Last updated:{" "}
              <span className="font-semibold">August 3, 2025</span>
            </p>
            <p className="mt-4 text-gray-100 text-sm sm:text-base">
              Jarwis AGI (jarwis.ai) is a service provided by{" "}
              <span className="font-semibold">BKD Labs Pvt Ltd</span> ("we," "us," or
              "our").
            </p>
          </div>

          {/* Quick Summary */}
          <div className="bg-blue-900 border border-blue-700 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-blue-100 mb-4">
              Quick Summary
            </h2>
            <ul className="space-y-2 text-blue-200 text-sm sm:text-base">
              <li className="flex items-start">
                <span className="text-blue-300 mr-2">*</span>
                <span>We only collect data necessary for security scanning</span>
              </li>
              <li className="flex items-start">
                <span className="text-blue-300 mr-2">*</span>
                <span>Scan data is{" "}
                <span className="font-semibold">
                  deleted automatically after each scan completes
                </span>
                .
                </span>
              </li>
              <li className="flex items-start">
                <span className="text-blue-300 mr-2">*</span>
                <span>We never sell your data</span>
              </li>
            </ul>
          </div>

          {/* Section 1: Information We Collect */}
          <div className="bg-gray-800 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              Information We Collect
            </h2>
            <p className="text-gray-200 mb-4 text-sm sm:text-base">
              We collect the following categories of information:
            </p>
            <div className="space-y-3">
              <div className="border-l-4 border-gray-400 pl-4">
                <h3 className="font-semibold text-gray-100 text-sm sm:text-base">
                  Account Data:
                </h3>
                <p className="text-gray-300 text-sm sm:text-base">
                  name, business email, company name, and authentication
                  credentials.
                </p>
              </div>
              <div className="border-l-4 border-gray-400 pl-4">
                <h3 className="font-semibold text-gray-100 text-sm sm:text-base">
                  Scan Data:
                </h3>
                <p className="text-gray-300 text-sm sm:text-base">
                  Discovered endpoints, responses, and vulnerability findings from your scans.
                </p>
              </div>
              <div className="border-l-4 border-gray-400 pl-4">
                <h3 className="font-semibold text-gray-100 text-sm sm:text-base">
                  Technical Data:
                </h3>
                <p className="text-gray-300 text-sm sm:text-base">
                  IP address, browser type, device identifiers, and cookies.
                </p>
              </div>
              <div className="border-l-4 border-gray-400 pl-4">
                <h3 className="font-semibold text-gray-100 text-sm sm:text-base">
                  Support Data:
                </h3>
                <p className="text-gray-300 text-sm sm:text-base">
                  messages or attachments you send to our team.
                </p>
              </div>
            </div>
          </div>

          {/* How We Use Your Information */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              How We Use Your Information
            </h2>
            <ul className="space-y-2 text-gray-200 text-sm sm:text-base">
              <li className="flex items-start">
                <span className="text-gray-400 mr-3">*</span>
                Provide and improve our security testing services
              </li>
              <li className="flex items-start">
                <span className="text-gray-400 mr-3">*</span>
                Process payments and manage subscriptions
              </li>
              <li className="flex items-start">
                <span className="text-gray-400 mr-3">*</span>
                Send service-related communications
              </li>
              <li className="flex items-start">
                <span className="text-gray-400 mr-3">*</span>
                Respond to support requests
              </li>
              <li className="flex items-start">
                <span className="text-gray-400 mr-3">*</span>
                Comply with legal obligations
              </li>
            </ul>
          </section>

          {/* Scan Credential Deletion */}
          <section className="bg-green-900 border border-green-700 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-green-100 mb-4">
              Scan Credential Deletion
            </h2>
            <p className="text-green-200 text-sm sm:text-base">
              Any credentials (API keys, user/password pairs, tokens) supplied
              solely for the purpose of running a scan are encrypted in memory
              and{" "}
              <span className="font-semibold">
                erased automatically once the scan finishes
              </span>
              . They are never written to disk.
            </p>
          </section>

          {/* Legal Bases */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              Legal Bases (GDPR)
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              We rely on contractual necessity, legitimate interest, consent,
              and legal obligation, as applicable.
            </p>
          </section>

          {/* Cookies & Analytics */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              Cookies & Analytics
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              We use cookies for essential site functionality and analytics.
            </p>
          </section>

          {/* Data Sharing */}
          <section className="bg-gray-800 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              Data Sharing
            </h2>
            <p className="text-gray-200 mb-4 text-sm sm:text-base">
              We do not sell or rent personal data. We disclose information only
              to:
            </p>
            <ul className="space-y-2 text-gray-200 text-sm sm:text-base">
              <li className="flex items-start">
                <span className="text-gray-400 mr-3">*</span>
                <span>Service providers who assist our operations</span>
              </li>
              <li className="flex items-start">
                <span className="text-gray-400 mr-3">*</span>
                <span>Legal authorities when required by law</span>
              </li>
              <li className="flex items-start">
                <span className="text-gray-400 mr-3">*</span>
                <span>Business partners with your consent</span>
              </li>
            </ul>
          </section>

          {/* Data Security */}
          <section className="bg-gray-800 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              Data Security
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              We implement industry-standard security measures to protect your data.
            </p>
          </section>

          {/* Data Retention */}
          <div className="bg-gray-800 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              Data Retention
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              We retain data only as long as necessary for service delivery and legal compliance.
            </p>
          </div>

          {/* Your Privacy Rights */}
          <section className="bg-yellow-900 border border-yellow-700 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-yellow-100 mb-4">
              Your Privacy Rights and Choices
            </h2>
            <p className="text-yellow-200 mb-4 text-sm sm:text-base">
              You have the right to access, correct, delete, restrict, or export
              your personal data. You may also object to certain processing or
              withdraw consent for marketing communications.
            </p>
            <p className="text-yellow-200 text-sm sm:text-base">
              To exercise your rights, email{" "}
              <a
                href="mailto:contact@jarwis.ai"
                className="text-yellow-300 hover:text-yellow-100 underline"
              >
                contact@jarwis.ai
              </a>{" "}
              or visit Your Privacy Center.
            </p>
          </section>

          {/* International Transfers */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              International Transfers
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              Where data is transferred outside your jurisdiction, we rely on
              Standard Contractual Clauses or equivalent safeguards.
            </p>
          </section>

          {/* Children */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              Children
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              Jarwis is intended for users 18 and older. We do not knowingly
              collect data from children.
            </p>
          </section>

          {/* Changes */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              Changes
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              We may update this policy periodically. We will notify you of material changes via email or in-app notification.
            </p>
          </section>

          {/* Contact */}
          <section className="border-t border-gray-400 pt-6">
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              Contact
            </h2>
            <div className="bg-gray-600 rounded-lg p-4 space-y-2">
              <p className="text-gray-200 text-sm sm:text-base">
                <span className="font-semibold">Data Protection Officer:</span>
                <a
                  href="mailto:contact@jarwis.ai"
                  className="text-blue-300 hover:text-blue-200 underline ml-1"
                >
                  contact@jarwis.ai
                </a>
              </p>
              <p className="text-gray-200 text-sm sm:text-base">
                <span className="font-semibold">BKD Labs Pvt Ltd</span>
                <br />
                221B Cyber Ave, Bengaluru 560102, India
              </p>
            </div>
          </section>

          {/* Footer */}
          <footer className="pt-6 text-center"></footer>
        </div>
      </div>
      <Footer />
    </div>
  );
};

export default Privacy;
