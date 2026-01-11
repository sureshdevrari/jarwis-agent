import React from "react";
import Footer from "../components/Footer";

const TermsofService = () => {
  return (
    <div className="min-h-screen relative py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto">
        <div className="space-y-8">
          {/* Header */}
          <div className="border-b border-gray-400 pb-6">
            <h1 className="text-3xl sm:text-4xl font-bold text-white mb-2">
              Terms of Service
            </h1>
            <p className="text-gray-200">
              Last updated:{" "}
              <span className="font-semibold">January 8, 2026</span>
            </p>
          </div>

          {/* Quick Snapshot */}
          <div className="bg-red-900 border border-red-700 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-red-100 mb-4">
              Quick Snapshot
            </h2>
            <ul className="space-y-2 text-red-200 text-sm sm:text-base">
              <li className="flex items-start">
                <span className="text-red-300 mr-2">-</span>
                You must own or have explicit permission to test the targets you
                submit.
              </li>
              <li className="flex items-start">
                <span className="text-red-300 mr-2">-</span>
                Fees paid are non-refundable once a Jarwis service starts.
              </li>
              <li className="flex items-start">
                <span className="text-red-300 mr-2">-</span>
                BKD Labs disclaims liability for indirect or consequential
                damages.
              </li>
              <li className="flex items-start">
                <span className="text-red-300 mr-2">-</span>
                Violations may result in immediate suspension.
              </li>
            </ul>
          </div>

          {/* 1. Acceptance */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              1. Acceptance
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              By creating an account, clicking "I agree," or using Jarwis AGI,
              you ("<span className="font-semibold">User</span>," "
              <span className="font-semibold">you</span>") accept these Terms of
              Service ("<span className="font-semibold">Terms</span>"). If you
              do not agree, do not use the service.
            </p>
          </section>

          {/* 2. Authorized Use */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              2. Authorized Use
            </h2>
            <ul className="space-y-2 text-gray-200 text-sm sm:text-base">
              <li className="flex items-start">
                <span className="text-gray-400 mr-3">-</span>
                You will submit only assets you own or are explicitly authorized
                to test.
              </li>
              <li className="flex items-start">
                <span className="text-gray-400 mr-3">-</span>
                You will not use Jarwis to attack third-party systems without
                permission.
              </li>
              <li className="flex items-start">
                <span className="text-gray-400 mr-3">-</span>
                You will comply with all applicable laws and regulations.
              </li>
            </ul>
          </section>

          {/* 3. Fees & Refunds */}
          <section className="bg-yellow-900 border border-yellow-700 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-yellow-100 mb-4">
              3. Fees & Refunds
            </h2>
            <p className="text-yellow-200 text-sm sm:text-base">
              Pricing is listed on jarwis.ai or a written quote.{" "}
              <span className="font-semibold">
                All payments are final and non-refundable once the Jarwis
                service has begun
              </span>{" "}
              (see Return Policy for details).
            </p>
          </section>

          {/* 4. Intellectual Property */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              4. Intellectual Property
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              Jarwis's software, models, and content remain the exclusive
              property of BKD Labs. You receive a non-exclusive,
              non-transferable license to use the platform during your
              subscription.
            </p>
          </section>

          {/* 5. Confidentiality */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              5. Confidentiality
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              We treat your scan data as confidential. You may not disclose
              proprietary information about the platform's internals without
              permission.
            </p>
          </section>

          {/* 6. Suspension & Termination */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              6. Suspension & Termination
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              We may suspend or terminate access if you breach these Terms,
              including unauthorized testing or non-payment. Upon termination,
              your licenses end and your data will be handled per our Privacy
              Policy.
            </p>
          </section>

          {/* 7. Disclaimers */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              7. Disclaimers
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              Jarwis is provided "as-is." We do not warrant that results are
              error-free or that all vulnerabilities will be found. BKD Labs
              disclaims all implied warranties to the fullest extent permitted
              by law.
            </p>
          </section>

          {/* 8. Limitation of Liability */}
          <section className="bg-orange-900 border border-orange-700 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-orange-100 mb-4">
              8. Limitation of Liability
            </h2>
            <p className="text-orange-200 text-sm sm:text-base">
              BKD Labs will not be liable for indirect, incidental, or
              consequential damages. Our total liability under these Terms will
              not exceed the amount you paid in the 12 months preceding the
              claim.
            </p>
          </section>

          {/* 9. Indemnification */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              9. Indemnification
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              You agree to indemnify and hold BKD Labs harmless from claims that
              arise from your misuse of Jarwis or breach of these Terms.
            </p>
          </section>

          {/* 10. Governing Law & Dispute Resolution */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              10. Governing Law & Dispute Resolution
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              These Terms are governed by the laws of the Republic of India.
              Disputes will be submitted to binding arbitration in Bengaluru,
              Karnataka.
            </p>
          </section>

          {/* 11. Changes to Terms */}
          <section>
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              11. Changes to Terms
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              We may revise these Terms at any time. Material changes will be
              posted here and emailed to account holders at least 15 days before
              taking effect.
            </p>
          </section>

          {/* 12. Contact */}
          <section className="border-t border-gray-400 pt-6">
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              12. Contact
            </h2>
            <div className="bg-gray-600 rounded-lg p-4 space-y-2">
              <p className="text-gray-200 text-sm sm:text-base">
                Questions? Email{" "}
                <a
                  href="mailto:contact@jarwis.ai"
                  className="text-blue-300 hover:text-blue-200 underline"
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
          <footer className="pt-6 text-center"></footer>
        </div>
      </div>
      <Footer />
    </div>
  );
};

export default TermsofService;
