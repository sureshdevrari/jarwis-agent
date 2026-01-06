import React from "react";
import Footer from "../components/Footer";

const RefundReturnPolicy = () => {
  return (
    <div className="min-h-screen relative py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto">
        <div className="space-y-8">
          {/* Header */}
          <div className="border-b border-gray-400 pb-6">
            <h1 className="text-3xl sm:text-4xl font-bold text-white mb-2">
              Refund & Return Policy
            </h1>
            <p className="text-gray-200">
              Last updated:{" "}
              <span className="font-semibold">August 4, 2025</span>
            </p>
            <p className="mt-4 text-gray-100 text-sm sm:text-base">
              This Refund & Return Policy ("
              <span className="font-semibold">Policy</span>") describes how BKD
              Labs Pvt Ltd ("<span className="font-semibold">we</span>," "
              <span className="font-semibold">us</span>," or "
              <span className="font-semibold">our</span>") handles subscription
              cancellations, refunds, and service credits for Jarwis AGI
              (jarwis.ai).
            </p>
          </div>

          {/* Quick Summary */}
          <div className="bg-purple-900 border border-purple-700 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-purple-100 mb-4">
              Quick Summary
            </h2>
            <ul className="space-y-2 text-purple-200 text-sm sm:text-base">
              <li className="flex items-start">
                <span className="text-purple-300 mr-2">*</span>
                <span><span className="font-semibold">No refunds</span> once a scan or
                subscription period has commenced.</span>
              </li>
              <li className="flex items-start">
                <span className="text-purple-300 mr-2">*</span>
                <span>You may cancel before scan starts for full refund.</span>
              </li>
            </ul>
          </div>

          {/* Section 1: Digital Service Nature */}
          <div className="bg-gray-800 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              1. Digital Service Nature
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              Jarwis provides digital security scanning services. Due to the nature of digital services,
              refunds are handled according to our policy below.
            </p>
          </div>

          {/* Section 2: Eligibility for Refunds */}
          <div className="bg-green-900 border border-green-700 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-green-100 mb-4">
              2. Eligibility for Refunds
            </h2>
            <div className="space-y-3 text-sm sm:text-base">
              <div className="border-l-4 border-green-400 pl-4">
                <h3 className="font-semibold text-green-100">Before scan starts:</h3>
                <p className="text-green-200">
                  You may cancel your order and request a full refund{" "}
                  <em>before</em> the scheduled scan start time.
                </p>
              </div>
              <div className="border-l-4 border-red-400 pl-4">
                <h3 className="font-semibold text-green-100">After scan starts:</h3>
                <p className="text-green-200">
                  Once a scan begins, <span className="font-semibold">no refund</span> will be
                  issued.
                </p>
              </div>
              <div className="border-l-4 border-yellow-400 pl-4">
                <h3 className="font-semibold text-green-100">
                  Subscription renewals:
                </h3>
                <p className="text-green-200">
                  Contact support within 48 hours of renewal for consideration.
                </p>
              </div>
            </div>
          </div>

          {/* Section 3: How to Request a Refund */}
          <div className="bg-gray-800 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              3. How to Request a Refund
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              If we terminate or materially suspend your service for reasons
              other than your violation of the Terms of Service, we will issue a{" "}
              <span className="font-semibold">pro-rata refund</span> for any unused period.
            </p>
          </div>

          {/* Section 4: How to Request a Cancellation */}
          <div className="bg-blue-900 border border-blue-700 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-blue-100 mb-4">
              4. How to Request a Cancellation
            </h2>
            <p className="text-blue-200 mb-4 text-sm sm:text-base">
              Email{" "}
              <a
                href="mailto:billing@bkd-labs.ai"
                className="text-blue-300 hover:text-blue-200 underline font-semibold"
              >
                billing@bkd-labs.ai
              </a>{" "}
              from your registered account address with:
            </p>
            <ul className="space-y-2 text-blue-200 text-sm sm:text-base">
              <li className="flex items-start">
                <span className="text-blue-300 mr-3">*</span>
                <span>Your name and email address</span>
              </li>
              <li className="flex items-start">
                <span className="text-blue-300 mr-3">*</span>
                <span>Order/subscription ID</span>
              </li>
              <li className="flex items-start">
                <span className="text-blue-300 mr-3">*</span>
                <span>Reason for refund request</span>
              </li>
            </ul>
            <p className="text-blue-200 mt-4 text-sm sm:text-base">
              We will confirm eligibility and process approved refunds within 7
              business days via the original payment method.
            </p>
          </div>

          {/* 5. Chargebacks */}
          <section className="bg-red-900 border border-red-700 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-red-100 mb-4">
              5. Chargebacks
            </h2>
            <p className="text-red-200 text-sm sm:text-base">
              Filing chargebacks without first contacting us may result in account termination.
            </p>
          </section>

          {/* 6. Changes */}
          <section className="bg-gray-800 rounded-lg p-4 sm:p-6">
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              6. Changes to This Policy
            </h2>
            <p className="text-gray-200 text-sm sm:text-base">
              We may update this policy. Changes will be posted on this page.
            </p>
          </section>

          {/* 7. Contact */}
          <section className="border-t border-gray-400 pt-6">
            <h2 className="text-xl sm:text-2xl font-bold text-white mb-4">
              7. Contact
            </h2>
            <div className="bg-gray-600 rounded-lg p-4 space-y-2">
              <p className="text-gray-200 text-sm sm:text-base">
                For billing support, contact{" "}
                <a
                  href="mailto: contact@jarwis.ai"
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

          {/* Footer */}
          <footer className="pt-6 text-center"></footer>
        </div>
      </div>
      <Footer />
    </div>
  );
};

export default RefundReturnPolicy;
