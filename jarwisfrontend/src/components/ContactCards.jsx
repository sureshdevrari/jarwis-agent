import { MdEmail, MdPhone, MdLocationOn, MdAccessTime } from "react-icons/md";
import { FaLinkedin, FaTwitter, FaGithub } from "react-icons/fa";
import { FcCollaboration } from "react-icons/fc";

const ContactCards = () => {
  return (
    <div className="p-6 relative">
      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Email Us Card */}
          <div className="border-2 border-gray-500 rounded-xl shadow-lg p-6 hover:shadow-xl transition-shadow duration-300">
            <div className="flex items-center mb-4">
              <div className="bg-blue-600/20 p-3 rounded-full mr-4">
                <MdEmail className="text-blue-400 text-2xl" />
              </div>
              <h3 className="text-xl font-bold text-white">Email Us</h3>
            </div>
            <p className="text-gray-200 mb-4">Get in touch anytime</p>
            <div className="space-y-2">
              <a
                href="mailto:contact@jarwis.ai"
                className="block text-blue-400 hover:text-blue-200 font-medium"
              >
                contact@jarwis.ai
              </a>
            </div>
          </div>

          {/* Call Us Card */}
          <div className="border-2 border-gray-500 rounded-xl shadow-lg p-6 hover:shadow-xl transition-shadow duration-300">
            <div className="flex items-center mb-4">
              <div className="bg-green-600/20 p-3 rounded-full mr-4">
                <MdPhone className="text-green-400 text-2xl" />
              </div>
              <h3 className="text-xl font-bold text-white">Call Us</h3>
            </div>
            <p className="text-gray-200 mb-4">Business hours: 24x7</p>
            <div className="space-y-2">
              <a
                href="tel:+15551234278947"
                className="block text-green-400 hover:text-green-200 font-medium"
              >
                +91 9044342357
              </a>
            </div>
          </div>

          {/* Visit Us Card */}
          <div className="border-2 border-gray-500 rounded-xl shadow-lg p-6 hover:shadow-xl transition-shadow duration-300">
            <div className="flex items-center mb-4">
              <div className="bg-purple-600/20 p-3 rounded-full mr-4">
                <MdLocationOn className="text-purple-400 text-2xl" />
              </div>
              <h3 className="text-xl font-bold text-white">Visit Us</h3>
            </div>
            <p className="text-gray-200 mb-4">Office Address</p>
            <div className="space-y-1 text-gray-200">
              <a
                href="https://www.google.com/maps/place/Rajajipuram,+Lucknow,+Uttar+Pradesh"
                target="_blank"
                rel="noopener noreferrer"
                className="block font-medium text-blue-400 hover:text-blue-200"
              >
                C 3736 Rajaji puram, Lucknow, India
              </a>
            </div>
          </div>

          {/* Follow Us Card */}
          {/* <div className="border-2 border-gray-500 rounded-xl shadow-lg p-6 hover:shadow-xl transition-shadow duration-300">
            <div className="flex items-center mb-4">
              <div className="bg-orange-600/20 p-3 rounded-full mr-4">
                <FcCollaboration className="text-orange-400 text-2xl" />
              </div>
              <h3 className="text-xl font-bold text-white">Follow Us</h3>
            </div>
            <div className="flex space-x-4">
              <a
                href="https://www.linkedin.com/company/jarwis-ai"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-blue-600 hover:bg-blue-700 text-white p-3 rounded-full transition-colors duration-200"
                aria-label="LinkedIn"
              >
                <FaLinkedin className="text-xl" />
              </a>
              <a
                href="https://twitter.com/jarwis_ai"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-sky-500 hover:bg-sky-600 text-white p-3 rounded-full transition-colors duration-200"
                aria-label="Twitter"
              >
                <FaTwitter className="text-xl" />
              </a>
              <a
                href="https://github.com/jarwis-ai"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-gray-800 hover:bg-gray-900 text-white p-3 rounded-full transition-colors duration-200"
                aria-label="GitHub"
              >
                <FaGithub className="text-xl" />
              </a>
            </div>
          </div> */}

          {/* Office Hours Card */}
          {/* <div className="border-2 border-gray-500 rounded-xl shadow-lg p-6 hover:shadow-xl transition-shadow duration-300 md:col-span-2 lg:col-span-1">
            <div className="flex items-center mb-4">
              <div className="bg-indigo-600/20 p-3 rounded-full mr-4">
                <MdAccessTime className="text-indigo-400 text-2xl" />
              </div>
              <h3 className="text-xl font-bold text-white">Office Hours</h3>
            </div>
            <div className="space-y-3 text-gray-200">
              <div className="flex justify-between items-center">
                <span className="font-medium">Monday - Friday</span>
                <span>9:00 AM - 6:00 PM PST</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="font-medium">Saturday</span>
                <span>10:00 AM - 2:00 PM PST</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="font-medium">Sunday</span>
                <span>Closed</span>
              </div>
            </div>
          </div> */}

          {/* Status Card */}
          {/* <div className="border-2 border-gray-500 rounded-xl shadow-lg p-6 hover:shadow-xl transition-shadow duration-300 md:col-span-2 lg:col-span-3">
            <div className="flex items-center justify-center text-gray-200">
              <MdCircle className="text-green-400 text-lg mr-2" />
              <span className="text-lg font-semibold">
                We're currently online!
              </span>
              <span className="ml-2">
                Expect quick responses during business hours.
              </span>
            </div>
          </div> */}
        </div>
      </div>
    </div>
  );
};

export default ContactCards;
