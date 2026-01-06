import { Link, useNavigate } from "react-router-dom";

const BuildMore = () => {
  const navigate = useNavigate();

  return (
    <div className="pb-6 relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-12 xl:gap-16 items-center">
          {/* Left Section */}
          <div className="space-y-6 sm:space-y-8 lg:space-y-10">
            {/* Main Heading */}
            <h2 className="text-3xl sm:text-4xl md:text-4xl lg:text-5xl xl:text-5xl font-light leading-tight">
              Be Among the first to experience{" "}
              <span className="bg-gradient-to-r from-blue-500 to-cyan-400 bg-clip-text text-transparent">
                Jarwis
              </span>
            </h2>

            {/* CTA Button */}
            <div>
              <button
                onClick={() => navigate("/pricing")}
                className="bg-blue-600 text-white px-4 py-2 sm:px-6 sm:py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium mb-8 sm:mb-12 text-sm sm:text-base"
              >
                Hire Jarwis
              </button>
            </div>
          </div>

          {/* Right Section */}
          <div className="space-y-4 sm:space-y-6 lg:space-y-8 border-2 border-white rounded-2xl p-12">
            {/* Enterprise Question */}
            <h3 className="text-lg sm:text-xl md:text-2xl lg:text-3xl xl:text-4xl font-light leading-relaxed">
              Need Jarwis for your enterprise?
            </h3>

            {/* Description */}
            <p className="text-gray-100 text-sm sm:text-base md:text-lg lg:text-xl leading-relaxed max-w-lg">
              Join our exclusive early access program and revolutionize your
              security testing
            </p>

            {/* Enterprise Link */}
            <div className="pt-2 sm:pt-4">
              <Link
                to="/about"
                className="text-gray-200 text-sm sm:text-base md:text-lg lg:text-xl font-medium border-b-2 border-gray-400 hover:border-blue-500 hover:text-blue-600 transition-colors duration-200 inline-block"
              >
                Learn about Jarwis AGI
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BuildMore;
