import { useNavigate } from "react-router-dom";

export default function NotFound() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gray-900 relative text-white">
      <div className="fixed inset-0 w-full h-full pointer-events-none z-0">
        <div className="absolute inset-0 bg-gradient-to-br from-gray-900/20 via-black to-gray-900/20"></div>
        <div className="absolute top-0 left-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-0 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute top-1/2 left-1/2 w-96 h-96 bg-pink-500/10 rounded-full blur-3xl animate-pulse"></div>
      </div>
      <div className="min-h-screen relative flex flex-col items-center justify-center text-white px-4">
        <h1 className="text-9xl font-extrabold mb-4">404</h1>
        <h2 className="text-3xl md:text-4xl font-bold mb-2">Page Not Found</h2>
        <p className="text-gray-400 mb-6 text-center max-w-md">
          Oops! The page you are looking for does not exist or has been moved.
        </p>
        <button
          onClick={() => navigate(-1)} // Go back to previous page
          className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-3 rounded-lg transition-colors font-medium"
        >
          Go Back
        </button>
      </div>
    </div>
  );
}
