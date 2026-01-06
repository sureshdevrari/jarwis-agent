import { useState } from "react";

export default function ImageToggleInterface({ imageOne, imageTwo }) {
  const [selected, setSelected] = useState(1);
  const totalImages = 2;

  const toggleImage = () => {
    setSelected((prev) => (prev === 1 ? 2 : 1));
  };

  return (
    <div className="flex-1 max-w-full xl:max-w-lg">
      <div className="bg-gradient-to-br from-slate-50 via-white to-slate-100 rounded-2xl sm:rounded-3xl shadow-2xl backdrop-blur-sm border border-white/20 mx-auto max-w-lg xl:max-w-none">
        <div className="relative bg-white/70 backdrop-blur-md rounded-xl sm:rounded-2xl p-4 sm:p-6 shadow-xl border border-white/30 overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-blue-50/30 via-transparent to-purple-50/30 pointer-events-none" />

          {/* Desktop */}
          <div className="hidden md:block relative z-10">
            <div className="relative overflow-hidden rounded-xl mb-6 group">
              <img
                src={selected === 1 ? imageOne : imageTwo}
                alt={selected === 1 ? "First image" : "Second image"}
                className="w-full h-56 sm:h-72 object-cover transition-all duration-500 ease-out transform group-hover:scale-105"
              />

              {/* Dots */}
              <div className="absolute bottom-3 left-1/2 -translate-x-1/2 flex space-x-2">
                {[1, 2].map((i) => (
                  <div
                    key={i}
                    className={`w-2 h-2 rounded-full ${
                      selected === i ? "bg-white shadow-lg" : "bg-white/50"
                    }`}
                  />
                ))}
              </div>
            </div>

            {/* Controls */}
            <div className="flex justify-center items-center space-x-6">
              <button
                aria-label="Previous Image"
                onClick={toggleImage}
                className="group relative w-10 h-10 rounded-full bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 shadow-lg hover:shadow-xl transition-all duration-300 flex items-center justify-center text-white overflow-hidden"
              >
                <svg
                  className="w-5 h-5 group-hover:-translate-x-0.5 transition-transform duration-200"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M15.41 7.41L14 6l-6 6 6 6 1.41-1.41L10.83 12z" />
                </svg>
              </button>

              <div className="flex flex-col items-center text-sm text-gray-600">
                <span>
                  {selected} / {totalImages}
                </span>
                <div className="flex space-x-1">
                  {[1, 2].map((i) => (
                    <div
                      key={i}
                      className={`w-6 h-1 rounded-full ${
                        selected === i
                          ? "bg-gradient-to-r from-blue-500 to-purple-600"
                          : "bg-gray-200"
                      }`}
                    />
                  ))}
                </div>
              </div>

              <button
                aria-label="Next Image"
                onClick={toggleImage}
                className="group relative w-10 h-10 rounded-full bg-gradient-to-r from-purple-500 to-pink-600 hover:from-purple-600 hover:to-pink-700 shadow-lg hover:shadow-xl transition-all duration-300 flex items-center justify-center text-white overflow-hidden"
              >
                <svg
                  className="w-5 h-5 group-hover:translate-x-0.5 transition-transform duration-200"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path d="M8.59 16.59L10 18l6-6-6-6-1.41 1.41L13.17 12z" />
                </svg>
              </button>
            </div>
          </div>

          {/* Mobile */}
          <div className="md:hidden space-y-4 relative z-10">
            {[imageOne, imageTwo].map((src, i) => (
              <div key={i}>
                <div className="group relative overflow-hidden rounded-lg">
                  <img
                    src={src}
                    alt={`Image ${i + 1}`}
                    className="w-full h-44 object-cover"
                  />
                  <span className="absolute top-3 left-3 bg-white/90 rounded-full px-2 py-1 text-xs font-medium text-gray-700">
                    {i + 1}
                  </span>
                </div>

                {/* Divider */}
                {i === 0 && (
                  <div className="w-full my-2 border-t-2 border-gray-300" />
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
