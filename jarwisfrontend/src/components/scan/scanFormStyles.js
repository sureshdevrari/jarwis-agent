// Shared styles for scan form components
export const getInputClass = (isDarkMode) =>
  isDarkMode
    ? "w-full px-4 py-3 bg-slate-800/50 backdrop-blur-xl border border-slate-700/50 rounded-xl text-white placeholder-gray-400 focus:border-blue-500/50 focus:ring-2 focus:ring-blue-500/20 transition-all duration-300 outline-none"
    : "w-full px-4 py-3 bg-white border border-gray-300 rounded-xl text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-300 outline-none shadow-sm";

export const getLabelClass = (isDarkMode) =>
  isDarkMode
    ? "block text-sm font-semibold text-white uppercase tracking-wide"
    : "block text-sm font-semibold text-gray-900 uppercase tracking-wide";

export const getCardClass = (isDarkMode) =>
  isDarkMode ? "function-card-dark p-6" : "function-card-light p-6";

export const getCancelButtonClass = (isDarkMode) =>
  isDarkMode
    ? "px-6 py-3 bg-slate-700/50 border border-slate-600/50 text-gray-300 rounded-xl hover:bg-slate-600/50 transition-all"
    : "px-6 py-3 bg-gray-100 border border-gray-300 text-gray-700 rounded-xl hover:bg-gray-200 transition-all";
