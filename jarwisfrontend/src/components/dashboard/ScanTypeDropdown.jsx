// ScanTypeDropdown.jsx - Syndash-style scan type dropdown for dashboard
import { useState, useRef, useEffect } from "react";
import { Globe, Smartphone, Wifi, Rocket, Key } from "lucide-react";

const scanTypes = [
  { id: "web", label: "Web Scan", icon: Globe, color: "bg-blue-500" },
  { id: "mobile", label: "Mobile Scan", icon: Smartphone, color: "bg-purple-500" },
  { id: "network", label: "Network Scan", icon: Wifi, color: "bg-cyan-500" },
  { id: "cloud", label: "Cloud Scan", icon: Rocket, color: "bg-amber-500" },
  { id: "api", label: "API Scan", icon: Key, color: "bg-green-500" },
];

export default function ScanTypeDropdown({ onSelect, buttonLabel = "Start Scan", isDarkMode }) {
  const [open, setOpen] = useState(false);
  const [hovered, setHovered] = useState(null);
  const btnRef = useRef();

  useEffect(() => {
    if (!open) return;
    const handleClick = (e) => {
      if (btnRef.current && !btnRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  return (
    <div className="relative inline-block text-left" ref={btnRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        className={`flex items-center gap-2 px-6 py-3 rounded-xl font-semibold shadow-lg transition-all duration-300
          ${isDarkMode ? "bg-gradient-to-r from-cyan-600 to-blue-700 text-white hover:from-cyan-500 hover:to-blue-600" : "bg-gradient-to-r from-cyan-400 to-blue-500 text-white hover:from-cyan-300 hover:to-blue-400"}
          focus:outline-none focus:ring-2 focus:ring-cyan-400/50
        `}
      >
        <span className="text-lg">+</span>
        <span>{buttonLabel}</span>
        <svg className="w-4 h-4 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
      </button>
      {open && (
        <div className={`absolute z-50 mt-2 w-56 rounded-xl shadow-2xl border
          ${isDarkMode ? "bg-gray-900 border-gray-700" : "bg-white border-gray-200"}
          animate-dropdownIn
        `}>
          {scanTypes.map((type) => (
            <button
              key={type.id}
              onClick={() => { setOpen(false); onSelect(type.id); }}
              onMouseEnter={() => setHovered(type.id)}
              onMouseLeave={() => setHovered(null)}
              className={`w-full flex items-center gap-3 px-5 py-3 text-left transition-all duration-200
                ${hovered === type.id
                  ? `${type.color} text-white scale-105` 
                  : isDarkMode ? "text-gray-200 hover:bg-gray-800" : "text-gray-700 hover:bg-gray-100"}
                rounded-xl mb-1 last:mb-0
              `}
            >
              <span className={`p-2 rounded-lg ${type.color} bg-opacity-20`}><type.icon className="w-5 h-5" /></span>
              <span className="font-medium">{type.label}</span>
            </button>
          ))}
        </div>
      )}
      <style>{`
        @keyframes dropdownIn {
          0% { opacity: 0; transform: translateY(-10px) scale(0.98); }
          100% { opacity: 1; transform: translateY(0) scale(1); }
        }
        .animate-dropdownIn { animation: dropdownIn 0.18s cubic-bezier(.4,1.4,.6,1) both; }
      `}</style>
    </div>
  );
}
