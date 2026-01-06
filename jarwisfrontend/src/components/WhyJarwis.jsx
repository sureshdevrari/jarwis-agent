import { useState, useEffect, useRef } from "react";

export default function WhyJarwis() {
  const topCards = [
    {
      title: "True AGI Intelligence in Security Domain",
      points: [
        "Jarwis thinks like an experienced security expert, understanding business logic and uncovering complex vulnerabilities that automated tools often miss.",
      ],
      bg: "bg-gradient-to-br from-[#1e293b] via-[#0f172a] to-[#0b1120] text-white",
    },
    {
      title: "Natural Language Interface",
      points: [
        "Simply tell Jarwis what to test--in plain English. No complicated setup or deep technical knowledge required.",
      ],
      bg: "bg-gradient-to-br from-[#2e1f47] via-[#1e1b4b] to-[#0f172a] text-white",
    },
    {
      title: "Complete Security Coverage",
      points: [
        "Thorough detection of OWASP Top 10, SANS Top 25, and custom business logic vulnerabilities--ensuring nothing slips through.",
      ],
      bg: "bg-gradient-to-br from-[#0f172a] via-[#1e3a8a] to-[#312e81] text-white",
    },
  ];

  const bottomBoxes = [
    {
      title: "Lightning Fast",
      points: [
        "Up to 10x faster than manual penetration testing, with 99.8% accuracy and virtually zero false positives.",
      ],
    },
    {
      title: "Always Learning",
      points: [
        "Jarwis evolves with every scan--learning new attack patterns and adapting to the latest security threats.",
      ],
    },
    {
      title: "Works Everywhere",
      points: [
        "Seamlessly integrates with web apps, APIs, mobile apps, and cloud infrastructure.",
      ],
    },
  ];

  const [activeIndex, setActiveIndex] = useState(0);
  const [isMobile, setIsMobile] = useState(false);
  const intervalRef = useRef(null);

  // Detect mobile vs desktop
  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth < 768);
    handleResize(); // Initial check
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  // Rotation only for desktop
  const startRotation = () => {
    if (!intervalRef.current && !isMobile) {
      intervalRef.current = setInterval(() => {
        setActiveIndex((prev) => (prev + 1) % topCards.length);
      }, 3000);
    }
  };

  const stopRotation = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  };

  useEffect(() => {
    if (!isMobile) startRotation();
    return () => stopRotation();
  }, [isMobile]);

  return (
    <section className="w-full py-12 px-4 sm:px-6 lg:px-8">
      {/* Header */}
      <div className="max-w-5xl mx-auto text-center mb-12">
        <h2 className="text-4xl font-bold">
          Why{" "}
          <span className="bg-gradient-to-r from-blue-500 to-cyan-400 bg-clip-text text-transparent">
            Jarwis
          </span>{" "}
          is Different
        </h2>
        <p className="mt-4 text-gray-400 max-w-xl mx-auto">
          Unlike traditional scanners, Jarwis understands context, logic, and
          intent
        </p>
      </div>

      {/* Top Cards */}
      <div
        className={`flex flex-col md:flex-row gap-4 max-w-6xl mx-auto ${
          isMobile ? "space-y-4 h-auto" : "h-[300px] md:h-[400px]"
        }`}
        onMouseEnter={isMobile ? null : stopRotation}
        onMouseLeave={isMobile ? null : startRotation}
      >
        {topCards.map((card, index) => (
          <div
            key={index}
            onMouseEnter={isMobile ? null : () => setActiveIndex(index)}
            className={`transition-all duration-500 ease-in-out rounded-xl overflow-hidden shadow-lg
        ${
          isMobile
            ? "flex-auto"
            : activeIndex === index
            ? "flex-[4]"
            : "flex-[0.5]"
        }
        ${card.bg}
      `}
          >
            <div
              className={`p-6 md:w-1/2 flex flex-col justify-center h-full transition-opacity duration-500 ${
                isMobile
                  ? "opacity-100"
                  : activeIndex === index
                  ? "opacity-100"
                  : "opacity-0"
              }`}
            >
              <h3 className="text-2xl font-bold mb-4">{card.title}</h3>
              <ul className="space-y-2">
                {card.points.map((point, i) => (
                  <li key={i} className="items-start gap-2">
                    <span className="text-cyan-400">&rarr; </span>
                    <p>{point}</p>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>

      {/* Bottom Boxes */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-6xl mx-auto mt-8">
        {bottomBoxes.map((box, index) => (
          <div
            key={index}
            className="border rounded-xl p-6 shadow-md hover:shadow-lg transition-shadow duration-300 bg-white"
          >
            <h4 className="text-xl font-semibold mb-4 text-black">
              {box.title}
            </h4>
            <ul className="space-y-2 text-gray-700">
              {box.points.map((point, i) => (
                <li key={i} className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-cyan-500 rounded-full"></span>
                  {point}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
}
