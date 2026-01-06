import React, { useState, useEffect } from "react";

const AnimatedTypingHeading = () => {
  const [displayText, setDisplayText] = useState("");
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isComplete, setIsComplete] = useState(false);

  const fullText = "Meet Jarwis AGI";

  useEffect(() => {
    if (currentIndex < fullText.length) {
      const timer = setTimeout(() => {
        setDisplayText(fullText.substring(0, currentIndex + 1));
        setCurrentIndex(currentIndex + 1);
      }, 150);

      return () => clearTimeout(timer);
    } else if (currentIndex === fullText.length && !isComplete) {
      // Animation complete, remove cursor after a brief pause
      setTimeout(() => setIsComplete(true), 500);
    }
  }, [currentIndex, fullText, isComplete]);

  const renderText = () => {
    const words = displayText.split(" ");

    return words.map((word, wordIndex) => {
      if (word === "Meet") {
        return (
          <span key={wordIndex} className="text-white">
            {word}
            {wordIndex < words.length - 1 ? " " : ""}
          </span>
        );
      } else if (word === "Jarwis") {
        return (
          <span
            key={wordIndex}
            className="bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent"
          >
            {word}
            {wordIndex < words.length - 1 ? " " : ""}
          </span>
        );
      } else if (word === "AI") {
        return (
          <span key={wordIndex} className="text-white">
            {word}
            {wordIndex < words.length - 1 ? " " : ""}
          </span>
        );
      }
      return (
        <span key={wordIndex} className="text-white">
          {word}
          {wordIndex < words.length - 1 ? " " : ""}
        </span>
      );
    });
  };

  return (
    <div className="">
      <div className="text-center">
        <h1 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl xl:text-7xl font-bold leading-tight">
          {renderText()}
          {!isComplete && <span className="animate-pulse text-white">|</span>}
        </h1>
      </div>
    </div>
  );
};

export default AnimatedTypingHeading;
