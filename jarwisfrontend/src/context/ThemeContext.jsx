import { createContext, useContext, useState, useEffect } from "react";

const ThemeContext = createContext();

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
};

export const ThemeProvider = ({ children }) => {
  const [isDarkMode, setIsDarkMode] = useState(() => {
    try {
      const savedTheme = localStorage.getItem("jarwis-theme");
      return savedTheme ? savedTheme === "dark" : true;
    } catch (error) {
      return true; // Default to dark mode if localStorage fails
    }
  });

  // Save theme to localStorage when changed
  useEffect(() => {
    try {
      localStorage.setItem("jarwis-theme", isDarkMode ? "dark" : "light");
    } catch (error) {
      console.log("localStorage not available, theme won't persist");
    }
  }, [isDarkMode]);

  const toggleTheme = () => {
    setIsDarkMode(!isDarkMode);
  };

  const value = {
    isDarkMode,
    toggleTheme,
  };

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
};
