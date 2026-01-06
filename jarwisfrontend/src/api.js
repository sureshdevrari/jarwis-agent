import axios from "axios";

// --- API Endpoints ---
const BASE_URL = "https://jarwis-api.onrender.com/api";

export const loginUser = async (email, password) => {
  try {
    const response = await axios.post(`${BASE_URL}/login/`, {
      email,
      password,
    });
    return response.data;
  } catch (error) {
    throw new Error(
      error.response?.data?.message ||
        "Login failed. Please check your credentials."
    );
  }
};

// Register API
export const registerUser = async (name, company, email, password) => {
  try {
    const response = await axios.post(`${BASE_URL}/register/`, {
      username: name,
      company,
      email,
      password,
    });
    return response.data;
  } catch (error) {
    throw new Error(
      error.response?.data?.error || "Registration failed. Please try again."
    );
  }
};

export const submitContactForm = async (formData) => {
  try {
    const response = await axios.post(`${BASE_URL}/contact`, formData);
    return response.data;
  } catch (error) {
    throw new Error(error.response?.data?.message || "Failed to send message.");
  }
};
