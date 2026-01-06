// src/App.jsx
// Main application with FastAPI + PostgreSQL authentication

import { RouterProvider } from "react-router-dom";
import router from "./routes/router";
import { AuthProvider } from "./context/AuthContext";
import { ThemeProvider } from "./context/ThemeContext";
import { UserManagementProvider } from "./context/UserManagementContext";
import { ContactFormProvider } from "./context/ContactFormContext";
import { SubscriptionProvider } from "./context/SubscriptionContext";

function App() {
  return (
    <AuthProvider>
      <SubscriptionProvider>
        <ThemeProvider>
          <UserManagementProvider>
            <ContactFormProvider>
              <RouterProvider router={router} />
            </ContactFormProvider>
          </UserManagementProvider>
        </ThemeProvider>
      </SubscriptionProvider>
    </AuthProvider>
  );
}

export default App;
