import { RouterProvider } from "react-router-dom";
import router from "./routes/router";
import { AuthProvider } from "./context/AuthContext";
import { ThemeProvider } from "./context/ThemeContext";
import { UserManagementProvider } from "./context/UserManagementContext";
import { ContactFormProvider } from "./context/ContactFormContext";

function App() {
  return (
    <AuthProvider>
      <ThemeProvider>
        <UserManagementProvider>
          <ContactFormProvider>
            <RouterProvider router={router} />
          </ContactFormProvider>
        </UserManagementProvider>
      </ThemeProvider>
    </AuthProvider>
  );
}

export default App;
