import { BrowserRouter } from "react-router-dom";
import { ThemeProvider } from "./components/shared/ThemeProvider";
import AppRoutes from "@/routes/AppRoutes";
import { Toaster } from "sonner";

function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
      <Toaster />
    </ThemeProvider>
  );
}

export default App;
