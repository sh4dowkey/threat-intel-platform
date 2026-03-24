import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";
import IOCLookup from "./pages/IOCLookup";
import AnalyzeFlow from "./pages/AnalyzeFlow";
import { healthCheck } from "./lib/api";

export default function App() {
  const [apiOnline, setApiOnline] = useState(false);

  useEffect(() => {
    const check = async () => {
      try {
        await healthCheck();
        setApiOnline(true);
      } catch {
        setApiOnline(false);
      }
    };
    check();
    const iv = setInterval(check, 30000);
    return () => clearInterval(iv);
  }, []);

  return (
    <BrowserRouter>
      <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
        <Sidebar apiOnline={apiOnline} />
        <main style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          <Routes>
            <Route path="/"           element={<Dashboard />} />
            <Route path="/alerts"     element={<Alerts />} />
            <Route path="/alerts/:id" element={<AlertDetail />} />
            <Route path="/ioc"        element={<IOCLookup />} />
            <Route path="/analyze"    element={<AnalyzeFlow />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
