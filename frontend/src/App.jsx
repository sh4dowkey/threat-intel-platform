import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";
import IOCLookup from "./pages/IOCLookup";
import AnalyzeFlow from "./pages/AnalyzeFlow";
import DataExplorer from "./pages/DataExplorer";
import { ToastContainer } from "./components/ui";
import { healthCheck, listAlerts } from "./lib/api";

export default function App() {
  const [apiOnline, setApiOnline] = useState(false);
  const [openAlertCount, setOpenAlertCount] = useState(0);

  useEffect(() => {
    const check = async () => {
      try {
        await healthCheck();
        setApiOnline(true);
        // Get open alert count for sidebar badge
        const alerts = await listAlerts({ status: "open", limit: 200 });
        setOpenAlertCount(alerts.length);
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
        <Sidebar apiOnline={apiOnline} alertCount={openAlertCount} />
        <main style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column", position: "relative" }}>
          <Routes>
            <Route path="/"            element={<Dashboard />} />
            <Route path="/alerts"      element={<Alerts />} />
            <Route path="/alerts/:id"  element={<AlertDetail />} />
            <Route path="/ioc"         element={<IOCLookup />} />
            <Route path="/analyze"     element={<AnalyzeFlow />} />
            <Route path="/explorer"    element={<DataExplorer />} />
          </Routes>
        </main>
      </div>
      <ToastContainer />
    </BrowserRouter>
  );
}
