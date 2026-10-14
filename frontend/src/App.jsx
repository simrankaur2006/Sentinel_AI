import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Ingest from "./pages/Ingest";
import Events from "./pages/Events";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";
import Incidents from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import System from "./pages/System";
import { Empty } from "./components/ui";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="ingest" element={<Ingest />} />
        <Route path="events" element={<Events />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="alerts/:id" element={<AlertDetail />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
        <Route path="reports" element={<Reports />} />
        <Route path="settings" element={<Settings />} />
        <Route path="system" element={<System />} />
        <Route path="*" element={<Empty title="Page not found">Use the navigation to continue.</Empty>} />
      </Route>
    </Routes>
  );
}
