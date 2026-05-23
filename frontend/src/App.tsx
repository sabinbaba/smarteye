import React from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import "./App.css";

import LoginPage from "./pages/LoginPage";
import DashboardLayout from "./pages/DashboardLayout";
import NetworkTrafficPage from "./pages/NetworkTrafficPage";
import AnalysisPage from "./pages/AnalysisPage";
import AttacksPage from "./pages/AttacksPage";
import NotificationsPage from "./pages/NotificationsPage";
import SettingsPage from "./pages/SettingsPage";

function RequireAuth({ children }: { children: React.ReactNode }) {
  // Flask session cookie is used. Frontend can't directly read it.
  // We optimistically show the layout; if backend redirects, user will be forced to login.
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/network-traffic" replace />} />
      <Route path="/login" element={<LoginPage />} />

      <Route
        path="/"
        element={
          <RequireAuth>
            <DashboardLayout />
          </RequireAuth>
        }
      >
        <Route path="network-traffic" element={<NetworkTrafficPage />} />
        <Route path="analysis" element={<AnalysisPage />} />
        <Route path="attacks" element={<AttacksPage />} />
        <Route path="notifications" element={<NotificationsPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>

      {/* fallback */}
      <Route path="*" element={<Navigate to="/network-traffic" replace />} />
    </Routes>
  );
}
