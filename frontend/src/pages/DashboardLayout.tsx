import React, { useEffect, useMemo, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import "../styles/dashboardLayout.css";

type NetStatus = {
  status?: string;
  interface?: string;
  uptime?: string;
  ml_enabled?: boolean;
  active_attacks?: number;
  attack_status?: string;
  baseline_ready?: boolean;
  baseline_progress?: number;
};

const routeTitle: Record<string, { title: string; subtitle: string }> = {
  "network-traffic": {
    title: "Network Traffic",
    subtitle: "Real-time packet capture and traffic analysis",
  },
  analysis: {
    title: "Analysis",
    subtitle: "Deep insights and pattern analysis of network traffic",
  },
  attacks: {
    title: "Attacks Detected",
    subtitle: "Comprehensive log of all detected security threats",
  },
  notifications: {
    title: "Notifications",
    subtitle: "Real-time alerts and system messages",
  },
  settings: {
    title: "Settings",
    subtitle: "Configure IDS settings and preferences",
  },
};

export default function DashboardLayout() {
  const location = useLocation();
  const pathKey = useMemo(
    () =>
      location.pathname.replace(/^\//, "").split("/")[0] || "network-traffic",
    [location.pathname],
  );
  const meta = routeTitle[pathKey] || routeTitle["network-traffic"];

  const [netStatus, setNetStatus] = useState<NetStatus>({});

  useEffect(() => {
    let t: number | undefined;
    const run = async () => {
      try {
        const res = await fetch("/api/network-status");
        const data = await res.json();
        setNetStatus(data);
      } catch {
        // ignore
      }
    };
    run();
    t = window.setInterval(run, 5000);
    return () => {
      if (t) window.clearInterval(t);
    };
  }, []);

  const status = netStatus.status || "normal";
  const statusLabel =
    status === "under_attack"
      ? "Attack Detected"
      : status === "warning"
        ? "Warning Detected"
        : "System Active";
  const statusBg =
    status === "under_attack"
      ? "#ef4444"
      : status === "warning"
        ? "#f59e0b"
        : "#10b981";

  return (
    <div className="app-container">
      <aside className="sidebar">
        <div className="logo">
          <h2>
            <i className="fas fa-shield-alt" /> Hybrid IDS
          </h2>
          <p>Intrusion Detection System</p>
        </div>

        <nav className="nav-menu">
          <NavLink
            to="/network-traffic"
            className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
          >
            <i className="fas fa-network-wired" /> <span>Network Traffic</span>
          </NavLink>
          <NavLink
            to="/analysis"
            className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
          >
            <i className="fas fa-chart-line" /> <span>Analysis</span>
          </NavLink>
          <NavLink
            to="/attacks"
            className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
          >
            <i className="fas fa-exclamation-triangle" />{" "}
            <span>Attacks Detected</span>
          </NavLink>
          <NavLink
            to="/notifications"
            className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
          >
            <i className="fas fa-bell" /> <span>Notifications</span>
          </NavLink>
          <NavLink
            to="/settings"
            className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
          >
            <i className="fas fa-cog" /> <span>Settings</span>
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <p>© 2024 Hybrid IDS v1.0</p>
          <p>Real-time Network Security</p>
        </div>
      </aside>

      <div className="main-content">
        <header className="header">
          <div className="header-left">
            <h1>{meta.title}</h1>
          </div>

          <div className="header-right">
            <div className="status-indicator" style={{ background: statusBg }}>
              <div className="status-dot" />
              <span>{statusLabel}</span>
            </div>

            <div className="user-profile">
              <div className="user-avatar">AD</div>
              <div>
                <div style={{ fontWeight: 600, color: "#1e293b" }}>Admin</div>
                <div style={{ fontSize: "0.8rem", color: "#64748b" }}>
                  Security Analyst
                </div>
              </div>
            </div>

            <a href="/logout" className="btn-logout">
              <i className="fas fa-sign-out-alt" /> Logout
            </a>
          </div>
        </header>

        <main className="content">
          <div className="content-header" style={{ marginBottom: 30 }}>
            <h2
              style={{
                color: "#1e293b",
                fontSize: "2rem",
                fontWeight: 700,
                marginBottom: 10,
              }}
            >
              {meta.title}
            </h2>
            <p style={{ color: "#64748b", fontSize: "1.1rem" }}>
              {meta.subtitle}
            </p>
          </div>

          <Outlet />
        </main>
      </div>
    </div>
  );
}
