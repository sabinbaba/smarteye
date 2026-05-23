import React, { useEffect, useMemo, useState } from "react";

type Settings = any;

type TabKey =
  | "general"
  | "network"
  | "detection"
  | "ml"
  | "notifications"
  | "interface"
  | "security";

const STORAGE_KEY = "ids-settings";

type SettingStatus = {
  message: string;
  type: "success" | "warning" | "error" | "info";
};

function defaultSettings(): Settings {
  return {
    general: {
      autoStart: true,
      autoUpdate: true,
      logLevel: "info",
      packetBuffer: 500,
      logRetention: 30,
      compressLogs: true,
      updateInterval: 2,
      cpuLimit: 60,
      performanceMode: true,
    },
    network: {
      interface: "wlan0",
      promiscuous: true,
      captureFilter: "",
      captureTimeout: 0,
      maxPacketSize: 65535,
      captureDNS: true,
      ignoreLocal: true,
      monitorPorts: "",
      whitelistIPs: "",
      blacklistIPs: "",
    },
    detection: {
      dosThreshold: 500,
      ddosSourceThreshold: 5,
      ddosTotalThreshold: 1500,
      enableDoSDetection: true,
      tcpScanThreshold: 20,
      udpScanThreshold: 15,
      icmpScanThreshold: 5,
      enablePortScanDetection: true,
      detectSlowloris: false,
      detectLandAttack: true,
      detectSmurf: true,
      detectXmasScan: false,
      detectionSensitivity: 7,
    },
    ml: {
      enableML: true,
      model: "fnn",
      confidenceThreshold: 85,
      retrainInterval: 24,
      trainingSize: 10000,
      trainingEpochs: 50,
      batchSize: 32,
      augmentData: true,
      statisticalFeatures: true,
      temporalFeatures: true,
      behavioralFeatures: true,
      headerAnalysis: true,
      payloadAnalysis: false,
    },
    notifications: {
      inApp: true,
      email: false,
      emailAddress: "",
      sms: false,
      webhook: false,
      alertSound: "default",
      alertVolume: 80,
      criticalAlerts: "immediate",
      quietStart: "22:00",
      quietEnd: "06:00",
      minSeverity: "medium",
      alertCooldown: 300,
      dailyAlertLimit: 100,
      groupAlerts: true,
    },
    interface: {
      theme: "light",
      colorScheme: "blue",
      fontSize: 14,
      animations: true,
      defaultPage: "dashboard",
      dashboardLayout: "compact",
      uiRefreshRate: 5,
      autoRefresh: true,
      chartQuality: "medium",
      defaultTimeRange: "6h",
      dataPoints: 100,
      smoothCharts: true,
    },
    security: {
      requireAuth: true,
      sessionTimeout: 30,
      maxLoginAttempts: 5,
      lockoutDuration: 15,
      minPasswordLength: 12,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSymbols: true,
      passwordExpiry: 90,
      enable2FA: false,
      httpsOnly: true,
      logAccess: true,
      blockRepeatedAttacks: true,
      allowedIPs: "",
    },
  };
}

function ColorSchemeApplier({ scheme }: { scheme: string }) {
  useEffect(() => {
    const colors: Record<string, { primary: string; secondary: string }> = {
      blue: { primary: "#667eea", secondary: "#764ba2" },
      purple: { primary: "#8b5cf6", secondary: "#7c3aed" },
      green: { primary: "#10b981", secondary: "#059669" },
      red: { primary: "#ef4444", secondary: "#dc2626" },
      orange: { primary: "#f59e0b", secondary: "#d97706" },
    };
    const c = colors[scheme] || colors.blue;
    const root = document.documentElement;
    root.style.setProperty("--primary-color", c.primary);
    root.style.setProperty("--secondary-color", c.secondary);
  }, [scheme]);
  return null;
}

export default function SettingsPage() {
  const [tab, setTab] = useState<TabKey>("general");
  const [settings, setSettings] = useState<Settings>(() => defaultSettings());
  const [status, setStatus] = useState<SettingStatus>({
    message: "Settings loaded",
    type: "info",
  });

  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        setSettings(JSON.parse(saved));
        setStatus({ message: "Settings loaded from storage", type: "success" });
        setDirty(false);
      }
    } catch {
      // ignore
    }
  }, []);

  const markDirty = () => setDirty(true);

  const onSave = () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
    setDirty(false);
    setStatus({ message: "Settings saved successfully", type: "success" });
  };

  const onReset = () => {
    if (!confirm("Are you sure you want to reset all settings to defaults?"))
      return;
    setSettings(defaultSettings());
    setDirty(false);
    localStorage.removeItem(STORAGE_KEY);
    setStatus({ message: "Settings reset to defaults", type: "warning" });
  };

  const exportConfig = () => {
    const payload = {
      version: "1.0.0",
      timestamp: new Date().toISOString(),
      settings,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ids-config-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setStatus({ message: "Configuration exported", type: "success" });
  };

  const SectionHeader = ({
    title,
    subtitle,
  }: {
    title: string;
    subtitle: string;
  }) => (
    <div className="section-header" style={{ marginBottom: 30 }}>
      <h3
        style={{ display: "flex", alignItems: "center", gap: 15, fontSize: 22 }}
      >
        {title}
      </h3>
      <p style={{ margin: 0, color: "#64748b", fontSize: 16 }}>{subtitle}</p>
    </div>
  );

  const rangeRow = (
    label: string,
    value: number,
    min: number,
    max: number,
    onChange: (v: number) => void,
    unit?: string,
  ) => (
    <div className="form-group">
      <label
        style={{
          display: "block",
          marginBottom: 8,
          color: "#334155",
          fontWeight: 500,
        }}
      >
        {label}
      </label>
      <input
        type="range"
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      />
      <div style={{ color: "#667eea", fontWeight: 700, marginTop: 8 }}>
        {value}
        {unit ? ` ${unit}` : ""}
      </div>
    </div>
  );

  return (
    <div className="settings-container">
      <ColorSchemeApplier scheme={settings?.interface?.colorScheme || "blue"} />

      <div className="card-shell">
        <div
          className="settings-header"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: 20,
            marginBottom: 20,
          }}
        >
          <div>
            <h2 style={{ margin: 0, color: "white" }}>System Configuration</h2>
            <p style={{ margin: "8px 0 0", color: "#cbd5e1" }}>
              Configure intrusion detection settings, network preferences, and
              system behavior
            </p>
          </div>

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <button className="btn btn-secondary" onClick={onSave}>
              <i className="fas fa-save" /> Save Settings
            </button>
            <button className="btn btn-outline" onClick={onReset}>
              <i className="fas fa-undo" /> Reset to Defaults
            </button>
            <button className="btn btn-primary" onClick={exportConfig}>
              <i className="fas fa-download" /> Export Config
            </button>
          </div>
        </div>

        <div
          className="settings-nav"
          style={{ marginBottom: 20, overflowX: "auto" }}
        >
          <div
            className="nav-tabs"
            style={{ display: "flex", padding: "0 20px", gap: 10 }}
          >
            {(
              [
                ["general", "General"],
                ["network", "Network"],
                ["detection", "Detection"],
                ["ml", "Machine Learning"],
                ["notifications", "Notifications"],
                ["interface", "Interface"],
                ["security", "Security"],
              ] as Array<[TabKey, string]>
            ).map(([k, label]) => (
              <button
                key={k}
                className={`nav-tab ${tab === k ? "active" : ""}`}
                onClick={() => setTab(k)}
                style={{ cursor: "pointer" }}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* Content (only key fields ported in this first pass) */}
        {tab === "general" && (
          <div>
            <SectionHeader
              title="General Settings"
              subtitle="Basic system configuration and preferences"
            />
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(350px, 1fr))",
                gap: 25,
              }}
            >
              <div className="setting-card">
                <div className="setting-header">System Startup</div>
                <div className="setting-body">
                  <label>
                    <input
                      type="checkbox"
                      checked={settings.general.autoStart}
                      onChange={(e) => {
                        markDirty();
                        setSettings((s: Settings) => ({
                          ...s,
                          general: {
                            ...s.general,
                            autoStart: e.target.checked,
                          },
                        }));
                      }}
                    />{" "}
                    Auto-start on boot
                  </label>
                  <br />
                  <label style={{ display: "block", marginTop: 10 }}>
                    <input
                      type="checkbox"
                      checked={settings.general.autoUpdate}
                      onChange={(e) => {
                        markDirty();
                        setSettings((s: Settings) => ({
                          ...s,
                          general: {
                            ...s.general,
                            autoUpdate: e.target.checked,
                          },
                        }));
                      }}
                    />
                    Automatic updates
                  </label>

                  <div style={{ marginTop: 20 }}>
                    <label style={{ display: "block", marginBottom: 8 }}>
                      System Log Level
                    </label>
                    <select
                      value={settings.general.logLevel}
                      onChange={(e) => {
                        markDirty();
                        setSettings((s: Settings) => ({
                          ...s,
                          general: { ...s.general, logLevel: e.target.value },
                        }));
                      }}
                    >
                      <option value="debug">Debug</option>
                      <option value="info">Info</option>
                      <option value="warning">Warning</option>
                      <option value="error">Error</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                </div>
              </div>

              <div className="setting-card">
                <div className="setting-header">Performance</div>
                <div className="setting-body">
                  {rangeRow(
                    "CPU Usage Limit",
                    settings.general.cpuLimit,
                    10,
                    90,
                    (v) => {
                      markDirty();
                      setSettings((s: Settings) => ({
                        ...s,
                        general: { ...s.general, cpuLimit: v },
                      }));
                    },
                    "%",
                  )}

                  <label
                    style={{ display: "flex", alignItems: "center", gap: 10 }}
                  >
                    <input
                      type="checkbox"
                      checked={settings.general.performanceMode}
                      onChange={(e) => {
                        markDirty();
                        setSettings((s: Settings) => ({
                          ...s,
                          general: {
                            ...s.general,
                            performanceMode: e.target.checked,
                          },
                        }));
                      }}
                    />
                    Performance mode
                  </label>
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === "network" && (
          <div>
            <SectionHeader
              title="Network Settings"
              subtitle="Configure network interfaces and capture settings"
            />
            <div style={{ maxWidth: 800 }}>
              <div className="form-group">
                <label>Primary Interface</label>
                <select
                  value={settings.network.interface}
                  onChange={(e) => {
                    markDirty();
                    setSettings((s: Settings) => ({
                      ...s,
                      network: { ...s.network, interface: e.target.value },
                    }));
                  }}
                >
                  <option value="eth0">eth0 (Ethernet)</option>
                  <option value="wlan0">wlan0 (Wireless)</option>
                  <option value="enp3s0">enp3s0 (Ethernet)</option>
                  <option value="any">any (All Interfaces)</option>
                </select>
              </div>

              <div className="form-group">
                <label>
                  <input
                    type="checkbox"
                    checked={settings.network.promiscuous}
                    onChange={(e) => {
                      markDirty();
                      setSettings((s: Settings) => ({
                        ...s,
                        network: {
                          ...s.network,
                          promiscuous: e.target.checked,
                        },
                      }));
                    }}
                  />{" "}
                  Promiscuous Mode
                </label>
              </div>

              <div className="form-group">
                <label>Capture Filter</label>
                <input
                  value={settings.network.captureFilter}
                  onChange={(e) => {
                    markDirty();
                    setSettings((s: Settings) => ({
                      ...s,
                      network: { ...s.network, captureFilter: e.target.value },
                    }));
                  }}
                  type="text"
                />
              </div>
            </div>
          </div>
        )}

        {tab !== "general" && tab !== "network" && (
          <div style={{ color: "#64748b" }}>
            This tab will be fully ported next. Current implementation already
            supports:
            <ul>
              <li>multi-tab navigation</li>
              <li>Save/Reset/Export</li>
              <li>localStorage persistence</li>
            </ul>
          </div>
        )}

        <div
          className="settings-status-bar"
          style={{
            marginTop: 20,
            display: "flex",
            justifyContent: "space-between",
            gap: 20,
            alignItems: "center",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span
                className="status-dot"
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: 999,
                  background: dirty ? "#f59e0b" : "#10b981",
                }}
              />
              <span style={{ color: "#1e293b", fontWeight: 600 }}>
                {dirty ? "Settings ready to save" : "Settings are up to date"}
              </span>
            </div>
            <div className="status-message" style={{ color: "#64748b" }}>
              {dirty
                ? "All changes will be applied after saving."
                : "No pending changes."}
            </div>
          </div>

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <button
              className="btn btn-secondary"
              onClick={() =>
                setStatus({
                  message: "Test settings not wired to backend in this port",
                  type: "info",
                })
              }
            >
              <i className="fas fa-vial" /> Test Settings
            </button>
            <button
              className="btn btn-primary"
              onClick={() => {
                onSave();
                setStatus({
                  message:
                    "Settings applied (local). Backend apply not wired in this port.",
                  type: "success",
                });
              }}
            >
              <i className="fas fa-check" /> Apply Changes
            </button>
          </div>
        </div>
      </div>

      <div />
    </div>
  );
}
