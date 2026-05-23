import React, { useEffect, useMemo, useState } from "react";

type PacketRow = {
  timestamp?: string;
  src?: string;
  dst?: string;
  protocol?: string;
  dport?: number | string;
  length?: number;
  status?: string;
  flags?: string;
};

type TrafficPayload = {
  packets: PacketRow[];
  stats: any;
  total_captured: number;
};

type NetStatus = { status?: string; interface?: string; uptime?: string };

const packetsPerPage = 15;

export default function NetworkTrafficPage() {
  const [traffic, setTraffic] = useState<PacketRow[]>([]);
  const [stats, setStats] = useState<any>({});
  const [lastUpdated, setLastUpdated] = useState("--:--:--");
  const [totalCaptured, setTotalCaptured] = useState(0);
  const [networkStatus, setNetworkStatus] = useState<NetStatus>({});

  const [currentPage, setCurrentPage] = useState(1);

  const [autoRefresh, setAutoRefresh] = useState(true);

  const pageCount = useMemo(
    () => Math.max(1, Math.ceil(traffic.length / packetsPerPage)),
    [traffic.length],
  );

  useEffect(() => {
    let t: number | undefined;

    const load = async () => {
      try {
        const res = await fetch("/api/real-time-traffic");
        const data = (await res.json()) as TrafficPayload;
        setTraffic(data.packets || []);
        setStats(data.stats || {});
        setLastUpdated(data ? new Date().toLocaleTimeString() : "--:--:--");
        setTotalCaptured(data.total_captured || 0);
      } catch {
        // ignore
      }
    };

    const loadStatus = async () => {
      try {
        const res = await fetch("/api/network-status");
        setNetworkStatus(await res.json());
      } catch {
        // ignore
      }
    };

    load();
    loadStatus();

    if (autoRefresh) {
      t = window.setInterval(() => {
        load();
        loadStatus();
      }, 1000);
    }

    return () => {
      if (t) window.clearInterval(t);
    };
  }, [autoRefresh]);

  const start = (currentPage - 1) * packetsPerPage;
  const end = start + packetsPerPage;
  const pageData = traffic.slice(start, end);

  return (
    <div className="nt-wrapper">
      <style>{ntCss}</style>

      <div className="nt-stats-grid">
        <div className="nt-stat-card">
          <div className="nt-stat-icon nt-ic-1">
            <i className="fas fa-broadcast-tower" />
          </div>
          <div>
            <div className="nt-stat-value" id="total-packets">
              {stats?.total ?? 0}
            </div>
            <div className="nt-stat-label">Total Packets</div>
          </div>
        </div>

        <div className="nt-stat-card">
          <div className="nt-stat-icon nt-ic-2">
            <i className="fas fa-shield-check" />
          </div>
          <div>
            <div className="nt-stat-value">{stats?.safe ?? 0}</div>
            <div className="nt-stat-label">Safe Packets</div>
          </div>
        </div>

        <div className="nt-stat-card">
          <div className="nt-stat-icon nt-ic-3">
            <i className="fas fa-exclamation-circle" />
          </div>
          <div>
            <div className="nt-stat-value">{stats?.suspicious ?? 0}</div>
            <div className="nt-stat-label">Suspicious</div>
          </div>
        </div>

        <div className="nt-stat-card">
          <div className="nt-stat-icon nt-ic-4">
            <i className="fas fa-skull-crossbones" />
          </div>
          <div>
            <div className="nt-stat-value">{stats?.attack ?? 0}</div>
            <div className="nt-stat-label">Attack Packets</div>
          </div>
        </div>
      </div>

      <div className="nt-table-card">
        <div className="nt-section-head">
          <h3>
            <i className="fas fa-table" /> Live Traffic
          </h3>

          <div className="nt-controls">
            <label className="nt-switch">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
              />
              <span className="nt-slider" />
            </label>
            <span style={{ color: "#64748b" }}>Auto-refresh</span>
          </div>
        </div>

        <div className="nt-table-wrap">
          <table className="nt-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Port</th>
                <th>Length</th>
                <th>Status</th>
                <th>Flags</th>
              </tr>
            </thead>
            <tbody>
              {pageData.length === 0 ? (
                <tr>
                  <td
                    colSpan={8}
                    style={{
                      textAlign: "center",
                      color: "#94a3b8",
                      padding: 40,
                    }}
                  >
                    <i className="fas fa-eye-slash" /> No packets captured
                  </td>
                </tr>
              ) : (
                pageData.map((p, idx) => {
                  const status = p.status || "normal";
                  const rowClass =
                    status === "attack"
                      ? "attack"
                      : status === "suspicious"
                        ? "suspicious"
                        : "";
                  const statusText =
                    status === "attack"
                      ? "Attack"
                      : status === "suspicious"
                        ? "Suspicious"
                        : "Normal";
                  const statusBg =
                    status === "attack"
                      ? "#fee2e2"
                      : status === "suspicious"
                        ? "#fef3c7"
                        : "#d1fae5";
                  const statusColor =
                    status === "attack"
                      ? "#991b1b"
                      : status === "suspicious"
                        ? "#92400e"
                        : "#065f46";

                  const flags = (p.flags || "").split(" ").filter(Boolean);
                  return (
                    <tr key={idx} className={rowClass}>
                      <td>{p.timestamp || "--:--:--"}</td>
                      <td>
                        <span className="mono">{p.src || "N/A"}</span>
                      </td>
                      <td>
                        <span className="mono">{p.dst || "N/A"}</span>
                      </td>
                      <td>
                        <span className="proto-pill">
                          {p.protocol || "N/A"}
                        </span>
                      </td>
                      <td>{p.dport ?? "N/A"}</td>
                      <td>{p.length ?? 0} bytes</td>
                      <td>
                        <span
                          className="status-pill"
                          style={{ background: statusBg, color: statusColor }}
                        >
                          {statusText}
                        </span>
                      </td>
                      <td>
                        {flags.length ? (
                          <div
                            style={{
                              display: "flex",
                              flexWrap: "wrap",
                              gap: 6,
                            }}
                          >
                            {flags.map((f) => (
                              <span key={f} className="flag-pill">
                                {f}
                              </span>
                            ))}
                          </div>
                        ) : (
                          "-"
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        <div className="nt-table-footer">
          <div style={{ color: "#64748b" }}>
            Showing <b>{traffic.length ? start + 1 : 0}</b>-
            <b>{Math.min(end, traffic.length)}</b> of <b>{traffic.length}</b>{" "}
            packets
          </div>

          <div className="nt-pagination">
            <button
              className="nt-page-btn"
              disabled={currentPage === 1}
              onClick={() => setCurrentPage((p) => p - 1)}
            >
              <i className="fas fa-chevron-left" /> Previous
            </button>
            <span className="nt-page-info">
              Page <b>{currentPage}</b> / {pageCount}
            </span>
            <button
              className="nt-page-btn"
              disabled={currentPage >= pageCount}
              onClick={() => setCurrentPage((p) => p + 1)}
            >
              Next <i className="fas fa-chevron-right" />
            </button>
          </div>
        </div>
      </div>

      {/* Placeholder charts area; existing backend already provides stats but charts are implemented in old templates.
          This keeps the task focused on React+custom CSS conversion. */}
      <div className="nt-charts-grid">
        <div className="nt-chart-card">
          <h4>
            <i className="fas fa-chart-pie" /> Protocol Distribution
          </h4>
          <div style={{ color: "#94a3b8" }}>
            Chart rendering not included in this conversion.
          </div>
        </div>
        <div className="nt-chart-card">
          <h4>
            <i className="fas fa-project-diagram" /> Traffic Flow
          </h4>
          <div style={{ color: "#94a3b8" }}>
            Chart rendering not included in this conversion.
          </div>
        </div>
      </div>

      <div style={{ marginTop: 20, color: "#64748b" }}>
        Last updated: <b>{lastUpdated}</b> | Interface:{" "}
        <b>{networkStatus.interface || "Unknown"}</b>| Total captured:{" "}
        <b>{totalCaptured}</b>
      </div>
    </div>
  );
}

const ntCss = `
.nt-wrapper{display:flex; flex-direction:column; gap:25px;}
.nt-stats-grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:20px;}
.nt-stat-card{background:white; border-radius:15px; padding:25px; display:flex; align-items:center; gap:20px; box-shadow:0 4px 20px rgba(0,0,0,0.08); border:1px solid #e2e8f0;}
.nt-stat-icon{width:70px; height:70px; border-radius:15px; display:flex; align-items:center; justify-content:center; color:white; font-size:28px;}
.nt-ic-1{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);} 
.nt-ic-2{background:linear-gradient(135deg,#10b981 0%,#059669 100%);} 
.nt-ic-3{background:linear-gradient(135deg,#f59e0b 0%,#d97706 100%);} 
.nt-ic-4{background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%);} 
.nt-stat-value{font-size:2.5rem; font-weight:800; color:#1e293b; line-height:1;}
.nt-stat-label{font-size:1rem; color:#64748b; margin-top:5px;}

.nt-table-card{background:white; border-radius:15px; padding:25px; box-shadow:0 4px 20px rgba(0,0,0,0.08); border:1px solid #e2e8f0;}
.nt-section-head{display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; padding-bottom:15px; border-bottom:2px solid #f1f5f9;}
.nt-section-head h3{color:#1e293b; font-size:1.4rem; display:flex; align-items:center; gap:10px; margin:0;}

.nt-controls{display:flex; align-items:center; gap:10px;}
.nt-switch{position:relative; display:inline-block; width:50px; height:24px;}
.nt-switch input{opacity:0; width:0; height:0;}
.nt-slider{position:absolute; cursor:pointer; top:0; left:0; right:0; bottom:0; background:#cbd5e1; transition:.4s; border-radius:24px;}
.nt-slider:before{position:absolute; content:''; height:16px; width:16px; left:4px; bottom:4px; background:white; transition:.4s; border-radius:50%;}
.nt-switch input:checked + .nt-slider{background:#10b981;}
.nt-switch input:checked + .nt-slider:before{transform:translateX(26px);} 

.nt-table-wrap{overflow-x:auto; margin-top:10px; border-radius:10px; border:1px solid #e2e8f0; max-height:500px; overflow-y:auto;}
.nt-table{width:100%; border-collapse:collapse; font-size:0.9rem;}
.nt-table th{background:#f8fafc; padding:15px; text-align:left; color:#475569; font-weight:600; border-bottom:2px solid #e2e8f0; position:sticky; top:0; z-index:10;}
.nt-table td{padding:12px 15px; border-bottom:1px solid #f1f5f9; color:#334155;}
.nt-table tr.attack{background:#fef2f2; animation: highlightAttack 2s;}
.nt-table tr.suspicious{background:#fffbeb;}
@keyframes highlightAttack{0%{background:#fee2e2;}100%{background:#fef2f2;}}

.mono{font-family:monospace;}
.proto-pill{background:#e2e8f0; padding:4px 10px; border-radius:12px; font-weight:500;}
.status-pill{padding:4px 10px; border-radius:12px; font-size:0.85rem; font-weight:600;}
.flag-pill{background:#e2e8f0; padding:2px 6px; border-radius:4px; font-size:0.8rem;}

.nt-table-footer{display:flex; justify-content:space-between; align-items:center; margin-top:20px; padding-top:15px; border-top:2px solid #f1f5f9;}
.nt-pagination{display:flex; align-items:center; gap:15px;}
.nt-page-btn{background:#f1f5f9; color:#475569; padding:8px 14px; border:none; border-radius:8px; cursor:pointer; display:flex; align-items:center; gap:8px;}
.nt-page-btn:hover:not(:disabled){background:#e2e8f0;}
.nt-page-btn:disabled{opacity:0.5; cursor:not-allowed;}
.nt-page-info{color:#64748b;}

.nt-charts-grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(400px,1fr)); gap:20px;}
.nt-chart-card{background:white; border-radius:12px; padding:20px; box-shadow:0 2px 10px rgba(0,0,0,0.08); border:1px solid #e2e8f0;}
.nt-chart-card h4{margin:0 0 10px; color:#1e293b; display:flex; align-items:center; gap:10px; font-size:1.1rem;}
`;
