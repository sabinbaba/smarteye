import React, { useEffect, useMemo, useState } from "react";

type AnalysisResponse = {
  packet_rate?: number;
  attack_ratio?: number;
  top_sources?: Array<{ ip: string; count: number }>;
  top_destinations?: Array<{ ip: string; count: number }>;
  protocols?: Record<string, number>;
  avg_packet_size?: number;
  total_packets?: number;
};

type StatusResponse = {
  status?: string;
  active_attacks?: number;
};

function getIPTag(ip: string) {
  if (ip.startsWith("192.168.") || ip.startsWith("10.")) return "Internal";
  if (ip.startsWith("172.")) {
    const parts = ip.split(".");
    const second = Number(parts[1]);
    if (!Number.isNaN(second) && second >= 16 && second <= 31)
      return "Internal";
  }
  return "External";
}

export default function AnalysisPage() {
  const [analysis, setAnalysis] = useState<AnalysisResponse>({});
  const [status, setStatus] = useState<StatusResponse>({});

  const threat = useMemo(() => {
    const s = status?.status;
    const active = status?.active_attacks ?? 0;
    if (s === "danger") return { label: "Critical", color: "#ef4444" };
    if (s === "warning") return { label: "Medium", color: "#f59e0b" };
    if (active > 0) return { label: "Elevated", color: "#f59e0b" };
    return { label: "Low", color: "#10b981" };
  }, [status]);

  useEffect(() => {
    let t: number | undefined;

    const load = async () => {
      try {
        const [aRes, sRes] = await Promise.all([
          fetch("/api/analysis"),
          fetch("/api/network-status"),
        ]);
        const a = (await aRes.json()) as AnalysisResponse;
        const s = (await sRes.json()) as StatusResponse;
        setAnalysis(a);
        setStatus(s);
      } catch {
        // ignore
      }
    };

    load();
    t = window.setInterval(load, 5000);

    return () => {
      if (t) window.clearInterval(t);
    };
  }, []);

  const packetRate = Math.round(analysis.packet_rate || 0);
  const attackRatio = analysis.attack_ratio || 0;
  const securityScore = Math.max(0, 100 - attackRatio * 100);

  return (
    <div className="analysis-container">
      <div className="card-shell">
        <div className="section-header">
          <h3>
            <i className="fas fa-chart-line" /> Traffic Analysis
          </h3>
          <div style={{ color: threat.color, fontWeight: 700 }}>
            Threat Level: {threat.label}
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: 20,
          }}
        >
          <div>
            <div style={{ color: "#64748b", fontWeight: 600 }}>
              Traffic Rate
            </div>
            <div
              style={{ fontSize: "2rem", fontWeight: 800, color: "#1e293b" }}
            >
              {packetRate}
            </div>
            <div style={{ color: "#94a3b8" }}>packets/min</div>
          </div>

          <div>
            <div style={{ color: "#64748b", fontWeight: 600 }}>
              Security Score
            </div>
            <div
              style={{ fontSize: "2rem", fontWeight: 800, color: "#1e293b" }}
            >
              {Math.round(securityScore)}
            </div>
            <div style={{ color: "#94a3b8" }}>out of 100</div>
          </div>

          <div>
            <div style={{ color: "#64748b", fontWeight: 600 }}>Top Sources</div>
            <div
              style={{ fontSize: "2rem", fontWeight: 800, color: "#1e293b" }}
            >
              {analysis.top_sources?.length ?? 0}
            </div>
            <div style={{ color: "#94a3b8" }}>tracked</div>
          </div>

          <div>
            <div style={{ color: "#64748b", fontWeight: 600 }}>ML Insights</div>
            <div
              style={{ fontSize: "2rem", fontWeight: 800, color: "#1e293b" }}
            >
              {/* backend flag not yet wired */}
              --
            </div>
            <div style={{ color: "#94a3b8" }}>pending</div>
          </div>
        </div>

        <div style={{ marginTop: 25 }}>
          <div className="section-header" style={{ marginBottom: 15 }}>
            <h3 style={{ fontSize: "1.2rem" }}>
              <i className="fas fa-project-diagram" /> Top Sources /
              Destinations
            </h3>
          </div>

          <div
            style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}
          >
            <div>
              <div
                style={{ color: "#64748b", fontWeight: 700, marginBottom: 10 }}
              >
                Top Sources
              </div>
              <div
                style={{ display: "flex", flexDirection: "column", gap: 10 }}
              >
                {(analysis.top_sources || []).slice(0, 6).map((s, idx) => (
                  <div
                    key={`${s.ip}-${idx}`}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      padding: "10px 12px",
                      border: "1px solid #e2e8f0",
                      borderRadius: 10,
                      background: "#f8fafc",
                    }}
                  >
                    <div
                      style={{ display: "flex", gap: 10, alignItems: "center" }}
                    >
                      <span
                        className="mono"
                        style={{ fontWeight: 700, color: "#1e293b" }}
                      >
                        {idx + 1}.
                      </span>
                      <span
                        className="mono"
                        style={{ color: "#334155", fontWeight: 700 }}
                      >
                        {s.ip}
                      </span>
                      <span
                        style={{
                          fontSize: 12,
                          padding: "3px 10px",
                          borderRadius: 999,
                          background: "#e2e8f0",
                          color: "#475569",
                        }}
                      >
                        {getIPTag(s.ip)}
                      </span>
                    </div>
                    <div style={{ color: "#1e293b", fontWeight: 800 }}>
                      {s.count}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <div
                style={{ color: "#64748b", fontWeight: 700, marginBottom: 10 }}
              >
                Top Destinations
              </div>
              <div
                style={{ display: "flex", flexDirection: "column", gap: 10 }}
              >
                {(analysis.top_destinations || []).slice(0, 6).map((d, idx) => (
                  <div
                    key={`${d.ip}-${idx}`}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      padding: "10px 12px",
                      border: "1px solid #e2e8f0",
                      borderRadius: 10,
                      background: "#f8fafc",
                    }}
                  >
                    <div
                      style={{ display: "flex", gap: 10, alignItems: "center" }}
                    >
                      <span
                        className="mono"
                        style={{ fontWeight: 700, color: "#1e293b" }}
                      >
                        {idx + 1}.
                      </span>
                      <span
                        className="mono"
                        style={{ color: "#334155", fontWeight: 700 }}
                      >
                        {d.ip}
                      </span>
                      <span
                        style={{
                          fontSize: 12,
                          padding: "3px 10px",
                          borderRadius: 999,
                          background: "#e2e8f0",
                          color: "#475569",
                        }}
                      >
                        {getIPTag(d.ip)}
                      </span>
                    </div>
                    <div style={{ color: "#1e293b", fontWeight: 800 }}>
                      {d.count}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div style={{ marginTop: 25, color: "#94a3b8" }}>
          Charts + recommendations will be ported next to match{" "}
          <code>templates/analysis.html</code>.
        </div>
      </div>
    </div>
  );
}
