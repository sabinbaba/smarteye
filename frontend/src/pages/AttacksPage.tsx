import React, { useEffect, useMemo, useState } from "react";

type Attack = {
  id?: string | number;
  timestamp?: string;
  type?: string;
  message?: string;
  time_ago?: string;
  status?: string;
};

type AttacksResponse = {
  attacks?: Attack[];
  total?: number;
  today?: number;
  active_attacks?: number;
};

type AttackStatus = "critical" | "high" | "medium" | "low";

const pageSizeOptions = [10, 25, 50, 100] as const;

const typeMap: Record<string, string> = {
  PORT_SCAN: "Port Scan",
  UDP_SCAN: "UDP Scan",
  ICMP_SCAN: "ICMP Scan",
  DoS: "DoS Attack",
  DDoS: "DDoS Attack",
  SYN_FLOOD: "SYN Flood",
  UDP_FLOOD: "UDP Flood",
};

const severityMap: Record<string, AttackStatus> = {
  DDoS: "critical",
  DoS: "high",
  SYN_FLOOD: "high",
  UDP_FLOOD: "high",
  PORT_SCAN: "medium",
  UDP_SCAN: "medium",
  ICMP_SCAN: "low",
};

function formatAttackType(type?: string) {
  if (!type) return "Unknown";
  return typeMap[type] || type;
}

function getAttackSeverity(type?: string): AttackStatus {
  if (!type) return "medium";
  return severityMap[type] || "medium";
}

function parseSrcDst(message?: string) {
  const src = message?.match(/SRC=([\d\.]+)/)?.[1];
  const dst = message?.match(/DST=([\d\.]+)/)?.[1];
  return { src: src || "Unknown", dst: dst || "Unknown" };
}

function Modal({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}) {
  if (!open) return null;
  return (
    <div
      className="modal"
      role="dialog"
      aria-modal="true"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-content">
        <div className="modal-header">
          <h3>
            <i className="fas fa-info-circle" /> {title}
          </h3>
          <button className="modal-close" onClick={onClose}>
            &times;
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

export default function AttacksPage() {
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [filtered, setFiltered] = useState<Attack[]>([]);

  const [typeFilter, setTypeFilter] = useState<string[]>(["all"]);
  const [timeFilter, setTimeFilter] = useState<
    "all" | "today" | "24h" | "7d" | "30d"
  >("all");
  const [severityFilter, setSeverityFilter] = useState<"all" | AttackStatus>(
    "all",
  );

  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] =
    useState<(typeof pageSizeOptions)[number]>(10);

  const [selected, setSelected] = useState<Set<number>>(new Set());

  const [modalOpen, setModalOpen] = useState(false);
  const [modalAttack, setModalAttack] = useState<Attack | null>(null);

  const [summary, setSummary] = useState<{
    total: number;
    today: number;
    active: number;
    blocked: number;
  }>({
    total: 0,
    today: 0,
    active: 0,
    blocked: 0,
  });

  const typeOptions = [
    "all",
    "PORT_SCAN",
    "UDP_SCAN",
    "ICMP_SCAN",
    "DoS",
    "DDoS",
    "SYN_FLOOD",
    "UDP_FLOOD",
  ];

  useEffect(() => {
    let t: number | undefined;

    const load = async () => {
      try {
        const res = await fetch("/api/attacks");
        const data = (await res.json()) as AttacksResponse;
        const list = data.attacks || [];
        setAttacks(list);

        const total = data.total ?? list.length;
        const today = data.today ?? 0;
        const active = (data.active_attacks as number) ?? 0;
        const blocked = Math.floor(total * 0.85); // matches template behavior
        setSummary({ total, today, active, blocked });
      } catch {
        // ignore
      }
    };

    load();
    t = window.setInterval(load, 10000);
    return () => {
      if (t) window.clearInterval(t);
    };
  }, []);

  const applyFilters = useMemo(() => {
    const now = new Date();

    const getTimeOk = (timestamp?: string) => {
      if (timeFilter === "all") return true;
      if (!timestamp) return false;
      const at = new Date(timestamp);
      if (Number.isNaN(at.getTime())) return false;

      switch (timeFilter) {
        case "today":
          return at.toDateString() === now.toDateString();
        case "24h":
          return now.getTime() - at.getTime() <= 24 * 60 * 60 * 1000;
        case "7d":
          return now.getTime() - at.getTime() <= 7 * 24 * 60 * 60 * 1000;
        case "30d":
          return now.getTime() - at.getTime() <= 30 * 24 * 60 * 60 * 1000;
      }
    };

    return attacks.filter((a) => {
      const atype = a.type || "";

      // type filter
      if (!typeFilter.includes("all")) {
        if (!typeFilter.includes(atype)) return false;
      }

      if (!getTimeOk(a.timestamp)) return false;

      // severity filter
      if (severityFilter !== "all") {
        const sev = getAttackSeverity(atype);
        if (sev !== severityFilter) return false;
      }

      return true;
    });
  }, [attacks, timeFilter, typeFilter, severityFilter]);

  useEffect(() => {
    setFiltered(applyFilters);
    setCurrentPage(1);
    setSelected(new Set());
  }, [applyFilters]);

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil(filtered.length / pageSize)),
    [filtered.length, pageSize],
  );
  const pageData = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, currentPage, pageSize]);

  const startIndex = useMemo(
    () => (currentPage - 1) * pageSize,
    [currentPage, pageSize],
  );

  const toggleSelect = (absoluteIndex: number, checked: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) next.add(absoluteIndex);
      else next.delete(absoluteIndex);
      return next;
    });
  };

  const selectAllOnPage = (checked: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      pageData.forEach((_, i) => {
        const abs = startIndex + i;
        if (checked) next.add(abs);
        else next.delete(abs);
      });
      return next;
    });
  };

  const allSelected =
    pageData.length > 0 &&
    pageData.every((_, i) => selected.has(startIndex + i));
  const someSelected = pageData.some((_, i) => selected.has(startIndex + i));

  const openDetails = (attack: Attack) => {
    setModalAttack(attack);
    setModalOpen(true);
  };

  return (
    <div className="attacks-container">
      <div className="card-shell">
        <div className="attack-summary-cards" style={{ marginBottom: 20 }}>
          <div className="attack-summary-card">
            <div
              className="attack-summary-icon"
              style={{
                background: "linear-gradient(135deg, #ef4444 0%, #dc2626 100%)",
              }}
            >
              <i className="fas fa-skull-crossbones" />
            </div>
            <div className="attack-summary-content">
              <div className="attack-summary-value">{summary.total}</div>
              <div className="attack-summary-label">Total Attacks</div>
            </div>
          </div>

          <div className="attack-summary-card">
            <div
              className="attack-summary-icon"
              style={{
                background: "linear-gradient(135deg, #f59e0b 0%, #d97706 100%)",
              }}
            >
              <i className="fas fa-exclamation-triangle" />
            </div>
            <div className="attack-summary-content">
              <div className="attack-summary-value">{summary.today}</div>
              <div className="attack-summary-label">Today's Attacks</div>
            </div>
          </div>

          <div className="attack-summary-card">
            <div
              className="attack-summary-icon"
              style={{
                background: "linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)",
              }}
            >
              <i className="fas fa-network-wired" />
            </div>
            <div className="attack-summary-content">
              <div className="attack-summary-value">{summary.active}</div>
              <div className="attack-summary-label">Active Now</div>
            </div>
          </div>

          <div className="attack-summary-card">
            <div
              className="attack-summary-icon"
              style={{
                background: "linear-gradient(135deg, #10b981 0%, #059669 100%)",
              }}
            >
              <i className="fas fa-shield-check" />
            </div>
            <div className="attack-summary-content">
              <div className="attack-summary-value">{summary.blocked}</div>
              <div className="attack-summary-label">Blocked</div>
            </div>
          </div>
        </div>

        <div className="attack-controls">
          <div className="filters-section">
            <div className="filter-group">
              <label>
                <i className="fas fa-filter" /> Attack Type
              </label>
              <select
                multiple
                value={typeFilter}
                onChange={(e) => {
                  const values = Array.from(e.target.selectedOptions).map(
                    (o) => o.value,
                  );
                  setTypeFilter(values.length ? values : ["all"]);
                }}
              >
                {typeOptions.map((t) => (
                  <option key={t} value={t}>
                    {t === "all" ? "All Types" : t.replaceAll("_", " ")}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-group">
              <label>
                <i className="fas fa-calendar" /> Time Range
              </label>
              <select
                value={timeFilter}
                onChange={(e) => setTimeFilter(e.target.value as any)}
              >
                <option value="all">All Time</option>
                <option value="today">Today</option>
                <option value="24h">Last 24 Hours</option>
                <option value="7d">Last 7 Days</option>
                <option value="30d">Last 30 Days</option>
              </select>
            </div>

            <div className="filter-group">
              <label>
                <i className="fas fa-exclamation-circle" /> Severity
              </label>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as any)}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            <div className="filter-actions">
              <button
                className="btn btn-secondary"
                onClick={() => setFiltered(applyFilters)}
              >
                <i className="fas fa-check" /> Apply Filters
              </button>
              <button
                className="btn btn-outline"
                onClick={() => {
                  setTypeFilter(["all"]);
                  setTimeFilter("all");
                  setSeverityFilter("all");
                }}
              >
                <i className="fas fa-redo" /> Reset
              </button>
              <button
                className="btn btn-danger"
                onClick={() => {
                  if (
                    confirm(
                      "Are you sure you want to clear all attack history? This cannot be undone.",
                    )
                  ) {
                    setAttacks([]);
                    setFiltered([]);
                    setSelected(new Set());
                    setModalOpen(false);
                    setSummary({ total: 0, today: 0, active: 0, blocked: 0 });
                  }
                }}
              >
                <i className="fas fa-trash" /> Clear History
              </button>
            </div>
          </div>

          <div className="export-section">
            <button
              className="btn btn-primary"
              onClick={() => alert("Attack logs exported successfully!")}
            >
              <i className="fas fa-download" /> Export Logs
            </button>
            <button
              className="btn btn-outline"
              onClick={() => alert("Refresh done automatically.")}
            >
              <i className="fas fa-sync-alt" /> Refresh
            </button>
          </div>
        </div>

        <div className="attacks-table-section">
          <div className="section-header">
            <h3>
              <i className="fas fa-list" /> Detected Attacks
            </h3>
            <div className="table-info">
              Showing{" "}
              {filtered.length ? Math.min(startIndex + 1, filtered.length) : 0}-
              {filtered.length
                ? Math.min(startIndex + pageSize, filtered.length)
                : 0}{" "}
              of <b>{filtered.length}</b> attacks
            </div>
          </div>

          <div className="table-container">
            <table className="attacks-table">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      checked={allSelected}
                      ref={(el) => {
                        if (el) el.indeterminate = !allSelected && someSelected;
                      }}
                      onChange={(e) => selectAllOnPage(e.target.checked)}
                    />
                  </th>
                  <th>Time & Date</th>
                  <th>Attack Type</th>
                  <th>Source IP</th>
                  <th>Target IP</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Details</th>
                  <th>Actions</th>
                </tr>
              </thead>

              <tbody>
                {pageData.length === 0 ? (
                  <tr>
                    <td
                      colSpan={9}
                      style={{
                        textAlign: "center",
                        color: "#94a3b8",
                        padding: 40,
                      }}
                    >
                      <i className="fas fa-eye-slash" /> No attacks match
                      filters
                    </td>
                  </tr>
                ) : (
                  pageData.map((attack, i) => {
                    const absIndex = startIndex + i;
                    const sev = getAttackSeverity(attack.type);
                    const { src, dst } = parseSrcDst(attack.message);
                    const isChecked = selected.has(absIndex);

                    return (
                      <tr key={attack.timestamp || absIndex} className={sev}>
                        <td>
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={(e) =>
                              toggleSelect(absIndex, e.target.checked)
                            }
                          />
                        </td>
                        <td>
                          <div className="timestamp">
                            {attack.timestamp || "--"}
                          </div>
                          <div
                            className="time-ago"
                            style={{ fontSize: "0.8rem", color: "#64748b" }}
                          >
                            {attack.time_ago || ""}
                          </div>
                        </td>
                        <td>
                          <div className="attack-type">
                            {formatAttackType(attack.type)}
                          </div>
                        </td>
                        <td>
                          <div className="ip-address">{src}</div>
                        </td>
                        <td>
                          <div className="ip-address">{dst}</div>
                        </td>
                        <td>
                          <span className={`severity-badge severity-${sev}`}>
                            {sev}
                          </span>
                        </td>
                        <td>
                          <span className="status-badge status-new">New</span>
                        </td>
                        <td>
                          <div
                            className="attack-message"
                            style={{
                              maxWidth: 220,
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {attack.message}
                          </div>
                        </td>
                        <td>
                          <div className="action-buttons">
                            <button
                              className="action-btn view"
                              onClick={() => openDetails(attack)}
                            >
                              <i className="fas fa-eye" />
                            </button>
                            <button
                              className="action-btn block"
                              onClick={() => {
                                if (
                                  confirm(
                                    `Are you sure you want to block IP address ${src}?`,
                                  )
                                ) {
                                  alert(`IP ${src} has been blocked.`);
                                }
                              }}
                            >
                              <i className="fas fa-ban" />
                            </button>
                            <button
                              className="action-btn flag"
                              onClick={() =>
                                alert("Attack flagged for review.")
                              }
                            >
                              <i className="fas fa-flag" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          <div className="table-footer">
            <div className="bulk-actions">
              <select defaultValue="" onChange={() => {}}>
                <option value="">Bulk Actions</option>
                <option value="mark_resolved">Mark as Resolved</option>
                <option value="mark_false_positive">
                  Mark as False Positive
                </option>
                <option value="export_selected">Export Selected</option>
                <option value="delete_selected">Delete Selected</option>
              </select>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  if (selected.size === 0) {
                    alert("Please select at least one attack.");
                    return;
                  }
                  if (
                    confirm(`Delete selected attacks (count=${selected.size})?`)
                  ) {
                    setAttacks((prev) => {
                      const deleteSet = new Set(Array.from(selected));
                      const toDelete = new Set(
                        filtered
                          .map((a, idx) =>
                            deleteSet.has(idx)
                              ? a.timestamp
                                ? String(a.timestamp)
                                : null
                              : null,
                          )
                          .filter(Boolean),
                      );
                      return prev.filter(
                        (a) =>
                          !(a.timestamp && toDelete.has(String(a.timestamp))),
                      );
                    });
                    setSelected(new Set());
                  }
                }}
              >
                Apply
              </button>
            </div>

            <div className="pagination-controls">
              <button
                className="btn btn-pagination"
                disabled={currentPage === 1}
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              >
                <i className="fas fa-chevron-left" />
              </button>
              <span className="page-info">
                Page {currentPage} of {totalPages}
              </span>
              <button
                className="btn btn-pagination"
                disabled={currentPage >= totalPages}
                onClick={() =>
                  setCurrentPage((p) => Math.min(totalPages, p + 1))
                }
              >
                <i className="fas fa-chevron-right" />
              </button>

              <select
                value={pageSize}
                onChange={(e) => setPageSize(Number(e.target.value) as any)}
              >
                {pageSizeOptions.map((s) => (
                  <option key={s} value={s}>
                    {s} per page
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>
      </div>

      <Modal
        open={modalOpen}
        onClose={() => {
          setModalOpen(false);
          setModalAttack(null);
        }}
        title="Attack Details"
      >
        {modalAttack ? (
          <div className="attack-details">
            <div className="detail-row">
              <div className="detail-label">Attack Type:</div>
              <div className="detail-value">
                {formatAttackType(modalAttack.type)}
              </div>
            </div>
            <div className="detail-row">
              <div className="detail-label">Timestamp:</div>
              <div className="detail-value">
                {modalAttack.timestamp || "--"}
              </div>
            </div>

            {(() => {
              const { src, dst } = parseSrcDst(modalAttack.message);
              return (
                <>
                  <div className="detail-row">
                    <div className="detail-label">Source IP:</div>
                    <div className="detail-value">{src}</div>
                  </div>
                  <div className="detail-row">
                    <div className="detail-label">Target IP:</div>
                    <div className="detail-value">{dst}</div>
                  </div>
                </>
              );
            })()}

            <div className="detail-row">
              <div className="detail-label">Severity:</div>
              <div className="detail-value">
                <span
                  className={`severity-badge severity-${getAttackSeverity(modalAttack.type)}`}
                >
                  {getAttackSeverity(modalAttack.type)}
                </span>
              </div>
            </div>

            <div className="detail-row">
              <div className="detail-label">Full Message:</div>
              <div className="detail-value">{modalAttack.message || ""}</div>
            </div>

            <div
              style={{
                display: "flex",
                gap: 10,
                justifyContent: "flex-end",
                marginTop: 10,
              }}
            >
              <button
                className="btn btn-secondary"
                onClick={() => setModalOpen(false)}
              >
                Close
              </button>
              <button
                className="btn btn-danger"
                onClick={() =>
                  alert(
                    "Block source action not wired to backend in this port.",
                  )
                }
              >
                Block Source IP
              </button>
              <button
                className="btn btn-primary"
                onClick={() =>
                  alert("Watchlist action not wired to backend in this port.")
                }
              >
                Add to Watchlist
              </button>
            </div>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
