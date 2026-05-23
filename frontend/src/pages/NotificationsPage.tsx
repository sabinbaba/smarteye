import React, { useEffect, useMemo, useState } from "react";

type Notification = {
  id?: string | number;
  type?: "system" | "attack" | "warning" | "info" | string;
  title?: string;
  message?: string;
  timestamp?: string;
  read?: boolean;
};

type NotificationsResponse = {
  notifications?: Notification[];
  unread?: number;
};

type TabKey = "all" | "unread" | "attack" | "system" | "warning";

type PriorityKey = "all" | "critical" | "high" | "medium" | "low";

const pageSizeOptions = [10, 25, 50, 100] as const;

function getPriority(type?: string): Exclude<PriorityKey, "all"> {
  if (type === "attack") return "critical";
  if (type === "warning") return "high";
  if (type === "system") return "medium";
  return "low";
}

function getIcon(type?: string) {
  switch (type) {
    case "system":
      return "fa-server";
    case "attack":
      return "fa-skull-crossbones";
    case "warning":
      return "fa-exclamation-triangle";
    case "info":
      return "fa-info-circle";
    default:
      return "fa-bell";
  }
}

function priorityClass(p: Exclude<PriorityKey, "all">) {
  switch (p) {
    case "critical":
      return "priority-critical";
    case "high":
      return "priority-high";
    case "medium":
      return "priority-medium";
    case "low":
      return "priority-low";
    default:
      return "";
  }
}

export default function NotificationsPage() {
  const [notifications, setNotifications] = useState<Notification[]>([]);

  const [tab, setTab] = useState<TabKey>("all");
  const [timeFilter, setTimeFilter] = useState<
    "all" | "today" | "24h" | "7d" | "30d"
  >("all");
  const [priorityFilter, setPriorityFilter] = useState<PriorityKey>("all");
  const [search, setSearch] = useState<string>("");
  const [sortBy, setSortBy] = useState<"newest" | "oldest" | "priority">(
    "newest",
  );

  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] =
    useState<(typeof pageSizeOptions)[number]>(10);

  const [selected, setSelected] = useState<Set<string | number>>(new Set());

  useEffect(() => {
    let t: number | undefined;

    const load = async () => {
      try {
        const res = await fetch("/api/notifications");
        const data = (await res.json()) as NotificationsResponse;
        setNotifications(data.notifications || []);
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

  const counts = useMemo(() => {
    const total = notifications.length;
    const unread = notifications.filter((n) => !n.read).length;
    const attack = notifications.filter((n) => n.type === "attack").length;
    const system = notifications.filter((n) => n.type === "system").length;
    const warning = notifications.filter((n) => n.type === "warning").length;
    return { total, unread, attack, system, warning };
  }, [notifications]);

  const filtered = useMemo(() => {
    let list = [...notifications];

    if (tab !== "all") {
      list = list.filter((n) => {
        if (tab === "unread") return !n.read;
        if (tab === "attack") return n.type === "attack";
        if (tab === "system") return n.type === "system";
        if (tab === "warning") return n.type === "warning";
        return true;
      });
    }

    // Template UI simplified: timeFilter no-op if backend doesn’t filter.
    if (priorityFilter !== "all") {
      list = list.filter((n) => getPriority(n.type) === priorityFilter);
    }

    const q = search.trim().toLowerCase();
    if (q) {
      list = list.filter((n) =>
        `${n.title || ""} ${n.message || ""}`.toLowerCase().includes(q),
      );
    }

    const priorityScore = (p: ReturnType<typeof getPriority>) =>
      p === "critical" ? 4 : p === "high" ? 3 : p === "medium" ? 2 : 1;

    list.sort((a, b) => {
      const da = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const db = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      if (sortBy === "newest") return db - da;
      if (sortBy === "oldest") return da - db;
      if (sortBy === "priority")
        return (
          priorityScore(getPriority(b.type)) -
          priorityScore(getPriority(a.type))
        );
      return 0;
    });

    return list;
  }, [notifications, tab, timeFilter, priorityFilter, search, sortBy]);

  useEffect(() => {
    setCurrentPage(1);
    setSelected(new Set());
  }, [tab, timeFilter, priorityFilter, search, sortBy]);

  const totalPages = useMemo(
    () => Math.max(1, Math.ceil(filtered.length / pageSize)),
    [filtered.length, pageSize],
  );

  const pageData = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, currentPage, pageSize]);

  const startIndex = (currentPage - 1) * pageSize;

  const selectedOnPageAll =
    pageData.length > 0 &&
    pageData.every((n) => n.id !== undefined && selected.has(n.id));
  const selectedOnPageSome = pageData.some(
    (n) => n.id !== undefined && selected.has(n.id),
  );

  const toggleAllOnPage = (checked: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const n of pageData) {
        if (n.id === undefined) continue;
        if (checked) next.add(n.id);
        else next.delete(n.id);
      }
      return next;
    });
  };

  const toggleOne = (id: string | number, checked: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  };

  const markAsRead = (ids: Array<string | number>) => {
    setNotifications((prev) =>
      prev.map((n) =>
        n.id !== undefined && ids.includes(n.id) ? { ...n, read: true } : n,
      ),
    );
  };

  const deleteNotifications = (ids: Array<string | number>) => {
    setNotifications((prev) =>
      prev.filter((n) => n.id === undefined || !ids.includes(n.id)),
    );
    setSelected(new Set());
  };

  const showingFrom = filtered.length ? startIndex + 1 : 0;
  const showingTo = Math.min(startIndex + pageSize, filtered.length);

  return (
    <div className="notifications-container">
      <div className="card-shell">
        <div className="section-header">
          <h3 style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <i className="fas fa-bell" /> System Notifications
          </h3>
        </div>

        <div className="notifications-header" style={{ marginBottom: 20 }}>
          <div
            className="notification-stats"
            style={{ display: "flex", gap: 40 }}
          >
            <div className="stat-item">
              <div className="stat-value">{counts.total}</div>
              <div className="stat-label">Total</div>
            </div>
            <div className="stat-item">
              <div className="stat-value">{counts.unread}</div>
              <div className="stat-label">Unread</div>
            </div>
            <div className="stat-item">
              <div className="stat-value">{counts.warning}</div>
              <div className="stat-label">Critical</div>
            </div>
          </div>

          <div
            className="notification-actions"
            style={{ display: "flex", gap: 15, alignItems: "center" }}
          >
            <button
              className="btn btn-primary"
              onClick={() => {
                const unreadIds = notifications
                  .filter((n) => n.id !== undefined && !n.read)
                  .map((n) => n.id!);
                markAsRead(unreadIds);
              }}
            >
              <i className="fas fa-check-double" /> Mark All as Read
            </button>
            <button
              className="btn btn-outline"
              onClick={() => {
                const ids = notifications
                  .filter((n) => n.id !== undefined)
                  .map((n) => n.id!);
                if (
                  confirm(
                    "Are you sure you want to clear all notifications? This cannot be undone.",
                  )
                ) {
                  deleteNotifications(ids);
                }
              }}
            >
              <i className="fas fa-trash" /> Clear All
            </button>
          </div>
        </div>

        <div className="notification-tabs" style={{ marginBottom: 20 }}>
          <div
            className="tabs-header"
            style={{ display: "flex", gap: 10, overflowX: "auto" }}
          >
            <button
              className={`tab-btn ${tab === "all" ? "active" : ""}`}
              onClick={() => setTab("all")}
            >
              <i className="fas fa-bell" /> All Notifications{" "}
              <span className="tab-badge">{counts.total}</span>
            </button>
            <button
              className={`tab-btn ${tab === "unread" ? "active" : ""}`}
              onClick={() => setTab("unread")}
            >
              <i className="fas fa-envelope" /> Unread{" "}
              <span className="tab-badge">{counts.unread}</span>
            </button>
            <button
              className={`tab-btn ${tab === "attack" ? "active" : ""}`}
              onClick={() => setTab("attack")}
            >
              <i className="fas fa-skull-crossbones" /> Attacks{" "}
              <span className="tab-badge">{counts.attack}</span>
            </button>
            <button
              className={`tab-btn ${tab === "system" ? "active" : ""}`}
              onClick={() => setTab("system")}
            >
              <i className="fas fa-server" /> System{" "}
              <span className="tab-badge">{counts.system}</span>
            </button>
            <button
              className={`tab-btn ${tab === "warning" ? "active" : ""}`}
              onClick={() => setTab("warning")}
            >
              <i className="fas fa-exclamation-triangle" /> Warnings{" "}
              <span className="tab-badge">{counts.warning}</span>
            </button>
          </div>
        </div>

        <div
          className="notification-filters"
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))",
            gap: 20,
            marginBottom: 20,
          }}
        >
          <div className="filter-group">
            <label>
              <i className="fas fa-calendar" /> Time
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
              <i className="fas fa-filter" /> Priority
            </label>
            <select
              value={priorityFilter}
              onChange={(e) => setPriorityFilter(e.target.value as any)}
            >
              <option value="all">All Priorities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div className="filter-group">
            <label>
              <i className="fas fa-search" /> Search
            </label>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              type="text"
              placeholder="Search notifications..."
              style={{
                width: "100%",
                padding: "12px 15px",
                borderRadius: 8,
                border: "2px solid #e2e8f0",
              }}
            />
          </div>

          <button className="btn btn-secondary" onClick={() => {}}>
            <i className="fas fa-filter" /> Apply Filters
          </button>
        </div>

        <div className="notifications-list-container">
          <div className="list-header" style={{ marginBottom: 20 }}>
            <div
              className="header-left"
              style={{ display: "flex", alignItems: "center", gap: 10 }}
            >
              <input
                type="checkbox"
                checked={selectedOnPageAll}
                ref={(el) => {
                  if (el)
                    el.indeterminate = !selectedOnPageAll && selectedOnPageSome;
                }}
                onChange={(e) => toggleAllOnPage(e.target.checked)}
              />
              <label>Select All</label>
            </div>

            <div
              className="header-right"
              style={{ display: "flex", alignItems: "center", gap: 15 }}
            >
              <button className="btn btn-small" onClick={() => {}}>
                <i className="fas fa-sync-alt" /> Refresh
              </button>

              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
              >
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
                <option value="priority">Priority</option>
              </select>
            </div>
          </div>

          <div
            className="notifications-list"
            style={{ maxHeight: 500, overflowY: "auto" }}
          >
            {pageData.length === 0 ? (
              <div style={{ padding: 30, color: "#64748b" }}>
                No notifications found
              </div>
            ) : (
              pageData.map((n) => {
                const id = n.id!;
                const p = getPriority(n.type);
                const isSelected = selected.has(id);
                const read = !!n.read;

                return (
                  <div
                    key={String(id)}
                    className={`notification-item ${read ? "" : "unread"} ${p}`}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      padding: 20,
                      borderBottom: "1px solid #f1f5f9",
                    }}
                  >
                    <div
                      className="notification-checkbox"
                      style={{ marginRight: 15 }}
                    >
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={(e) => toggleOne(id, e.target.checked)}
                      />
                    </div>

                    <div
                      className={`notification-icon ${n.type || "info"}`}
                      style={{
                        width: 50,
                        height: 50,
                        borderRadius: 12,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        background:
                          "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)",
                        color: "white",
                      }}
                    >
                      <i className={`fas ${getIcon(n.type)}`} />
                    </div>

                    <div
                      className="notification-content"
                      style={{ flex: 1, minWidth: 0 }}
                    >
                      <div
                        className="notification-header"
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                        }}
                      >
                        <div
                          className="notification-title"
                          style={{
                            fontWeight: 600,
                            color: "#1e293b",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {n.title || ""}
                        </div>
                        <div
                          className="notification-time"
                          style={{
                            color: "#64748b",
                            fontSize: 12,
                            whiteSpace: "nowrap",
                          }}
                        >
                          {n.timestamp || ""}
                        </div>
                      </div>
                      <div
                        className="notification-message"
                        style={{
                          color: "#64748b",
                          marginTop: 6,
                          fontSize: 14,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          display: "-webkit-box",
                          WebkitLineClamp: 2,
                          WebkitBoxOrient: "vertical",
                        }}
                      >
                        {n.message || ""}
                      </div>
                      <div
                        className="notification-footer"
                        style={{
                          display: "flex",
                          gap: 10,
                          alignItems: "center",
                          marginTop: 10,
                        }}
                      >
                        <span
                          className="notification-tag"
                          style={{
                            padding: "4px 10px",
                            borderRadius: 12,
                            background: "#e2e8f0",
                            color: "#475569",
                            fontSize: 12,
                          }}
                        >
                          {n.type || "info"}
                        </span>
                        <span
                          className={`notification-priority ${priorityClass(p)}`}
                        >
                          {p}
                        </span>
                      </div>
                    </div>

                    <div
                      className="notification-actions"
                      style={{ display: "flex", gap: 5, flexShrink: 0 }}
                    >
                      <button
                        className="notification-action-btn read"
                        onClick={() => markAsRead([id])}
                        title="Mark as read"
                      >
                        <i className="fas fa-check" />
                      </button>
                      <button
                        className="notification-action-btn delete"
                        onClick={() => deleteNotifications([id])}
                        title="Delete"
                      >
                        <i className="fas fa-trash" />
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          <div
            className="list-footer"
            style={{
              marginTop: 20,
              paddingTop: 15,
              borderTop: "2px solid #f1f5f9",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div className="footer-left" style={{ display: "flex", gap: 10 }}>
              <button
                className="btn btn-outline"
                disabled={selected.size === 0}
                onClick={() => {
                  if (selected.size === 0) return;
                  deleteNotifications(Array.from(selected));
                }}
              >
                <i className="fas fa-trash" /> Delete Selected
              </button>

              <button
                className="btn btn-outline"
                disabled={selected.size === 0}
                onClick={() => {
                  if (selected.size === 0) return;
                  markAsRead(Array.from(selected));
                }}
              >
                <i className="fas fa-check" /> Mark as Read
              </button>
            </div>

            <div
              className="footer-right"
              style={{ display: "flex", alignItems: "center", gap: 20 }}
            >
              <div
                className="pagination-info"
                style={{ color: "#64748b", fontSize: 14 }}
              >
                Showing {showingFrom}-{showingTo} of {filtered.length}
              </div>

              <div className="pagination-controls">
                <button
                  className="btn btn-pagination"
                  disabled={currentPage === 1}
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                >
                  <i className="fas fa-chevron-left" />
                </button>

                <span
                  className="page-info"
                  style={{ color: "#475569", fontWeight: 500 }}
                >
                  Page {currentPage}
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
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
