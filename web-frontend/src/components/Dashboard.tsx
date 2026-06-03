import { useEffect, useState } from "react";

interface Stats {
  total: number;
  confirmed: number;
  false_positive: number;
  unreviewed: number;
  by_severity: Record<string, number>;
  false_positive_by_type: Record<string, number>;
  fp_rate: number;
}

interface MonitorStatus {
  enabled: boolean;
  interval_seconds: number;
}

interface Case {
  report_id: string;
  created_at: string;
  title: string;
  severity: string;
  confidence: number;
  kill_chain: string;
  verdict: string | null;
}

interface Props {
  apiUrl: string;
}

export default function Dashboard({ apiUrl }: Props) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [monitor, setMonitor] = useState<MonitorStatus | null>(null);
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  async function fetchAll() {
    try {
      const [statsRes, monitorRes, casesRes] = await Promise.all([
        fetch(`${apiUrl}/stats`),
        fetch(`${apiUrl}/monitor/status`),
        fetch(`${apiUrl}/cases`),
      ]);
      const [statsData, monitorData, casesData] = await Promise.all([
        statsRes.json(),
        monitorRes.json(),
        casesRes.json(),
      ]);
      setStats(statsData);
      setMonitor(monitorData);
      setCases(casesData.slice(0, 8));
      setLastRefresh(new Date());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 30000);
    return () => clearInterval(interval);
  }, []);

  const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
  const SEVERITY_COLOR: Record<string, string> = {
    critical: "var(--critical)",
    high: "var(--high)",
    medium: "var(--medium)",
    low: "var(--low)",
  };

  if (loading) return (
    <div style={{ color: "var(--text-muted)", fontFamily: "Geist Mono", fontSize: 13 }}>
      Loading dashboard...
    </div>
  );

  const maxSeverityCount = Math.max(...SEVERITY_ORDER.map((s) => stats?.by_severity[s] ?? 0), 1);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>

      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 600, color: "var(--text-primary)", marginBottom: 6 }}>
            SOC Dashboard
          </h1>
          <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
            Auto-refreshes every 30s · Last updated {lastRefresh.toLocaleTimeString()}
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            onClick={fetchAll}
            style={{
              padding: "6px 14px", borderRadius: 4,
              border: "1px solid var(--border)", background: "transparent",
              color: "var(--text-muted)", fontSize: 12, fontFamily: "Geist Mono",
              cursor: "pointer", transition: "all 0.15s",
            }}
            onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--accent)"; }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--border)"; }}
          >
            ↻ Refresh
          </button>
          <a href="/investigate" style={{
            padding: "6px 14px", borderRadius: 4,
            background: "var(--accent)", color: "#fff",
            fontSize: 12, fontFamily: "Geist Mono", fontWeight: 600,
            textDecoration: "none",
          }}>+ New Investigation</a>
        </div>
      </div>

      {/* Top stats row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
        <StatCard label="Total Cases" value={stats?.total ?? 0} color="var(--text-primary)" />
        <StatCard label="Confirmed Incidents" value={stats?.confirmed ?? 0} color="var(--critical)" />
        <StatCard label="False Positives" value={stats?.false_positive ?? 0} color="var(--text-muted)" />
        <StatCard
          label="FP Rate"
          value={`${stats?.fp_rate ?? 0}%`}
          color={stats?.fp_rate && stats.fp_rate > 30 ? "var(--high)" : "var(--low)"}
          sub={`${stats?.unreviewed ?? 0} unreviewed`}
        />
      </div>

      {/* Middle row — severity breakdown + monitor status */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>

        {/* Severity breakdown */}
        <div className="card">
          <div className="card-header">Cases by Severity</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {SEVERITY_ORDER.map((sev) => {
              const count = stats?.by_severity[sev] ?? 0;
              const pct = (count / maxSeverityCount) * 100;
              return (
                <div key={sev} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{
                    width: 60, fontSize: 11, fontFamily: "Geist Mono",
                    color: SEVERITY_COLOR[sev], textTransform: "uppercase", fontWeight: 600,
                    flexShrink: 0,
                  }}>{sev}</div>
                  <div style={{ flex: 1, height: 8, background: "var(--bg-hover)", borderRadius: 4 }}>
                    <div style={{
                      height: 8, borderRadius: 4,
                      background: SEVERITY_COLOR[sev],
                      width: `${pct}%`,
                      transition: "width 0.4s",
                      boxShadow: `0 0 6px ${SEVERITY_COLOR[sev]}66`,
                    }} />
                  </div>
                  <div style={{
                    width: 24, textAlign: "right",
                    fontFamily: "Geist Mono", fontSize: 13, fontWeight: 600,
                    color: SEVERITY_COLOR[sev],
                  }}>{count}</div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Monitor status */}
        <div className="card">
          <div className="card-header">Monitor Status</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{
                width: 10, height: 10, borderRadius: "50%",
                background: monitor?.enabled ? "var(--low)" : "var(--text-muted)",
                boxShadow: monitor?.enabled ? "0 0 8px var(--low)" : "none",
              }} />
              <span style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)" }}>
                {monitor?.enabled ? "Active" : "Inactive"}
              </span>
            </div>
            {monitor?.enabled && (
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                Polling every {monitor.interval_seconds}s
              </div>
            )}
            <div style={{ paddingTop: 8, borderTop: "1px solid var(--border)" }}>
              <a href="/patterns" style={{
                fontSize: 12, color: "var(--accent)", textDecoration: "none",
                fontFamily: "Geist Mono",
              }}>⚡ Run EDR Hunts →</a>
            </div>
            <div>
              <a href="/health" style={{
                fontSize: 12, color: "var(--text-muted)", textDecoration: "none",
                fontFamily: "Geist Mono",
              }}>⬡ Splunk Health →</a>
            </div>
          </div>
        </div>
      </div>

      {/* Recent cases */}
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <div className="card-header" style={{ marginBottom: 0 }}>Recent Cases</div>
          <a href="/" style={{ fontSize: 12, color: "var(--accent)", textDecoration: "none", fontFamily: "Geist Mono" }}>
            View all →
          </a>
        </div>
        {cases.length === 0 ? (
          <div style={{ fontSize: 13, color: "var(--text-muted)" }}>
            No cases yet. <a href="/investigate" style={{ color: "var(--accent)" }}>Start an investigation →</a>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {cases.map((c) => (
              <a key={c.report_id} href={`/cases/${c.report_id}`} style={{ textDecoration: "none" }}>
                <div style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  padding: "10px 12px", borderRadius: 6,
                  background: "var(--bg-hover)", border: "1px solid var(--border)",
                  transition: "border-color 0.15s",
                }}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLDivElement).style.borderColor = "var(--accent)"; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLDivElement).style.borderColor = "var(--border)"; }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0 }}>
                    <span className={`badge badge-${c.severity}`}>{c.severity}</span>
                    <span style={{ fontSize: 13, color: "var(--text-primary)", fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {c.title}
                    </span>
                    {c.verdict === "confirmed" && (
                      <span style={{ fontSize: 10, fontFamily: "Geist Mono", color: "var(--low)", flexShrink: 0 }}>✓</span>
                    )}
                    {c.verdict === "false_positive" && (
                      <span style={{ fontSize: 10, fontFamily: "Geist Mono", color: "var(--text-muted)", flexShrink: 0 }}>✗</span>
                    )}
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 16, flexShrink: 0 }}>
                    <span style={{ fontFamily: "Geist Mono", fontSize: 12, fontWeight: 600, color: confidenceColor(c.confidence) }}>
                      {Math.round(c.confidence * 100)}%
                    </span>
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                      {new Date(c.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              </a>
            ))}
          </div>
        )}
      </div>

      {/* Quick actions */}
      <div className="card">
        <div className="card-header">Quick Actions</div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          {[
            { label: "▶ New Investigation", href: "/investigate", accent: true },
            { label: "⚡ Pattern Library", href: "/patterns" },
            { label: "⇄ Compare Cases", href: "/compare" },
            { label: "◷ Timeline", href: "/timeline" },
            { label: "⬡ Splunk Health", href: "/health" },
            { label: "⌕ Search Logs", href: "/search" },
          ].map((action) => (
            <a
              key={action.href}
              href={action.href}
              style={{
                padding: "8px 16px", borderRadius: 6,
                background: action.accent ? "var(--accent)" : "transparent",
                border: `1px solid ${action.accent ? "var(--accent)" : "var(--border)"}`,
                color: action.accent ? "#fff" : "var(--text-secondary)",
                fontSize: 13, fontFamily: "Geist Mono",
                textDecoration: "none", transition: "all 0.15s",
              }}
              onMouseEnter={(e) => { if (!action.accent) (e.currentTarget as HTMLAnchorElement).style.borderColor = "var(--accent)"; }}
              onMouseLeave={(e) => { if (!action.accent) (e.currentTarget as HTMLAnchorElement).style.borderColor = "var(--border)"; }}
            >
              {action.label}
            </a>
          ))}
        </div>
      </div>

    </div>
  );
}

function StatCard({ label, value, color, sub }: { label: string; value: any; color: string; sub?: string }) {
  return (
    <div className="card" style={{ textAlign: "center" }}>
      <div style={{ fontSize: 36, fontWeight: 700, fontFamily: "Geist Mono", color, marginBottom: 4 }}>
        {value}
      </div>
      <div style={{ fontSize: 12, color: "var(--text-muted)", textTransform: "uppercase", fontFamily: "Geist Mono", letterSpacing: "0.05em" }}>
        {label}
      </div>
      {sub && (
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>{sub}</div>
      )}
    </div>
  );
}

function confidenceColor(c: number): string {
  if (c >= 0.7) return "var(--critical)";
  if (c >= 0.5) return "var(--high)";
  if (c >= 0.3) return "var(--medium)";
  return "var(--low)";
}