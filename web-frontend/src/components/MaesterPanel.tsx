import { useState, useEffect } from "react";

const API = import.meta.env.PUBLIC_API_URL ?? "http://localhost:3000";

type MaesterStatus = {
  available: boolean;
  last_run?: string;
  run_status?: string;
  result?: string;
  tenant_name?: string;
  total?: number;
  passed?: number;
  failed?: number;
  skipped?: number;
  errors?: number;
  total_duration?: string;
  executed_at?: string;
  message?: string;
};

type MaesterTest = {
  id: string;
  title: string;
  result: string;
  severity: string;
  block: string;
  duration: string;
  tags: string[];
  help_url: string;
  test_result: string;
  description: string;
  skipped_reason: string;
  error: any[];
};

type Summary = {
  by_block: Record<string, { passed: number; failed: number; skipped: number; error: number }>;
  by_severity: Record<string, { passed: number; failed: number }>;
  failed_high_severity: { id: string; title: string; severity: string; block: string }[];
};

const RESULT_COLORS: Record<string, string> = {
  Passed: "#06d6a0",
  Failed: "#ff4d6a",
  Skipped: "#888",
  Error: "#ff8c42",
};

const SEV_COLORS: Record<string, string> = {
  High: "#ff4d6a",
  Medium: "#ff8c42",
  Low: "#ffd166",
  Critical: "#ff0044",
  Informational: "#888",
};

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: "inline-block", padding: "2px 8px", borderRadius: 4,
      fontSize: 11, fontWeight: 700, textTransform: "uppercase",
      border: `1px solid ${color}44`, background: `${color}22`, color,
      fontFamily: "monospace",
    }}>
      {label}
    </span>
  );
}

function ScoreBar({ passed, failed, skipped, total }: { passed: number; failed: number; skipped: number; total: number }) {
  if (!total) return null;
  const pct = (n: number) => `${Math.round((n / total) * 100)}%`;
  return (
    <div style={{ display: "flex", height: 8, borderRadius: 4, overflow: "hidden", gap: 1, margin: "12px 0" }}>
      <div style={{ width: pct(passed), background: "#06d6a0" }} title={`Passed: ${passed}`} />
      <div style={{ width: pct(failed), background: "#ff4d6a" }} title={`Failed: ${failed}`} />
      <div style={{ width: pct(skipped), background: "#333" }} title={`Skipped: ${skipped}`} />
    </div>
  );
}

export default function MaesterPanel() {
  const [tab, setTab] = useState<"overview" | "failed" | "passed" | "all">("overview");
  const [status, setStatus] = useState<MaesterStatus | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [tests, setTests] = useState<MaesterTest[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<MaesterTest | null>(null);
  const [search, setSearch] = useState("");

  useEffect(() => {
    fetch(`${API}/maester/status`)
      .then(r => r.json())
      .then(d => { setStatus(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!status?.available) return;
    fetch(`${API}/maester/summary`).then(r => r.json()).then(setSummary);
  }, [status]);

  useEffect(() => {
    if (!status?.available) return;
    const resultFilter = tab === "failed" ? "?result=Failed" : tab === "passed" ? "?result=Passed" : "";
    const searchParam = search ? `${resultFilter ? "&" : "?"}search=${encodeURIComponent(search)}` : "";
    fetch(`${API}/maester/tests${resultFilter}${searchParam}`)
      .then(r => r.json())
      .then(d => setTests(d.tests ?? []));
  }, [tab, status, search]);

  if (loading) return <div style={{ color: "#888", fontFamily: "monospace", padding: 32 }}>Loading...</div>;

  if (!status?.available) return (
    <div style={{ color: "#ff8c42", fontFamily: "monospace", padding: 32 }}>
      {status?.message ?? "Maester container not running. Start with: docker compose --profile maester up -d maester"}
    </div>
  );

  const TABS = [
    { id: "overview", label: "Overview" },
    { id: "failed", label: `Failed (${status.failed ?? 0})` },
    { id: "passed", label: `Passed (${status.passed ?? 0})` },
    { id: "all", label: `All (${status.total ?? 0})` },
  ] as const;

  return (
    <div style={{ fontFamily: "system-ui, sans-serif" }}>

      {/* Score header */}
      <div style={{
        background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 8,
        padding: 20, marginBottom: 20, display: "flex", justifyContent: "space-between", alignItems: "center",
      }}>
        <div>
          <div style={{ fontSize: 12, color: "#888", marginBottom: 8 }}>
            {status.tenant_name} · Last run: {status.executed_at ? new Date(status.executed_at).toLocaleString() : "—"} · {status.total_duration}
          </div>
          <ScoreBar passed={status.passed ?? 0} failed={status.failed ?? 0} skipped={status.skipped ?? 0} total={status.total ?? 0} />
          <div style={{ display: "flex", gap: 20, fontSize: 13 }}>
            <span style={{ color: "#06d6a0" }}>✓ {status.passed} passed</span>
            <span style={{ color: "#ff4d6a" }}>✗ {status.failed} failed</span>
            <span style={{ color: "#888" }}>⊘ {status.skipped} skipped</span>
            {(status.errors ?? 0) > 0 && <span style={{ color: "#ff8c42" }}>⚠ {status.errors} errors</span>}
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{
            fontSize: 36, fontWeight: 700, fontFamily: "monospace",
            color: status.result === "Passed" ? "#06d6a0" : "#ff4d6a",
          }}>
            {status.total ? Math.round(((status.passed ?? 0) / status.total) * 100) : 0}%
          </div>
          <div style={{ fontSize: 11, color: "#888" }}>pass rate</div>
        </div>
      </div>

      {/* High severity failures */}
      {summary && summary.failed_high_severity.length > 0 && (
        <div style={{
          background: "#1a0a0a", border: "1px solid #ff4d6a44", borderRadius: 8,
          padding: 16, marginBottom: 20,
        }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: "#ff4d6a", fontFamily: "monospace", marginBottom: 10, textTransform: "uppercase" }}>
            ⚠ High / Critical Failures
          </div>
          {summary.failed_high_severity.map(t => (
            <div key={t.id} style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid #2a0a0a" }}>
              <span style={{ fontFamily: "monospace", fontSize: 12, color: "#ff4d6a", marginRight: 12 }}>{t.id}</span>
              <span style={{ fontSize: 12, color: "#c0c0d0", flex: 1 }}>{t.title}</span>
              <Badge label={t.severity} color={SEV_COLORS[t.severity] ?? "#888"} />
            </div>
          ))}
        </div>
      )}

      {/* By block summary */}
      {summary && tab === "overview" && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 12, marginBottom: 20 }}>
          {Object.entries(summary.by_block).sort((a, b) => b[1].failed - a[1].failed).map(([block, counts]) => (
            <div key={block} style={{
              background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 8, padding: 14,
            }}>
              <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 8 }}>{block}</div>
              <div style={{ fontSize: 12, color: "#888", display: "flex", gap: 10 }}>
                <span style={{ color: "#06d6a0" }}>{counts.passed}✓</span>
                <span style={{ color: "#ff4d6a" }}>{counts.failed}✗</span>
                <span style={{ color: "#555" }}>{counts.skipped}⊘</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab bar */}
      <div style={{ display: "flex", gap: 4, marginBottom: 16, borderBottom: "1px solid #2a2a3a" }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: "8px 16px", background: "none", border: "none",
            borderBottom: tab === t.id ? "2px solid #7b61ff" : "2px solid transparent",
            color: tab === t.id ? "#7b61ff" : "#888",
            cursor: "pointer", fontSize: 13, fontWeight: 600,
          }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Search */}
      {tab !== "overview" && (
        <input
          type="text"
          placeholder="Search by ID or title..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            width: "100%", padding: "8px 12px", marginBottom: 16, boxSizing: "border-box",
            background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 6,
            color: "#e0e0f0", fontFamily: "monospace", fontSize: 13, outline: "none",
          }}
        />
      )}

      {/* Test list */}
      {tab !== "overview" && (
        <div>
          {tests.length === 0 && <div style={{ color: "#888" }}>No tests found.</div>}
          {tests.map(t => (
            <div
              key={t.id}
              onClick={() => setSelected(selected?.id === t.id ? null : t)}
              style={{
                background: "#13131e", border: `1px solid ${selected?.id === t.id ? "#7b61ff" : "#2a2a3a"}`,
                borderRadius: 8, padding: 14, marginBottom: 8, cursor: "pointer",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div style={{ flex: 1 }}>
                  <span style={{ fontFamily: "monospace", fontSize: 11, color: "#7b61ff", marginRight: 10 }}>{t.id}</span>
                  <span style={{ fontSize: 13, color: "#e0e0f0" }}>{t.title}</span>
                </div>
                <div style={{ display: "flex", gap: 6, marginLeft: 12, flexShrink: 0 }}>
                  {t.severity && <Badge label={t.severity} color={SEV_COLORS[t.severity] ?? "#888"} />}
                  <Badge label={t.result} color={RESULT_COLORS[t.result] ?? "#888"} />
                </div>
              </div>

              {selected?.id === t.id && (
                <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid #2a2a3a" }}>
                  {t.test_result && (
                    <div style={{
                      background: "#0d0d14", borderRadius: 6, padding: 12,
                      fontFamily: "monospace", fontSize: 12, color: "#c0c0d0",
                      whiteSpace: "pre-wrap", marginBottom: 10,
                    }}>
                      {t.test_result}
                    </div>
                  )}
                  {t.skipped_reason && (
                    <div style={{ fontSize: 12, color: "#888", marginBottom: 8 }}>
                      Skipped: {t.skipped_reason}
                    </div>
                  )}
                  {t.error?.length > 0 && (
                    <div style={{ fontSize: 12, color: "#ff4d6a", marginBottom: 8 }}>
                      Error: {JSON.stringify(t.error)}
                    </div>
                  )}
                  {t.help_url && (
                    <a href={t.help_url} target="_blank" rel="noopener noreferrer"
                      style={{ fontSize: 12, color: "#7b61ff" }}>
                      Documentation →
                    </a>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}