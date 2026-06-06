import { useState, useEffect } from "react";

const API = import.meta.env.PUBLIC_API_URL ?? "http://localhost:3000";

type Status = {
  available: boolean;
  last_run?: string;
  tenant?: string;
  products?: string[];
  summary?: Record<string, { Passes: number; Failures: number; Warnings: number; Manual: number; Errors: number }>;
  total?: number;
  passed?: number;
  failed?: number;
  warnings?: number;
  manual?: number;
  scubagear_version?: string;
  executed_at?: string;
  message?: string;
};

type Control = {
  product: string;
  group_name: string;
  group_number: string;
  group_url: string;
  control_id: string;
  requirement: string;
  result: string;
  criticality: string;
  details: string;
  resolution_date: string | null;
};

type Summary = {
  by_product: Record<string, any>;
  failed_shall: { product: string; control_id: string; requirement: string; details: string; group_name: string }[];
};

const RESULT_COLORS: Record<string, string> = {
  Pass: "#06d6a0",
  Fail: "#ff4d6a",
  Warning: "#ffd166",
  Manual: "#888",
  Error: "#ff8c42",
};

const CRIT_COLORS: Record<string, string> = {
  Shall: "#ff4d6a",
  Should: "#ff8c42",
  May: "#888",
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

function ScoreBar({ passed, failed, warnings, total }: { passed: number; failed: number; warnings: number; total: number }) {
  if (!total) return null;
  const pct = (n: number) => `${Math.round((n / total) * 100)}%`;
  return (
    <div style={{ display: "flex", height: 8, borderRadius: 4, overflow: "hidden", gap: 1, margin: "12px 0" }}>
      <div style={{ width: pct(passed), background: "#06d6a0" }} title={`Pass: ${passed}`} />
      <div style={{ width: pct(failed), background: "#ff4d6a" }} title={`Fail: ${failed}`} />
      <div style={{ width: pct(warnings), background: "#ffd166" }} title={`Warning: ${warnings}`} />
    </div>
  );
}

export default function ScubaGearPanel() {
  const [tab, setTab] = useState<"overview" | "failed" | "passed" | "all">("overview");
  const [status, setStatus] = useState<Status | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [controls, setControls] = useState<Control[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Control | null>(null);
  const [search, setSearch] = useState("");

  useEffect(() => {
    fetch(`${API}/scubagear/status`)
      .then(r => r.json())
      .then(d => { setStatus(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!status?.available) return;
    fetch(`${API}/scubagear/summary`).then(r => r.json()).then(setSummary);
  }, [status]);

  useEffect(() => {
    if (!status?.available) return;
    const resultFilter = tab === "failed" ? "?result=Fail" : tab === "passed" ? "?result=Pass" : "";
    const searchParam = search ? `${resultFilter ? "&" : "?"}search=${encodeURIComponent(search)}` : "";
    fetch(`${API}/scubagear/results${resultFilter}${searchParam}`)
      .then(r => r.json())
      .then(d => setControls(d.controls ?? []));
  }, [tab, status, search]);

  if (loading) return <div style={{ color: "#888", fontFamily: "monospace", padding: 32 }}>Loading...</div>;

  if (!status?.available) return (
    <div style={{ color: "#ff8c42", fontFamily: "monospace", padding: 32 }}>
      {status?.message ?? "ScubaGear container not running. Start with: docker compose --profile scubagear up -d scubagear"}
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
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 12, color: "#888", marginBottom: 8 }}>
            {status.tenant ?? "Unknown tenant"} · Products: {(status.products ?? []).join(", ")} · {status.executed_at ? new Date(status.executed_at).toLocaleString() : "—"}
          </div>
          <ScoreBar passed={status.passed ?? 0} failed={status.failed ?? 0} warnings={status.warnings ?? 0} total={status.total ?? 0} />
          <div style={{ display: "flex", gap: 20, fontSize: 13 }}>
            <span style={{ color: "#06d6a0" }}>✓ {status.passed} passed</span>
            <span style={{ color: "#ff4d6a" }}>✗ {status.failed} failed</span>
            {(status.warnings ?? 0) > 0 && <span style={{ color: "#ffd166" }}>⚠ {status.warnings} warnings</span>}
            {(status.manual ?? 0) > 0 && <span style={{ color: "#888" }}>◎ {status.manual} manual</span>}
          </div>
        </div>
        <div style={{ textAlign: "right", marginLeft: 24 }}>
          <div style={{
            fontSize: 36, fontWeight: 700, fontFamily: "monospace",
            color: (status.failed ?? 0) > 0 ? "#ff4d6a" : "#06d6a0",
          }}>
            {status.total ? Math.round(((status.passed ?? 0) / status.total) * 100) : 0}%
          </div>
          <div style={{ fontSize: 11, color: "#888" }}>pass rate</div>
        </div>
      </div>

      {/* Failed SHALL controls */}
      {summary && summary.failed_shall.length > 0 && (
        <div style={{
          background: "#1a0a0a", border: "1px solid #ff4d6a44", borderRadius: 8,
          padding: 16, marginBottom: 20,
        }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: "#ff4d6a", fontFamily: "monospace", marginBottom: 10, textTransform: "uppercase" }}>
            ⚠ Shall Failures
          </div>
          {summary.failed_shall.map(c => (
            <div key={c.control_id} style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid #2a0a0a", gap: 12 }}>
              <span style={{ fontFamily: "monospace", fontSize: 12, color: "#ff4d6a", flexShrink: 0 }}>{c.control_id}</span>
              <span style={{ fontSize: 12, color: "#c0c0d0", flex: 1 }}>{c.requirement}</span>
              <span style={{ fontSize: 11, color: "#888", flexShrink: 0 }}>{c.group_name}</span>
            </div>
          ))}
        </div>
      )}

      {/* By product overview */}
      {tab === "overview" && summary && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 12, marginBottom: 20 }}>
          {Object.entries(summary.by_product).map(([prod, counts]) => (
            <div key={prod} style={{ background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 8, padding: 14 }}>
              <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8, fontFamily: "monospace" }}>{prod}</div>
              <div style={{ fontSize: 12, display: "flex", gap: 10 }}>
                <span style={{ color: "#06d6a0" }}>{counts.Passes}✓</span>
                <span style={{ color: "#ff4d6a" }}>{counts.Failures}✗</span>
                {counts.Warnings > 0 && <span style={{ color: "#ffd166" }}>{counts.Warnings}⚠</span>}
                {counts.Manual > 0 && <span style={{ color: "#888" }}>{counts.Manual}◎</span>}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
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
          placeholder="Search by control ID or requirement..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            width: "100%", padding: "8px 12px", marginBottom: 16, boxSizing: "border-box",
            background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 6,
            color: "#e0e0f0", fontFamily: "monospace", fontSize: 13, outline: "none",
          }}
        />
      )}

      {/* Control list */}
      {tab !== "overview" && (
        <div>
          {controls.length === 0 && <div style={{ color: "#888" }}>No controls found.</div>}
          {controls.map(c => (
            <div
              key={c.control_id}
              onClick={() => setSelected(selected?.control_id === c.control_id ? null : c)}
              style={{
                background: "#13131e", border: `1px solid ${selected?.control_id === c.control_id ? "#7b61ff" : "#2a2a3a"}`,
                borderRadius: 8, padding: 14, marginBottom: 8, cursor: "pointer",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div style={{ flex: 1 }}>
                  <span style={{ fontFamily: "monospace", fontSize: 11, color: "#7b61ff", marginRight: 10 }}>{c.control_id}</span>
                  <span style={{ fontSize: 13, color: "#e0e0f0" }}>{c.requirement}</span>
                  <div style={{ fontSize: 11, color: "#555", marginTop: 4 }}>{c.group_name}</div>
                </div>
                <div style={{ display: "flex", gap: 6, marginLeft: 12, flexShrink: 0 }}>
                  {c.criticality && <Badge label={c.criticality} color={CRIT_COLORS[c.criticality] ?? "#888"} />}
                  <Badge label={c.result} color={RESULT_COLORS[c.result] ?? "#888"} />
                </div>
              </div>

              {selected?.control_id === c.control_id && (
                <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid #2a2a3a" }}>
                  {c.details && (
                    <div style={{
                      background: "#0d0d14", borderRadius: 6, padding: 12,
                      fontFamily: "monospace", fontSize: 12, color: "#c0c0d0",
                      whiteSpace: "pre-wrap", marginBottom: 10,
                    }}>
                      {c.details}
                    </div>
                  )}
                  {c.group_url && (
                    <a href={c.group_url} target="_blank" rel="noopener noreferrer"
                      style={{ fontSize: 12, color: "#7b61ff" }}>
                      CISA Baseline →
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