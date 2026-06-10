// web-frontend/src/components/PlaybooksPanel.tsx
import { useState, useEffect } from "react";

const API = import.meta.env.PUBLIC_API_URL ?? "http://localhost:3000";

type PlaybookSummary = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  conditions: Record<string, any>;
  action_count: number;
  action_types: string[];
};

type Execution = {
  id: number;
  playbook_id: string;
  playbook_name: string;
  report_id: string;
  triggered_at: string;
  action_results: { type: string; status: string; detail: string }[];
  overall_status: string;
};

const ACTION_COLORS: Record<string, string> = {
  ok: "#06d6a0",
  skipped: "#888",
  error: "#ff4d6a",
};

const ACTION_ICONS: Record<string, string> = {
  entra_revoke_sessions: "⬡",
  entra_disable_user: "⬡",
  entra_enable_user: "⬡",
  okta_suspend: "✦",
  okta_clear_sessions: "✦",
  auth0_block: "◈",
  splunk_saved_search: "⊕",
  webhook: "↗",
  teams: "💬",
};

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: "inline-block", padding: "2px 8px", borderRadius: 4,
      fontSize: 11, fontWeight: 700, textTransform: "uppercase",
      border: `1px solid ${color}44`, background: `${color}22`, color,
      fontFamily: "monospace",
    }}>{label}</span>
  );
}

function ConditionList({ conditions }: { conditions: Record<string, any> }) {
  const entries = Object.entries(conditions);
  if (entries.length === 0) return <span style={{ color: "#444", fontSize: 12 }}>No conditions</span>;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
      {entries.map(([key, value]) => (
        <span key={key} style={{
          fontSize: 11, fontFamily: "monospace",
          background: "rgba(123,97,255,0.08)", border: "1px solid rgba(123,97,255,0.2)",
          borderRadius: 4, padding: "3px 8px", color: "#c0c0d0",
        }}>
          <span style={{ color: "#7b61ff" }}>{key}</span>
          {" "}
          <span style={{ color: "#888" }}>
            {Array.isArray(value) ? value.join(", ") : String(value)}
          </span>
        </span>
      ))}
    </div>
  );
}

export default function PlaybooksPanel() {
  const [tab, setTab] = useState<"playbooks" | "history">("playbooks");
  const [playbooks, setPlaybooks] = useState<PlaybookSummary[]>([]);
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      fetch(`${API}/playbooks`).then(r => r.json()).then(d => setPlaybooks(d.playbooks ?? [])),
      fetch(`${API}/playbooks/executions?limit=50`).then(r => r.json()).then(d => setExecutions(d.executions ?? [])),
    ]).finally(() => setLoading(false));
  }, []);

  if (loading) return <div style={{ color: "#888", fontFamily: "monospace", padding: 32 }}>Loading...</div>;

  return (
    <div style={{ fontFamily: "system-ui, sans-serif" }}>
      {/* Stats bar */}
      <div style={{
        display: "flex", gap: 16, marginBottom: 24, flexWrap: "wrap",
      }}>
        {[
          { label: "Playbooks loaded", value: playbooks.length, color: "#7b61ff" },
          { label: "Enabled", value: playbooks.filter(p => p.enabled).length, color: "#06d6a0" },
          { label: "Executions total", value: executions.length, color: "#ff8c42" },
          { label: "Errors", value: executions.filter(e => e.overall_status === "error" || e.overall_status === "partial").length, color: "#ff4d6a" },
        ].map(stat => (
          <div key={stat.label} style={{
            background: "#13131e", border: "1px solid #2a2a3a",
            borderRadius: 8, padding: "14px 20px", flex: 1, minWidth: 120,
          }}>
            <div style={{ fontSize: 28, fontWeight: 700, fontFamily: "monospace", color: stat.color }}>{stat.value}</div>
            <div style={{ fontSize: 11, color: "#555", textTransform: "uppercase", letterSpacing: "0.06em" }}>{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 20, borderBottom: "1px solid #2a2a3a" }}>
        {[
          { id: "playbooks", label: `Playbooks (${playbooks.length})` },
          { id: "history", label: `Execution History (${executions.length})` },
        ].map(t => (
          <button key={t.id} onClick={() => setTab(t.id as any)} style={{
            padding: "8px 16px", background: "none", border: "none",
            borderBottom: tab === t.id ? "2px solid #7b61ff" : "2px solid transparent",
            color: tab === t.id ? "#7b61ff" : "#888",
            cursor: "pointer", fontSize: 13, fontWeight: 600,
          }}>{t.label}</button>
        ))}
      </div>

      {/* Playbooks list */}
      {tab === "playbooks" && (
        <div>
          {playbooks.length === 0 && (
            <div style={{ color: "#555", fontFamily: "monospace", fontSize: 13, padding: "40px 0", textAlign: "center" }}>
              No playbooks found. Add YAML files to the <code style={{ color: "#7b61ff" }}>playbooks/</code> directory.
            </div>
          )}
          {playbooks.map(pb => (
            <div key={pb.id} style={{
              background: "#13131e",
              border: `1px solid ${expanded === pb.id ? "#7b61ff44" : "#2a2a3a"}`,
              borderRadius: 10, padding: 18, marginBottom: 12,
              cursor: "pointer",
            }} onClick={() => setExpanded(expanded === pb.id ? null : pb.id)}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                    <span style={{ fontWeight: 700, fontSize: 15 }}>{pb.name}</span>
                    <Badge label={pb.enabled ? "enabled" : "disabled"} color={pb.enabled ? "#06d6a0" : "#555"} />
                  </div>
                  {pb.description && (
                    <div style={{ fontSize: 13, color: "#888", marginBottom: 10, lineHeight: 1.5 }}>{pb.description}</div>
                  )}
                  <ConditionList conditions={pb.conditions} />
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 6, flexShrink: 0 }}>
                  <div style={{ display: "flex", gap: 4 }}>
                    {pb.action_types.map((type, i) => (
                      <span key={i} title={type} style={{ fontSize: 14, color: "#7b61ff" }}>
                        {ACTION_ICONS[type] ?? "▶"}
                      </span>
                    ))}
                  </div>
                  <div style={{ fontSize: 11, color: "#555" }}>{pb.action_count} action{pb.action_count !== 1 ? "s" : ""}</div>
                  <div style={{ fontSize: 11, color: "#444", fontFamily: "monospace" }}>{pb.id}</div>
                </div>
              </div>

              {expanded === pb.id && (
                <div style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid #2a2a3a" }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: "#555", textTransform: "uppercase", fontFamily: "monospace", marginBottom: 10 }}>
                    Actions
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    {/* We only have action types here, not full action details */}
                    {pb.action_types.map((type, i) => (
                      <div key={i} style={{
                        display: "flex", alignItems: "center", gap: 8,
                        padding: "6px 10px", background: "rgba(123,97,255,0.05)",
                        borderRadius: 6, border: "1px solid rgba(123,97,255,0.1)",
                      }}>
                        <span style={{ fontSize: 13, color: "#7b61ff" }}>{ACTION_ICONS[type] ?? "▶"}</span>
                        <span style={{ fontSize: 12, fontFamily: "monospace", color: "#c0c0d0" }}>{type}</span>
                      </div>
                    ))}
                  </div>
                  <div style={{ marginTop: 10, fontSize: 11, color: "#444", fontFamily: "monospace" }}>
                    Edit: <code style={{ color: "#555" }}>playbooks/{pb.id}.yml</code>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Execution history */}
      {tab === "history" && (
        <div>
          {executions.length === 0 && (
            <div style={{ color: "#555", fontFamily: "monospace", fontSize: 13, padding: "40px 0", textAlign: "center" }}>
              No playbook executions yet. Playbooks run automatically after investigations complete.
            </div>
          )}
          {executions.map(ex => (
            <div key={ex.id} style={{
              background: "#13131e", border: "1px solid #2a2a3a",
              borderRadius: 10, padding: 16, marginBottom: 10,
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 3 }}>{ex.playbook_name}</div>
                  <div style={{ fontSize: 11, fontFamily: "monospace", color: "#555" }}>
                    Case: <span style={{ color: "#7b61ff" }}>{ex.report_id}</span>
                  </div>
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
                  <Badge
                    label={ex.overall_status}
                    color={ex.overall_status === "ok" ? "#06d6a0" : ex.overall_status === "partial" ? "#ff8c42" : "#ff4d6a"}
                  />
                  <div style={{ fontSize: 11, color: "#555" }}>
                    {new Date(ex.triggered_at).toLocaleString()}
                  </div>
                </div>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {ex.action_results.map((ar, i) => (
                  <div key={i} style={{
                    display: "flex", alignItems: "center", gap: 8,
                    padding: "5px 10px", background: "rgba(255,255,255,0.02)",
                    borderRadius: 5, borderLeft: `2px solid ${ACTION_COLORS[ar.status] ?? "#888"}`,
                  }}>
                    <span style={{ fontSize: 12, color: ACTION_COLORS[ar.status] ?? "#888", width: 50, flexShrink: 0 }}>
                      {ar.status}
                    </span>
                    <span style={{ fontSize: 11, fontFamily: "monospace", color: "#7b61ff", width: 160, flexShrink: 0 }}>
                      {ACTION_ICONS[ar.type] ?? "▶"} {ar.type}
                    </span>
                    <span style={{ fontSize: 11, color: "#666" }}>{ar.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}