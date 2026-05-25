import { useEffect, useState } from "react";

interface Case {
  report_id: string;
  created_at: string;
  title: string;
  severity: string;
  alert_type: string;
  confidence: number;
  kill_chain: string;
  summary: string;
}

interface Props {
  apiUrl: string;
}

export default function CaseList({ apiUrl }: Props) {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${apiUrl}/cases`)
      .then((r) => r.json())
      .then((data) => { setCases(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  if (loading) return (
    <div style={{ color: "var(--text-muted)", fontFamily: "Geist Mono", fontSize: 13 }}>
      Loading cases...
    </div>
  );

  if (cases.length === 0) return (
    <div style={{ color: "var(--text-muted)", fontFamily: "Geist Mono", fontSize: 13 }}>
      No cases yet. <a href="/investigate" style={{ color: "var(--accent)" }}>Start an investigation →</a>
    </div>
  );

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: "var(--text-primary)" }}>Case Files</h1>
        <a href="/investigate" style={{
          background: "var(--accent)",
          color: "#fff",
          padding: "8px 16px",
          borderRadius: 6,
          textDecoration: "none",
          fontSize: 13,
          fontWeight: 500,
        }}>+ New Investigation</a>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {cases.map((c) => (
          <a key={c.report_id} href={`/cases/${c.report_id}`} style={{ textDecoration: "none", color: "var(--text-primary)" }}>
            <div className="card" style={{ cursor: "pointer", transition: "border-color 0.15s" }}
              onMouseEnter={e => (e.currentTarget.style.borderColor = "var(--accent)")}
              onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--border)")}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                    <span className={`badge badge-${c.severity}`}>{c.severity}</span>
                    <span style={{ fontFamily: "Geist Mono", fontSize: 11, color: "var(--text-secondary)" }}>
                      {c.report_id}
                    </span>
                  </div>
                  <div style={{ fontWeight: 600, fontSize: 15, marginBottom: 4, color: "var(--text-primary)" }}>
                    {c.title}
                  </div>
                  <div style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 8 }}>
                    {c.summary}
                  </div>
                  {c.kill_chain && (
                    <div style={{ fontFamily: "Geist Mono", fontSize: 11, color: "var(--accent)" }}>
                      {c.kill_chain}
                    </div>
                  )}
                </div>
                <div style={{ textAlign: "right", flexShrink: 0 }}>
                  <div style={{ fontFamily: "Geist Mono", fontSize: 20, fontWeight: 600, color: confidenceColor(c.confidence) }}>
                    {Math.round(c.confidence * 100)}%
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)" }}>confidence</div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>
                    {new Date(c.created_at).toLocaleString()}
                  </div>
                </div>
              </div>
            </div>
          </a>
        ))}
      </div>
    </div>
  );
}

function confidenceColor(c: number): string {
  if (c >= 0.7) return "var(--critical)";
  if (c >= 0.5) return "var(--high)";
  if (c >= 0.3) return "var(--medium)";
  return "var(--low)";
}