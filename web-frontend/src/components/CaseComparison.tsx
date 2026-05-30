import { useState } from "react";

interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  url: string;
}

interface CaseData {
  report_id: string;
  title: string;
  severity: string;
  confidence: number;
  summary: string;
  mitre_techniques: MitreTechnique[];
  kill_chain: string;
  findings_count: number;
  blast_radius: {
    attacker_ips: string[];
    compromised_users: string[];
    affected_hosts: string[];
    risk_summary: string;
  };
  adversarial_review: { verdict: string; critique: string };
  generated_at: string;
  verdict: string | null;
}

interface Diff {
  techniques_only_in_a: string[];
  techniques_only_in_b: string[];
  techniques_in_both: string[];
  severity_match: boolean;
  confidence_delta: number;
}

interface CompareResult {
  case_a: CaseData;
  case_b: CaseData;
  diff: Diff;
}

interface Props {
  apiUrl: string;
  initialA?: string;
  initialB?: string;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
};

export default function CaseComparison({ apiUrl, initialA = "", initialB = "" }: Props) {
  const [idA, setIdA] = useState(initialA);
  const [idB, setIdB] = useState(initialB);
  const [result, setResult] = useState<CompareResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleCompare() {
    if (!idA.trim() || !idB.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch(`${apiUrl}/cases/compare?a=${encodeURIComponent(idA)}&b=${encodeURIComponent(idB)}`);
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail ?? `HTTP ${res.status}`);
      }
      setResult(await res.json());
    } catch (e: any) {
      setError(e.message ?? "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 600, color: "var(--text-primary)", marginBottom: 6 }}>
          Case Comparison
        </h1>
        <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          Compare two IR reports side by side — techniques, severity, confidence, blast radius.
        </p>
      </div>

      {/* Input */}
      <div className="card" style={{ display: "flex", gap: 12, alignItems: "flex-end" }}>
        <div style={{ flex: 1 }}>
          <label style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono", display: "block", marginBottom: 6 }}>CASE A</label>
          <input
            value={idA}
            onChange={(e) => setIdA(e.target.value)}
            placeholder="IR-20260529-123456"
            style={{ width: "100%" }}
          />
        </div>
        <div style={{ flex: 1 }}>
          <label style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono", display: "block", marginBottom: 6 }}>CASE B</label>
          <input
            value={idB}
            onChange={(e) => setIdB(e.target.value)}
            placeholder="IR-20260530-789012"
            style={{ width: "100%" }}
          />
        </div>
        <button
          onClick={handleCompare}
          disabled={loading || !idA.trim() || !idB.trim()}
          style={{
            padding: "10px 20px", borderRadius: 6,
            background: loading ? "var(--bg-hover)" : "var(--accent)",
            color: loading ? "var(--text-muted)" : "#fff",
            border: "none", fontSize: 13, fontWeight: 600,
            cursor: loading ? "not-allowed" : "pointer",
            whiteSpace: "nowrap",
          }}
        >
          {loading ? "Comparing..." : "Compare →"}
        </button>
      </div>

      {error && (
        <div style={{
          padding: 16, borderRadius: 8,
          background: "rgba(255,77,106,0.05)",
          border: "1px solid rgba(255,77,106,0.3)",
          color: "var(--critical)", fontSize: 13,
        }}>✗ {error}</div>
      )}

      {result && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>

          {/* Diff summary */}
          <div className="card" style={{ background: "rgba(123,97,255,0.05)", borderColor: "rgba(123,97,255,0.2)" }}>
            <div className="card-header">Diff Summary</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
              <DiffStat
                label="Confidence Delta"
                value={`${result.diff.confidence_delta > 0 ? "+" : ""}${result.diff.confidence_delta}%`}
                color={Math.abs(result.diff.confidence_delta) > 20 ? "var(--high)" : "var(--text-primary)"}
              />
              <DiffStat
                label="Severity Match"
                value={result.diff.severity_match ? "Yes" : "No"}
                color={result.diff.severity_match ? "var(--low)" : "var(--high)"}
              />
              <DiffStat
                label="Shared Techniques"
                value={result.diff.techniques_in_both.length}
                color="var(--accent)"
              />
            </div>
            {result.diff.techniques_only_in_a.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono", marginBottom: 6 }}>
                  ONLY IN A
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {result.diff.techniques_only_in_a.map((t) => (
                    <TechPill key={t} id={t} color="rgba(255,77,106,0.6)" />
                  ))}
                </div>
              </div>
            )}
            {result.diff.techniques_only_in_b.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono", marginBottom: 6 }}>
                  ONLY IN B
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {result.diff.techniques_only_in_b.map((t) => (
                    <TechPill key={t} id={t} color="rgba(6,214,160,0.6)" />
                  ))}
                </div>
              </div>
            )}
            {result.diff.techniques_in_both.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono", marginBottom: 6 }}>
                  IN BOTH
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {result.diff.techniques_in_both.map((t) => (
                    <TechPill key={t} id={t} color="rgba(123,97,255,0.6)" />
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Side by side */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <CasePanel label="A" c={result.case_a} />
            <CasePanel label="B" c={result.case_b} />
          </div>
        </div>
      )}
    </div>
  );
}

function CasePanel({ label, c }: { label: string; c: CaseData }) {
  const color = SEVERITY_COLOR[c.severity] ?? "var(--text-muted)";
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div className="card" style={{ borderColor: color }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
          <div>
            <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "Geist Mono", marginBottom: 4 }}>
              CASE {label}
            </div>
            <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)", marginBottom: 4 }}>{c.title}</div>
            <div style={{ fontFamily: "Geist Mono", fontSize: 11, color: "var(--text-muted)" }}>{c.report_id}</div>
          </div>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontFamily: "Geist Mono", fontSize: 24, fontWeight: 700, color }}>
              {Math.round(c.confidence * 100)}%
            </div>
            <span className={`badge badge-${c.severity}`}>{c.severity}</span>
          </div>
        </div>
        <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6, margin: 0 }}>{c.summary}</p>
        <div style={{ marginTop: 8 }}>
          <a href={`/cases/${c.report_id}`} style={{
            fontSize: 11, color: "var(--accent)", textDecoration: "none",
            fontFamily: "Geist Mono",
          }}>View full report →</a>
        </div>
      </div>

      <div className="card">
        <div className="card-header">MITRE Techniques ({c.mitre_techniques.length})</div>
        {c.mitre_techniques.length === 0 ? (
          <span style={{ fontSize: 12, color: "var(--text-muted)" }}>None mapped</span>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {c.mitre_techniques.map((t) => (
              <div key={t.technique_id} style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span style={{ fontFamily: "Geist Mono", fontSize: 11, color: "var(--accent)", fontWeight: 600 }}>
                  {t.technique_id}
                </span>
                <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{t.technique_name}</span>
                <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{t.tactic}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">Blast Radius</div>
        <div style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 8 }}>
          {c.blast_radius?.risk_summary ?? "Unknown"}
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {(c.blast_radius?.attacker_ips ?? []).map((ip) => (
            <span key={ip} style={{ fontFamily: "Geist Mono", fontSize: 11, color: "var(--critical)" }}>{ip}</span>
          ))}
          {(c.blast_radius?.compromised_users ?? []).map((u) => (
            <span key={u} style={{ fontFamily: "Geist Mono", fontSize: 11, color: "var(--high)" }}>{u}</span>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="card-header">Adversarial Review</div>
        <span style={{
          fontFamily: "Geist Mono", fontSize: 10, fontWeight: 600,
          padding: "2px 6px", borderRadius: 3, textTransform: "uppercase",
          background: c.adversarial_review?.verdict === "approved" ? "rgba(6,214,160,0.1)" : "rgba(255,209,102,0.1)",
          color: c.adversarial_review?.verdict === "approved" ? "var(--low)" : "var(--medium)",
          border: `1px solid ${c.adversarial_review?.verdict === "approved" ? "rgba(6,214,160,0.3)" : "rgba(255,209,102,0.3)"}`,
        }}>{c.adversarial_review?.verdict ?? "—"}</span>
        <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6, marginTop: 8, marginBottom: 0 }}>
          {c.adversarial_review?.critique ?? ""}
        </p>
      </div>

      {c.verdict && (
        <div style={{
          padding: "8px 12px", borderRadius: 6,
          background: c.verdict === "confirmed" ? "rgba(6,214,160,0.05)" : "rgba(120,120,120,0.05)",
          border: `1px solid ${c.verdict === "confirmed" ? "rgba(6,214,160,0.2)" : "rgba(120,120,120,0.2)"}`,
          fontSize: 12, fontFamily: "Geist Mono",
          color: c.verdict === "confirmed" ? "var(--low)" : "var(--text-muted)",
        }}>
          {c.verdict === "confirmed" ? "✓ Confirmed incident" : "✗ Marked as false positive"}
        </div>
      )}
    </div>
  );
}

function DiffStat({ label, value, color }: { label: string; value: any; color: string }) {
  return (
    <div style={{ padding: "10px 12px", borderRadius: 6, background: "var(--bg-hover)", border: "1px solid var(--border)" }}>
      <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "Geist Mono", marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, color }}>{value}</div>
    </div>
  );
}

function TechPill({ id, color }: { id: string; color: string }) {
  return (
    <span style={{
      fontFamily: "Geist Mono", fontSize: 10, fontWeight: 600,
      padding: "2px 8px", borderRadius: 3,
      background: color.replace("0.6", "0.15"),
      color, border: `1px solid ${color.replace("0.6", "0.3")}`,
    }}>{id}</span>
  );
}