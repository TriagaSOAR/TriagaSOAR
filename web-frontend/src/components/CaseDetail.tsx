import { useEffect, useState } from "react";

interface Finding {
  depth: number;
  finding: string;
  confidence: number;
  pivot_reason: string;
}

interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  parent_id: string;
  parent_name: string;
  tactic: string;
  url: string;
}

interface BlastRadius {
  attacker_ips: string[];
  compromised_users: string[];
  affected_hosts: string[];
  related_events: { entity: string; type: string; host: string; event_count: number }[];
  risk_summary: string;
}

interface PriorCase {
  report_id: string;
  title: string;
  severity: string;
  kill_chain: string;
  created_at: string;
  matched_entity: { type: string; value: string };
}

interface Report {
  report_id: string;
  generated_at: string;
  case_id: number;
  alert: { title: string; index: string; time_range: string };
  severity: string;
  alert_type: string;
  final_confidence: number;
  summary: string;
  findings: Finding[];
  queries_run: string[];
  adversarial_review: { verdict: string; critique: string };
  mitre_techniques: MitreTechnique[];
  kill_chain_summary: string;
  recommendations: string[];
  blast_radius: BlastRadius;
  prior_cases: PriorCase[];
  repeated_attacker: boolean;
  threat_intel: Record<string, any>;
}

interface Props {
  reportId: string;
  apiUrl: string;
}

export default function CaseDetail({ reportId, apiUrl }: Props) {
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${apiUrl}/cases/${reportId}`)
      .then((r) => r.json())
      .then((data) => { setReport(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, [reportId]);

  if (loading) {
    return (
      <div style={{ color: "var(--text-muted)", fontFamily: "Geist Mono", fontSize: 13 }}>
        Loading case...
      </div>
    );
  }

  if (!report) {
    return (
      <div style={{ color: "var(--critical)", fontFamily: "Geist Mono", fontSize: 13 }}>
        Case not found.
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>

      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
            <a href="/" style={{ color: "var(--text-muted)", fontSize: 13, textDecoration: "none" }}>← Cases</a>
            <span style={{ color: "var(--text-muted)" }}>/</span>
            <span style={{ fontFamily: "Geist Mono", fontSize: 12, color: "var(--text-secondary)" }}>{report.report_id}</span>
            {report.repeated_attacker && (
              <span style={{
                background: "rgba(255,77,106,0.15)",
                color: "var(--critical)",
                border: "1px solid rgba(255,77,106,0.3)",
                padding: "2px 8px",
                borderRadius: 4,
                fontSize: 11,
                fontFamily: "Geist Mono",
                fontWeight: 500,
              }}>⚠ REPEATED ATTACKER</span>
            )}
          </div>
          <h1 style={{ fontSize: 22, fontWeight: 600, marginBottom: 4 }}>{report.alert.title}</h1>
          <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>
            {report.alert.index} · {report.alert.time_range} · {new Date(report.generated_at).toLocaleString()}
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ fontFamily: "Geist Mono", fontSize: 32, fontWeight: 700, color: confidenceColor(report.final_confidence) }}>
            {Math.round(report.final_confidence * 100)}%
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>confidence</div>
          <span className={`badge badge-${report.severity}`} style={{ marginTop: 8, display: "inline-block" }}>
            {report.severity}
          </span>
        </div>
      </div>

      {/* Summary */}
      <div className="card">
        <div className="card-header">Summary</div>
        <p style={{ color: "var(--text-secondary)", lineHeight: 1.7 }}>{report.summary}</p>
      </div>

      {/* Prior cases warning */}
      {report.prior_cases?.length > 0 && (
        <div className="card" style={{ borderColor: "rgba(255,77,106,0.4)", background: "rgba(255,77,106,0.05)" }}>
          <div className="card-header" style={{ color: "var(--critical)" }}>⚠ Prior Cases — Repeated Attacker</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {report.prior_cases.map((pc) => (
              <a key={pc.report_id} href={`/cases/${pc.report_id}`} style={{ textDecoration: "none" }}>
                <div style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  padding: "10px 12px", borderRadius: 6, background: "var(--bg-hover)",
                  border: "1px solid var(--border)",
                }}>
                  <div>
                    <span className={`badge badge-${pc.severity}`} style={{ marginRight: 8 }}>{pc.severity}</span>
                    <span style={{ color: "var(--text-primary)", fontWeight: 500 }}>{pc.title}</span>
                    <span style={{ fontFamily: "Geist Mono", fontSize: 11, color: "var(--text-muted)", marginLeft: 8 }}>
                      matched {pc.matched_entity.type}: {pc.matched_entity.value}
                    </span>
                  </div>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    {new Date(pc.created_at).toLocaleString()}
                  </span>
                </div>
              </a>
            ))}
          </div>
        </div>
      )}

      {/* MITRE Kill Chain */}
      {report.mitre_techniques?.length > 0 && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <div className="card-header" style={{ marginBottom: 0 }}>MITRE ATT&amp;CK Kill Chain</div>
            <a
              href={`${apiUrl}/cases/${report.report_id}/navigator`}
              download={`navigator_${report.report_id}.json`}
              style={{
                fontSize: 12,
                color: "var(--accent)",
                textDecoration: "none",
                fontFamily: "Geist Mono",
                padding: "4px 10px",
                border: "1px solid var(--accent)",
                borderRadius: 4,
                transition: "all 0.15s",
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLAnchorElement).style.background = "var(--accent-glow)"; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLAnchorElement).style.background = "transparent"; }}
            >
              ↓ Navigator Export
            </a>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 0, flexWrap: "wrap" }}>
            {report.mitre_techniques.map((t, i) => (
              <div key={t.technique_id} style={{ display: "flex", alignItems: "center" }}>
                <a href={t.url} target="_blank" rel="noopener" style={{ textDecoration: "none" }}>
                  <div
                    style={{
                      padding: "10px 14px",
                      borderRadius: 8,
                      border: "1px solid var(--border)",
                      background: "var(--bg-hover)",
                      transition: "border-color 0.15s",
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
                    onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
                  >
                    <div style={{ fontFamily: "Geist Mono", fontSize: 12, color: "var(--accent)", fontWeight: 600 }}>
                      {t.technique_id}
                    </div>
                    <div style={{ fontSize: 13, color: "var(--text-primary)", fontWeight: 500, marginTop: 2 }}>
                      {t.technique_name}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                      {t.tactic}
                    </div>
                  </div>
                </a>
                {i < report.mitre_techniques.length - 1 && (
                  <span style={{ color: "var(--text-muted)", margin: "0 8px", fontSize: 18 }}>→</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings timeline */}
      <div className="card">
        <div className="card-header">Investigation Timeline</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {report.findings.map((f, i) => (
            <div key={i} style={{
              display: "flex", gap: 16,
              paddingBottom: 12,
              borderBottom: i < report.findings.length - 1 ? "1px solid var(--border)" : "none",
            }}>
              <div style={{ flexShrink: 0 }}>
                <div style={{
                  width: 28, height: 28, borderRadius: "50%",
                  background: "var(--bg-hover)", border: "1px solid var(--border)",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontFamily: "Geist Mono", fontSize: 11, color: "var(--text-muted)",
                }}>{i + 1}</div>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ fontSize: 13, color: "var(--text-primary)" }}>{f.finding}</span>
                  <span style={{
                    fontFamily: "Geist Mono", fontSize: 12, fontWeight: 600,
                    color: confidenceColor(f.confidence), flexShrink: 0, marginLeft: 16,
                  }}>{Math.round(f.confidence * 100)}%</span>
                </div>
                {f.pivot_reason && (
                  <div style={{ fontSize: 12, color: "var(--text-muted)", fontStyle: "italic" }}>
                    → {f.pivot_reason}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Blast Radius */}
      {report.blast_radius && (
        <div className="card">
          <div className="card-header">Blast Radius</div>
          <div style={{ marginBottom: 12, fontSize: 14, color: "var(--text-primary)", fontWeight: 500 }}>
            {report.blast_radius.risk_summary}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
            <div style={{ padding: "12px", borderRadius: 6, background: "var(--bg-hover)", border: "1px solid var(--border)" }}>
              <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono", marginBottom: 6 }}>ATTACKER IPS</div>
              {report.blast_radius.attacker_ips.map((ip) => (
                <div key={ip} style={{ fontFamily: "Geist Mono", fontSize: 13, color: "var(--critical)" }}>{ip}</div>
              ))}
            </div>
            <div style={{ padding: "12px", borderRadius: 6, background: "var(--bg-hover)", border: "1px solid var(--border)" }}>
              <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono", marginBottom: 6 }}>COMPROMISED USERS</div>
              {report.blast_radius.compromised_users.map((u) => (
                <div key={u} style={{ fontFamily: "Geist Mono", fontSize: 13, color: "var(--high)" }}>{u}</div>
              ))}
            </div>
            <div style={{ padding: "12px", borderRadius: 6, background: "var(--bg-hover)", border: "1px solid var(--border)" }}>
              <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono", marginBottom: 6 }}>AFFECTED HOSTS</div>
              {report.blast_radius.affected_hosts.length > 0
                ? report.blast_radius.affected_hosts.map((h) => (
                    <div key={h} style={{ fontFamily: "Geist Mono", fontSize: 13, color: "var(--medium)" }}>{h}</div>
                  ))
                : <div style={{ fontSize: 13, color: "var(--text-muted)" }}>None detected</div>
              }
            </div>
          </div>
        </div>
      )}

      {/* Threat Intel */}
      {report.threat_intel && Object.keys(report.threat_intel).length > 0 && (
        <div className="card">
          <div className="card-header">Threat Intelligence</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {Object.entries(report.threat_intel).map(([ip, intel]: [string, any]) => (
              <div key={ip} style={{
                padding: "12px",
                borderRadius: 8,
                background: "var(--bg-hover)",
                border: `1px solid ${intel.available && intel.abuse_confidence_score > 0 ? "rgba(255,77,106,0.3)" : "var(--border)"}`,
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                  <span style={{ fontFamily: "Geist Mono", fontSize: 13, color: "var(--critical)", fontWeight: 600 }}>{ip}</span>
                  {intel.available ? (
                    <span style={{
                      fontFamily: "Geist Mono", fontSize: 11, fontWeight: 600,
                      padding: "2px 8px", borderRadius: 4,
                      background: threatLevelBg(intel.threat_level),
                      color: threatLevelColor(intel.threat_level),
                      border: `1px solid ${threatLevelColor(intel.threat_level)}44`,
                      textTransform: "uppercase",
                    }}>{intel.threat_level}</span>
                  ) : (
                    <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{intel.message}</span>
                  )}
                </div>
                {intel.available && (
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
                    <Stat label="Abuse Score" value={`${intel.abuse_confidence_score}%`} highlight={intel.abuse_confidence_score > 50} />
                    <Stat label="Country" value={intel.country_code} />
                    <Stat label="ISP" value={intel.isp} />
                    <Stat label="Total Reports" value={intel.total_reports} highlight={intel.total_reports > 10} />
                    <Stat label="Distinct Users" value={intel.num_distinct_users} />
                    <Stat label="Usage Type" value={intel.usage_type} />
                    {intel.is_tor && <Stat label="TOR Exit Node" value="YES" highlight />}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Adversarial Review */}
      <div className="card">
        <div className="card-header">Adversarial Review</div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <span style={{
            fontFamily: "Geist Mono", fontSize: 11, fontWeight: 600,
            color: report.adversarial_review.verdict === "approved" ? "var(--low)" : "var(--medium)",
            background: report.adversarial_review.verdict === "approved" ? "rgba(6,214,160,0.1)" : "rgba(255,209,102,0.1)",
            border: `1px solid ${report.adversarial_review.verdict === "approved" ? "rgba(6,214,160,0.3)" : "rgba(255,209,102,0.3)"}`,
            padding: "2px 8px", borderRadius: 4, textTransform: "uppercase",
          }}>{report.adversarial_review.verdict}</span>
        </div>
        <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7 }}>
          {report.adversarial_review.critique}
        </p>
      </div>

      {/* Recommendations */}
      {report.recommendations?.length > 0 && (
        <div className="card">
          <div className="card-header">Recommendations</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {report.recommendations.map((r, i) => (
              <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <span style={{ color: "var(--accent)", fontFamily: "Geist Mono", fontSize: 13, flexShrink: 0 }}>→</span>
                <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{r}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Queries run */}
      {report.queries_run?.length > 0 && (
        <div className="card">
          <div className="card-header">SPL Queries Executed</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {report.queries_run.map((q, i) => (
              <div key={i} style={{
                fontFamily: "Geist Mono", fontSize: 12, color: "var(--text-secondary)",
                padding: "8px 12px", borderRadius: 6, background: "var(--bg-hover)",
                border: "1px solid var(--border)",
              }}>{q}</div>
            ))}
          </div>
        </div>
      )}

    </div>
  );
}

function Stat({ label, value, highlight = false }: { label: string; value: any; highlight?: boolean }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "Geist Mono", marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 13, color: highlight ? "var(--critical)" : "var(--text-primary)", fontWeight: highlight ? 600 : 400 }}>{value}</div>
    </div>
  );
}

function threatLevelColor(level: string): string {
  const colors: Record<string, string> = {
    critical: "var(--critical)",
    high: "var(--high)",
    medium: "var(--medium)",
    low: "var(--low)",
    clean: "var(--low)",
  };
  return colors[level] ?? "var(--text-muted)";
}

function threatLevelBg(level: string): string {
  const colors: Record<string, string> = {
    critical: "rgba(255,77,106,0.15)",
    high: "rgba(255,140,66,0.15)",
    medium: "rgba(255,209,102,0.15)",
    low: "rgba(6,214,160,0.15)",
    clean: "rgba(6,214,160,0.1)",
  };
  return colors[level] ?? "var(--bg-hover)";
}

function confidenceColor(c: number): string {
  if (c >= 0.7) return "var(--critical)";
  if (c >= 0.5) return "var(--high)";
  if (c >= 0.3) return "var(--medium)";
  return "var(--low)";
}