import { useEffect, useState } from "react";

interface Technique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  url: string;
  count: number;
}

interface Case {
  report_id: string;
  created_at: string;
  title: string;
  severity: string;
  alert_type: string;
  confidence: number;
  kill_chain: string;
}

interface Profile {
  ip: string;
  first_seen: string;
  last_seen: string;
  total_incidents: number;
  total_events: number;
  compromised_users: string[];
  techniques: Technique[];
  cases: Case[];
}

interface Props {
  ip: string;
  apiUrl: string;
}

export default function AttackerProfile({ ip, apiUrl }: Props) {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${apiUrl}/attackers/${encodeURIComponent(ip)}`)
      .then((r) => { if (!r.ok) throw new Error("Not found"); return r.json(); })
      .then((d) => { setProfile(d); setLoading(false); })
      .catch((e) => { setError(e.message); setLoading(false); });
  }, [ip]);

  if (loading) return (
    <div style={{ color: "var(--text-muted)", fontFamily: "Geist Mono", fontSize: 13 }}>
      Loading attacker profile...
    </div>
  );

  if (error || !profile) return (
    <div style={{ color: "var(--critical)", fontFamily: "Geist Mono", fontSize: 13 }}>
      No cases found for IP {ip}
    </div>
  );

  const daysSinceFirst = Math.floor(
    (new Date(profile.last_seen).getTime() - new Date(profile.first_seen).getTime()) / 86400000
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>

      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
            <a href="/" style={{ color: "var(--text-muted)", fontSize: 13, textDecoration: "none" }}>← Cases</a>
            <span style={{ color: "var(--text-muted)" }}>/</span>
            <span style={{ fontSize: 12, color: "var(--text-muted)" }}>Attacker</span>
            <span style={{ color: "var(--text-muted)" }}>/</span>
            <span style={{ fontFamily: "Geist Mono", fontSize: 13, color: "var(--critical)", fontWeight: 600 }}>{profile.ip}</span>
          </div>
          <h1 style={{ fontSize: 22, fontWeight: 600, marginBottom: 4 }}>Attacker Profile</h1>
          <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>
            First seen {new Date(profile.first_seen).toLocaleString()} ·
            Last seen {new Date(profile.last_seen).toLocaleString()}
            {daysSinceFirst > 0 && ` · Active for ${daysSinceFirst} day${daysSinceFirst !== 1 ? "s" : ""}`}
          </div>
        </div>
        <div style={{
          padding: "16px 24px", borderRadius: 8,
          background: "rgba(255,77,106,0.05)",
          border: "1px solid rgba(255,77,106,0.3)",
          textAlign: "center",
        }}>
          <div style={{ fontFamily: "Geist Mono", fontSize: 32, fontWeight: 700, color: "var(--critical)" }}>
            {profile.total_incidents}
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>incidents</div>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
        <StatCard label="Total Events" value={profile.total_events || "—"} color="var(--critical)" />
        <StatCard label="Techniques Used" value={profile.techniques.length} color="var(--accent)" />
        <StatCard label="Compromised Users" value={profile.compromised_users.length} color="var(--high)" />
        <StatCard label="Active Days" value={daysSinceFirst || "<1"} color="var(--medium)" />
      </div>

      {/* Compromised users */}
      {profile.compromised_users.length > 0 && (
        <div className="card">
          <div className="card-header">Compromised Users</div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {profile.compromised_users.map((u) => (
              <span key={u} style={{
                fontFamily: "Geist Mono", fontSize: 12,
                padding: "4px 10px", borderRadius: 4,
                background: "rgba(255,140,66,0.1)",
                border: "1px solid rgba(255,140,66,0.3)",
                color: "var(--high)",
              }}>{u}</span>
            ))}
          </div>
        </div>
      )}

      {/* Techniques */}
      {profile.techniques.length > 0 && (
        <div className="card">
          <div className="card-header">MITRE ATT&amp;CK Techniques</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {profile.techniques.map((t) => (
              <div key={t.technique_id} style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                padding: "10px 14px", borderRadius: 6,
                background: "var(--bg-hover)", border: "1px solid var(--border)",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <a href={t.url} target="_blank" rel="noopener" style={{ textDecoration: "none" }}>
                    <span style={{ fontFamily: "Geist Mono", fontSize: 12, color: "var(--accent)", fontWeight: 600 }}>
                      {t.technique_id}
                    </span>
                  </a>
                  <span style={{ fontSize: 13, color: "var(--text-primary)" }}>{t.technique_name}</span>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{t.tactic}</span>
                </div>
                <span style={{
                  fontFamily: "Geist Mono", fontSize: 11,
                  padding: "2px 8px", borderRadius: 4,
                  background: "var(--accent-glow)",
                  border: "1px solid var(--accent)",
                  color: "var(--accent)",
                }}>×{t.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Incident timeline */}
      <div className="card">
        <div className="card-header">Incident Timeline</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {profile.cases.map((c, i) => (
            <a key={c.report_id} href={`/cases/${c.report_id}`} style={{ textDecoration: "none" }}>
              <div style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                padding: "10px 14px", borderRadius: 6,
                background: "var(--bg-hover)", border: "1px solid var(--border)",
                transition: "border-color 0.15s",
              }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = "var(--accent)")}
                onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--border)")}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{
                    fontFamily: "Geist Mono", fontSize: 10,
                    color: "var(--text-muted)", width: 20, textAlign: "center",
                  }}>{i + 1}</span>
                  <span className={`badge badge-${c.severity}`}>{c.severity}</span>
                  <span style={{ color: "var(--text-primary)", fontWeight: 500 }}>{c.title}</span>
                  {c.kill_chain && (
                    <span style={{ fontFamily: "Geist Mono", fontSize: 11, color: "var(--accent)" }}>
                      {c.kill_chain}
                    </span>
                  )}
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 12, flexShrink: 0 }}>
                  <span style={{
                    fontFamily: "Geist Mono", fontSize: 12, fontWeight: 600,
                    color: confidenceColor(c.confidence),
                  }}>{Math.round(c.confidence * 100)}%</span>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    {new Date(c.created_at).toLocaleString()}
                  </span>
                </div>
              </div>
            </a>
          ))}
        </div>
      </div>

    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: any; color: string }) {
  return (
    <div className="card" style={{ textAlign: "center" }}>
      <div style={{ fontFamily: "Geist Mono", fontSize: 28, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>{label}</div>
    </div>
  );
}

function confidenceColor(c: number): string {
  if (c >= 0.7) return "var(--critical)";
  if (c >= 0.5) return "var(--high)";
  if (c >= 0.3) return "var(--medium)";
  return "var(--low)";
}