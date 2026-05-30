import { useEffect, useState } from "react";

interface Pattern {
  id: string;
  name: string;
  description: string;
  category: string;
  search_terms: string;
  index: string;
  earliest: string;
  mitre_techniques: string[];
  severity: string;
}

interface Props {
  apiUrl: string;
}

export default function PatternLibrary({ apiUrl }: Props) {
  const [patterns, setPatterns] = useState<Pattern[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("all");
  const [launching, setLaunching] = useState<string | null>(null);
  const [launched, setLaunched] = useState<Record<string, string>>({});

  useEffect(() => {
    fetch(`${apiUrl}/patterns`)
      .then((r) => r.json())
      .then((data) => { setPatterns(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const categories = ["all", ...Array.from(new Set(patterns.map((p) => p.category)))];
  const filtered = filter === "all" ? patterns : patterns.filter((p) => p.category === filter);

  async function launchInvestigation(pattern: Pattern) {
    setLaunching(pattern.id);
    try {
      const res = await fetch(`${apiUrl}/investigate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: pattern.name,
          search_terms: pattern.search_terms,
          index: pattern.index,
          earliest: pattern.earliest,
          latest: "now",
        }),
      });
      const data = await res.json();
      if (data.report_id) {
        setLaunched((prev) => ({ ...prev, [pattern.id]: data.report_id }));
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLaunching(null);
    }
  }

  const severityColor: Record<string, string> = {
    critical: "var(--critical)",
    high: "var(--high)",
    medium: "var(--medium)",
    low: "var(--low)",
  };

  if (loading) return (
    <div style={{ color: "var(--text-muted)", fontFamily: "Geist Mono", fontSize: 13 }}>
      Loading patterns...
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 600, color: "var(--text-primary)", marginBottom: 6 }}>
            Attack Pattern Library
          </h1>
          <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
            Pre-built investigation templates. Click any pattern to launch an immediate investigation.
          </p>
        </div>
      </div>

      {/* Category filter */}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setFilter(cat)}
            style={{
              padding: "4px 12px",
              borderRadius: 4,
              border: `1px solid ${filter === cat ? "var(--accent)" : "var(--border)"}`,
              background: filter === cat ? "var(--accent-glow)" : "transparent",
              color: filter === cat ? "var(--accent)" : "var(--text-muted)",
              fontSize: 12,
              fontFamily: "Geist Mono",
              cursor: "pointer",
              textTransform: "uppercase",
              transition: "all 0.15s",
            }}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Pattern grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 16 }}>
        {filtered.map((pattern) => {
          const color = severityColor[pattern.severity] ?? "var(--text-muted)";
          const isLaunching = launching === pattern.id;
          const reportId = launched[pattern.id];

          return (
            <div key={pattern.id} className="card" style={{
              display: "flex", flexDirection: "column", gap: 12,
              borderColor: reportId ? "rgba(6,214,160,0.3)" : "var(--border)",
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                    <span style={{
                      fontSize: 10, fontFamily: "Geist Mono", fontWeight: 600,
                      padding: "2px 6px", borderRadius: 3,
                      background: `${color}22`, color, border: `1px solid ${color}44`,
                      textTransform: "uppercase",
                    }}>{pattern.severity}</span>
                    <span style={{
                      fontSize: 10, fontFamily: "Geist Mono",
                      padding: "2px 6px", borderRadius: 3,
                      background: "var(--bg-hover)", color: "var(--text-muted)",
                      border: "1px solid var(--border)", textTransform: "uppercase",
                    }}>{pattern.category}</span>
                  </div>
                  <div style={{ fontSize: 15, fontWeight: 600, color: "var(--text-primary)" }}>{pattern.name}</div>
                </div>
              </div>

              <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, margin: 0 }}>
                {pattern.description}
              </p>

              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono" }}>
                  <span style={{ color: "var(--text-secondary)" }}>search: </span>{pattern.search_terms}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "Geist Mono" }}>
                  <span style={{ color: "var(--text-secondary)" }}>window: </span>{pattern.earliest} to now
                </div>
              </div>

              {pattern.mitre_techniques.length > 0 && (
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {pattern.mitre_techniques.map((t) => (
                    <span key={t} style={{
                      fontFamily: "Geist Mono", fontSize: 10,
                      padding: "2px 6px", borderRadius: 3,
                      background: "rgba(123,97,255,0.1)",
                      color: "var(--accent)",
                      border: "1px solid rgba(123,97,255,0.2)",
                    }}>{t}</span>
                  ))}
                </div>
              )}

              <div style={{ marginTop: "auto", display: "flex", gap: 8, alignItems: "center" }}>
                {reportId ? (
                  <a
                    href={`/cases/${reportId}`}
                    style={{
                      flex: 1, textAlign: "center",
                      padding: "8px 16px", borderRadius: 6,
                      background: "rgba(6,214,160,0.1)",
                      border: "1px solid rgba(6,214,160,0.3)",
                      color: "var(--low)", fontSize: 13, fontWeight: 600,
                      textDecoration: "none",
                    }}
                  >
                    ✓ View Report →
                  </a>
                ) : (
                  <button
                    onClick={() => launchInvestigation(pattern)}
                    disabled={isLaunching}
                    style={{
                      flex: 1,
                      padding: "8px 16px", borderRadius: 6,
                      background: isLaunching ? "var(--bg-hover)" : "var(--accent)",
                      border: "none",
                      color: isLaunching ? "var(--text-muted)" : "#fff",
                      fontSize: 13, fontWeight: 600,
                      cursor: isLaunching ? "not-allowed" : "pointer",
                      transition: "all 0.15s",
                    }}
                  >
                    {isLaunching ? "Investigating..." : "▶ Investigate"}
                  </button>
                )}
                <a
                  href={`/investigate?title=${encodeURIComponent(pattern.name)}&search_terms=${encodeURIComponent(pattern.search_terms)}&index=${pattern.index}&earliest=${pattern.earliest}`}
                  style={{
                    padding: "8px 12px", borderRadius: 6,
                    background: "transparent",
                    border: "1px solid var(--border)",
                    color: "var(--text-muted)", fontSize: 12,
                    textDecoration: "none", fontFamily: "Geist Mono",
                    transition: "all 0.15s",
                  }}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLAnchorElement).style.borderColor = "var(--accent)"; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLAnchorElement).style.borderColor = "var(--border)"; }}
                >
                  customize
                </a>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}