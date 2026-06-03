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

interface BulkResult {
  pattern_id: string;
  pattern_name: string;
  status: "pending" | "running" | "done" | "error";
  report_id?: string;
  severity?: string;
  confidence?: number;
  error?: string;
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

  // Bulk run state
  const [bulkRunning, setBulkRunning] = useState(false);
  const [bulkResults, setBulkResults] = useState<BulkResult[]>([]);
  const [bulkTarget, setBulkTarget] = useState<"all" | "edr" | null>(null);
  const [bulkCurrent, setBulkCurrent] = useState<number>(0);

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

  async function runBulk(target: "all" | "edr") {
    const toRun = target === "edr"
      ? patterns.filter((p) => p.category === "edr-evasion")
      : patterns;

    if (toRun.length === 0) return;

    setBulkTarget(target);
    setBulkRunning(true);
    setBulkCurrent(0);
    setBulkResults(toRun.map((p) => ({
      pattern_id: p.id,
      pattern_name: p.name,
      status: "pending",
    })));

    for (let i = 0; i < toRun.length; i++) {
      const pattern = toRun[i];
      setBulkCurrent(i + 1);
      setBulkResults((prev) => prev.map((r) =>
        r.pattern_id === pattern.id ? { ...r, status: "running" } : r
      ));

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
        setBulkResults((prev) => prev.map((r) =>
          r.pattern_id === pattern.id ? {
            ...r,
            status: "done",
            report_id: data.report_id,
            severity: data.severity,
            confidence: data.final_confidence,
          } : r
        ));
        if (data.report_id) {
          setLaunched((prev) => ({ ...prev, [pattern.id]: data.report_id }));
        }
      } catch (e: any) {
        setBulkResults((prev) => prev.map((r) =>
          r.pattern_id === pattern.id ? { ...r, status: "error", error: e.message } : r
        ));
      }
    }

    setBulkRunning(false);
  }

  function clearBulk() {
    setBulkResults([]);
    setBulkTarget(null);
    setBulkCurrent(0);
  }

  const severityColor: Record<string, string> = {
    critical: "var(--critical)",
    high: "var(--high)",
    medium: "var(--medium)",
    low: "var(--low)",
  };

  const edrCount = patterns.filter((p) => p.category === "edr-evasion").length;
  const bulkDone = bulkResults.filter((r) => r.status === "done").length;
  const bulkErrors = bulkResults.filter((r) => r.status === "error").length;

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
            {patterns.length} patterns · {edrCount} EDR evasion hunts
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            onClick={() => runBulk("edr")}
            disabled={bulkRunning}
            style={{
              padding: "8px 16px", borderRadius: 6,
              background: bulkRunning ? "var(--bg-hover)" : "rgba(255,77,106,0.1)",
              border: `1px solid ${bulkRunning ? "var(--border)" : "rgba(255,77,106,0.4)"}`,
              color: bulkRunning ? "var(--text-muted)" : "var(--critical)",
              fontSize: 13, fontWeight: 600, fontFamily: "Geist Mono",
              cursor: bulkRunning ? "not-allowed" : "pointer",
              transition: "all 0.15s",
            }}
          >
            {bulkRunning && bulkTarget === "edr" ? `Running ${bulkCurrent}/${edrCount}...` : `⚡ Run All EDR Hunts (${edrCount})`}
          </button>
          <button
            onClick={() => runBulk("all")}
            disabled={bulkRunning}
            style={{
              padding: "8px 16px", borderRadius: 6,
              background: bulkRunning ? "var(--bg-hover)" : "var(--accent)",
              border: "none",
              color: bulkRunning ? "var(--text-muted)" : "#fff",
              fontSize: 13, fontWeight: 600,
              cursor: bulkRunning ? "not-allowed" : "pointer",
              transition: "all 0.15s",
            }}
          >
            {bulkRunning && bulkTarget === "all" ? `Running ${bulkCurrent}/${patterns.length}...` : `▶ Run All Patterns (${patterns.length})`}
          </button>
        </div>
      </div>

      {/* Bulk run progress */}
      {bulkResults.length > 0 && (
        <div className="card" style={{
          borderColor: bulkRunning ? "var(--accent)" : bulkErrors > 0 ? "rgba(255,209,102,0.3)" : "rgba(6,214,160,0.3)",
          background: bulkRunning ? "var(--accent-glow)" : "transparent",
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <div>
              <div style={{ fontFamily: "Geist Mono", fontSize: 12, color: bulkRunning ? "var(--accent)" : "var(--low)", fontWeight: 600, marginBottom: 4 }}>
                {bulkRunning
                  ? `⠋ Running ${bulkTarget === "edr" ? "EDR hunts" : "all patterns"} — ${bulkCurrent}/${bulkResults.length}`
                  : `✓ Bulk run complete — ${bulkDone} done${bulkErrors > 0 ? `, ${bulkErrors} errors` : ""}`
                }
              </div>
              {/* Progress bar */}
              <div style={{ width: 400, height: 4, background: "var(--border)", borderRadius: 2 }}>
                <div style={{
                  height: 4, borderRadius: 2,
                  background: bulkErrors > 0 ? "var(--medium)" : "var(--low)",
                  width: `${(bulkDone / bulkResults.length) * 100}%`,
                  transition: "width 0.3s",
                }} />
              </div>
            </div>
            {!bulkRunning && (
              <button
                onClick={clearBulk}
                style={{
                  padding: "4px 10px", borderRadius: 4,
                  border: "1px solid var(--border)", background: "transparent",
                  color: "var(--text-muted)", fontSize: 12, fontFamily: "Geist Mono",
                  cursor: "pointer",
                }}
              >
                clear
              </button>
            )}
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {bulkResults.map((r) => (
              <div key={r.pattern_id} style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                padding: "8px 12px", borderRadius: 6,
                background: "var(--bg-hover)", border: "1px solid var(--border)",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{
                    fontFamily: "Geist Mono", fontSize: 11,
                    color: r.status === "done" ? "var(--low)"
                      : r.status === "running" ? "var(--accent)"
                      : r.status === "error" ? "var(--critical)"
                      : "var(--text-muted)",
                    width: 16, textAlign: "center",
                  }}>
                    {r.status === "done" ? "✓"
                      : r.status === "running" ? "⠋"
                      : r.status === "error" ? "✗"
                      : "·"}
                  </span>
                  <span style={{ fontSize: 13, color: "var(--text-primary)" }}>{r.pattern_name}</span>
                  {r.error && (
                    <span style={{ fontSize: 11, color: "var(--critical)", fontFamily: "Geist Mono" }}>{r.error}</span>
                  )}
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  {r.severity && (
                    <span className={`badge badge-${r.severity}`}>{r.severity}</span>
                  )}
                  {r.confidence !== undefined && (
                    <span style={{ fontFamily: "Geist Mono", fontSize: 12, color: confidenceColor(r.confidence) }}>
                      {Math.round(r.confidence * 100)}%
                    </span>
                  )}
                  {r.report_id && (
                    <a href={`/cases/${r.report_id}`} style={{
                      fontSize: 11, color: "var(--accent)", textDecoration: "none",
                      fontFamily: "Geist Mono",
                    }}>view →</a>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Category filter */}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setFilter(cat)}
            style={{
              padding: "4px 12px", borderRadius: 4,
              border: `1px solid ${filter === cat ? "var(--accent)" : "var(--border)"}`,
              background: filter === cat ? "var(--accent-glow)" : "transparent",
              color: filter === cat ? "var(--accent)" : "var(--text-muted)",
              fontSize: 12, fontFamily: "Geist Mono",
              cursor: "pointer", textTransform: "uppercase", transition: "all 0.15s",
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
          const bulkResult = bulkResults.find((r) => r.pattern_id === pattern.id);

          return (
            <div key={pattern.id} className="card" style={{
              display: "flex", flexDirection: "column", gap: 12,
              borderColor: reportId ? "rgba(6,214,160,0.3)"
                : bulkResult?.status === "running" ? "var(--accent)"
                : "var(--border)",
              background: bulkResult?.status === "running" ? "var(--accent-glow)" : undefined,
              transition: "all 0.2s",
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
                {bulkResult?.status === "running" && (
                  <span style={{ fontFamily: "Geist Mono", fontSize: 11, color: "var(--accent)" }}>running...</span>
                )}
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
                    disabled={isLaunching || bulkRunning}
                    style={{
                      flex: 1, padding: "8px 16px", borderRadius: 6,
                      background: isLaunching || bulkRunning ? "var(--bg-hover)" : "var(--accent)",
                      border: "none",
                      color: isLaunching || bulkRunning ? "var(--text-muted)" : "#fff",
                      fontSize: 13, fontWeight: 600,
                      cursor: isLaunching || bulkRunning ? "not-allowed" : "pointer",
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

function confidenceColor(c: number): string {
  if (c >= 0.7) return "var(--critical)";
  if (c >= 0.5) return "var(--high)";
  if (c >= 0.3) return "var(--medium)";
  return "var(--low)";
}