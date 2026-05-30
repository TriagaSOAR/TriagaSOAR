import { useState, useEffect } from "react";

interface AlertPayload {
  title: string;
  search_terms: string;
  indexes: string[];
  earliest: string;
  latest: string;
}

interface Props {
  apiUrl: string;
}

type Stage = "idle" | "routing" | "investigating" | "reviewing" | "reinvestigating" | "blast_radius" | "threat_intel" | "correlating" | "generating_report" | "done" | "error";

export default function InvestigateForm({ apiUrl }: Props) {
  const [form, setForm] = useState<AlertPayload>({
    title: "",
    search_terms: "",
    indexes: ["main"],
    earliest: "-1h",
    latest: "now",
  });
  const [availableIndexes, setAvailableIndexes] = useState<string[]>([]);
  const [stage, setStage] = useState<Stage>("idle");
  const [statusMessage, setStatusMessage] = useState<string>("");
  const [findings, setFindings] = useState<any[]>([]);
  const [queries, setQueries] = useState<{ spl: string; count?: number }[]>([]);
  const [reportId, setReportId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Pre-fill from URL params (for pattern library)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const title = params.get("title");
    const search_terms = params.get("search_terms");
    const index = params.get("index");
    const earliest = params.get("earliest");
    if (title || search_terms) {
      setForm((prev) => ({
        ...prev,
        title: title ?? prev.title,
        search_terms: search_terms ?? prev.search_terms,
        indexes: index ? [index] : prev.indexes,
        earliest: earliest ?? prev.earliest,
      }));
    }
  }, []);

  // Fetch available indexes
  useEffect(() => {
    fetch(`${apiUrl}/splunk/health`)
      .then((r) => r.json())
      .then((data) => {
        const names = (data.indexes ?? [])
          .map((i: any) => i.title ?? i.name)
          .filter((n: string) => n && !n.startsWith("_"));
        if (names.length > 0) setAvailableIndexes(names);
      })
      .catch(() => {});
  }, []);

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));
  }

  function toggleIndex(idx: string) {
    setForm((prev) => {
      const has = prev.indexes.includes(idx);
      if (has && prev.indexes.length === 1) return prev; // keep at least one
      return {
        ...prev,
        indexes: has ? prev.indexes.filter((i) => i !== idx) : [...prev.indexes, idx],
      };
    });
  }

  async function handleSubmit() {
    if (!form.title || !form.search_terms) return;

    setStage("routing");
    setStatusMessage("Classifying alert...");
    setFindings([]);
    setQueries([]);
    setReportId(null);
    setError(null);

    // Use first index as primary for streaming (multi-index handled server-side)
    const payload = {
      title: form.title,
      search_terms: form.search_terms,
      index: form.indexes[0],
      indexes: form.indexes,
      earliest: form.earliest,
      latest: form.latest,
    };

    try {
      const response = await fetch(`${apiUrl}/investigate/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      if (!response.body) throw new Error("No response body");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";

        for (const part of parts) {
          if (!part.trim()) continue;
          const lines = part.split("\n");
          let eventType = "message";
          let dataStr = "";
          for (const line of lines) {
            if (line.startsWith("event: ")) eventType = line.slice(7).trim();
            if (line.startsWith("data: ")) dataStr = line.slice(6).trim();
          }
          if (!dataStr) continue;
          try {
            const data = JSON.parse(dataStr);
            handleEvent(eventType, data);
          } catch {}
        }
      }
    } catch (e: any) {
      setError(e.message ?? "Unknown error");
      setStage("error");
    }
  }

  function handleEvent(type: string, data: any) {
    switch (type) {
      case "status":
        setStage(data.stage as Stage);
        setStatusMessage(data.message);
        break;
      case "finding":
        setFindings((prev) => [...prev, data]);
        break;
      case "query":
        setQueries((prev) => [...prev, { spl: data.spl }]);
        break;
      case "query_result":
        setQueries((prev) =>
          prev.map((q) => q.spl === data.spl ? { ...q, count: data.count } : q)
        );
        break;
      case "complete":
        if (data.report_id) {
          setReportId(data.report_id);
          setStage("done");
        } else if (data.status === "skipped") {
          setError(`Skipped: ${data.reason}`);
          setStage("error");
        }
        break;
    }
  }

  const isLoading = !["idle", "done", "error"].includes(stage);

  return (
    <div style={{ maxWidth: 720, margin: "0 auto" }}>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: 22, fontWeight: 600, color: "var(--text-primary)", marginBottom: 6 }}>
          New Investigation
        </h1>
        <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          Trigger an AI-powered SOC triage investigation against your Splunk data.
        </p>
      </div>

      <div className="card" style={{ display: "flex", flexDirection: "column", gap: 20, marginBottom: 24 }}>
        <Field label="Title" hint="Short description of the alert">
          <input name="title" value={form.title} onChange={handleChange}
            placeholder="e.g. Brute force attempt from external IP" disabled={isLoading} />
        </Field>
        <Field label="Search Terms" hint="Keywords or phrases to search in Splunk logs">
          <input name="search_terms" value={form.search_terms} onChange={handleChange}
            placeholder='e.g. 10.10.10.99 or "Failed password"' disabled={isLoading} />
        </Field>

        {/* Multi-index selector */}
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label style={{ fontSize: 12, fontWeight: 500, color: "var(--text-primary)" }}>Indexes</label>
          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: -4 }}>
            Select one or more Splunk indexes to search
          </div>
          {availableIndexes.length > 0 ? (
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {availableIndexes.map((idx) => {
                const selected = form.indexes.includes(idx);
                return (
                  <button
                    key={idx}
                    onClick={() => toggleIndex(idx)}
                    disabled={isLoading}
                    style={{
                      padding: "4px 10px", borderRadius: 4,
                      border: `1px solid ${selected ? "var(--accent)" : "var(--border)"}`,
                      background: selected ? "var(--accent-glow)" : "transparent",
                      color: selected ? "var(--accent)" : "var(--text-muted)",
                      fontSize: 12, fontFamily: "Geist Mono",
                      cursor: isLoading ? "not-allowed" : "pointer",
                      transition: "all 0.15s",
                    }}
                  >
                    {idx}
                  </button>
                );
              })}
            </div>
          ) : (
            <input
              value={form.indexes.join(", ")}
              onChange={(e) => setForm((prev) => ({ ...prev, indexes: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) }))}
              placeholder="main"
              disabled={isLoading}
            />
          )}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <Field label="Earliest" hint="e.g. -1h, -24h, -7d">
            <input name="earliest" value={form.earliest} onChange={handleChange} placeholder="-1h" disabled={isLoading} />
          </Field>
          <Field label="Latest" hint="e.g. now, -1h">
            <input name="latest" value={form.latest} onChange={handleChange} placeholder="now" disabled={isLoading} />
          </Field>
        </div>

        <button
          onClick={handleSubmit}
          disabled={isLoading || !form.title || !form.search_terms}
          style={{
            background: isLoading ? "var(--bg-hover)" : "var(--accent)",
            color: isLoading ? "var(--text-muted)" : "#fff",
            border: "none", padding: "12px 24px", borderRadius: 8,
            fontSize: 14, fontWeight: 600,
            cursor: isLoading ? "not-allowed" : "pointer",
            transition: "all 0.15s",
            display: "flex", alignItems: "center", gap: 8, justifyContent: "center",
          }}
        >
          {isLoading ? <><Spinner /> {statusMessage}</> : "Start Investigation"}
        </button>
      </div>

      {/* Live stream output */}
      {(isLoading || findings.length > 0 || queries.length > 0) && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {isLoading && (
            <div className="card" style={{ borderColor: "var(--accent)", background: "var(--accent-glow)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <Spinner />
                <span style={{ fontFamily: "Geist Mono", fontSize: 12, color: "var(--accent)" }}>
                  {stageLabel(stage)}
                </span>
                <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{statusMessage}</span>
              </div>
            </div>
          )}

          {findings.length > 0 && (
            <div className="card">
              <div className="card-header">Investigation Findings</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {findings.map((f, i) => (
                  <div key={i} style={{
                    display: "flex", gap: 12, alignItems: "flex-start",
                    paddingBottom: 10,
                    borderBottom: i < findings.length - 1 ? "1px solid var(--border)" : "none",
                  }}>
                    <div style={{
                      width: 24, height: 24, borderRadius: "50%", flexShrink: 0,
                      background: "var(--bg-hover)", border: "1px solid var(--border)",
                      display: "flex", alignItems: "center", justifyContent: "center",
                      fontFamily: "Geist Mono", fontSize: 10, color: "var(--text-muted)",
                    }}>{i + 1}</div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                        <span style={{ fontSize: 13, color: "var(--text-primary)" }}>{f.finding}</span>
                        <span style={{
                          fontFamily: "Geist Mono", fontSize: 12, fontWeight: 600, flexShrink: 0,
                          color: confidenceColor(f.confidence),
                        }}>{Math.round(f.confidence * 100)}%</span>
                      </div>
                      {f.pivot_reason && (
                        <div style={{ fontSize: 12, color: "var(--text-muted)", fontStyle: "italic", marginTop: 4 }}>
                          → {f.pivot_reason}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {queries.length > 0 && (
            <div className="card">
              <div className="card-header">SPL Queries Executed</div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {queries.map((q, i) => (
                  <div key={i} style={{
                    display: "flex", justifyContent: "space-between", alignItems: "center",
                    padding: "8px 12px", borderRadius: 6,
                    background: "var(--bg-hover)", border: "1px solid var(--border)",
                  }}>
                    <span style={{ fontFamily: "Geist Mono", fontSize: 12, color: "var(--text-secondary)" }}>{q.spl}</span>
                    {q.count !== undefined && (
                      <span style={{
                        fontFamily: "Geist Mono", fontSize: 11,
                        color: q.count > 0 ? "var(--low)" : "var(--text-muted)",
                        flexShrink: 0, marginLeft: 12,
                      }}>{q.count} events</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {stage === "done" && reportId && (
        <div style={{
          marginTop: 16, padding: 16, borderRadius: 8,
          background: "rgba(6,214,160,0.05)", border: "1px solid rgba(6,214,160,0.3)",
        }}>
          <div style={{ color: "var(--low)", fontWeight: 600, marginBottom: 8 }}>✓ Investigation complete</div>
          <div style={{ fontFamily: "Geist Mono", fontSize: 12, color: "var(--text-muted)", marginBottom: 12 }}>{reportId}</div>
          <a href={`/cases/${reportId}`} style={{
            background: "var(--accent)", color: "#fff",
            padding: "8px 16px", borderRadius: 6,
            textDecoration: "none", fontSize: 13, fontWeight: 500,
          }}>View IR Report →</a>
        </div>
      )}

      {stage === "error" && (
        <div style={{
          marginTop: 16, padding: 16, borderRadius: 8,
          background: "rgba(255,77,106,0.05)", border: "1px solid rgba(255,77,106,0.3)",
          color: "var(--critical)", fontSize: 13,
        }}>✗ {error}</div>
      )}
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint: string; children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <label style={{ fontSize: 12, fontWeight: 500, color: "var(--text-primary)" }}>{label}</label>
      <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: -4 }}>{hint}</div>
      {children}
    </div>
  );
}

function Spinner() {
  return (
    <span style={{
      display: "inline-block", width: 12, height: 12,
      border: "2px solid var(--text-muted)", borderTopColor: "var(--text-primary)",
      borderRadius: "50%", animation: "spin 0.6s linear infinite",
    }} />
  );
}

function stageLabel(stage: string): string {
  const labels: Record<string, string> = {
    routing: "ROUTING",
    investigating: "INVESTIGATING",
    reviewing: "ADVERSARIAL REVIEW",
    reinvestigating: "RE-INVESTIGATING",
    blast_radius: "BLAST RADIUS",
    threat_intel: "THREAT INTELLIGENCE",
    correlating: "CORRELATING",
    generating_report: "GENERATING REPORT",
  };
  return labels[stage] ?? stage.toUpperCase();
}

function confidenceColor(c: number): string {
  if (c >= 0.7) return "var(--critical)";
  if (c >= 0.5) return "var(--high)";
  if (c >= 0.3) return "var(--medium)";
  return "var(--low)";
}