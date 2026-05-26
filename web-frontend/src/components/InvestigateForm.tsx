import { useState } from "react";

interface AlertPayload {
  title: string;
  search_terms: string;
  index: string;
  earliest: string;
  latest: string;
}

interface Props {
  apiUrl: string;
}

type Stage = "idle" | "routing" | "investigating" | "reviewing" | "reinvestigating" | "blast_radius" | "correlating" | "generating_report" | "done" | "error";

interface StreamEvent {
  type: string;
  data: any;
}

export default function InvestigateForm({ apiUrl }: Props) {
  const [form, setForm] = useState<AlertPayload>({
    title: "",
    search_terms: "",
    index: "main",
    earliest: "-1h",
    latest: "now",
  });
  const [stage, setStage] = useState<Stage>("idle");
  const [statusMessage, setStatusMessage] = useState<string>("");
  const [findings, setFindings] = useState<any[]>([]);
  const [queries, setQueries] = useState<{ spl: string; count?: number }[]>([]);
  const [reportId, setReportId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));
  }

  async function handleSubmit() {
    if (!form.title || !form.search_terms) return;

    setStage("routing");
    setStatusMessage("Classifying alert...");
    setFindings([]);
    setQueries([]);
    setReportId(null);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/investigate/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
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
          <input name="title" value={form.title} onChange={handleChange} placeholder="e.g. Brute force attempt from external IP" disabled={isLoading} />
        </Field>
        <Field label="Search Terms" hint="Keywords or phrases to search in Splunk logs">
          <input name="search_terms" value={form.search_terms} onChange={handleChange} placeholder='e.g. 10.10.10.99 or "Failed password"' disabled={isLoading} />
        </Field>
        <Field label="Index" hint="Splunk index to search">
          <input name="index" value={form.index} onChange={handleChange} placeholder="main" disabled={isLoading} />
        </Field>
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
            border: "none",
            padding: "12px 24px",
            borderRadius: 8,
            fontSize: 14,
            fontWeight: 600,
            cursor: isLoading ? "not-allowed" : "pointer",
            transition: "all 0.15s",
            display: "flex",
            alignItems: "center",
            gap: 8,
            justifyContent: "center",
          }}
        >
          {isLoading ? <><Spinner /> {statusMessage}</> : "Start Investigation"}
        </button>
      </div>

      {/* Live stream output */}
      {isLoading || findings.length > 0 || queries.length > 0 ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

          {/* Stage indicator */}
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

          {/* Live findings */}
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

          {/* Live queries */}
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
                      <span style={{ fontFamily: "Geist Mono", fontSize: 11, color: q.count > 0 ? "var(--low)" : "var(--text-muted)", flexShrink: 0, marginLeft: 12 }}>
                        {q.count} events
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : null}

      {/* Done */}
      {stage === "done" && reportId && (
        <div style={{
          marginTop: 16, padding: "16px",
          borderRadius: 8,
          background: "rgba(6,214,160,0.05)",
          border: "1px solid rgba(6,214,160,0.3)",
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

      {/* Error */}
      {stage === "error" && (
        <div style={{
          marginTop: 16, padding: "16px", borderRadius: 8,
          background: "rgba(255,77,106,0.05)",
          border: "1px solid rgba(255,77,106,0.3)",
          color: "var(--critical)", fontSize: 13,
        }}>
          ✗ {error}
        </div>
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
      border: "2px solid var(--text-muted)",
      borderTopColor: "var(--text-primary)",
      borderRadius: "50%",
      animation: "spin 0.6s linear infinite",
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