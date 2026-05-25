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

type Status = "idle" | "loading" | "done" | "error";

export default function InvestigateForm({ apiUrl }: Props) {
  const [form, setForm] = useState<AlertPayload>({
    title: "",
    search_terms: "",
    index: "main",
    earliest: "-1h",
    latest: "now",
  });
  const [status, setStatus] = useState<Status>("idle");
  const [reportId, setReportId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function handleChange(e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) {
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));
  }

  async function handleSubmit() {
    if (!form.title || !form.search_terms) return;
    setStatus("loading");
    setError(null);
    setReportId(null);

    try {
      const res = await fetch(`${apiUrl}/investigate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setReportId(data.report_id);
      setStatus("done");
    } catch (e: any) {
      setError(e.message ?? "Unknown error");
      setStatus("error");
    }
  }

  return (
    <div style={{ maxWidth: 640, margin: "0 auto" }}>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: 22, fontWeight: 600, color: "var(--text-primary)", marginBottom: 6 }}>
          New Investigation
        </h1>
        <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          Trigger an autonomous SOC triage investigation against your Splunk data.
        </p>
      </div>

      <div className="card" style={{ display: "flex", flexDirection: "column", gap: 20 }}>

        <Field label="Title" hint="Short description of the alert">
          <input
            name="title"
            value={form.title}
            onChange={handleChange}
            placeholder="e.g. Brute force attempt from external IP"
            disabled={status === "loading"}
          />
        </Field>

        <Field label="Search Terms" hint="Keywords or phrases to search in Splunk logs">
          <input
            name="search_terms"
            value={form.search_terms}
            onChange={handleChange}
            placeholder='e.g. 10.10.10.99 or "Failed password"'
            disabled={status === "loading"}
          />
        </Field>

        <Field label="Index" hint="Splunk index to search">
          <input
            name="index"
            value={form.index}
            onChange={handleChange}
            placeholder="main"
            disabled={status === "loading"}
          />
        </Field>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <Field label="Earliest" hint="e.g. -1h, -24h, -7d">
            <input
              name="earliest"
              value={form.earliest}
              onChange={handleChange}
              placeholder="-1h"
              disabled={status === "loading"}
            />
          </Field>
          <Field label="Latest" hint="e.g. now, -1h">
            <input
              name="latest"
              value={form.latest}
              onChange={handleChange}
              placeholder="now"
              disabled={status === "loading"}
            />
          </Field>
        </div>

        <button
          onClick={handleSubmit}
          disabled={status === "loading" || !form.title || !form.search_terms}
          style={{
            background: status === "loading" ? "var(--bg-hover)" : "var(--accent)",
            color: status === "loading" ? "var(--text-muted)" : "#fff",
            border: "none",
            padding: "12px 24px",
            borderRadius: 8,
            fontSize: 14,
            fontWeight: 600,
            cursor: status === "loading" ? "not-allowed" : "pointer",
            transition: "all 0.15s",
            display: "flex",
            alignItems: "center",
            gap: 8,
            justifyContent: "center",
          }}
        >
          {status === "loading" ? (
            <>
              <Spinner /> Investigating...
            </>
          ) : "Start Investigation"}
        </button>

        {status === "loading" && (
          <div style={{
            padding: "16px",
            borderRadius: 8,
            background: "var(--bg-hover)",
            border: "1px solid var(--border)",
            fontFamily: "Geist Mono",
            fontSize: 12,
            color: "var(--text-secondary)",
            lineHeight: 1.8,
          }}>
            <div style={{ color: "var(--accent)", marginBottom: 4 }}>⬡ Agent running...</div>
            <div>→ Routing alert with Qwen3 1.7B</div>
            <div>→ Primary investigation loop (Qwen3 14B)</div>
            <div>→ Adversarial review</div>
            <div>→ MITRE ATT&CK mapping</div>
            <div>→ Blast radius estimation</div>
            <div style={{ color: "var(--text-muted)", marginTop: 4 }}>This takes 20–60 seconds.</div>
          </div>
        )}

        {status === "done" && reportId && (
          <div style={{
            padding: "16px",
            borderRadius: 8,
            background: "rgba(6,214,160,0.05)",
            border: "1px solid rgba(6,214,160,0.3)",
          }}>
            <div style={{ color: "var(--low)", fontWeight: 600, marginBottom: 8 }}>
              ✓ Investigation complete
            </div>
            <div style={{ fontFamily: "Geist Mono", fontSize: 12, color: "var(--text-muted)", marginBottom: 12 }}>
              {reportId}
            </div>
            <a href={`/cases/${reportId}`} style={{
              background: "var(--accent)",
              color: "#fff",
              padding: "8px 16px",
              borderRadius: 6,
              textDecoration: "none",
              fontSize: 13,
              fontWeight: 500,
            }}>View IR Report →</a>
          </div>
        )}

        {status === "error" && (
          <div style={{
            padding: "16px",
            borderRadius: 8,
            background: "rgba(255,77,106,0.05)",
            border: "1px solid rgba(255,77,106,0.3)",
            color: "var(--critical)",
            fontSize: 13,
          }}>
            ✗ Error: {error}
          </div>
        )}

      </div>
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint: string; children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <label style={{ fontSize: 12, fontWeight: 500, color: "var(--text-primary)" }}>{label}</label>
      <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: -4 }}>{hint}</div>
      <div style={{ position: "relative" }}>
        {children}
      </div>
    </div>
  );
}

function Spinner() {
  return (
    <span style={{
      display: "inline-block",
      width: 12,
      height: 12,
      border: "2px solid var(--text-muted)",
      borderTopColor: "var(--text-primary)",
      borderRadius: "50%",
      animation: "spin 0.6s linear infinite",
    }} />
  );
}