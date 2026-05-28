import { useEffect, useState } from "react";

interface Props {
  apiUrl: string;
}

interface HealthData {
  instance: Record<string, any>;
  indexes: Record<string, any>[];
  sourcetypes: Record<string, any>[];
}

export default function IndexHealth({ apiUrl }: Props) {
  const [data, setData] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${apiUrl}/splunk/health`)
      .then((r) => r.json())
      .then((d) => { setData(d); setLoading(false); })
      .catch((e) => { setError(e.message); setLoading(false); });
  }, []);

  if (loading) return (
    <div style={{ color: "var(--text-muted)", fontFamily: "Geist Mono", fontSize: 13 }}>
      Fetching Splunk environment data...
    </div>
  );

  if (error || !data) return (
    <div style={{ color: "var(--critical)", fontFamily: "Geist Mono", fontSize: 13 }}>
      Failed to load health data: {error}
    </div>
  );

  const inst = data.instance;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>

      <div style={{ marginBottom: 8 }}>
        <h1 style={{ fontSize: 22, fontWeight: 600, color: "var(--text-primary)", marginBottom: 6 }}>
          Splunk Environment
        </h1>
        <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          Live data from Splunk MCP Server
        </p>
      </div>

      {/* Instance info */}
      <div className="card">
        <div className="card-header">Instance Info</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
          <InfoStat label="Version" value={inst.version ?? "—"} />
          <InfoStat label="Host" value={inst.serverName ?? inst.host ?? "—"} />
          <InfoStat label="Health" value={inst.health_info ?? "—"} highlight={inst.health_info === "green"} />
          <InfoStat label="License" value={inst.licenseState ?? "—"} highlight={inst.licenseState === "OK"} />
          <InfoStat label="CPU Cores" value={inst.numberOfCores ?? "—"} />
          <InfoStat label="Memory" value={inst.physicalMemoryMB ? `${Math.round(inst.physicalMemoryMB / 1024)}GB` : "—"} />
          <InfoStat label="OS" value={inst.os_name ?? "—"} />
          <InfoStat label="Product" value={inst.product_type ?? "—"} />
        </div>
      </div>

      {/* Sourcetypes */}
      {data.sourcetypes.length > 0 && (
        <div className="card">
          <div className="card-header">Sourcetypes ({data.sourcetypes.length})</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {data.sourcetypes.map((s, i) => (
              <span key={i} style={{
                fontFamily: "Geist Mono", fontSize: 11,
                padding: "3px 10px", borderRadius: 4,
                background: "var(--bg-hover)",
                border: "1px solid var(--border)",
                color: "var(--accent)",
              }}>
                {s.sourcetype ?? s.value ?? JSON.stringify(s)}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Indexes */}
      {data.indexes.length > 0 && (
        <div className="card">
          <div className="card-header">Indexes ({data.indexes.length})</div>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr>
                  {["Name", "Total Events", "Size (MB)", "Min Time", "Max Time"].map((h) => (
                    <th key={h} style={{
                      textAlign: "left", padding: "8px 12px",
                      fontFamily: "Geist Mono", fontSize: 11,
                      color: "var(--text-muted)",
                      borderBottom: "1px solid var(--border)",
                      whiteSpace: "nowrap",
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.indexes.map((idx, i) => (
                  <tr key={i}
                    style={{ borderBottom: "1px solid var(--border)" }}
                    onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-hover)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  >
                    <td style={{ padding: "8px 12px", fontFamily: "Geist Mono", fontSize: 12, color: "var(--accent)" }}>
                      {idx.title ?? idx.name ?? "—"}
                    </td>
                    <td style={{ padding: "8px 12px", color: "var(--text-secondary)" }}>
                      {idx.totalEventCount ?? idx.total_event_count ?? "—"}
                    </td>
                    <td style={{ padding: "8px 12px", color: "var(--text-secondary)" }}>
                      {idx.currentDBSizeMB ?? idx.current_db_size_mb ?? "—"}
                    </td>
                    <td style={{ padding: "8px 12px", color: "var(--text-muted)", fontFamily: "Geist Mono", fontSize: 11 }}>
                      {idx.minTime ?? "—"}
                    </td>
                    <td style={{ padding: "8px 12px", color: "var(--text-muted)", fontFamily: "Geist Mono", fontSize: 11 }}>
                      {idx.maxTime ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
}

function InfoStat({ label, value, highlight = false }: { label: string; value: any; highlight?: boolean }) {
  return (
    <div style={{
      padding: "12px", borderRadius: 6,
      background: "var(--bg-hover)", border: "1px solid var(--border)",
    }}>
      <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "Geist Mono", marginBottom: 4 }}>{label}</div>
      <div style={{
        fontSize: 14, fontWeight: 600,
        color: highlight ? "var(--low)" : "var(--text-primary)",
      }}>{String(value)}</div>
    </div>
  );
}