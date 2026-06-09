// web-frontend/src/components/IdentityPanel.tsx
import { useState } from "react";

const API = import.meta.env.PUBLIC_API_URL ?? "http://localhost:3000";

type IdpProfile = {
  // Entra
  id?: string;
  upn?: string;
  display_name?: string;
  email?: string;
  risk_level?: string;
  risk_state?: string;
  account_enabled?: boolean;
  signin_count_48h?: number;
  failed_signin_count_48h?: number;
  // Okta
  login?: string;
  status?: string;
  recent_ips?: string[];
  // Auth0
  name?: string;
  blocked?: boolean;
  logins_count?: number;
  last_login?: string;
  last_ip?: string;
};

type CorrelationResult = {
  search: string;
  entra: IdpProfile | null;
  okta: IdpProfile | null;
  auth0: IdpProfile | null;
  found_in: string[];
  correlation_confidence: number;
  overall_risk: string;
  risk_summary: string[];
};

const RISK_COLORS: Record<string, string> = {
  high: "#ff4d6a",
  medium: "#ff8c42",
  low: "#06d6a0",
};

const STATUS_COLORS: Record<string, string> = {
  ACTIVE: "#06d6a0",
  SUSPENDED: "#ff8c42",
  LOCKED_OUT: "#ff4d6a",
  DEPROVISIONED: "#ff4d6a",
};

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: "inline-block", padding: "2px 8px", borderRadius: 4,
      fontSize: 11, fontWeight: 700, textTransform: "uppercase",
      border: `1px solid ${color}44`, background: `${color}22`, color,
      fontFamily: "monospace",
    }}>{label}</span>
  );
}

function IdpCard({ name, icon, data, fields }: {
  name: string;
  icon: string;
  data: IdpProfile | null;
  fields: { label: string; key: keyof IdpProfile; format?: (v: any) => string }[];
}) {
  return (
    <div style={{
      background: "#13131e",
      border: `1px solid ${data ? "#2a2a3a" : "#1a1a2a"}`,
      borderRadius: 10, padding: 20, flex: 1, minWidth: 0,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 16 }}>{icon}</span>
          <span style={{ fontWeight: 700, fontSize: 14 }}>{name}</span>
        </div>
        {data
          ? <Badge label="Found" color="#06d6a0" />
          : <Badge label="Not found" color="#444" />
        }
      </div>

      {!data && (
        <div style={{ fontSize: 12, color: "#444", fontFamily: "monospace" }}>
          No matching account
        </div>
      )}

      {data && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {fields.map(({ label, key, format }) => {
            const val = data[key];
            if (val === undefined || val === null) return null;
            const display = format ? format(val) : String(val);
            return (
              <div key={label} style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
                <span style={{ fontSize: 11, color: "#555", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.06em", flexShrink: 0 }}>
                  {label}
                </span>
                <span style={{ fontSize: 12, color: "#c0c0d0", textAlign: "right", wordBreak: "break-all" }}>
                  {display}
                </span>
              </div>
            );
          })}

          {/* Recent IPs */}
          {data.recent_ips && data.recent_ips.length > 0 && (
            <div>
              <div style={{ fontSize: 11, color: "#555", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>
                Recent IPs
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {data.recent_ips.slice(0, 5).map(ip => (
                  <span key={ip} style={{
                    fontSize: 11, fontFamily: "monospace", color: "#7b61ff",
                    background: "rgba(123,97,255,0.08)", padding: "2px 6px",
                    borderRadius: 4, border: "1px solid rgba(123,97,255,0.2)",
                  }}>{ip}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function IdentityPanel() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CorrelationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const search = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch(`${API}/identity/correlate?email=${encodeURIComponent(query.trim())}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setResult(await res.json());
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ fontFamily: "system-ui, sans-serif" }}>

      {/* Search bar */}
      <div style={{ display: "flex", gap: 10, marginBottom: 28 }}>
        <input
          type="text"
          placeholder="user@example.com or UPN"
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === "Enter" && search()}
          style={{
            flex: 1, padding: "11px 16px",
            background: "rgba(255,255,255,0.04)",
            border: "1px solid rgba(255,255,255,0.08)",
            borderRadius: 8, fontFamily: "'Geist Mono', monospace",
            fontSize: 14, color: "#e0e0f0", outline: "none",
          }}
        />
        <button
          onClick={search}
          disabled={loading || !query.trim()}
          style={{
            padding: "11px 24px", borderRadius: 8,
            background: loading ? "rgba(123,97,255,0.3)" : "#7b61ff",
            border: "none", color: "#fff",
            fontFamily: "'Geist Mono', monospace", fontSize: 13,
            fontWeight: 600, cursor: loading ? "not-allowed" : "pointer",
            opacity: !query.trim() ? 0.4 : 1,
            transition: "opacity 0.15s",
          }}
        >
          {loading ? "Searching..." : "Correlate →"}
        </button>
      </div>

      {error && (
        <div style={{
          background: "rgba(255,77,106,0.08)", border: "1px solid rgba(255,77,106,0.25)",
          borderRadius: 8, padding: "12px 16px", color: "#ff6b6b",
          fontFamily: "monospace", fontSize: 13, marginBottom: 20,
        }}>{error}</div>
      )}

      {result && (
        <div>
          {/* Summary bar */}
          <div style={{
            background: "#13131e", border: "1px solid #2a2a3a",
            borderRadius: 10, padding: "16px 20px", marginBottom: 20,
            display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12,
          }}>
            <div>
              <div style={{ fontSize: 11, color: "#555", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>
                Search
              </div>
              <div style={{ fontFamily: "monospace", fontSize: 14, color: "#e0e0f0" }}>{result.search}</div>
            </div>

            <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 24, fontWeight: 700, fontFamily: "monospace", color: "#7b61ff" }}>
                  {result.found_in.length}/3
                </div>
                <div style={{ fontSize: 11, color: "#555" }}>IDPs matched</div>
              </div>

              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 24, fontWeight: 700, fontFamily: "monospace", color: RISK_COLORS[result.overall_risk] ?? "#888" }}>
                  {result.overall_risk.toUpperCase()}
                </div>
                <div style={{ fontSize: 11, color: "#555" }}>overall risk</div>
              </div>

              <div style={{ display: "flex", gap: 6 }}>
                {["entra", "okta", "auth0"].map(idp => (
                  <span key={idp} style={{
                    padding: "4px 10px", borderRadius: 5, fontSize: 11, fontWeight: 600,
                    fontFamily: "monospace", textTransform: "uppercase",
                    background: result.found_in.includes(idp) ? "rgba(6,214,160,0.1)" : "rgba(255,255,255,0.03)",
                    border: `1px solid ${result.found_in.includes(idp) ? "rgba(6,214,160,0.3)" : "#2a2a3a"}`,
                    color: result.found_in.includes(idp) ? "#06d6a0" : "#444",
                  }}>{idp}</span>
                ))}
              </div>
            </div>
          </div>

          {/* Risk signals */}
          {result.risk_summary.length > 0 && (
            <div style={{
              background: "rgba(255,77,106,0.06)",
              border: "1px solid rgba(255,77,106,0.2)",
              borderRadius: 10, padding: "14px 18px", marginBottom: 20,
            }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: "#ff4d6a", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 10 }}>
                ⚠ Risk Signals
              </div>
              {result.risk_summary.map((signal, i) => (
                <div key={i} style={{ fontSize: 13, color: "#ff8c42", padding: "3px 0", display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ color: "#ff4d6a", fontSize: 10 }}>▶</span>
                  {signal}
                </div>
              ))}
            </div>
          )}

          {result.risk_summary.length === 0 && result.found_in.length > 0 && (
            <div style={{
              background: "rgba(6,214,160,0.06)",
              border: "1px solid rgba(6,214,160,0.2)",
              borderRadius: 10, padding: "12px 18px", marginBottom: 20,
              fontSize: 13, color: "#06d6a0",
            }}>
              ✓ No risk signals detected across {result.found_in.length} IDP{result.found_in.length > 1 ? "s" : ""}
            </div>
          )}

          {/* IDP cards */}
          <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
            <IdpCard
              name="Microsoft Entra ID"
              icon="⬡"
              data={result.entra}
              fields={[
                { label: "UPN", key: "upn" },
                { label: "Display name", key: "display_name" },
                { label: "Risk level", key: "risk_level" },
                { label: "Risk state", key: "risk_state" },
                { label: "Account", key: "account_enabled", format: v => v ? "Enabled" : "Disabled" },
                { label: "Sign-ins 48h", key: "signin_count_48h" },
                { label: "Failures 48h", key: "failed_signin_count_48h" },
              ]}
            />

            <IdpCard
              name="Okta"
              icon="✦"
              data={result.okta}
              fields={[
                { label: "Login", key: "login" },
                { label: "Display name", key: "display_name" },
                { label: "Status", key: "status" },
                { label: "Sign-ins 48h", key: "signin_count_48h" },
                { label: "Failures 48h", key: "failed_signin_count_48h" },
              ]}
            />

            <IdpCard
              name="Auth0"
              icon="◈"
              data={result.auth0}
              fields={[
                { label: "Email", key: "email" },
                { label: "Name", key: "name" },
                { label: "Blocked", key: "blocked", format: v => v ? "Yes" : "No" },
                { label: "Total logins", key: "logins_count" },
                { label: "Failures 48h", key: "failed_signin_count_48h" },
                { label: "Last IP", key: "last_ip" },
              ]}
            />
          </div>
        </div>
      )}

      {!result && !loading && !error && (
        <div style={{
          textAlign: "center", padding: "60px 0",
          color: "#333", fontFamily: "monospace", fontSize: 13,
        }}>
          Enter an email or UPN to correlate identity across all configured IDPs
        </div>
      )}
    </div>
  );
}