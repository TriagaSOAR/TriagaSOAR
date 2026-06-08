import { useState, useEffect } from "react";
import { useSatAction, SatConfirmModal } from "./SatConfirmModal";

const API = import.meta.env.PUBLIC_API_URL ?? "http://localhost:3000";

type RiskyUser = {
  id: string;
  userPrincipalName: string;
  displayName: string;
  riskLevel: string;
  riskState: string;
  riskLastUpdatedDateTime: string;
};

type RiskDetection = {
  id: string;
  userPrincipalName: string;
  riskEventType: string;
  riskLevel: string;
  detectedDateTime: string;
  ipAddress: string;
  location?: { city: string; countryOrRegion: string };
  additionalInfo?: string;
};

type SecurityAlert = {
  id: string;
  title: string;
  severity: string;
  status: string;
  createdDateTime: string;
  description: string;
  userStates?: { userPrincipalName: string }[];
};

type ActionLog = {
  id: number;
  action: string;
  target: string;
  performed_at: string;
  details: string;
};

const RISK_COLORS: Record<string, string> = {
  high: "#ff4d6a", medium: "#ff8c42", low: "#ffd166", none: "#888",
};
const SEV_COLORS: Record<string, string> = {
  high: "#ff4d6a", medium: "#ff8c42", low: "#ffd166", informational: "#888",
};

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: "inline-block", padding: "2px 8px", borderRadius: 4,
      fontSize: 11, fontWeight: 700, textTransform: "uppercase",
      border: `1px solid ${color}44`, background: `${color}22`, color,
      fontFamily: "monospace",
    }}>
      {label}
    </span>
  );
}

function ActionButton({ label, color, onClick, loading }: {
  label: string; color: string; onClick: () => void; loading: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      style={{
        padding: "4px 12px", borderRadius: 4, border: `1px solid ${color}55`,
        background: `${color}18`, color, fontSize: 11, fontWeight: 600,
        cursor: loading ? "not-allowed" : "pointer", opacity: loading ? 0.5 : 1,
        fontFamily: "monospace", textTransform: "uppercase",
      }}
    >
      {loading ? "..." : label}
    </button>
  );
}

export default function EntraPanel() {
  const [tab, setTab] = useState<"risky" | "detections" | "alerts" | "actions">("risky");
  const [available, setAvailable] = useState<boolean | null>(null);
  const [riskyUsers, setRiskyUsers] = useState<RiskyUser[]>([]);
  const [detections, setDetections] = useState<RiskDetection[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [actionLog, setActionLog] = useState<ActionLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  const { modal, setModal, requestAction, close, issueToken, confirm } = useSatAction();

  const showToast = (msg: string, ok: boolean) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 3500);
  };

  useEffect(() => {
    fetch(`${API}/entra/health`)
      .then(r => r.json())
      .then(d => setAvailable(d.available))
      .catch(() => setAvailable(false));
  }, []);

  useEffect(() => {
    if (!available) return;
    setLoading(true);
    const fetches: Promise<void>[] = [];
    if (tab === "risky") {
      fetches.push(fetch(`${API}/entra/risky-users`).then(r => r.json()).then(d => setRiskyUsers(d.users ?? [])));
    } else if (tab === "detections") {
      fetches.push(fetch(`${API}/entra/risk-detections?hours=48`).then(r => r.json()).then(d => setDetections(d.detections ?? [])));
    } else if (tab === "alerts") {
      fetches.push(fetch(`${API}/entra/alerts?hours=48`).then(r => r.json()).then(d => setAlerts(d.alerts ?? [])));
    } else if (tab === "actions") {
      fetches.push(fetch(`${API}/entra/actions`).then(r => r.json()).then(d => setActionLog(d.actions ?? [])));
    }
    Promise.all(fetches).finally(() => setLoading(false));
  }, [tab, available]);

  const doAction = (action: "disable-user" | "revoke-sessions" | "enable-user", userId: string, label: string) => {
    const actionTypeMap: Record<string, string> = {
      "disable-user": "disable_user",
      "revoke-sessions": "revoke_sessions",
      "enable-user": "enable_user",
    };
    requestAction({
      actionType: actionTypeMap[action],
      target: userId,
      label,
      onConfirmed: async () => {
        const resp = await fetch(`${API}/entra/actions/${action}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user_id: userId }),
        });
        if (!resp.ok) throw new Error(await resp.text());
        showToast(`${label} — success`, true);
        fetch(`${API}/entra/actions`).then(r => r.json()).then(d => setActionLog(d.actions ?? []));
      },
    });
  };

  const TABS = [
    { id: "risky", label: "Risky Users" },
    { id: "detections", label: "Risk Detections" },
    { id: "alerts", label: "Security Alerts" },
    { id: "actions", label: "Action Log" },
  ] as const;

  if (available === null) return <div style={{ color: "#888", fontFamily: "monospace", padding: 32 }}>Connecting to Entra ID...</div>;
  if (!available) return <div style={{ color: "#ff4d6a", fontFamily: "monospace", padding: 32 }}>Entra ID not configured. Set ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET in .env.</div>;

  return (
    <div style={{ fontFamily: "system-ui, sans-serif" }}>
      {toast && (
        <div style={{
          position: "fixed", top: 20, right: 20, zIndex: 1000,
          padding: "10px 20px", borderRadius: 6,
          background: toast.ok ? "#06d6a022" : "#ff4d6a22",
          border: `1px solid ${toast.ok ? "#06d6a0" : "#ff4d6a"}`,
          color: toast.ok ? "#06d6a0" : "#ff4d6a",
          fontFamily: "monospace", fontSize: 13,
        }}>{toast.msg}</div>
      )}

      <div style={{ display: "flex", gap: 4, marginBottom: 20, borderBottom: "1px solid #2a2a3a" }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: "8px 16px", background: "none", border: "none",
            borderBottom: tab === t.id ? "2px solid #7b61ff" : "2px solid transparent",
            color: tab === t.id ? "#7b61ff" : "#888",
            cursor: "pointer", fontSize: 13, fontWeight: 600,
          }}>{t.label}</button>
        ))}
      </div>

      {loading && <div style={{ color: "#888", fontFamily: "monospace" }}>Loading...</div>}

      {!loading && tab === "risky" && (
        <div>
          {riskyUsers.length === 0 && <div style={{ color: "#888" }}>No risky users found.</div>}
          {riskyUsers.map(u => (
            <div key={u.id} style={{ background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 8, padding: 16, marginBottom: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div>
                  <div style={{ fontWeight: 600, marginBottom: 4 }}>{u.displayName}</div>
                  <div style={{ fontFamily: "monospace", fontSize: 12, color: "#888" }}>{u.userPrincipalName}</div>
                  <div style={{ fontSize: 11, color: "#666", marginTop: 4 }}>Updated: {new Date(u.riskLastUpdatedDateTime).toLocaleString()}</div>
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 6 }}>
                  <Badge label={u.riskLevel} color={RISK_COLORS[u.riskLevel] ?? "#888"} />
                  <Badge label={u.riskState} color="#7b61ff" />
                </div>
              </div>
              <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                <ActionButton label="Disable Account" color="#ff4d6a" loading={false}
                  onClick={() => doAction("disable-user", u.id, `Disable ${u.userPrincipalName}`)} />
                <ActionButton label="Revoke Sessions" color="#ff8c42" loading={false}
                  onClick={() => doAction("revoke-sessions", u.id, `Revoke sessions for ${u.userPrincipalName}`)} />
                <ActionButton label="Enable Account" color="#06d6a0" loading={false}
                  onClick={() => doAction("enable-user", u.id, `Enable ${u.userPrincipalName}`)} />
              </div>
            </div>
          ))}
        </div>
      )}

      {!loading && tab === "detections" && (
        <div>
          {detections.length === 0 && <div style={{ color: "#888" }}>No risk detections in the last 48h.</div>}
          {detections.map(d => (
            <div key={d.id} style={{ background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 8, padding: 16, marginBottom: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <div>
                  <div style={{ fontWeight: 600, marginBottom: 4 }}>{d.riskEventType}</div>
                  <div style={{ fontFamily: "monospace", fontSize: 12, color: "#888" }}>{d.userPrincipalName}</div>
                  {d.ipAddress && <div style={{ fontFamily: "monospace", fontSize: 11, color: "#666", marginTop: 2 }}>IP: {d.ipAddress}</div>}
                  {d.location?.city && <div style={{ fontSize: 11, color: "#666" }}>Location: {d.location.city}, {d.location.countryOrRegion}</div>}
                  <div style={{ fontSize: 11, color: "#666", marginTop: 4 }}>{new Date(d.detectedDateTime).toLocaleString()}</div>
                </div>
                <Badge label={d.riskLevel} color={RISK_COLORS[d.riskLevel] ?? "#888"} />
              </div>
            </div>
          ))}
        </div>
      )}

      {!loading && tab === "alerts" && (
        <div>
          {alerts.length === 0 && <div style={{ color: "#888" }}>No security alerts in the last 48h.</div>}
          {alerts.map(a => (
            <div key={a.id} style={{ background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 8, padding: 16, marginBottom: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                <div style={{ fontWeight: 600 }}>{a.title}</div>
                <div style={{ display: "flex", gap: 8 }}>
                  <Badge label={a.severity} color={SEV_COLORS[a.severity] ?? "#888"} />
                  <Badge label={a.status} color="#7b61ff" />
                </div>
              </div>
              <div style={{ fontSize: 12, color: "#c0c0d0", lineHeight: 1.6, marginBottom: 8 }}>{a.description}</div>
              {a.userStates && a.userStates.length > 0 && (
                <div style={{ fontFamily: "monospace", fontSize: 11, color: "#888" }}>
                  Users: {a.userStates.map(u => u.userPrincipalName).join(", ")}
                </div>
              )}
              <div style={{ fontSize: 11, color: "#666", marginTop: 4 }}>{new Date(a.createdDateTime).toLocaleString()}</div>
            </div>
          ))}
        </div>
      )}

      {!loading && tab === "actions" && (
        <div>
          {actionLog.length === 0 && <div style={{ color: "#888" }}>No response actions recorded yet.</div>}
          {actionLog.map(a => (
            <div key={a.id} style={{
              background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 8,
              padding: 12, marginBottom: 8, display: "flex", justifyContent: "space-between", alignItems: "center",
            }}>
              <div>
                <span style={{ fontFamily: "monospace", fontSize: 12, color: "#7b61ff", marginRight: 12 }}>{a.action}</span>
                <span style={{ fontFamily: "monospace", fontSize: 12, color: "#c0c0d0" }}>{a.target}</span>
              </div>
              <div style={{ fontSize: 11, color: "#666" }}>{new Date(a.performed_at).toLocaleString()}</div>
            </div>
          ))}
        </div>
      )}

      <SatConfirmModal modal={modal} setModal={setModal} close={close} issueToken={issueToken} confirm={confirm} />
    </div>
  );
}