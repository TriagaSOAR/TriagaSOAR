import { useState, useEffect } from "react";
import { useSatAction, SatConfirmModal } from "./SatConfirmModal";

const API = import.meta.env.PUBLIC_API_URL ?? "http://localhost:3000";

type OktaUser = {
  id: string; login: string; display_name: string; email: string;
  status: string; created: string; last_login: string; dept: string; title: string;
};
type OktaLog = {
  uuid: string; published: string; eventType: string; displayMessage: string;
  outcome: { result: string; reason: string };
  actor: { displayName: string; alternateId: string; type: string };
  client: { ipAddress: string; geographicalContext: { city: string; country: string } };
  target: { displayName: string; type: string }[];
};
type UserDetail = {
  available: boolean; login?: string; display_name?: string; status?: string;
  last_login?: string; dept?: string; title?: string;
  signin_count_48h?: number; failed_signin_count_48h?: number;
  recent_ips?: string[]; recent_apps?: string[]; message?: string;
};

const STATUS_COLORS: Record<string, string> = {
  ACTIVE: "#06d6a0", SUSPENDED: "#ff8c42", DEPROVISIONED: "#ff4d6a",
  LOCKED_OUT: "#ff4d6a", PASSWORD_EXPIRED: "#ffd166", PROVISIONED: "#888", STAGED: "#888",
};
const OUTCOME_COLORS: Record<string, string> = {
  SUCCESS: "#06d6a0", FAILURE: "#ff4d6a", SKIPPED: "#888", ALLOW: "#06d6a0", DENY: "#ff4d6a",
};

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      display: "inline-block", padding: "2px 8px", borderRadius: 4,
      fontSize: 11, fontWeight: 700, textTransform: "uppercase",
      border: `1px solid ${color}44`, background: `${color}22`, color, fontFamily: "monospace",
    }}>{label}</span>
  );
}

export default function OktaPanel() {
  const [tab, setTab] = useState<"users" | "logs" | "failed" | "suspicious">("users");
  const [health, setHealth] = useState<{ available: boolean; domain?: string; message?: string } | null>(null);
  const [users, setUsers] = useState<OktaUser[]>([]);
  const [logs, setLogs] = useState<OktaLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedUser, setSelectedUser] = useState<string | null>(null);
  const [userDetail, setUserDetail] = useState<UserDetail | null>(null);
  const [search, setSearch] = useState("");

  const { modal, setModal, requestAction, close, issueToken, confirm } = useSatAction();

  useEffect(() => {
    fetch(`${API}/okta/health`).then(r => r.json()).then(d => { setHealth(d); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!health?.available) return;
    if (tab === "users") {
      const q = search ? `?search=profile.login+sw+"${encodeURIComponent(search)}"` : "";
      fetch(`${API}/okta/users${q}`).then(r => r.json()).then(d => setUsers(d.users ?? []));
    } else if (tab === "logs") {
      fetch(`${API}/okta/logs?limit=100`).then(r => r.json()).then(d => setLogs(d.logs ?? []));
    } else if (tab === "failed") {
      fetch(`${API}/okta/logs/failed?limit=50`).then(r => r.json()).then(d => setLogs(d.logs ?? []));
    } else if (tab === "suspicious") {
      fetch(`${API}/okta/logs/suspicious?limit=50`).then(r => r.json()).then(d => setLogs(d.logs ?? []));
    }
  }, [tab, health, search]);

  useEffect(() => {
    if (!selectedUser) { setUserDetail(null); return; }
    fetch(`${API}/okta/users/${selectedUser}`).then(r => r.json()).then(setUserDetail);
  }, [selectedUser]);

  const doAction = (action: string, userId: string) => {
    const actionTypeMap: Record<string, string> = {
      "clear-sessions": "clear_sessions",
      "suspend": "suspend_user",
      "unsuspend": "unsuspend_user",
    };
    requestAction({
      actionType: actionTypeMap[action] ?? action,
      target: userId,
      label: action,
      onConfirmed: async () => {
        await fetch(`${API}/okta/actions/${action}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user_id: userId }),
        });
        fetch(`${API}/okta/users`).then(r => r.json()).then(d => setUsers(d.users ?? []));
        if (selectedUser) {
          fetch(`${API}/okta/users/${selectedUser}`).then(r => r.json()).then(setUserDetail);
        }
      },
    });
  };

  if (loading) return <div style={{ color: "#888", fontFamily: "monospace", padding: 32 }}>Loading...</div>;
  if (!health?.available) return <div style={{ color: "#ff8c42", fontFamily: "monospace", padding: 32 }}>{health?.message ?? "Okta not configured. Set OKTA_DOMAIN and OKTA_API_TOKEN in .env."}</div>;

  const TABS = [
    { id: "users", label: `Users (${users.length})` },
    { id: "logs", label: "System Logs" },
    { id: "failed", label: "Failed Logins" },
    { id: "suspicious", label: "Suspicious Activity" },
  ] as const;

  return (
    <div style={{ fontFamily: "system-ui, sans-serif" }}>
      <div style={{ background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 8, padding: "14px 20px", marginBottom: 20, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ fontSize: 12, color: "#888" }}>Connected to <span style={{ color: "#7b61ff", fontFamily: "monospace" }}>{health.domain}</span></div>
        <Badge label="Live" color="#06d6a0" />
      </div>

      <div style={{ display: "flex", gap: 4, marginBottom: 16, borderBottom: "1px solid #2a2a3a" }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => { setTab(t.id); setSelectedUser(null); }} style={{
            padding: "8px 16px", background: "none", border: "none",
            borderBottom: tab === t.id ? "2px solid #7b61ff" : "2px solid transparent",
            color: tab === t.id ? "#7b61ff" : "#888", cursor: "pointer", fontSize: 13, fontWeight: 600,
          }}>{t.label}</button>
        ))}
      </div>

      {tab === "users" && (
        <div style={{ display: "grid", gridTemplateColumns: selectedUser ? "1fr 360px" : "1fr", gap: 16 }}>
          <div>
            <input type="text" placeholder="Search users..." value={search} onChange={e => setSearch(e.target.value)}
              style={{ width: "100%", padding: "8px 12px", marginBottom: 16, boxSizing: "border-box", background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 6, color: "#e0e0f0", fontFamily: "monospace", fontSize: 13, outline: "none" }} />
            {users.map(u => (
              <div key={u.id} onClick={() => setSelectedUser(selectedUser === u.id ? null : u.id)}
                style={{ background: "#13131e", border: `1px solid ${selectedUser === u.id ? "#7b61ff" : "#2a2a3a"}`, borderRadius: 8, padding: 14, marginBottom: 8, cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{u.display_name || u.login}</div>
                  <div style={{ fontSize: 11, color: "#888", fontFamily: "monospace" }}>{u.login}</div>
                  {u.dept && <div style={{ fontSize: 11, color: "#555", marginTop: 2 }}>{u.dept}{u.title ? ` · ${u.title}` : ""}</div>}
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
                  <Badge label={u.status} color={STATUS_COLORS[u.status] ?? "#888"} />
                  {u.last_login && <div style={{ fontSize: 10, color: "#555" }}>{new Date(u.last_login).toLocaleDateString()}</div>}
                </div>
              </div>
            ))}
          </div>

          {selectedUser && userDetail && (
            <div style={{ background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 8, padding: 16, height: "fit-content", position: "sticky", top: 16 }}>
              {!userDetail.available ? (
                <div style={{ color: "#ff4d6a", fontSize: 13 }}>{userDetail.message}</div>
              ) : (
                <>
                  <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 4 }}>{userDetail.display_name}</div>
                  <div style={{ fontSize: 11, color: "#888", fontFamily: "monospace", marginBottom: 12 }}>{userDetail.login}</div>
                  <Badge label={userDetail.status ?? ""} color={STATUS_COLORS[userDetail.status ?? ""] ?? "#888"} />
                  <div style={{ marginTop: 16, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                    <div style={{ background: "#0d0d14", borderRadius: 6, padding: 10 }}>
                      <div style={{ fontSize: 10, color: "#888", fontFamily: "monospace", marginBottom: 4 }}>SIGN-INS 48H</div>
                      <div style={{ fontSize: 20, fontWeight: 700 }}>{userDetail.signin_count_48h}</div>
                    </div>
                    <div style={{ background: "#0d0d14", borderRadius: 6, padding: 10 }}>
                      <div style={{ fontSize: 10, color: "#888", fontFamily: "monospace", marginBottom: 4 }}>FAILURES 48H</div>
                      <div style={{ fontSize: 20, fontWeight: 700, color: (userDetail.failed_signin_count_48h ?? 0) > 0 ? "#ff4d6a" : "#e0e0f0" }}>{userDetail.failed_signin_count_48h}</div>
                    </div>
                  </div>
                  {(userDetail.recent_ips?.length ?? 0) > 0 && (
                    <div style={{ marginTop: 12 }}>
                      <div style={{ fontSize: 10, color: "#888", fontFamily: "monospace", marginBottom: 6 }}>RECENT IPS</div>
                      {userDetail.recent_ips?.map(ip => <div key={ip} style={{ fontSize: 12, fontFamily: "monospace", color: "#c0c0d0", padding: "2px 0" }}>{ip}</div>)}
                    </div>
                  )}
                  <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 8 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: "#888", textTransform: "uppercase", fontFamily: "monospace" }}>Response Actions</div>
                    <button onClick={() => doAction("clear-sessions", selectedUser)} style={{ padding: "8px 12px", borderRadius: 6, border: "1px solid #ffd16644", background: "#ffd16611", color: "#ffd166", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>Clear Sessions</button>
                    {userDetail.status === "ACTIVE" && (
                      <button onClick={() => doAction("suspend", selectedUser)} style={{ padding: "8px 12px", borderRadius: 6, border: "1px solid #ff4d6a44", background: "#ff4d6a11", color: "#ff4d6a", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>Suspend User</button>
                    )}
                    {userDetail.status === "SUSPENDED" && (
                      <button onClick={() => doAction("unsuspend", selectedUser)} style={{ padding: "8px 12px", borderRadius: 6, border: "1px solid #06d6a044", background: "#06d6a011", color: "#06d6a0", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>Unsuspend User</button>
                    )}
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      )}

      {tab !== "users" && (
        <div>
          {logs.length === 0 && <div style={{ color: "#888" }}>No events found.</div>}
          {logs.map(l => (
            <div key={l.uuid} style={{ background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 8, padding: 14, marginBottom: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 13, color: "#e0e0f0", marginBottom: 4 }}>{l.displayMessage}</div>
                  <div style={{ fontSize: 11, color: "#888", fontFamily: "monospace" }}>
                    {l.actor?.displayName}{l.actor?.alternateId ? ` (${l.actor.alternateId})` : ""}{l.client?.ipAddress ? ` · ${l.client.ipAddress}` : ""}{l.client?.geographicalContext?.city ? ` · ${l.client.geographicalContext.city}, ${l.client.geographicalContext.country}` : ""}
                  </div>
                  <div style={{ fontSize: 10, color: "#555", fontFamily: "monospace", marginTop: 4 }}>{l.eventType} · {l.published ? new Date(l.published).toLocaleString() : ""}</div>
                </div>
                {l.outcome?.result && <Badge label={l.outcome.result} color={OUTCOME_COLORS[l.outcome.result] ?? "#888"} />}
              </div>
            </div>
          ))}
        </div>
      )}

      <SatConfirmModal modal={modal} setModal={setModal} close={close} issueToken={issueToken} confirm={confirm} />
    </div>
  );
}