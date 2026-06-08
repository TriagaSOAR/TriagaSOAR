import { useState, useEffect } from "react";
import { useSatAction, SatConfirmModal } from "./SatConfirmModal";

const API = import.meta.env.PUBLIC_API_URL ?? "http://localhost:3000";

type Auth0User = {
  user_id: string; email: string; name: string; blocked: boolean;
  email_verified: boolean; created_at: string; last_login: string;
  last_ip: string; logins_count: number; identities: string[];
};
type Auth0Log = {
  _id: string; date: string; type: string; description: string;
  ip: string; client_name: string; user_name: string; details: any;
};
type UserDetail = {
  available: boolean; user_id?: string; email?: string; name?: string;
  blocked?: boolean; email_verified?: boolean; last_login?: string; last_ip?: string;
  logins_count?: number; identities?: string[]; signin_count_48h?: number;
  failed_signin_count_48h?: number; recent_ips?: string[]; recent_apps?: string[]; message?: string;
};
type AttackProtection = { brute_force: any; suspicious_ip: any; breached_password: any; };

const LOG_TYPE_LABELS: Record<string, string> = {
  s: "Success Login", f: "Failed Login", fp: "Brute Force", fu: "Failed User",
  fco: "Failed Connector", limit_wc: "Anomaly", cls: "Credential Stuffing",
  slo: "Logout", ss: "Success Signup", sce: "Success Change Email", scp: "Success Change Password",
};
const LOG_TYPE_COLORS: Record<string, string> = {
  s: "#06d6a0", ss: "#06d6a0", f: "#ff4d6a", fp: "#ff4d6a", fu: "#ff4d6a",
  fco: "#ff4d6a", limit_wc: "#ff8c42", cls: "#ff8c42", slo: "#888",
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

export default function Auth0Panel() {
  const [tab, setTab] = useState<"users" | "logs" | "failed" | "suspicious" | "protection">("users");
  const [health, setHealth] = useState<{ available: boolean; domain?: string; message?: string } | null>(null);
  const [users, setUsers] = useState<Auth0User[]>([]);
  const [logs, setLogs] = useState<Auth0Log[]>([]);
  const [protection, setProtection] = useState<AttackProtection | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedUser, setSelectedUser] = useState<string | null>(null);
  const [userDetail, setUserDetail] = useState<UserDetail | null>(null);
  const [search, setSearch] = useState("");

  const { modal, setModal, requestAction, close, issueToken, confirm } = useSatAction();

  useEffect(() => {
    fetch(`${API}/auth0/health`).then(r => r.json()).then(d => { setHealth(d); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!health?.available) return;
    if (tab === "users") {
      const q = search ? `?q=email%3A*${encodeURIComponent(search)}*&per_page=50` : "?per_page=50";
      fetch(`${API}/auth0/users${q}`).then(r => r.json()).then(d => setUsers(d.users ?? []));
    } else if (tab === "logs") {
      fetch(`${API}/auth0/logs?per_page=100`).then(r => r.json()).then(d => setLogs(d.logs ?? []));
    } else if (tab === "failed") {
      fetch(`${API}/auth0/logs/failed`).then(r => r.json()).then(d => setLogs(d.logs ?? []));
    } else if (tab === "suspicious") {
      fetch(`${API}/auth0/logs/suspicious`).then(r => r.json()).then(d => setLogs(d.logs ?? []));
    } else if (tab === "protection") {
      fetch(`${API}/auth0/attack-protection`).then(r => r.json()).then(setProtection);
    }
  }, [tab, health, search]);

  useEffect(() => {
    if (!selectedUser) { setUserDetail(null); return; }
    fetch(`${API}/auth0/users/${encodeURIComponent(selectedUser)}`).then(r => r.json()).then(setUserDetail);
  }, [selectedUser]);

  const doAction = (action: string, userId: string) => {
    const actionTypeMap: Record<string, string> = {
      "block": "block_user",
      "unblock": "unblock_user",
    };
    requestAction({
      actionType: actionTypeMap[action] ?? action,
      target: userId,
      label: action,
      onConfirmed: async () => {
        await fetch(`${API}/auth0/actions/${action}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user_id: userId }),
        });
        fetch(`${API}/auth0/users?per_page=50`).then(r => r.json()).then(d => setUsers(d.users ?? []));
        if (selectedUser) {
          fetch(`${API}/auth0/users/${encodeURIComponent(selectedUser)}`).then(r => r.json()).then(setUserDetail);
        }
      },
    });
  };

  if (loading) return <div style={{ color: "#888", fontFamily: "monospace", padding: 32 }}>Loading...</div>;
  if (!health?.available) return <div style={{ color: "#ff8c42", fontFamily: "monospace", padding: 32 }}>{health?.message ?? "Auth0 not configured. Set AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET in .env."}</div>;

  const TABS = [
    { id: "users", label: `Users (${users.length})` },
    { id: "logs", label: "Logs" },
    { id: "failed", label: "Failed Logins" },
    { id: "suspicious", label: "Suspicious" },
    { id: "protection", label: "Attack Protection" },
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
            <input type="text" placeholder="Search by email..." value={search} onChange={e => setSearch(e.target.value)}
              style={{ width: "100%", padding: "8px 12px", marginBottom: 16, boxSizing: "border-box", background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 6, color: "#e0e0f0", fontFamily: "monospace", fontSize: 13, outline: "none" }} />
            {users.map(u => (
              <div key={u.user_id} onClick={() => setSelectedUser(selectedUser === u.user_id ? null : u.user_id)}
                style={{ background: "#13131e", border: `1px solid ${selectedUser === u.user_id ? "#7b61ff" : "#2a2a3a"}`, borderRadius: 8, padding: 14, marginBottom: 8, cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{u.name || u.email}</div>
                  <div style={{ fontSize: 11, color: "#888", fontFamily: "monospace" }}>{u.email}</div>
                  <div style={{ fontSize: 11, color: "#555", marginTop: 2 }}>{u.identities?.join(", ")} · {u.logins_count} logins</div>
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
                  {u.blocked ? <Badge label="Blocked" color="#ff4d6a" /> : <Badge label="Active" color="#06d6a0" />}
                  {!u.email_verified && <Badge label="Unverified" color="#ffd166" />}
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
                  <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 4 }}>{userDetail.name}</div>
                  <div style={{ fontSize: 11, color: "#888", fontFamily: "monospace", marginBottom: 12 }}>{userDetail.email}</div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
                    {userDetail.blocked ? <Badge label="Blocked" color="#ff4d6a" /> : <Badge label="Active" color="#06d6a0" />}
                    {!userDetail.email_verified && <Badge label="Unverified" color="#ffd166" />}
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 12 }}>
                    <div style={{ background: "#0d0d14", borderRadius: 6, padding: 10 }}>
                      <div style={{ fontSize: 10, color: "#888", fontFamily: "monospace", marginBottom: 4 }}>TOTAL LOGINS</div>
                      <div style={{ fontSize: 20, fontWeight: 700 }}>{userDetail.logins_count}</div>
                    </div>
                    <div style={{ background: "#0d0d14", borderRadius: 6, padding: 10 }}>
                      <div style={{ fontSize: 10, color: "#888", fontFamily: "monospace", marginBottom: 4 }}>FAILURES 48H</div>
                      <div style={{ fontSize: 20, fontWeight: 700, color: (userDetail.failed_signin_count_48h ?? 0) > 0 ? "#ff4d6a" : "#e0e0f0" }}>{userDetail.failed_signin_count_48h}</div>
                    </div>
                  </div>
                  {userDetail.last_ip && <div style={{ fontSize: 12, color: "#888", marginBottom: 8, fontFamily: "monospace" }}>Last IP: {userDetail.last_ip}</div>}
                  {(userDetail.recent_apps?.length ?? 0) > 0 && (
                    <div style={{ marginBottom: 12 }}>
                      <div style={{ fontSize: 10, color: "#888", fontFamily: "monospace", marginBottom: 4 }}>RECENT APPS</div>
                      {userDetail.recent_apps?.map(a => <div key={a} style={{ fontSize: 12, color: "#c0c0d0", padding: "2px 0" }}>{a}</div>)}
                    </div>
                  )}
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: "#888", textTransform: "uppercase", fontFamily: "monospace" }}>Response Actions</div>
                    {!userDetail.blocked ? (
                      <button onClick={() => doAction("block", selectedUser)} style={{ padding: "8px 12px", borderRadius: 6, border: "1px solid #ff4d6a44", background: "#ff4d6a11", color: "#ff4d6a", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>Block User</button>
                    ) : (
                      <button onClick={() => doAction("unblock", selectedUser)} style={{ padding: "8px 12px", borderRadius: 6, border: "1px solid #06d6a044", background: "#06d6a011", color: "#06d6a0", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>Unblock User</button>
                    )}
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      )}

      {(tab === "logs" || tab === "failed" || tab === "suspicious") && (
        <div>
          {logs.length === 0 && <div style={{ color: "#888" }}>No events found.</div>}
          {logs.map(l => (
            <div key={l._id} style={{ background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 8, padding: 14, marginBottom: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 13, color: "#e0e0f0", marginBottom: 4 }}>{l.description || LOG_TYPE_LABELS[l.type] || l.type}</div>
                  <div style={{ fontSize: 11, color: "#888", fontFamily: "monospace" }}>{l.user_name || ""}{l.ip ? ` · ${l.ip}` : ""}{l.client_name ? ` · ${l.client_name}` : ""}</div>
                  <div style={{ fontSize: 10, color: "#555", fontFamily: "monospace", marginTop: 4 }}>{l.type} · {l.date ? new Date(l.date).toLocaleString() : ""}</div>
                </div>
                <Badge label={LOG_TYPE_LABELS[l.type] || l.type} color={LOG_TYPE_COLORS[l.type] || "#888"} />
              </div>
            </div>
          ))}
        </div>
      )}

      {tab === "protection" && protection && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {[
            { key: "brute_force", label: "Brute Force Protection", data: protection.brute_force },
            { key: "suspicious_ip", label: "Suspicious IP Throttling", data: protection.suspicious_ip },
            { key: "breached_password", label: "Breached Password Detection", data: protection.breached_password },
          ].map(({ key, label, data }) => (
            <div key={key} style={{ background: "#13131e", border: "1px solid #2a2a3a", borderRadius: 8, padding: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                <div style={{ fontWeight: 600, fontSize: 14 }}>{label}</div>
                {data?.enabled !== undefined && <Badge label={data.enabled ? "Enabled" : "Disabled"} color={data.enabled ? "#06d6a0" : "#ff4d6a"} />}
              </div>
              <pre style={{ background: "#0d0d14", borderRadius: 6, padding: 12, fontSize: 11, color: "#888", fontFamily: "monospace", whiteSpace: "pre-wrap", margin: 0 }}>{JSON.stringify(data, null, 2)}</pre>
            </div>
          ))}
        </div>
      )}

      <SatConfirmModal modal={modal} setModal={setModal} close={close} issueToken={issueToken} confirm={confirm} />
    </div>
  );
}