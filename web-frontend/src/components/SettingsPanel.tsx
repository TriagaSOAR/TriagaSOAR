// web-frontend/src/components/SettingsPanel.tsx
import { useState, useEffect } from "react";

type User = {
  id: string;
  username: string;
  email: string;
  role: string;
  active: boolean;
};

const ROLE_COLORS: Record<string, string> = {
  admin: "#7b61ff",
  analyst: "#06d6a0",
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

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 32 }}>
      <div style={{
        fontSize: 11, fontWeight: 600, color: "#555", textTransform: "uppercase",
        letterSpacing: "0.1em", fontFamily: "monospace", marginBottom: 14,
        paddingBottom: 8, borderBottom: "1px solid #2a2a3a",
      }}>{title}</div>
      {children}
    </div>
  );
}

function Input({ label, type = "text", value, onChange, placeholder }: {
  label: string; type?: string; value: string;
  onChange: (v: string) => void; placeholder?: string;
}) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{ display: "block", fontSize: 11, color: "#666", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>
        {label}
      </label>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: "100%", padding: "10px 14px", boxSizing: "border-box",
          background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 7, fontFamily: "'Geist Mono', monospace",
          fontSize: 13, color: "#e0e0f0", outline: "none",
        }}
      />
    </div>
  );
}

export default function SettingsPanel({ isAdmin }: { isAdmin: boolean }) {
  // Change password state
  const [cpCurrent, setCpCurrent] = useState("");
  const [cpNew, setCpNew] = useState("");
  const [cpConfirm, setCpConfirm] = useState("");
  const [cpLoading, setCpLoading] = useState(false);
  const [cpMsg, setCpMsg] = useState<{ text: string; ok: boolean } | null>(null);

  // User management state
  const [users, setUsers] = useState<User[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [cuUsername, setCuUsername] = useState("");
  const [cuEmail, setCuEmail] = useState("");
  const [cuPassword, setCuPassword] = useState("");
  const [cuRole, setCuRole] = useState("analyst");
  const [cuLoading, setCuLoading] = useState(false);
  const [cuMsg, setCuMsg] = useState<{ text: string; ok: boolean } | null>(null);

  const showMsg = (setter: any, text: string, ok: boolean) => {
    setter({ text, ok });
    setTimeout(() => setter(null), 4000);
  };

  const loadUsers = async () => {
    setUsersLoading(true);
    try {
      const res = await fetch('/api/users');
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users ?? []);
      }
    } finally {
      setUsersLoading(false);
    }
  };

  useEffect(() => {
    if (isAdmin) loadUsers();
  }, [isAdmin]);

  const changePassword = async () => {
    if (cpNew !== cpConfirm) {
      showMsg(setCpMsg, "New passwords do not match", false);
      return;
    }
    if (cpNew.length < 12) {
      showMsg(setCpMsg, "New password must be at least 12 characters", false);
      return;
    }
    setCpLoading(true);
    try {
      const res = await fetch('/api/users/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: cpCurrent, new_password: cpNew }),
      });
      const data = await res.json();
      if (res.ok) {
        showMsg(setCpMsg, "Password changed successfully", true);
        setCpCurrent(""); setCpNew(""); setCpConfirm("");
      } else {
        showMsg(setCpMsg, data.error || "Failed to change password", false);
      }
    } catch {
      showMsg(setCpMsg, "Network error", false);
    } finally {
      setCpLoading(false);
    }
  };

  const createUser = async () => {
    if (!cuUsername || !cuEmail || !cuPassword) {
      showMsg(setCuMsg, "All fields required", false);
      return;
    }
    setCuLoading(true);
    try {
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: cuUsername, email: cuEmail, password: cuPassword, role: cuRole }),
      });
      const data = await res.json();
      if (res.ok) {
        showMsg(setCuMsg, `User ${cuUsername} created`, true);
        setCuUsername(""); setCuEmail(""); setCuPassword(""); setCuRole("analyst");
        loadUsers();
      } else {
        showMsg(setCuMsg, data.error || "Failed to create user", false);
      }
    } catch {
      showMsg(setCuMsg, "Network error", false);
    } finally {
      setCuLoading(false);
    }
  };

  const deactivateUser = async (user: User) => {
    if (!confirm(`Deactivate ${user.username}?`)) return;
    try {
      const res = await fetch(`/api/users/${user.id}`, { method: 'DELETE' });
      if (res.ok) loadUsers();
    } catch {}
  };

  const msgStyle = (ok: boolean): React.CSSProperties => ({
    padding: "10px 14px", borderRadius: 7, fontSize: 13, marginBottom: 14,
    background: ok ? "rgba(6,214,160,0.08)" : "rgba(255,77,106,0.08)",
    border: `1px solid ${ok ? "rgba(6,214,160,0.25)" : "rgba(255,77,106,0.25)"}`,
    color: ok ? "#06d6a0" : "#ff6b6b",
    fontFamily: "monospace",
  });

  const btnStyle = (danger = false, disabled = false): React.CSSProperties => ({
    padding: "10px 20px", borderRadius: 7,
    border: `1px solid ${danger ? "rgba(255,77,106,0.4)" : "rgba(123,97,255,0.4)"}`,
    background: danger ? "rgba(255,77,106,0.1)" : "rgba(123,97,255,0.1)",
    color: danger ? "#ff4d6a" : "#7b61ff",
    fontFamily: "'Geist Mono', monospace", fontSize: 13, fontWeight: 600,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.5 : 1,
  });

  return (
    <div style={{ fontFamily: "system-ui, sans-serif" }}>

      {/* Change password */}
      <Section title="Change Password">
        {cpMsg && <div style={msgStyle(cpMsg.ok)}>{cpMsg.text}</div>}
        <Input label="Current password" type="password" value={cpCurrent} onChange={setCpCurrent} />
        <Input label="New password" type="password" value={cpNew} onChange={setCpNew} placeholder="Min 12 characters" />
        <Input label="Confirm new password" type="password" value={cpConfirm} onChange={setCpConfirm} />
        <button onClick={changePassword} disabled={cpLoading} style={btnStyle(false, cpLoading)}>
          {cpLoading ? "Updating..." : "Update Password"}
        </button>
      </Section>

      {/* Admin: create user */}
      {isAdmin && (
        <Section title="Create User">
          {cuMsg && <div style={msgStyle(cuMsg.ok)}>{cuMsg.text}</div>}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Input label="Username" value={cuUsername} onChange={setCuUsername} placeholder="analyst1" />
            <Input label="Email" type="email" value={cuEmail} onChange={setCuEmail} placeholder="user@example.com" />
          </div>
          <Input label="Password" type="password" value={cuPassword} onChange={setCuPassword} placeholder="Min 12 characters" />
          <div style={{ marginBottom: 14 }}>
            <label style={{ display: "block", fontSize: 11, color: "#666", fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>
              Role
            </label>
            <div style={{ display: "flex", gap: 8 }}>
              {["analyst", "admin"].map(r => (
                <button key={r} onClick={() => setCuRole(r)} style={{
                  padding: "8px 16px", borderRadius: 6, fontFamily: "monospace", fontSize: 12,
                  fontWeight: 600, cursor: "pointer", textTransform: "uppercase",
                  border: `1px solid ${cuRole === r ? (r === "admin" ? "#7b61ff" : "#06d6a0") : "#2a2a3a"}`,
                  background: cuRole === r ? (r === "admin" ? "rgba(123,97,255,0.15)" : "rgba(6,214,160,0.15)") : "transparent",
                  color: cuRole === r ? (r === "admin" ? "#7b61ff" : "#06d6a0") : "#555",
                }}>
                  {r}
                </button>
              ))}
            </div>
          </div>
          <button onClick={createUser} disabled={cuLoading} style={btnStyle(false, cuLoading)}>
            {cuLoading ? "Creating..." : "Create User"}
          </button>
        </Section>
      )}

      {/* Admin: user list */}
      {isAdmin && (
        <Section title={`Users (${users.length})`}>
          {usersLoading && <div style={{ color: "#555", fontSize: 13, fontFamily: "monospace" }}>Loading...</div>}
          {users.map(u => (
            <div key={u.id} style={{
              display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "12px 16px", background: "#13131e", border: "1px solid #2a2a3a",
              borderRadius: 8, marginBottom: 8,
            }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 3 }}>{u.username}</div>
                <div style={{ fontSize: 11, color: "#555", fontFamily: "monospace" }}>{u.email}</div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <Badge label={u.role} color={ROLE_COLORS[u.role] ?? "#888"} />
                <Badge label={u.active ? "active" : "inactive"} color={u.active ? "#06d6a0" : "#555"} />
                {u.active && u.role !== "admin" && (
                  <button onClick={() => deactivateUser(u)} style={{
                    padding: "4px 10px", borderRadius: 5, fontSize: 11, fontWeight: 600,
                    fontFamily: "monospace", cursor: "pointer", textTransform: "uppercase",
                    border: "1px solid rgba(255,77,106,0.3)", background: "rgba(255,77,106,0.08)",
                    color: "#ff4d6a",
                  }}>
                    Deactivate
                  </button>
                )}
              </div>
            </div>
          ))}
        </Section>
      )}
    </div>
  );
}