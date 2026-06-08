// web-frontend/src/components/SatConfirmModal.tsx
import { useState, useCallback } from "react";

const AUTH_URL = '';

interface SatRequest {
  actionType: string;
  target: string;
  label: string;
  onConfirmed: () => Promise<void>;
}

interface SatModalState {
  open: boolean;
  request: SatRequest | null;
  reason: string;
  satToken: string | null;
  step: "reason" | "confirm" | "executing";
  error: string | null;
}

// ── Hook ─────────────────────────────────────────────────────────────────────

export function useSatAction() {
  const [modal, setModal] = useState<SatModalState>({
    open: false,
    request: null,
    reason: "",
    satToken: null,
    step: "reason",
    error: null,
  });

  const requestAction = useCallback((req: SatRequest) => {
    setModal({
      open: true,
      request: req,
      reason: "",
      satToken: null,
      step: "reason",
      error: null,
    });
  }, []);

  const close = useCallback(() => {
    setModal(s => ({ ...s, open: false, satToken: null, error: null }));
  }, []);

  const issueToken = useCallback(async (reason: string) => {
    if (!modal.request) return;
    if (reason.length < 20) {
      setModal(s => ({ ...s, error: "Reason must be at least 20 characters" }));
      return;
    }
    setModal(s => ({ ...s, error: null }));
    try {
      const res = await fetch(`/api/sat/issue`, {
        method: "POST",

        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action_type: modal.request.actionType,
          target: modal.request.target,
          reason,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setModal(s => ({ ...s, satToken: data.token, step: "confirm", reason }));
    } catch (e: any) {
      setModal(s => ({ ...s, error: e.message }));
    }
  }, [modal.request]);

  const confirm = useCallback(async () => {
    if (!modal.request || !modal.satToken) return;
    setModal(s => ({ ...s, step: "executing", error: null }));
    try {
      // Consume the SAT
      const res = await fetch(`/api/sat/consume`, {
        method: "POST",

        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token: modal.satToken,
          action_type: modal.request.actionType,
          target: modal.request.target,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || "Token invalid or expired");
      }
      // Execute the actual action
      await modal.request.onConfirmed();
      close();
    } catch (e: any) {
      setModal(s => ({ ...s, step: "confirm", error: e.message }));
    }
  }, [modal.request, modal.satToken, close]);

  return { modal, setModal, requestAction, close, issueToken, confirm };
}

// ── Modal component ───────────────────────────────────────────────────────────

interface Props {
  modal: SatModalState;
  setModal: (fn: (s: SatModalState) => SatModalState) => void;
  close: () => void;
  issueToken: (reason: string) => Promise<void>;
  confirm: () => Promise<void>;
}

export function SatConfirmModal({ modal, setModal, close, issueToken, confirm }: Props) {
  if (!modal.open || !modal.request) return null;

  const { step, reason, error, request } = modal;

  const ACTION_LABELS: Record<string, string> = {
    disable_user: "Disable User",
    enable_user: "Enable User",
    revoke_sessions: "Revoke Sessions",
    suspend_user: "Suspend User",
    unsuspend_user: "Unsuspend User",
    deactivate_user: "Deactivate User",
    clear_sessions: "Clear Sessions",
    block_user: "Block User",
    unblock_user: "Unblock User",
  };

  const actionLabel = ACTION_LABELS[request.actionType] ?? request.label;
  const isDangerous = ["disable_user", "block_user", "suspend_user", "deactivate_user", "revoke_sessions"].includes(request.actionType);

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9999,
      background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)",
      display: "flex", alignItems: "center", justifyContent: "center",
      padding: 20,
    }}>
      <div style={{
        background: "#13131e",
        border: `1px solid ${isDangerous ? "#ff4d6a33" : "#2a2a3a"}`,
        borderRadius: 12,
        padding: 28,
        width: "100%",
        maxWidth: 460,
        fontFamily: "'Geist Mono', monospace",
      }}>
        {/* Header */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.12em", textTransform: "uppercase", color: isDangerous ? "#ff4d6a" : "#7b61ff", marginBottom: 8 }}>
            {isDangerous ? "⚠ Response Action" : "✦ Response Action"}
          </div>
          <div style={{ fontSize: 16, fontWeight: 500, color: "#e0e0f0" }}>{actionLabel}</div>
          <div style={{ fontSize: 12, color: "#555", marginTop: 4, wordBreak: "break-all" }}>
            Target: {request.target}
          </div>
        </div>

        {/* Error */}
        {error && (
          <div style={{
            background: "rgba(255,77,106,0.08)", border: "1px solid rgba(255,77,106,0.25)",
            borderRadius: 7, padding: "10px 13px", fontSize: 12, color: "#ff6b6b", marginBottom: 16,
          }}>
            {error}
          </div>
        )}

        {/* Step 1: Reason */}
        {step === "reason" && (
          <>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 11, fontWeight: 500, letterSpacing: "0.08em", textTransform: "uppercase", color: "#666", marginBottom: 7 }}>
                Reason <span style={{ color: "#444" }}>(min 20 chars)</span>
              </label>
              <textarea
                value={reason}
                onChange={e => setModal(s => ({ ...s, reason: e.target.value }))}
                placeholder="Describe why this action is being taken..."
                rows={3}
                style={{
                  width: "100%", background: "rgba(255,255,255,0.04)",
                  border: "1px solid rgba(255,255,255,0.08)", borderRadius: 7,
                  padding: "10px 13px", fontFamily: "'Geist Mono', monospace",
                  fontSize: 12, color: "#e0e0f0", outline: "none", resize: "vertical",
                  boxSizing: "border-box",
                }}
              />
              <div style={{ fontSize: 11, color: reason.length >= 20 ? "#06d6a0" : "#555", marginTop: 4 }}>
                {reason.length}/20 minimum
              </div>
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <button onClick={close} style={cancelBtn}>Cancel</button>
              <button
                onClick={() => issueToken(reason)}
                disabled={reason.length < 20}
                style={reason.length >= 20 ? primaryBtn(isDangerous) : disabledBtn}
              >
                Request Token →
              </button>
            </div>
          </>
        )}

        {/* Step 2: Confirm */}
        {step === "confirm" && (
          <>
            <div style={{
              background: "rgba(6,214,160,0.06)", border: "1px solid rgba(6,214,160,0.2)",
              borderRadius: 7, padding: "12px 14px", marginBottom: 16,
            }}>
              <div style={{ fontSize: 11, color: "#06d6a0", fontWeight: 600, marginBottom: 6 }}>✓ Action token issued — 60 second window</div>
              <div style={{ fontSize: 11, color: "#666" }}>Review and confirm to execute the action.</div>
            </div>
            <div style={{ marginBottom: 16, fontSize: 12, color: "#888", lineHeight: 1.6 }}>
              <span style={{ color: "#555" }}>Action: </span><span style={{ color: "#e0e0f0" }}>{actionLabel}</span><br />
              <span style={{ color: "#555" }}>Target: </span><span style={{ color: "#e0e0f0" }}>{request.target}</span><br />
              <span style={{ color: "#555" }}>Reason: </span><span style={{ color: "#e0e0f0" }}>{reason}</span>
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <button onClick={close} style={cancelBtn}>Cancel</button>
              <button onClick={confirm} style={primaryBtn(isDangerous)}>
                {isDangerous ? "⚠ Confirm & Execute" : "✓ Confirm & Execute"}
              </button>
            </div>
          </>
        )}

        {/* Step 3: Executing */}
        {step === "executing" && (
          <div style={{ textAlign: "center", padding: "20px 0", color: "#7b61ff", fontSize: 13 }}>
            Executing...
          </div>
        )}
      </div>
    </div>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────

const cancelBtn: React.CSSProperties = {
  flex: 1, padding: "10px", borderRadius: 7,
  border: "1px solid rgba(255,255,255,0.08)",
  background: "transparent", color: "#888",
  fontFamily: "'Geist Mono', monospace", fontSize: 12,
  cursor: "pointer",
};

const primaryBtn = (danger: boolean): React.CSSProperties => ({
  flex: 2, padding: "10px", borderRadius: 7,
  border: `1px solid ${danger ? "#ff4d6a55" : "#7b61ff55"}`,
  background: danger ? "rgba(255,77,106,0.12)" : "rgba(123,97,255,0.12)",
  color: danger ? "#ff4d6a" : "#7b61ff",
  fontFamily: "'Geist Mono', monospace", fontSize: 12, fontWeight: 600,
  cursor: "pointer",
});

const disabledBtn: React.CSSProperties = {
  flex: 2, padding: "10px", borderRadius: 7,
  border: "1px solid rgba(255,255,255,0.05)",
  background: "transparent", color: "#444",
  fontFamily: "'Geist Mono', monospace", fontSize: 12,
  cursor: "not-allowed",
};