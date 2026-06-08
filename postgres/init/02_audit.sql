-- ============================================================
-- SOC Triage Audit Log Schema
-- Separate schema, separate DB user with INSERT only.
-- Cryptographically chained — each entry hashes the previous.
-- ============================================================

CREATE SCHEMA IF NOT EXISTS audit;

-- ── Audit log ─────────────────────────────────────────────────
CREATE TABLE audit.log (
    id              BIGSERIAL PRIMARY KEY,
    entry_id        UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    prev_hash       TEXT,                             -- SHA-256 of previous entry, NULL for first
    entry_hash      TEXT NOT NULL,                    -- SHA-256 of this entry's canonical fields
    event_type      TEXT NOT NULL,                    -- see event types below
    actor_id        UUID,                             -- user who performed the action (NULL = system)
    actor_username  TEXT,
    actor_ip        INET,
    actor_ua        TEXT,
    target_type     TEXT,                             -- user | session | action_token | system
    target_id       TEXT,
    action          TEXT NOT NULL,
    outcome         TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'pending')),
    reason          TEXT,                             -- mandatory for response actions
    metadata        JSONB,                            -- additional context
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- No UPDATE or DELETE ever — enforced by INSERT-only DB user
-- Index only on lookup fields needed for the UI
CREATE INDEX idx_audit_log_created_at ON audit.log (created_at DESC);
CREATE INDEX idx_audit_log_actor_id ON audit.log (actor_id) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_audit_log_event_type ON audit.log (event_type);
CREATE INDEX idx_audit_log_target_id ON audit.log (target_id) WHERE target_id IS NOT NULL;

-- ── Event types (documented, not enforced — extensible) ───────
-- auth.login.success
-- auth.login.failure
-- auth.login.lockout
-- auth.logout
-- auth.session.created
-- auth.session.invalidated
-- auth.session.expired
-- auth.stepup.l2
-- auth.stepup.l3
-- auth.stepup.failure
-- sat.issued
-- sat.consumed
-- sat.expired
-- sat.rejected
-- sat.approved        (four-eyes)
-- action.disable_user
-- action.enable_user
-- action.suspend_user
-- action.unsuspend_user
-- action.block_user
-- action.unblock_user
-- action.revoke_sessions
-- action.clear_sessions
-- device.registered
-- device.approved
-- device.rejected
-- admin.user.created
-- admin.user.deactivated
-- admin.ip_allowlist.added
-- system.startup
-- system.error

-- ── Audit DB user (INSERT only) ───────────────────────────────
-- Created separately in 03_seed.sql with GRANT INSERT ON audit.log

COMMENT ON TABLE audit.log IS
'Append-only cryptographically chained audit log. '
'The audit_writer role has INSERT only — no UPDATE or DELETE. '
'Chain integrity can be verified by recomputing entry_hash from fields '
'and checking prev_hash matches the previous row entry_hash.';