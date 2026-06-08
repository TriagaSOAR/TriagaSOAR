# Architecture — TriagaSOAR

---

## System diagram

```mermaid
graph TD
    Browser --> auth

    subgraph auth["auth — Rust/Axum :4000"]
        A1[Session validation]
        A2[Single-Action Tokens]
        A3[Audit log writer]
        A4[Reverse proxy]
    end

    auth --> frontend
    auth --> backend

    subgraph frontend["web-frontend — Astro+React :4321"]
        F1[Login page]
        F2[SAT confirmation modal]
        F3[Identity panels — Entra / Okta / Auth0]
        F4[Investigation UI + SSE]
        F5[Astro API proxies]
    end

    subgraph backend["web-backend — Rust/Axum :3000"]
        B1[Transparent proxy to soc-agent]
    end

    backend --> agent

    subgraph agent["soc-agent — Python/FastAPI :8000"]
        AG1[Agentic investigation pipeline]
        AG2[Identity correlation engine]
        AG3[NL to SPL — sanitized]
        AG4[Blast radius estimation]
        AG5[MITRE ATT&CK mapping]
        AG6[PDF + Navigator export]
    end

    agent --> ollama
    agent --> splunk
    agent --> sqlite

    subgraph ollama["ollama :11434 — local profile"]
        O1[qwen3:14b — primary + adversarial]
        O2[qwen3:1.7b — router]
    end

    subgraph splunk["Splunk Enterprise — KVM VM :8089"]
        S1[MCP Server v1.1.3]
        S2[splunk_run_query]
        S3[splunk_get_indexes]
    end

    sqlite[(SQLite — cases.db)]
    postgres[(Postgres :5432)]

    auth --> postgres

    subgraph postgres_schemas["Postgres schemas"]
        P1[public — sessions, action_tokens, devices]
        P2[audit — hash-chained, INSERT-only role]
    end

    postgres --- postgres_schemas

    agent --> entra["Microsoft Graph API"]
    agent --> okta_api["Okta Management API"]
    agent --> auth0_api["Auth0 Management API"]
    agent --> abuseipdb["AbuseIPDB"]

    maester["maester — optional profile"] --> maester_vol[(./data/maester)]
    scubagear["scubagear — optional profile"] --> scubagear_vol[(./data/scubagear)]
    agent --> maester_vol
    agent --> scubagear_vol
```

---

## Auth layer

```mermaid
sequenceDiagram
    participant Browser
    participant auth as auth :4000
    participant Postgres

    Browser->>auth: POST /auth/login {username, password, totp}
    auth->>Postgres: verify argon2id hash
    Postgres-->>auth: user record
    auth->>Postgres: create session (token hash, IP, UA, expires)
    auth-->>Browser: Set-Cookie: soc_session (HttpOnly, SameSite=Strict)

    Browser->>auth: GET /entra/risky-users + cookie
    auth->>Postgres: validate session token hash + IP + UA
    Postgres-->>auth: session valid
    auth->>auth: proxy request to soc-agent
    auth-->>Browser: response
```

---

## Single-Action Token flow

```mermaid
sequenceDiagram
    participant Analyst
    participant Frontend
    participant auth as auth :4000
    participant Postgres
    participant IDP

    Analyst->>Frontend: click response action
    Frontend->>Analyst: SAT modal — enter reason (min 20 chars)
    Analyst->>Frontend: submit reason

    Frontend->>auth: POST /api/sat/issue {action, target, reason}
    auth->>Postgres: store token hash, 60s TTL
    auth-->>Frontend: raw token + expires_in_seconds

    Frontend->>Analyst: confirmation screen — action / target / reason
    Analyst->>Frontend: Confirm & Execute

    Frontend->>auth: POST /api/sat/consume {token, action, target}
    auth->>Postgres: validate hash, mark consumed
    Postgres-->>auth: valid
    auth->>IDP: execute action (disable / suspend / block / revoke)
    IDP-->>auth: success
    auth->>Postgres: write audit record (hash-chained)
    auth-->>Frontend: success
    Frontend->>Analyst: toast notification
```

---

## Investigation pipeline

```mermaid
flowchart TD
    A[Alert arrives via webhook or manual] --> B[correlate — check prior cases]
    B --> C[router_agent — Qwen3 1.7B]
    C --> D[classifies alert type, selects initial SPL]
    D --> E[primary_agent loop — Qwen3 14B]
    E --> F[run SPL via Splunk MCP]
    F --> G[parse results, score finding]
    G --> H{new pivot found?}
    H -- yes --> E
    H -- no --> I[adversarial_agent — Qwen3 14B]
    I --> J{verdict}
    J -- challenged --> E
    J -- approved --> K[generate_ir_report]
    K --> L[estimate_blast_radius]
    K --> M[enrich_ips via AbuseIPDB]
    K --> N[map MITRE ATT&CK techniques]
    L & M & N --> O[save_report to SQLite]
    O --> P[stream findings via SSE]
```

---

## Identity correlation

```mermaid
flowchart LR
    Q["GET /identity/correlate?email=user@example.com"]
    Q --> E[Entra ID\nrisk level, state, sign-in failures]
    Q --> O[Okta\nstatus, failed logins, recent IPs]
    Q --> A[Auth0\nblocked, failed logins, recent IPs]
    E & O & A --> R[aggregate risk signals]
    R --> S[flag shared IPs across IDPs]
    S --> T[unified risk assessment]
```

---

## Container details

### auth (port 4000)

- **Stack:** Rust, Axum, sqlx, argon2, totp-rs, sha2

**Session properties**

- 32-byte CSPRNG opaque tokens, Argon2id-hashed at rest
- HttpOnly, SameSite=Strict cookies
- 30-minute absolute expiry, no sliding window
- IP address and user agent binding: either changes, session is invalidated
- One concurrent session per user: new login kills the previous one

**Authentication tiers**

| Level | Required for |
|-------|-------------|
| L1 (password + TOTP) | Read access, view cases and reports |
| L2 (L1 + re-auth prompt) | Run investigations, query Splunk |
| L3 (L1 + hardware key) | Any response action, SAT required per action |

**Audit log**

- Separate `audit` Postgres schema with a dedicated INSERT-only DB role
- Application cannot modify or delete its own audit records
- Each entry contains SHA-256 of the previous entry (hash-chained)
- Chain integrity verifiable at any time via `GET /audit/verify`

---

### web-frontend (port 4321)

- **Stack:** Astro (SSR), React, Geist Mono, Recharts
- **Auth:** Astro middleware redirects unauthenticated requests to `/login`
- **Astro API routes:** `/api/login`, `/api/sat/issue`, `/api/sat/consume` proxy server-side to auth, forwarding cookies. Browser never talks directly to port 4000.

**Pages**

| Route | Description |
|-------|-------------|
| `/login` | Login page |
| `/` | Case list |
| `/dashboard` | SOC statistics |
| `/investigate` | Manual alert submission |
| `/search` | Natural language SPL |
| `/timeline` | Case timeline |
| `/patterns` | 21 attack patterns + 9 EDR evasion hunts |
| `/compare` | Side-by-side case diff |
| `/health` | Splunk index health |
| `/entra` | Entra ID panel |
| `/okta` | Okta panel |
| `/auth0` | Auth0 panel |
| `/maester` | Maester M365 baseline results |
| `/scubagear` | ScubaGear CISA baseline results |
| `/attackers/[ip]` | Attacker profile across all cases |
| `/cases/[id]` | Full case detail |

---

### soc-agent (port 8000)

- **Stack:** Python, FastAPI, SQLite, httpx, WeasyPrint

**Key modules**

| File | Responsibility |
|------|---------------|
| `main.py` | FastAPI app, all route handlers, identity correlation |
| `agent.py` | Router + primary agent loop |
| `streaming.py` | SSE generator |
| `blast_radius.py` | Affected IPs, users, hosts |
| `report.py` | Structured IR report assembly |
| `database.py` | SQLite: cases, entities, verdicts, queue |
| `patterns.py` | 21 attack patterns + 9 EDR evasion hunts |
| `threat_intel.py` | AbuseIPDB lookups with cache |
| `splunk_mcp.py` | MCP client wrapper |
| `monitor.py` | Saved search polling loop |
| `llm_client.py` | Ollama / cloud LLM abstraction |
| `entra.py` | Microsoft Graph API client |
| `okta.py` | Okta Management API client |
| `auth0.py` | Auth0 Management API client |

**NL to SPL security controls**

- User input placed in a separate LLM message, not interpolated into system instructions
- Input validated against injection pattern blocklist before LLM sees it
- Generated SPL validated before execution: expected index check, dangerous command ban (exec, script, runshellscript, sendemail, outputlookup, collect), 1000-character cap

---

### maester — optional profile

- **Stack:** PowerShell 7.4, Maester 2.1.0
- **Auth:** Client secret against Entra ID
- **Scope:** Entra ID, Teams, Exchange Online, SharePoint
- **Output:** JSON written to `./data/maester/`, read by soc-agent

---

### scubagear — optional profile

- **Stack:** PowerShell 7, ScubaGear, Linux-patched
- **Patch:** `patch_windows_principal.py` removes `WindowsIdentity` and `WindowsPrincipal` calls at build time. OPA binary symlinked to `opa_linux_amd64_static`. Patch submitted upstream to CISA.
- **Scope:** AAD product only (Teams and Exchange blocked by Unix X509Store limitation)
- **Output:** JSON written to `./data/scubagear/`, read by soc-agent

---

## Storage

| Store | Location | Contents |
|-------|----------|---------|
| SQLite | `./data/cases.db` | Cases, entities, verdicts, triage queue, threat intel cache |
| Postgres | Docker volume `postgres_data` | Sessions, action tokens, devices, audit log |
| Ollama models | Docker volume `ollama_data` | Model weights |
| Maester output | `./data/maester/` | latest.json, status.json |
| ScubaGear output | `./data/scubagear/` | latest.json, status.json |

---

## Ports

| Service | Port | Externally reachable |
|---------|------|---------------------|
| auth | 4000 | Yes (single entry point) |
| web-frontend | 4321 | Via auth proxy |
| web-backend | 3000 | Via auth proxy |
| soc-agent | 8000 | Via auth proxy |
| ollama | 11434 | Via auth proxy |
| postgres | 5432 | Internal only |

---

## Profiles

| Profile | Services |
|---------|---------|
| `local` | ollama, soc-agent-local, web-backend, web-frontend, auth, postgres |
| `cloud` | soc-agent-cloud, web-backend, web-frontend, auth, postgres |
| `maester` | maester (additive) |
| `scubagear` | scubagear (additive) |

---

## Deployment

```bash
# Start with local GPU (pulls Ollama models automatically)
make up

# Start with cloud LLM (OpenAI / Anthropic)
make up-cloud

# Rebuild and restart (local)
make rebuild

# Rebuild and restart (cloud)
make rebuild-cloud

# Stop everything
make down

# Pull Ollama models without restarting
make pull-models

# View soc-agent logs
make logs

# Run demo scenario (resets DB + fires attack simulation)
make demo

# Reset case database only
make reset-db

# Run attack simulation
make attack

# Run a raw Splunk query
make query Q="index=main | head 10"

# Splunk VM (KVM)
sudo virsh start splunk-lab
```