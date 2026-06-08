# TriagaSOAR

Most SOAR platforms are expensive, opaque, and built for enterprises that already have a full security team. TriagaSOAR is different. It is an open, agentic SOAR platform that combines Splunk alert ingestion, local LLM-powered investigation, cross-platform identity correlation, and cryptographically gated response actions into a single deployable stack. You bring your Splunk instance and your IDPs. TriagaSOAR does the rest.

Built for the [Splunk Agentic Ops Hackathon 2026](https://splunk.devpost.com/) — Security track + Best Use of Splunk MCP Server.

---

## What it does

### Splunk-native investigation

TriagaSOAR uses the Splunk MCP Server as the exclusive interface between its AI agents and Splunk data. No direct SDK calls. No hardcoded queries. Everything goes through MCP tool calls, and every query is generated autonomously by the LLM based on what it finds at each investigation step.

When an alert arrives (via webhook or manual submission), the investigation pipeline runs:

1. A router agent (Qwen3 1.7B) classifies the alert type and selects an initial SPL query
2. A primary agent (Qwen3 14B) runs a multi-step pivot loop: it executes SPL via MCP, reads the results, scores the finding, and derives the next query from what it found. IP to user to process to timeline — each pivot is a live decision, not a template
3. An adversarial agent (Qwen3 14B) critiques the findings and issues a verdict. If it challenges the conclusions, the primary agent re-investigates with the critique as context
4. The final report assembles: MITRE ATT&CK technique mapping, blast radius (affected users, hosts, IPs), AbuseIPDB threat intelligence enrichment, confidence score, kill chain summary, and remediation recommendations

Reports export as PDF or MITRE Navigator JSON layers. Every SPL query executed is recorded in the report so analysts can reproduce the investigation.

**MCP tools used in the investigation loop:**

| Tool | Usage |
|------|-------|
| `splunk_run_query` | Execute dynamically generated SPL at each pivot step |
| `splunk_get_indexes` | Discover available indexes on startup |
| `splunk_get_metadata` | Query hosts, sources, sourcetypes for blast radius |
| `splunk_get_knowledge_objects` | Enumerate saved searches and alerts |

### Cross-platform identity correlation

When an alert involves a user, TriagaSOAR looks that user up across all three configured IDPs simultaneously:

```
GET /identity/correlate?email=user@example.com
```

The response joins the Entra ID profile (risk level, risk state, sign-in failures), the Okta profile (account status, failed logins, recent IPs), and the Auth0 profile (blocked status, recent IPs, login count) into a unified view. It aggregates risk signals across all three, flags cases where the same suspicious IP appears in multiple providers, and returns an overall risk assessment. This is the correlation that normally requires a dedicated SIEM and hours of analyst work.

### Identity IDP integrations

TriagaSOAR integrates with Entra ID, Okta, and Auth0 as monitoring targets, not just login providers.

**Microsoft Entra ID** connects via the Microsoft Graph API with client credentials. It surfaces risky users with risk level and state, risk detections with IP and geolocation, Microsoft security alerts, and sign-in logs. Response actions: disable account, enable account, revoke all sessions.

**Okta** connects via the Okta Management API. It surfaces users with status, system logs, failed login patterns, and suspicious activity. Response actions: suspend user, unsuspend user, clear all sessions.

**Auth0** connects via the Auth0 Management API. It surfaces users, login logs, failed login patterns, suspicious activity, and attack protection configuration (brute force, suspicious IP throttling, breached password detection). Response actions: block user, unblock user.

All response actions across all three IDPs are gated by the Single-Action Token system described below.

### M365 security posture

Two optional containers surface Microsoft 365 compliance results directly in the UI.

**Maester** runs automated security tests against your M365 tenant using the Maester PowerShell framework. Results are categorised by test block and severity. Failed high-severity tests are surfaced immediately in the overview.

**ScubaGear** runs the CISA SCuBA M365 baseline checks. TriagaSOAR ships a patched version of ScubaGear that runs on Linux inside Docker, removing the Windows-only dependency on `WindowsIdentity` and `WindowsPrincipal` at the source level. AAD baseline checks run fully. The patch has been submitted upstream to the CISA ScubaGear repository.

### Single-Action Tokens

Every destructive response action requires a Single-Action Token before it executes. The flow:

1. Analyst clicks a response action (disable user, suspend, revoke sessions, block, clear sessions)
2. A modal opens and requires a written reason with a minimum of 20 characters
3. The frontend calls the auth service, which issues a cryptographically random 32-byte token, stores its Argon2id hash in Postgres with a 60-second TTL, and returns the raw token
4. The confirmation screen shows the exact action, target, and reason before commitment
5. The analyst confirms. The token is consumed (marked used, never replayable), and the action executes against the IDP
6. Every step is written to the tamper-evident audit log: who issued the token, who consumed it, the reason they gave, the action taken, the target, the timestamp, the originating IP

The consequences: you cannot execute a response action by accident. You cannot execute one without a written reason. You cannot replay a token. You cannot take two actions with one token. A compromised session alone is not enough to cause damage.

### Auth layer

A dedicated Rust/Axum auth proxy sits in front of the entire platform. No backend service is reachable without passing through it.

Sessions are 32-byte CSPRNG tokens stored as Argon2id hashes at rest. Sessions bind to the originating IP address and user agent. 30-minute absolute expiry, no sliding window. One concurrent session per user.

The audit log is in a separate Postgres schema with a dedicated INSERT-only database role. The application cannot modify or delete its own audit records. Each entry contains the SHA-256 hash of the previous entry, making the chain tamper-evident and independently verifiable.

### Natural language to SPL

Analysts can query Splunk in plain English. Security controls on the pipeline:

- User input placed in a separate LLM message, not interpolated into system instructions
- Input validated against an injection pattern blocklist before the LLM sees it
- Generated SPL validated before execution: must start with the expected index, bans dangerous commands (exec, script, runshellscript, sendemail, outputlookup, collect), capped at 1000 characters

---

## Stack

| Layer | Technology |
|-------|-----------|
| Auth proxy | Rust / Axum |
| Session store | Postgres 16 |
| SOC agent | Python / FastAPI |
| Local LLM | Ollama / Qwen3:14b + Qwen3:1.7b |
| Frontend | Astro + React |
| Backend | Rust / Axum |
| Splunk integration | Splunk MCP Server v1.1.3 |
| Entra ID | Microsoft Graph API |
| Okta | Okta Management API |
| Auth0 | Auth0 Management API |
| M365 baseline | Maester, ScubaGear (Linux-patched) |
| Case persistence | SQLite |
| Threat intel | AbuseIPDB |

---

## Prerequisites

**Hardware**
- NVIDIA GPU with 12GB+ VRAM (Qwen3 14B requires ~9GB at Q4)
- 16GB+ system RAM

**Software**
- Docker + Docker Compose
- nvidia-container-toolkit ([install guide](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html))

**Splunk**
- Splunk Enterprise 10.x ([60-day free trial](https://www.splunk.com/en_us/download/splunk-enterprise.html))
- [Splunk Developer License](https://dev.splunk.com/enterprise/dev_license/) applied
- [Splunk MCP Server v1.1.3](https://splunkbase.splunk.com/app/7931) installed
- Token authentication enabled
- A role named exactly `mcp_user` with `mcp_tool_execute` capability
- An encrypted MCP token generated from within the MCP Server app (not Settings → Tokens)

---

## Setup

### 1. Clone

```bash
git clone https://github.com/InfinitiWarrior/Splunk-Hackaton-Project
cd Splunk-Hackaton-Project
```

### 2. Configure environment

```bash
cp .env.example .env
```

Fill in `.env` with your values. At minimum:

```env
SPLUNK_HOST=192.168.x.x
SPLUNK_PORT=8089
SPLUNK_TOKEN=your-mcp-token
SESSION_SECRET=        # openssl rand -hex 32
ADMIN_EMAIL=
ADMIN_PASSWORD=
```

### 3. Configure Splunk MCP Server

On your Splunk instance:

1. Install the MCP Server app from Splunkbase (app ID 7931)
2. Enable token authentication: Settings → Tokens → enable
3. Create a role named exactly `mcp_user`: Settings → Access Controls → Roles → New Role
4. Assign `mcp_tool_execute` capability to `mcp_user`
5. Assign `mcp_user` to your user
6. Open the MCP Server app → generate a new encrypted token with **Audience: `mcp`**
7. Paste the token into `.env` as `SPLUNK_TOKEN`

Verify it works:

```bash
source .env
curl -k -X POST https://$SPLUNK_HOST:$SPLUNK_PORT/services/mcp \
  -H "Authorization: Bearer $SPLUNK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

### 4. Start

```bash
make up
```

Open `http://localhost:4321`. Log in with the admin credentials you set in `.env`.

For cloud LLM mode (OpenAI or Anthropic instead of Ollama):

```bash
make up-cloud
```

For M365 posture checks:

```bash
sudo docker compose --profile local --profile maester up -d maester
sudo docker compose --profile local --profile scubagear up -d scubagear
```

---

## Makefile

| Command | Description |
|---------|-------------|
| `make up` | Start all services (local GPU, pulls Ollama models) |
| `make up-cloud` | Start all services (cloud LLM) |
| `make down` | Stop everything |
| `make rebuild` | Rebuild and restart (local) |
| `make rebuild-cloud` | Rebuild and restart (cloud) |
| `make pull-models` | Pull Ollama models without restarting |
| `make logs` | Tail soc-agent logs |
| `make demo` | Full clean demo run (reset DB + attack simulation) |
| `make reset-db` | Wipe case database |
| `make attack` | Run attack simulation only |
| `make query Q="..."` | Run a raw Splunk query |

---

## Environment variables

```bash
# Postgres
POSTGRES_DB=soc_triage
POSTGRES_USER=postgres
POSTGRES_PASSWORD=
AUTH_APP_PASSWORD=
AUDIT_WRITER_PASSWORD=
AUDIT_READER_PASSWORD=

# Auth
SESSION_SECRET=          # openssl rand -hex 32
ADMIN_EMAIL=
ADMIN_PASSWORD=

# Splunk
SPLUNK_HOST=
SPLUNK_PORT=8089
SPLUNK_TOKEN=
SPLUNK_WRITE_TOKEN=      # separate token with write access for saved searches
SPLUNK_VERIFY_SSL=false

# Local LLM
REASONER_MODEL=qwen3:14b
ROUTER_MODEL=qwen3:1.7b

# Cloud LLM (cloud profile only)
CLOUD_PROVIDER=openai    # or anthropic
CLOUD_MODEL=gpt-4o
OPENAI_API_KEY=
ANTHROPIC_API_KEY=

# Microsoft Entra ID (optional)
ENTRA_TENANT_ID=
ENTRA_CLIENT_ID=
ENTRA_CLIENT_SECRET=

# Okta (optional)
OKTA_DOMAIN=
OKTA_API_TOKEN=

# Auth0 (optional)
AUTH0_DOMAIN=
AUTH0_CLIENT_ID=
AUTH0_CLIENT_SECRET=

# Maester (optional)
MAESTER_TENANT_ID=
MAESTER_CLIENT_ID=
MAESTER_CLIENT_SECRET=

# ScubaGear (optional)
SCUBAGEAR_TENANT_ID=
SCUBAGEAR_CLIENT_ID=
SCUBAGEAR_CERT_THUMBPRINT=
SCUBAGEAR_ORGANIZATION=

# Threat intelligence (optional)
ABUSEIPDB_API_KEY=

# Monitoring
MONITOR_ENABLED=false
MONITOR_INTERVAL_SECONDS=60
```

---

## API reference

All endpoints served through the auth proxy at port 4000. Session cookie required for everything except `/auth/login` and `/auth/health`.

**Auth**

| Endpoint | Description |
|----------|-------------|
| `POST /auth/login` | Authenticate, receive session cookie |
| `POST /auth/logout` | Invalidate session |
| `GET /auth/health` | Health check |

**Investigation**

| Endpoint | Description |
|----------|-------------|
| `POST /investigate` | Submit alert for investigation |
| `POST /investigate/stream` | Streaming investigation via SSE |
| `POST /webhook` | Receive Splunk webhook alert |
| `GET /cases` | All cases |
| `GET /cases/{id}` | Single case |
| `GET /cases/{id}/pdf` | Export as PDF |
| `GET /cases/{id}/navigator` | Export MITRE Navigator JSON layer |
| `PATCH /cases/{id}/verdict` | Set confirmed or false positive |
| `GET /cases/compare?a=&b=` | Compare two cases |
| `GET /stats` | Platform statistics |
| `GET /attackers/{ip}` | Attacker profile across all cases |
| `GET /patterns` | Attack pattern library |

**Identity**

| Endpoint | Description |
|----------|-------------|
| `GET /identity/correlate?email=` | Cross-platform identity lookup |
| `GET /entra/risky-users` | Entra ID risky users |
| `GET /entra/risk-detections` | Risk detections |
| `GET /entra/alerts` | Security alerts |
| `GET /entra/signins` | Sign-in logs |
| `POST /entra/actions/disable-user` | Disable Entra account (SAT required) |
| `POST /entra/actions/revoke-sessions` | Revoke Entra sessions (SAT required) |
| `POST /entra/actions/enable-user` | Enable Entra account (SAT required) |
| `GET /okta/users` | Okta users |
| `GET /okta/logs/failed` | Failed logins |
| `GET /okta/logs/suspicious` | Suspicious activity |
| `POST /okta/actions/suspend` | Suspend Okta user (SAT required) |
| `POST /okta/actions/clear-sessions` | Clear Okta sessions (SAT required) |
| `GET /auth0/users` | Auth0 users |
| `GET /auth0/attack-protection` | Attack protection config |
| `POST /auth0/actions/block` | Block Auth0 user (SAT required) |
| `POST /auth0/actions/unblock` | Unblock Auth0 user (SAT required) |

**Response actions**

| Endpoint | Description |
|----------|-------------|
| `POST /sat/issue` | Issue a Single-Action Token |
| `POST /sat/consume` | Consume token and execute action |

**Splunk**

| Endpoint | Description |
|----------|-------------|
| `POST /splunk/query` | Natural language to SPL |
| `GET /splunk/health` | Splunk instance info and indexes |
| `POST /splunk/saved-searches` | Create saved search |

**Audit**

| Endpoint | Description |
|----------|-------------|
| `GET /audit` | Audit log (admin only) |
| `GET /audit/verify` | Verify audit chain integrity |

---

## Project structure

```
├── auth/                       # Rust/Axum auth proxy
│   ├── src/
│   │   ├── main.rs             # Entry point, router, AppState
│   │   ├── db/                 # Postgres: sessions, users, tokens, audit, devices
│   │   ├── middleware/         # Session validation, rate limiting
│   │   ├── routes/             # Login, SAT issue/consume, audit
│   │   ├── proxy/              # Reverse proxy to web-backend and soc-agent
│   │   ├── crypto/             # Argon2id, token generation, audit hashing
│   │   └── totp/               # TOTP verification and enrollment
│   └── Dockerfile
├── soc-agent/                  # Python investigation agent
│   ├── main.py                 # FastAPI app, all routes, identity correlation
│   ├── agent.py                # Router + primary + adversarial agents
│   ├── splunk_mcp.py           # Splunk MCP client wrapper
│   ├── report.py               # IR report generator
│   ├── blast_radius.py         # Blast radius estimation
│   ├── database.py             # SQLite case persistence
│   ├── patterns.py             # 21 attack patterns + 9 EDR evasion hunts
│   ├── threat_intel.py         # AbuseIPDB enrichment with cache
│   ├── entra.py                # Microsoft Graph API client
│   ├── okta.py                 # Okta Management API client
│   └── auth0.py                # Auth0 Management API client
├── web-backend/                # Rust/Axum transparent proxy
├── web-frontend/               # Astro + React dashboard
│   └── src/
│       ├── pages/
│       │   ├── login.astro
│       │   ├── api/login.ts    # Server-side auth proxy
│       │   └── api/sat/        # Server-side SAT proxies
│       ├── components/         # EntraPanel, OktaPanel, Auth0Panel, SatConfirmModal
│       └── middleware.ts       # Session guard
├── postgres/                   # Postgres init scripts and Dockerfile
│   └── init/
│       ├── 01_schema.sql       # Tables: users, sessions, action_tokens, devices
│       ├── 02_audit.sql        # Audit schema (INSERT-only)
│       ├── 03_seed.sql         # Roles and grants
│       └── 04_update_passwords.sh
├── integrations/
│   ├── maester/                # PowerShell + Maester container
│   └── scubagear/              # PowerShell + ScubaGear (Linux-patched)
├── scripts/
│   ├── attack-simulation.sh
│   ├── demo.sh
│   ├── reset-db.sh
│   └── splunk-query.sh
├── data/                       # SQLite DB and integration outputs (gitignored)
├── docker-compose.yml
├── Makefile
└── .env.example
```

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design with Mermaid diagrams covering the container topology, auth sequence, SAT flow, investigation pipeline, and identity correlation.

---

## License

MIT