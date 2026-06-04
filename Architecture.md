# Architecture — Splunk SOC Triage Agent

## Overview

A four-container autonomous SOC triage system. Alerts enter via webhook or manual form, are investigated end-to-end by a multi-agent LLM pipeline, and surface as structured IR reports with MITRE ATT&CK mappings, blast radius estimation, threat intel enrichment, and PDF export.

---

## System Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Host Network (network_mode: host)           │
│                                                                     │
│  ┌──────────────────┐     ┌──────────────────────────────────────┐  │
│  │   web-frontend   │     │           web-backend                │  │
│  │  Astro + React   │────▶│         Rust / Axum                  │  │
│  │   port 4321      │     │           port 3000                  │  │
│  │                  │     │  · CORS proxy to soc-agent           │  │
│  │  · Case browser  │     │  · Forwards all routes to :8000      │  │
│  │  · Live SSE UI   │     │  · Passes content-type / accept /    │  │
│  │  · Attack forms  │     │    authorization headers             │  │
│  │  · Dashboards    │     └──────────────┬───────────────────────┘  │
│  │  · MITRE export  │                    │                           │
│  └──────────────────┘                    ▼                           │
│                          ┌───────────────────────────────────────┐  │
│                          │            soc-agent                  │  │
│                          │         Python / FastAPI              │  │
│                          │            port 8000                  │  │
│                          │                                       │  │
│                          │  Router agent (Qwen3 1.7B)            │  │
│                          │      ↓ classifies alert               │  │
│                          │  Primary agent (Qwen3 14B)            │  │
│                          │      ↓ multi-step pivot loop          │  │
│                          │  Adversarial agent (Qwen3 14B)        │  │
│                          │      ↓ critiques findings             │  │
│                          │  Primary re-investigates if challenged│  │
│                          │                                       │  │
│                          │  · SQLite case persistence            │  │
│                          │  · AbuseIPDB enrichment               │  │
│                          │  · Blast radius estimation            │  │
│                          │  · MITRE ATT&CK mapping               │  │
│                          │  · PDF export (WeasyPrint)            │  │
│                          │  · Saved search monitor               │  │
│                          │  · Triage queue worker                │  │
│                          └──────────┬──────────┬─────────────────┘  │
│                                     │          │                     │
│                    ┌────────────────┘          └──────────────────┐  │
│                    ▼                                              ▼  │
│  ┌─────────────────────────┐            ┌────────────────────────┐  │
│  │         Ollama          │            │   Splunk Enterprise    │  │
│  │      port 11434         │            │   KVM VM :8089/:8000   │  │
│  │   (local profile only)  │            │   192.168.122.10       │  │
│  │                         │            │                        │  │
│  │  · qwen3:14b  (RTX4090) │            │  · MCP Server v1.1.3   │  │
│  │  · qwen3:1.7b (routing) │            │    (Splunkbase #7931)  │  │
│  └─────────────────────────┘            │  · splunk_run_query    │  │
│                                         │  · splunk_get_indexes  │  │
│  Cloud profile: OpenAI / Anthropic      │  · splunk_get_info     │  │
│  via CLOUD_PROVIDER env var             │  · splunk_get_metadata │  │
│  (no Ollama container)                  │  · splunk_get_knowledge│  │
│                                         └────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘

External:
  · AbuseIPDB API   — IP reputation enrichment (cached in SQLite)
  · MITRE Navigator — https://mitre-attack.github.io/attack-navigator/
```

---

## Container Details

### web-frontend (port 4321)
- **Stack:** Astro + React, SSR, Vite, Recharts, Tailwind
- **Pages:** `/` case list, `/investigate` trigger form, `/dashboard` SOC stats, `/health` Splunk index health, `/search` natural language SPL, `/timeline` case timeline, `/patterns` attack pattern library, `/compare` case diff, `/cases/[id]` case detail, `/attackers/[ip]` attacker profile
- **Key features:** Live SSE streaming investigation view, MITRE Navigator JSON download, PDF download, verdict buttons, dark/light theme

### web-backend (port 3000)
- **Stack:** Rust, Axum, Tokio, reqwest, tower-http
- **Role:** Transparent reverse proxy — all routes fall through to soc-agent at `:8000`. Adds CORS headers. Single `main.rs`.

### soc-agent (port 8000)
- **Stack:** Python, FastAPI, SQLite, httpx, WeasyPrint, APScheduler
- **Key modules:**

| File | Responsibility |
|---|---|
| `main.py` | FastAPI app, all route handlers |
| `agent.py` | Router + primary agent loop, Qwen3 chat |
| `streaming.py` | SSE generator — streams findings per step |
| `blast_radius.py` | Estimates affected IPs, users, hosts |
| `mitre.py` | Maps findings to ATT&CK techniques |
| `report.py` | Assembles structured IR report |
| `database.py` | SQLite: cases, entities, verdicts, queue |
| `patterns.py` | 21 attack patterns + 9 EDR evasion hunts |
| `threat_intel.py` | AbuseIPDB lookups with SQLite cache |
| `splunk_mcp.py` | MCP client wrapper for Splunk tools |
| `monitor.py` | Saved search polling loop |
| `webhook.py` | Splunk alert webhook parser |
| `llm_client.py` | LLM abstraction — local Ollama or cloud API |

- **Agent pipeline:**
  1. Router (1.7B) classifies alert type and selects initial SPL
  2. Primary (14B) runs multi-step pivot loop: IP → user → process → timeline
  3. Each step: run SPL via MCP → parse → generate finding + confidence score
  4. Loop terminates at max depth or when no new pivots found
  5. Adversarial agent (14B) critiques findings
  6. Primary re-investigates if adversarial verdict is "challenged"
  7. MITRE mapping, blast radius, threat intel, report assembly

### Ollama (port 11434) — local profile only
- **Runtime:** NVIDIA container toolkit, RTX 4090 GPU passthrough
- **Models:** `qwen3:14b` (primary + adversarial), `qwen3:1.7b` (router)
- **Cloud profile:** Replaces Ollama with direct OpenAI/Anthropic API calls via `LLM_MODE=cloud`, controlled by `CLOUD_PROVIDER` env var

---

## Data Flow — Inbound Alert

```
Splunk alert fires
      │
      ▼
POST /webhook  ──── parse_splunk_webhook() ────▶ background task
      │
      │   or
      ▼
POST /investigate/stream  (manual / queue)
      │
      ▼
correlate() — check SQLite for prior cases with same IPs/users
      │
      ▼
triage(alert)
  ├── router_agent() → alert_type, initial_spl
  └── primary_agent() loop
        ├── splunk_run_query(spl) via MCP
        ├── parse findings, confidence
        ├── pivot: next SPL from finding
        └── repeat up to max_depth
      │
      ▼
adversarial_agent() → critique + verdict
      │
      ▼ (if challenged)
primary_agent() re-investigates with critique context
      │
      ▼
generate_ir_report()
      │
      ├── estimate_blast_radius()
      │     └── splunk queries for related IPs, users, hosts
      │
      ├── enrich_ips() → AbuseIPDB (cached)
      │
      ├── map_mitre_techniques()
      │
      └── save_report() → SQLite
            └── stream final report via SSE
```

---

## Data Flow — SSE Streaming

```
Browser                 web-backend            soc-agent
   │                        │                      │
   │── GET /investigate ────▶│── proxy ────────────▶│
   │                        │                      │ stream_investigation()
   │◀── text/event-stream ──│◀────────────────────│   yield step events:
   │                        │                      │   · routing
   │  event: step           │                      │   · query_run
   │  event: finding        │                      │   · finding
   │  event: adversarial    │                      │   · adversarial_review
   │  event: complete       │                      │   · complete (full report)
```

---

## Deployment

```
# Local (GPU, Ollama)
make up         # docker compose --profile local up -d

# Cloud (OpenAI / Anthropic)
make up-cloud   # docker compose --profile cloud up -d

# Rebuild after code changes
make rebuild

# Teardown
make down

# Splunk VM must be running first
sudo virsh start splunk-lab
```

### Required environment variables (`.env`)

| Variable | Description |
|---|---|
| `SPLUNK_HOST` | Splunk VM IP (e.g. `192.168.122.10`) |
| `SPLUNK_TOKEN` | Read token with `mcp_tool_execute` capability |
| `SPLUNK_WRITE_TOKEN` | Write token for saved search creation |
| `ABUSEIPDB_API_KEY` | Optional — IP enrichment |
| `LLM_MODE` | `local` or `cloud` |
| `CLOUD_PROVIDER` | `openai` or `anthropic` (cloud mode) |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Cloud mode credentials |
| `MONITOR_ENABLED` | `true` to start saved search monitor |
| `REASONER_MODEL` | Default `qwen3:14b` |
| `ROUTER_MODEL` | Default `qwen3:1.7b` |

---

## Storage

- **SQLite** at `./data/cases.db` (bind-mounted into soc-agent container)
- **Tables:** `cases`, `entities`, `triage_queue`, `monitored_searches`
- **Ollama model weights** in Docker volume `ollama_data`