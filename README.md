# Splunk SOC Triage Agent

An AI-powered security operations triage system built on Splunk, powered by the **Splunk MCP Server**. Submit an alert, and the system investigates it through Splunk data via MCP tool calls — pivoting across log sources, scoring confidence, mapping findings to MITRE ATT&CK techniques, estimating blast radius, and generating a structured IR report. A second adversarial agent critiques the primary investigation and flags gaps.

Built for the [Splunk Agentic Ops Hackathon](https://splunk.devpost.com/)  Security track + Best Use of Splunk MCP Server.


---

## Features

- **Multi-stage investigation loop** — primary agent runs iterative SPL queries, pivoting on IPs, users, and processes
- **Adversarial review** — a second agent critiques findings and forces re-investigation of weak points
- **MITRE ATT&CK mapping** — findings mapped to technique IDs with kill chain assembly
- **Confidence scoring** — every finding scored 0–100% based on evidence quality
- **Cross-session correlation** — SQLite case persistence flags repeated attackers across investigations
- **Blast radius estimation** — queries Splunk for lateral spread across hosts and users
- **Structured IR reports** — severity, confidence, kill chain, recommendations, SPL queries executed
- **Web UI** — dark/light theme dashboard with case browser, detail view, and investigation form

---
## Splunk MCP Server Integration

This project uses the Splunk MCP Server as the exclusive interface between the AI agents and Splunk data. No direct Splunk SDK calls — everything goes through MCP.

The primary investigation agent uses the following MCP tools in its autonomous loop:

| Tool | Usage |
|---|---|
| `splunk_run_query` | Execute dynamically generated SPL queries at each investigation step |
| `splunk_get_indexes` | Discover available indexes on startup |
| `splunk_get_metadata` | Query hosts, sources, and sourcetypes for blast radius estimation |
| `splunk_get_knowledge_objects` | Enumerate saved searches and alerts |

The agent generates SPL queries autonomously based on what it finds at each step — it is not working from a pre-written query library. Each pivot decision (IP → user → process → timeline) is made by the LLM after reading the previous MCP tool result.

---
## Architecture

```
browser → web-frontend (Astro/React, :4321)
        → web-backend (Rust/Axum proxy, :3000)
        → soc-agent (Python/FastAPI, :8000)
        → Splunk MCP Server (:8089)
        → Ollama (Qwen3 14B + 1.7B, :11434)
```

See `architecture.md` for the full diagram.

---

## Tech Stack

| Layer               | Technology                                          |
| ------------------- | --------------------------------------------------- |
| Investigation agent | Python, FastAPI, httpx                              |
| LLM inference       | Ollama, Qwen3 14B (reasoning), Qwen3 1.7B (routing) |
| Splunk integration  | Splunk MCP Server v1.1.3                            |
| Case persistence    | SQLite                                              |
| API proxy           | Rust, Axum, tower-http                              |
| Frontend            | Astro, React, TypeScript                            |
| Infrastructure      | Docker, docker compose, nvidia-container-toolkit    |

---

## Prerequisites

### Hardware
- NVIDIA GPU with 12GB+ VRAM (Qwen3 14B requires ~9GB at Q4)
- 16GB+ system RAM

### Software
- Docker + docker compose
- nvidia-container-toolkit ([install guide](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html))
- A KVM/VM hypervisor (or any machine) to run Splunk

### Splunk
- Splunk Enterprise 10.x ([60-day free trial](https://www.splunk.com/en_us/download/splunk-enterprise.html))
- [Splunk Developer License](https://dev.splunk.com/enterprise/dev_license/) applied to your instance
- [Splunk MCP Server v1.1.3](https://splunkbase.splunk.com/app/7931) installed on your Splunk instance
- Token authentication enabled
- A role named exactly `mcp_user` with `mcp_tool_execute` capability assigned
- An encrypted MCP token generated from within the MCP Server app (not Settings → Tokens)

---

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/InfinitiWarrior/Splunk-Hackaton-Project
cd Splunk-Hackaton-Project
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` with your values:

```env
SPLUNK_HOST=192.168.x.x       # IP of your Splunk VM
SPLUNK_PORT=8089
SPLUNK_TOKEN=your-mcp-token   # Generated from MCP Server app with audience=mcp
SPLUNK_VERIFY_SSL=false
OLLAMA_HOST=http://localhost:11434
REASONER_MODEL=qwen3:14b
ROUTER_MODEL=qwen3:1.7b
DB_PATH=/app/data/cases.db
```

### 3. Configure Splunk MCP Server

On your Splunk instance:

1. Install the MCP Server app from Splunkbase (app ID 7931)
2. Enable token authentication: Settings → Tokens → enable
3. Create a role named exactly `mcp_user`: Settings → Access Controls → Roles → New Role
4. Assign `mcp_tool_execute` capability to `mcp_user`
5. Assign `mcp_user` role to your user
6. Open the MCP Server app → generate a new encrypted token with **Audience: `mcp`**
7. Paste the token into your `.env` as `SPLUNK_TOKEN`

Verify it works:

```bash
source .env
curl -k -X POST https://$SPLUNK_HOST:$SPLUNK_PORT/services/mcp \
  -H "Authorization: Bearer $SPLUNK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

### 4. Pull models

```bash
make up
docker exec -it ollama ollama pull qwen3:14b
docker exec -it ollama ollama pull qwen3:1.7b
```

### 5. Start everything

```bash
make up
```

Open `http://localhost:4321` in your browser.

---

## Usage

### From the web UI

1. Navigate to `http://localhost:4321`
2. Click **+ New Investigation**
3. Fill in the alert title, search terms, Splunk index, and time range
4. Click **Start Investigation** — takes 20–60 seconds
5. View the generated IR report

### From the API

```bash
curl -X POST http://localhost:8000/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Brute force attempt",
    "search_terms": "Failed password",
    "index": "main",
    "earliest": "-1h",
    "latest": "now"
  }'
```

### Demo

Run a full simulated attack chain and investigation:

```bash
make demo
```

This runs the attack simulation on your Splunk VM, waits for indexing, then triggers an investigation automatically.

### Reset

Wipe the case database for a clean run:

```bash
make reset-db
```

---

## Makefile

| Command | Description |
|---|---|
| `make up` | Start all services |
| `make down` | Stop all services |
| `make rebuild` | Rebuild and restart all services |
| `make demo` | Full clean demo run |
| `make reset-db` | Wipe case database |
| `make logs` | Tail soc-agent logs |

---

## Project Structure

```
├── soc-agent/                  # Python investigation agent (FastAPI)
│   ├── main.py                 # API endpoints
│   ├── agent.py                # Router + primary + adversarial agents
│   ├── splunk_mcp.py           # Splunk MCP client wrapper
│   ├── report.py               # IR report generator
│   ├── mitre.py                # MITRE ATT&CK mapping
│   ├── blast_radius.py         # Blast radius estimation
│   └── database.py             # SQLite case persistence
├── web-backend/                # Rust/Axum API proxy
├── web-frontend/               # Astro + React dashboard
├── scripts/
│   ├── attack-simulation.sh    # Simulated brute force + escalation
│   ├── splunk-query.sh         # Quick SPL query tool
│   ├── demo.sh                 # Full demo runner
│   └── reset-db.sh             # Wipe case database
├── data/                       # SQLite database (gitignored)
├── docker-compose.yml
├── Makefile
└── .env.example
```

---

## License

MIT — see [LICENSE](LICENSE)
