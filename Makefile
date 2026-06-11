.PHONY: up up-cloud down rebuild rebuild-cloud demo reset-db logs attack query pull-models

# ── Local mode (Ollama on GPU) ────────────────────────────────────────────
up:
	sudo docker compose --profile cloud down 2>/dev/null || true
	sudo docker compose --profile local up --remove-orphans -d
	sudo docker exec ollama ollama pull qwen3:14b
	sudo docker exec ollama ollama pull qwen3:1.7b
	sudo docker compose --profile local logs -f

# ── Cloud mode (OpenAI / Anthropic API) ──────────────────────────────────
up-cloud:
	sudo docker compose --profile local down 2>/dev/null || true
	sudo docker compose --profile cloud up --remove-orphans -d
	sudo docker compose --profile cloud logs -f

# ── Stop everything ───────────────────────────────────────────────────────
down:
	sudo docker compose --profile local --profile cloud down

# ── Rebuild (local) ───────────────────────────────────────────────────────
rebuild:
	sudo docker compose --profile cloud down 2>/dev/null || true
	sudo docker compose --profile local build
	sudo docker compose --profile local up --remove-orphans -d
	sudo docker compose --profile local logs -f

# ── Rebuild (cloud) ───────────────────────────────────────────────────────
rebuild-cloud:
	sudo docker compose --profile local down 2>/dev/null || true
	sudo docker compose --profile cloud build
	sudo docker compose --profile cloud up --remove-orphans -d
	sudo docker compose --profile cloud logs -f

# ── Pull Ollama models (local mode only) ──────────────────────────────────
pull-models:
	sudo docker exec ollama ollama pull qwen3:14b
	sudo docker exec ollama ollama pull qwen3:1.7b

# ── Demo ──────────────────────────────────────────────────────────────────
demo:
	bash scripts/reset-db.sh
	sudo docker compose --profile local restart soc-agent 2>/dev/null || sudo docker compose --profile cloud restart soc-agent
	bash scripts/demo.sh

# ── Utilities ─────────────────────────────────────────────────────────────
reset-db:
	bash scripts/reset-db.sh

logs:
	sudo docker compose --profile local logs -f soc-agent 2>/dev/null || sudo docker compose --profile cloud logs -f soc-agent

attack:
	bash scripts/attack-simulation.sh

query:
	bash scripts/splunk-query.sh $(Q)
	
# ── Splunk self-contained mode ─────────────────────────────────────────
up-splunk:
	sudo docker compose --profile local --profile splunk up --remove-orphans -d
	@echo "Waiting for Splunk to be healthy..."
	@until sudo docker inspect splunk --format='{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; do sleep 5; echo "Still waiting..."; done
	@echo "Running Splunk setup..."
	sudo docker exec splunk bash /setup.sh
	sudo docker exec splunk bash /seed.sh
	sudo docker compose --profile local --profile splunk logs -f

splunk-setup:
	@echo "Waiting for Splunk to be healthy..."
	@until sudo docker inspect splunk --format='{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; do sleep 5; echo "Still waiting..."; done
	sudo docker exec splunk bash /setup.sh
	sudo docker exec splunk bash /seed.sh
	@echo "Setup complete."

splunk-token:
	@sudo docker exec splunk cat /tmp/splunk_mcp_token 2>/dev/null || echo "Token not yet generated — run make splunk-setup first"