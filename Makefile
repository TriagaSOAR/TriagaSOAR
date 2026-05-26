.PHONY: up down rebuild demo reset-db logs attack query

up:
	sudo docker compose up --remove-orphans -d ollama soc-agent web-backend web-frontend
	sudo docker exec ollama ollama pull qwen3:14b
	sudo docker exec ollama ollama pull qwen3:1.7b
	sudo docker compose logs -f

down:
	sudo docker compose down

rebuild:
	sudo docker compose build soc-agent web-backend web-frontend
	sudo docker compose up --remove-orphans ollama soc-agent web-backend web-frontend

demo:
	bash scripts/reset-db.sh
	sudo docker compose restart soc-agent
	bash scripts/demo.sh

reset-db:
	bash scripts/reset-db.sh

logs:
	sudo docker compose logs -f soc-agent

attack:
	bash scripts/attack-simulation.sh

query:
	bash scripts/splunk-query.sh $(Q)