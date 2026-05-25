.PHONY: up down rebuild demo reset-db logs

up:
	sudo docker compose up ollama soc-agent web-frontend

down:
	sudo docker compose down

rebuild:
	sudo docker compose build soc-agent web-frontend
	sudo docker compose up --remove-orphans ollama soc-agent web-frontend

demo:
	bash scripts/demo.sh

reset-db:
	bash scripts/reset-db.sh

logs:
	sudo docker compose logs -f soc-agent