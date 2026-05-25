#!/bin/bash
# scripts/rebuild.sh — rebuild and restart all services

sudo docker compose build soc-agent web-backend web-frontend
sudo docker compose up --remove-orphans ollama soc-agent web-backend web-frontend