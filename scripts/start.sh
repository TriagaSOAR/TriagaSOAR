#!/bin/bash
# scripts/start.sh — start all services

sudo docker compose up --remove-orphans ollama soc-agent web-backend web-frontend