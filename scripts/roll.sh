#!/usr/bin/env bash
set -Eeuo pipefail
TAG="${1:-latest}"
echo "TAG=$TAG" > .env
docker compose --env-file .env -f docker-compose.yml -f docker-compose.ghcr.yml pull
docker compose --env-file .env -f docker-compose.yml -f docker-compose.ghcr.yml up -d --force-recreate --wait
docker compose ps --format '{{.Name}} -> {{.Image}}'
./scripts/health.sh
