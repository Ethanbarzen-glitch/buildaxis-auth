#!/usr/bin/env bash
set -Eeuo pipefail
pairs=("api:9001" "projects:9010" "teams:9020")
for p in "${pairs[@]}"; do
  name="${p%%:*}"; port="${p#*:}"
  printf "%-9s " "$name"
  curl -fsS "http://localhost:${port}/healthz" || echo "FAIL"
done
echo
