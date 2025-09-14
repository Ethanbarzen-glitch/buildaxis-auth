
[![smoke](https://github.com/Ethanbarzen-glitch/buildaxis-auth/actions/workflows/smoke.yml/badge.svg)](https://github.com/Ethanbarzen-glitch/buildaxis-auth/actions/workflows/smoke.yml)
[![smoke](https://github.com/Ethanbarzen-glitch/buildaxis-auth/actions/workflows/smoke.yml/badge.svg)](https://github.com/Ethanbarzen-glitch/buildaxis-auth/actions/workflows/smoke.yml)

## Run released images (GHCR)

```bash
# Login once per shell (paste your GHCR PAT when prompted)
docker login ghcr.io -u Ethanbarzen-glitch

# Run a released version
TAG=v0.1.8 docker compose -f docker-compose.yml -f docker-compose.ghcr.yml up -d --wait

# Health checks (expect 200)
curl -s -o /dev/null -w "api:%{http_code}\n"      http://localhost:9001/healthz
curl -s -o /dev/null -w "projects:%{http_code}\n" http://localhost:9010/healthz
curl -s -o /dev/null -w "teams:%{http_code}\n"    http://localhost:9020/healthz
```
