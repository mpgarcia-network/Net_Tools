# Changelog — rConfig (deploy)

## v1.0 — 2026-09-19

- Stack Docker Swarm padronizada (`manager-docker.sh` + `docker-compose.yml`).
- Terminação TLS via Nginx (portas dedicadas) e proxy reverso.
- Patch **"Keep Unchanged Config"**: não grava novo arquivo/registro quando a
  configuração coletada não mudou.
- Scripts: **retenção** (purge mensal de configs antigas) e **reset de
  inventário**.
- `CHECKLIST-DEPLOY.md` (passo a passo de campo) e documentação de deploy.
