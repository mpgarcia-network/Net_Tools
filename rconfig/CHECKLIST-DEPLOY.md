# 📋 Checklist de campo — rConfig (`rconfig`)

> Passo a passo detalhado: [`README.md`](README.md). Esta folha é para uso em campo.

## 1. Pré-requisitos
- [ ] Docker Swarm ativo: `docker node ls`
- [ ] Repo em `/opt/rconfig` → `cd /opt/rconfig`
- [ ] Portas livres: `8443` (HTTPS) e `8088` (HTTP)
- [ ] (Opcional) container com saída para `github.com` (templates)

## 2. Deploy
- [ ] `./manager-docker.sh init-env`
- [ ] Editar `.env`:
  - [ ] `APP_URL=https://<IP-do-host>:8443`
  - [ ] `SANCTUM_STATEFUL_DOMAINS=<IP-LAN>:8443,<IP-TAILSCALE>:8443,localhost:8443`
  - [ ] `LOG_VIEWER_API_STATEFUL_DOMAINS=<mesmos hosts:porta>`
  - [ ] `TIMEZONE=America/Sao_Paulo`
- [ ] `./manager-docker.sh start`
- [ ] `./manager-docker.sh status` → **4/4** (`nginx`, `app`, `db`, `redis`)
- [ ] `curl -k -s -o /dev/null -w '%{http_code}\n' https://localhost:8443/` → `302`
- [ ] `./manager-docker.sh console` → `php artisan v8core:install` (1ª instalação)

## 3. Acesso e TLS
- [ ] Usuário admin criado e login OK
- [ ] Certificado com SAN (LAN + Tailscale) + `docker service update --force rconfig_nginx`
- [ ] Web UI abre em `https://<IP-do-host>:8443`

## 4. Coleta (device de teste)
- [ ] Device cadastrado (categoria, vendor, modelo, **credenciais**)
- [ ] Command group / commands atribuídos
- [ ] `Download Now` → 1ª config (v1) aparece em **Configurations**
- [ ] 2ª coleta **sem mudança** → **não** cria registro novo;
      **Application Log** mostra `Config unchanged - skipped saving (Keep Unchanged Config)`

## 5. Recursos
- [ ] Keep Unchanged ligado: `docker exec $(docker ps -q -f name=rconfig_app | head -n1) printenv RCONFIG_KEEP_UNCHANGED` → `true`
- [ ] Templates: **Templates → Import from GitHub** → Ctrl+F5 → escolher **Vendor**/`.yml`
- [ ] Log Viewer: `/log-viewer` lista os logs (se `403`, revisar stateful domains)
- [ ] Retenção agendada no crontab (dia 1, 04:00):
      `0 4 1 * * cd /opt/rconfig && ./purge-old-configs.sh >> /var/log/rconfig-purge.log 2>&1`

## 6. Finalização
- [ ] Backup: dump do MariaDB + `.env` + `nginx/ssl/`
- [ ] Registrar segredos/IPs/URLs no Bitwarden
- [ ] Anotar hosts de acesso (usados no SAN e nos stateful domains)

---
*Mantido pela equipe de Engenharia e Operações © 2026*
