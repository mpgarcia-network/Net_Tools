#!/bin/bash
# =============================================================================
# Net Tools - LibreNMS (manager docker compose)
# Uso: ./manager-docker.sh {start|stop|restart|status|logs|pull|console|init-env}
# =============================================================================
set -euo pipefail

COMPOSE_FILE="compose.yml"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

load_env() {
    if [ -f .env ]; then
        set -a
        # shellcheck disable=SC1091
        . ./.env
        set +a
    fi
}

generate_secret() { openssl rand -hex 24; }

set_if_empty() {
    # set_if_empty CHAVE  -> gera e grava se estiver vazia
    local key="$1"
    if ! grep -q "^${key}=.\+" .env 2>/dev/null; then
        local value; value=$(generate_secret)
        if grep -q "^${key}=" .env; then
            sed -i "s|^${key}=.*|${key}=${value}|" .env
        else
            echo "${key}=${value}" >> .env
        fi
        echo "$value"
    fi
}

ensure_env() {
    if [ ! -f .env ]; then
        cp .env.example .env
        echo -e "${GREEN}[SUCESSO] .env criado a partir do .env.example.${NC}"
    fi
    [ -f librenms.env ] || cp librenms.env.example librenms.env
    [ -f msmtpd.env ] || cp msmtpd.env.example msmtpd.env
    local pw; pw=$(set_if_empty MYSQL_PASSWORD)
    if [ -n "$pw" ]; then
        echo -e "${BLUE}[INFO] Senha do banco gerada (MYSQL_PASSWORD) no .env.${NC}"
    fi
}

ensure_dirs() {
    load_env
    mkdir -p data/db data/librenms
    if command -v sudo >/dev/null 2>&1; then
        # MariaDB roda como uid 999; o app como PUID:PGID
        sudo chown -R 999:999 data/db 2>/dev/null || true
        sudo chown -R "${PUID:-1000}:${PGID:-1000}" data/librenms 2>/dev/null || true
    fi
}

usage() {
    echo "Uso: $0 {start|stop|restart|status|logs|pull|console|init-env}"
    exit 1
}

[ -z "${1:-}" ] && usage

case "$1" in
    start)
        ensure_env; load_env; ensure_dirs
        echo -e "${BLUE}[INFO] Subindo LibreNMS...${NC}"
        docker compose -f "$COMPOSE_FILE" up -d
        echo -e "${GREEN}[SUCESSO] LibreNMS em http://<host>:${APP_PORT:-8001}${NC}"
        ;;
    stop)      docker compose -f "$COMPOSE_FILE" down ;;
    restart)
        docker compose -f "$COMPOSE_FILE" down
        ensure_env; load_env; ensure_dirs
        docker compose -f "$COMPOSE_FILE" up -d
        ;;
    status)    docker compose -f "$COMPOSE_FILE" ps ;;
    logs)      docker compose -f "$COMPOSE_FILE" logs -f --tail 100 ;;
    pull)
        load_env
        docker compose -f "$COMPOSE_FILE" pull
        docker compose -f "$COMPOSE_FILE" up -d
        ;;
    console)   docker compose -f "$COMPOSE_FILE" exec librenms bash ;;
    init-env)
        if [ -f .env ]; then
            read -p "[AVISO] .env ja existe. Recriar? (s/N): " CONFIRM
            [[ ! "$CONFIRM" =~ ^[sS]$ ]] && { echo "Abortado."; exit 0; }
            rm -f .env
        fi
        ensure_env
        ;;
    *) usage ;;
esac
