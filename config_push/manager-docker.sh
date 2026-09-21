#!/bin/bash

# =============================================================================
# Net Tools - Manager Docker Swarm
# =============================================================================
# Uso: ./manager-docker.sh {start|stop|restart|status|logs|console|init-env}
#
# O ".env" guarda os segredos (SECRET_KEY de cripto, sessao e senha admin).
# Local da VM e gitignored - NUNCA versionar.
# =============================================================================

STACK_NAME="nettools"
SERVICE_NAME="app"
COMPOSE_FILE="docker-compose.yml"
IMAGE="nettools:local"

# Rede overlay dedicada (fora do range das outras stacks)
NET_NAME="nettools-net"
NET_SUBNET="10.192.201.0/24"
NET_GATEWAY="10.192.201.1"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

load_env() {
    ENV_FILE="${NETTOOLS_ENV_PATH:-./.env}"
    if [ -f "$ENV_FILE" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            clean_line=$(echo "$line" | tr -d '\r')
            [[ "$clean_line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$clean_line" ]] && continue
            key="${clean_line%%=*}"; value="${clean_line#*=}"
            key=$(echo "$key" | tr -d ' ')
            case "$key" in
                APP_NAME|BRAND_LOGIN|BRAND_APP|APP_PORT|SECRET_KEY|SESSION_SECRET|SESSION_MAX_AGE|SESSION_HTTPS_ONLY|ADMIN_USER|ADMIN_PASSWORD|REQUIRE_APPROVAL|TIMEZONE|NETMIKO_MAX_WORKERS|NETMIKO_CONN_TIMEOUT|LIBRENMS_URL|LIBRENMS_TOKEN|LIBRENMS_VERIFY_TLS|RCONFIG_URL|RCONFIG_TOKEN|RCONFIG_VERIFY_TLS|SWARM_NODE_CONSTRAINT|NETTOOLS_ENV_PATH)
                    value="${value%\"}"; value="${value#\"}"
                    export "$key=$value"
                    ;;
            esac
        done < "$ENV_FILE"
    fi

    if [ -z "$SWARM_NODE_CONSTRAINT" ]; then
        export SWARM_NODE_CONSTRAINT="$(hostname)"
    fi

    local env_rel="${NETTOOLS_ENV_PATH:-./.env}"
    if [[ "$env_rel" =~ ^\./ ]]; then
        export NETTOOLS_ENV_PATH="$(pwd)/${env_rel#./}"
    else
        export NETTOOLS_ENV_PATH="$env_rel"
    fi
}

generate_secret() { openssl rand -hex 32; }

set_if_empty() {
    # set_if_empty ARQUIVO CHAVE
    local file="$1" key="$2"
    if ! grep -q "^$key=." "$file" 2>/dev/null; then
        local value; value=$(generate_secret)
        if grep -q "^$key=" "$file"; then
            sed -i "s|^$key=.*|$key=$value|" "$file"
        else
            echo "$key=$value" >> "$file"
        fi
        echo "$value"
    fi
}

ensure_env() {
    if [ ! -f .env ]; then
        if [ ! -f .env.example ]; then
            echo -e "${RED}[ERRO] .env.example nao encontrado.${NC}"; exit 1
        fi
        cp .env.example .env
        echo -e "${GREEN}[SUCESSO] .env criado a partir do .env.example.${NC}"
    fi
    SECRET_KEY=$(set_if_empty .env SECRET_KEY)
    SESSION_SECRET=$(set_if_empty .env SESSION_SECRET)
    ADMIN_PASSWORD=$(set_if_empty .env ADMIN_PASSWORD)
    if [ -n "$SECRET_KEY" ] || [ -n "$SESSION_SECRET" ] || [ -n "$ADMIN_PASSWORD" ]; then
        echo -e "${YELLOW}[AVISO] Segredos gerados e gravados no .env. Guarde este arquivo!${NC}"
        [ -n "$ADMIN_PASSWORD" ] && echo -e "${BLUE}[INFO] Senha inicial do admin: ${ADMIN_PASSWORD}${NC}"
    fi
    echo -e "${YELLOW}[AVISO] Nunca altere SECRET_KEY depois de cadastrar devices (as senhas deixam de ser decifradas).${NC}"
}

ensure_network() {
    if docker network ls --format '{{.Name}}' | grep -q "^${NET_NAME}$"; then
        echo -e "${GREEN}[SUCESSO] Rede '${NET_NAME}' ja existe.${NC}"
    else
        echo -e "${BLUE}[INFO] Criando rede '${NET_NAME}' (${NET_SUBNET})...${NC}"
        docker network create -d overlay --opt encrypted \
            --subnet $NET_SUBNET --gateway $NET_GATEWAY --attachable $NET_NAME \
            && echo -e "${GREEN}[SUCESSO] Rede criada.${NC}" \
            || { echo -e "${RED}[ERRO] Falha ao criar a rede.${NC}"; exit 1; }
    fi
}

build_image() {
    # --network host: necessario p/ o pip resolver DNS em hosts com Tailscale
    # (o /etc/resolv.conf aponta para 100.100.100.100 e o build nao o herda).
    echo -e "${BLUE}[INFO] Construindo imagem ${IMAGE}...${NC}"
    docker build --network host -t "$IMAGE" . || { echo -e "${RED}[ERRO] Falha no build da imagem.${NC}"; exit 1; }
    echo -e "${GREEN}[SUCESSO] Imagem ${IMAGE} pronta.${NC}"
}

usage() {
    echo "Uso: $0 {start|stop|restart|status|logs|console|init-env}"
    echo ""
    echo "  start    : Garante .env/rede, constroi a imagem e sobe a stack"
    echo "  stop     : Remove a stack (volume e rede preservados)"
    echo "  restart  : Remove, aguarda e sobe novamente"
    echo "  status   : Status dos servicos"
    echo "  logs     : Logs do app (follow)"
    echo "  console  : Shell dentro do container"
    echo "  init-env : (Re)cria o .env com segredos novos"
    exit 1
}

if [ -z "$1" ]; then usage; fi

case "$1" in
    start)
        ensure_env; load_env; ensure_network; build_image
        echo -e "${BLUE}[INFO] Subindo stack '$STACK_NAME'...${NC}"
        docker stack deploy -c $COMPOSE_FILE --with-registry-auth $STACK_NAME
        ;;

    stop)
        echo -e "${RED}[INFO] Parando stack '$STACK_NAME'...${NC}"
        docker stack rm $STACK_NAME
        ;;

    restart)
        docker stack rm $STACK_NAME
        echo "[INFO] Aguardando 10s..."
        sleep 10
        ensure_env; load_env; ensure_network; build_image
        docker stack deploy -c $COMPOSE_FILE --with-registry-auth $STACK_NAME
        ;;

    status)  docker stack ps $STACK_NAME --no-trunc ;;
    logs)    docker service logs -f --tail 100 ${STACK_NAME}_${SERVICE_NAME} ;;

    console)
        CID=$(docker ps -q -f name=${STACK_NAME}_${SERVICE_NAME} | head -n1)
        if [ -z "$CID" ]; then
            echo -e "${RED}[ERRO] Container nao encontrado.${NC}"
        else
            docker exec -it $CID sh
        fi
        ;;

    init-env)
        if [ -f .env ]; then
            read -p "[AVISO] .env ja existe. Recriar com segredos novos (pode invalidar senhas de devices)? (s/N): " CONFIRM
            [[ ! "$CONFIRM" =~ ^[sS]$ ]] && { echo "Abortado."; exit 0; }
            rm -f .env
        fi
        ensure_env
        ;;

    *) usage ;;
esac
