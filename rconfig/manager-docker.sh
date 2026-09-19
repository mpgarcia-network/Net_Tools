#!/bin/bash

# =============================================================================
# rConfig - Manager Docker Swarm
# =============================================================================
# Uso: ./manager-docker.sh {start|stop|restart|status|logs|console|init-env|update}
#
# O ".env" tem dupla função: é a config do Laravel (bind-mountada no container)
# E as variáveis de composição lidas aqui (RCONFIG_VERSION, portas, paths, etc.).
# Ele é local da VM e gitignored — NUNCA versionar (guarda senhas do banco).
# =============================================================================

STACK_NAME="rconfig"
SERVICE_NAME="app"
COMPOSE_FILE="docker-compose.yml"

# Rede overlay dedicada (subnet fora do range em uso pelas outras stacks)
NET_NAME="rconfig-net"
NET_SUBNET="10.192.200.0/24"
NET_GATEWAY="10.192.200.1"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Carrega do .env somente as variáveis usadas pelo compose (whitelist).
# Não exporta APP_KEY/secrets: o container lê direto do arquivo bind-mountado.
load_env() {
    ENV_FILE="${RCONFIG_ENV_PATH:-./.env}"
    if [ -f "$ENV_FILE" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            clean_line=$(echo "$line" | tr -d '\r')
            [[ "$clean_line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$clean_line" ]] && continue
            key="${clean_line%%=*}"
            value="${clean_line#*=}"
            key=$(echo "$key" | tr -d ' ')
            case "$key" in
                RCONFIG_VERSION|APP_ENV|APP_DEBUG|APP_URL|APP_FORCE_HTTPS|TRUSTED_PROXIES|RCONFIG_KEEP_UNCHANGED|DB_DATABASE|DB_USERNAME|DB_PASSWORD|MYSQL_ROOT_PASSWORD|SWARM_NODE_CONSTRAINT|RCONFIG_ENV_PATH|RCONFIG_DB_DATA_PATH|RCONFIG_NGINX_CONF_PATH|RCONFIG_NGINX_SSL_PATH|RCONFIG_PATCH_PATH|RCONFIG_HTTP_PORT|RCONFIG_HTTPS_PORT|REDIS_HOST|REDIS_PORT|REDIS_PASSWORD|QUEUE_CONNECTION)
                    value="${value%\"}"; value="${value#\"}"
                    export "$key=$value"
                    ;;
            esac
        done < "$ENV_FILE"
    fi

    # Determinação dinâmica do hostname (vazio => usa o hostname do nó)
    if [ -z "$SWARM_NODE_CONSTRAINT" ]; then
        export SWARM_NODE_CONSTRAINT="$(hostname)"
    fi

    # Swarm exige bind mount com caminho absoluto
    local env_rel="${RCONFIG_ENV_PATH:-./.env}"
    if [[ "$env_rel" =~ ^\./ ]]; then
        export RCONFIG_ENV_PATH="$(pwd)/${env_rel#./}"
    else
        export RCONFIG_ENV_PATH="$env_rel"
    fi

    local db_rel="${RCONFIG_DB_DATA_PATH:-./data/mariadb}"
    if [[ "$db_rel" =~ ^\./ ]]; then
        export RCONFIG_DB_DATA_PATH="$(pwd)/${db_rel#./}"
    else
        export RCONFIG_DB_DATA_PATH="$db_rel"
    fi

    local conf_rel="${RCONFIG_NGINX_CONF_PATH:-./nginx/conf.d}"
    if [[ "$conf_rel" =~ ^\./ ]]; then
        export RCONFIG_NGINX_CONF_PATH="$(pwd)/${conf_rel#./}"
    else
        export RCONFIG_NGINX_CONF_PATH="$conf_rel"
    fi

    local ssl_rel="${RCONFIG_NGINX_SSL_PATH:-./nginx/ssl}"
    if [[ "$ssl_rel" =~ ^\./ ]]; then
        export RCONFIG_NGINX_SSL_PATH="$(pwd)/${ssl_rel#./}"
    else
        export RCONFIG_NGINX_SSL_PATH="$ssl_rel"
    fi

    local patch_rel="${RCONFIG_PATCH_PATH:-./patch/SaveConfigsToDiskAndDb.php}"
    if [[ "$patch_rel" =~ ^\./ ]]; then
        export RCONFIG_PATCH_PATH="$(pwd)/${patch_rel#./}"
    else
        export RCONFIG_PATCH_PATH="$patch_rel"
    fi
}

# Garante o arquivo de patch (bind mount file precisa existir no host).
ensure_patch() {
    if [ ! -f "$RCONFIG_PATCH_PATH" ]; then
        echo -e "${RED}[ERRO] Patch nao encontrado em $RCONFIG_PATCH_PATH.${NC}"
        echo -e "${YELLOW}       O bind mount falharia no Swarm. Rode 'git pull' no repo ou ajuste RCONFIG_PATCH_PATH.${NC}"
        exit 1
    fi
}

# Garante o datadir do MariaDB com dono do container (mysql = uid 999).
ensure_db_data() {
    if [ ! -d "$RCONFIG_DB_DATA_PATH" ]; then
        echo -e "${BLUE}[INFO] Criando datadir do MariaDB em $RCONFIG_DB_DATA_PATH...${NC}"
        mkdir -p "$RCONFIG_DB_DATA_PATH" 2>/dev/null || sudo mkdir -p "$RCONFIG_DB_DATA_PATH"
    fi
    chown -R 999:999 "$RCONFIG_DB_DATA_PATH" 2>/dev/null || sudo chown -R 999:999 "$RCONFIG_DB_DATA_PATH" 2>/dev/null || true
    chmod 700 "$RCONFIG_DB_DATA_PATH" 2>/dev/null || true
}

# Garante os diretórios do Nginx e gera um par TLS self-signed se não houver.
ensure_nginx() {
    if [ ! -d "$RCONFIG_NGINX_CONF_PATH" ]; then
        echo -e "${BLUE}[INFO] Criando diretório de config do Nginx em $RCONFIG_NGINX_CONF_PATH...${NC}"
        mkdir -p "$RCONFIG_NGINX_CONF_PATH" 2>/dev/null || sudo mkdir -p "$RCONFIG_NGINX_CONF_PATH"
    fi
    if [ ! -d "$RCONFIG_NGINX_SSL_PATH" ]; then
        echo -e "${BLUE}[INFO] Criando diretório de TLS do Nginx em $RCONFIG_NGINX_SSL_PATH...${NC}"
        mkdir -p "$RCONFIG_NGINX_SSL_PATH" 2>/dev/null || sudo mkdir -p "$RCONFIG_NGINX_SSL_PATH"
    fi

    if [ ! -f "$RCONFIG_NGINX_SSL_PATH/rconfig.crt" ] || [ ! -f "$RCONFIG_NGINX_SSL_PATH/rconfig.key" ]; then
        echo -e "${YELLOW}[AVISO] Certificado TLS ausente em $RCONFIG_NGINX_SSL_PATH.${NC}"
        echo -e "${BLUE}[INFO] Gerando par self-signed (válido 825 dias) para o Nginx...${NC}"
        openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
            -keyout "$RCONFIG_NGINX_SSL_PATH/rconfig.key" \
            -out "$RCONFIG_NGINX_SSL_PATH/rconfig.crt" \
            -subj "/C=BR/O=rConfig/CN=$(hostname)" >/dev/null 2>&1 \
            || sudo sh -c "openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
                -keyout '$RCONFIG_NGINX_SSL_PATH/rconfig.key' \
                -out '$RCONFIG_NGINX_SSL_PATH/rconfig.crt' \
                -subj '/C=BR/O=rConfig/CN=$(hostname)' >/dev/null 2>&1" \
            || { echo -e "${RED}[ERRO] Falha ao gerar certificado. Coloque rconfig.crt/rconfig.key em $RCONFIG_NGINX_SSL_PATH.${NC}"; exit 1; }
        echo -e "${GREEN}[SUCESSO] Certificado self-signed gerado (substitua por um válido em produção).${NC}"
    fi
}

# Gera o .env a partir do exemplo com senhas de banco aleatórias (1ª vez).
ensure_env() {
    if [ ! -f .env ]; then
        if [ ! -f .env.example ]; then
            echo -e "${RED}[ERRO] .env.example não encontrado.${NC}"
            exit 1
        fi
        cp .env.example .env
        ROOT_PASS=$(openssl rand -hex 24)
        DB_PASS=$(openssl rand -hex 24)
        sed -i "s/^MYSQL_ROOT_PASSWORD=.*/MYSQL_ROOT_PASSWORD=${ROOT_PASS}/" .env
        sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=${DB_PASS}/" .env
        echo -e "${GREEN}[SUCESSO] .env criado a partir de .env.example com senhas aleatórias.${NC}"
        echo -e "${YELLOW}[AVISO]  Guarde este .env — contém as credenciais do banco do rConfig.${NC}"
    fi
}

# Garante a rede overlay dedicada
ensure_network() {
    if docker network ls --format '{{.Name}}' | grep -q "^${NET_NAME}$"; then
        echo -e "${GREEN}[SUCESSO] Rede '${NET_NAME}' já existe.${NC}"
    else
        echo -e "${BLUE}[INFO] Rede '${NET_NAME}' não encontrada. Criando...${NC}"
        docker network create -d overlay --opt encrypted \
            --subnet $NET_SUBNET --gateway $NET_GATEWAY \
            --attachable $NET_NAME
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[SUCESSO] Rede '${NET_NAME}' criada (${NET_SUBNET}).${NC}"
        else
            echo -e "${RED}[ERRO] Falha ao criar a rede. Verifique subnet/conflitos.${NC}"
            exit 1
        fi
    fi
}

usage() {
    echo "Uso: $0 {start|stop|restart|status|logs|console|init-env|update}"
    echo ""
    echo "  start    : Garante .env/rede e sobe a stack (docker stack deploy)"
    echo "  stop     : Remove a stack (volumes e rede são preservados)"
    echo "  restart  : Remove, aguarda e sobe novamente"
    echo "  status   : Mostra o status dos serviços"
    echo "  logs     : Acompanha os logs do app"
    echo "  console  : Entra no terminal do container do app"
    echo "  init-env : (Re)cria o .env a partir do .env.example com senhas novas"
    echo "  update   : Atualiza para a imagem indicada em RCONFIG_VERSION (.env)"
    exit 1
}

if [ -z "$1" ]; then
    usage
fi

case "$1" in
    start)
        ensure_env
        load_env
        ensure_db_data
        ensure_nginx
        ensure_patch
        ensure_network
        echo -e "${BLUE}[INFO] Iniciando stack '$STACK_NAME'...${NC}"
        docker stack deploy -c $COMPOSE_FILE --with-registry-auth $STACK_NAME
        ;;

    stop)
        echo -e "${RED}[INFO] Parando stack '$STACK_NAME'...${NC}"
        docker stack rm $STACK_NAME
        ;;

    restart)
        echo -e "${YELLOW}[INFO] Reiniciando stack '$STACK_NAME'...${NC}"
        docker stack rm $STACK_NAME
        echo "[INFO] Aguardando 10s para limpeza do Swarm..."
        sleep 10
        ensure_env
        load_env
        ensure_db_data
        ensure_nginx
        ensure_patch
        ensure_network
        docker stack deploy -c $COMPOSE_FILE --with-registry-auth $STACK_NAME
        ;;

    status)
        docker stack ps $STACK_NAME --no-trunc
        ;;

    logs)
        echo -e "${YELLOW}[INFO] Logs de ${STACK_NAME}_${SERVICE_NAME}:${NC}"
        docker service logs -f --tail 100 ${STACK_NAME}_${SERVICE_NAME}
        ;;

    console)
        CONTAINER_ID=$(docker ps -q -f name=${STACK_NAME}_${SERVICE_NAME} | head -n 1)
        if [ -z "$CONTAINER_ID" ]; then
            echo -e "${RED}[ERRO] Container do app não encontrado neste nó.${NC}"
        else
            echo -e "${GREEN}[INFO] Acessando terminal do app ($CONTAINER_ID)...${NC}"
            docker exec -it $CONTAINER_ID bash
        fi
        ;;

    init-env)
        if [ -f .env ]; then
            read -p "[AVISO] .env já existe. Recriar do exemplo (perde credenciais atuais)? (s/N): " CONFIRM
            if [[ ! "$CONFIRM" =~ ^[sS]$ ]]; then
                echo "Operação abortada."
                exit 0
            fi
            rm -f .env
        fi
        ensure_env
        ;;

    update)
        load_env
        IMG="rconfig/rconfig:${RCONFIG_VERSION:-latest}"
        echo -e "${BLUE}[INFO] Atualizando app para imagem $IMG (migrações rodam no entrypoint)...${NC}"
        docker service update --image $IMG --force ${STACK_NAME}_${SERVICE_NAME}
        ;;

    *)
        usage
        ;;
esac