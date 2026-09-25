#!/usr/bin/env bash
# =============================================================================
# Net Tools - Setup de Descoberta de Ativos no LibreNMS (assistente)
# -----------------------------------------------------------------------------
# Configura a descoberta no LibreNMS (communities SNMP + redes de scan) e
# dispara o scan / a descoberta de topologia (LLDP). Interativo (menu) ou por
# subcomando.
#
# Uso:
#   scripts/setup-ativos.sh                     # menu interativo
#   scripts/setup-ativos.sh communities         # communities SNMP (listar/add/alterar/remover)
#   scripts/setup-ativos.sh networks            # redes de descoberta (listar/add/alterar/remover)
#   scripts/setup-ativos.sh scan "<subnets>"    # scan (usa communities registradas)
#   scripts/setup-ativos.sh topology            # forca descoberta de topologia (LLDP)
#
# Requisitos no host: docker + python3 (para manipular os arrays JSON).
# Variaveis opcionais: LNMS_CONTAINER (container do LibreNMS).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$(realpath "$0")")/.." && pwd)"
LIBRENMS_DIR="$ROOT/librenms"
LB_CONTAINER=""

# carrega credenciais do banco (MYSQL_USER/MYSQL_PASSWORD) do stack
if [ -f "$LIBRENMS_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$LIBRENMS_DIR/.env"
  set +a
fi
MYSQL_USER="${MYSQL_USER:-librenms}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"

# ---------- utilitarios LibreNMS ----------
find_librenms() {
  LB_CONTAINER="${LNMS_CONTAINER:-}"
  if [ -z "$LB_CONTAINER" ]; then
    LB_CONTAINER=$(docker ps -q -f name='^librenms$' | head -n1)
  fi
  if [ -z "$LB_CONTAINER" ]; then
    LB_CONTAINER=$(docker ps -q -f 'label=com.docker.compose.service=librenms' | head -n1)
  fi
  if [ -z "$LB_CONTAINER" ]; then
    echo "[ERRO] container do LibreNMS nao encontrado."
    echo "       Suba a stack: cd $LIBRENMS_DIR && ./manager-docker.sh start"
    exit 1
  fi
}

lnms() { docker exec -u librenms "$LB_CONTAINER" sh -c "cd /opt/librenms && lnms $*"; }

config_get() { lnms config:get "$1" 2>/dev/null; }

# adiciona/alterar no indice N (adicionar = proximo indice livre)
config_set_index() { # KEY INDEX VALUE
  lnms config:set "$1.$2" "$3" >/dev/null && echo "[OK] $1[$2] = '$3'"
}

# atualiza o array JSON inteiro direto no banco + limpa cache
db_replace_config() { # KEY JSON
  local key="$1" value="$2"
  local db
  db=$(docker ps -q -f name='^librenms_db$' | head -n1)
  [ -n "$db" ] || { echo "[ERRO] container db do LibreNMS nao encontrado."; exit 1; }
  if [ -z "$MYSQL_PASSWORD" ]; then
    echo "[ERRO] MYSQL_PASSWORD nao encontrado (defina em $LIBRENMS_DIR/.env)."
    exit 1
  fi
  docker exec -i "$db" mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" librenms <<SQL
UPDATE config SET config_value='$value' WHERE config_name='$key';
SQL
  lnms config:clear >/dev/null 2>&1 || true
  echo "[OK] $key atualizado no banco."
}

next_index() { # KEY -> proximo indice livre
  local arr
  arr=$(config_get "$1")
  printf '%s' "$arr" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(len(d) if isinstance(d, list) else 0)"
}

# ---------- menus de comunidade ----------
cmd_communities() {
  find_librenms
  while true; do
    echo ""
    echo "=== Communities SNMP ==="
    config_get snmp.community | python3 -c "import sys,json; [print(f'  [\$i] \$c') for i,c in enumerate(json.load(sys.stdin))]"
    echo ""
    echo "  1) Adicionar community"
    echo "  2) Alterar uma community"
    echo "  3) Remover uma community"
    echo "  0) Voltar"
    read -p "Opcao: " op
    case "$op" in
      1) read -p "Community nova: " v
         config_set_index snmp.community "$(next_index snmp.community)" "$v" ;;
      2) read -p "Indice a alterar: " i
         read -p "Novo valor: " v
         config_set_index snmp.community "$i" "$v" ;;
      3) read -p "Indice a remover: " i
         arr=$(config_get snmp.community)
         new=$(printf '%s' "$arr" | python3 -c "import sys,json; d=json.load(sys.stdin); d.pop(int('$i')) if len(d)>int('$i') else None; print(json.dumps(d))")
         db_replace_config snmp.community "$new" ;;
      0) return ;;
    esac
  done
}

# ---------- menus de redes de descoberta ----------
cmd_networks() {
  find_librenms
  while true; do
    echo ""
    echo "=== Redes de descoberta (nets) ==="
    config_get nets | python3 -c "import sys,json; [print(f'  [\$i] \$n') for i,n in enumerate(json.load(sys.stdin))]"
    echo ""
    echo "  1) Adicionar rede (CIDR)"
    echo "  2) Alterar uma rede"
    echo "  3) Remover uma rede"
    echo "  4) Scan da rede agora"
    echo "  0) Voltar"
    read -p "Opcao: " op
    case "$op" in
      1) read -p "CIDR nova (ex: 10.0.120.0/24): " v
         config_set_index nets "$(next_index nets)" "$v" ;;
      2) read -p "Indice a alterar: " i
         read -p "Novo CIDR: " v
         config_set_index nets "$i" "$v" ;;
      3) read -p "Indice a remover: " i
         arr=$(config_get nets)
         new=$(printf '%s' "$arr" | python3 -c "import sys,json; d=json.load(sys.stdin); d.pop(int('$i')) if len(d)>int('$i') else None; print(json.dumps(d))")
         db_replace_config nets "$new" ;;
      4) read -p "CIDR para scan (Enter = todas as registradas): " sn
         [ -z "$sn" ] && sn=$(config_get nets | python3 -c "import sys,json; print(' '.join(json.load(sys.stdin)))")
         [ -z "$sn" ] && { echo "[ERRO] Nenhuma rede registrada."; continue; }
         scan_subnets "$sn" ;;
      0) return ;;
    esac
  done
}

# ---------- scan ----------
scan_subnets() { # SUBNETS (espaco separado)
  find_librenms
  local sn
  for sn in $1; do
    echo "[SCAN] $sn ..."
    docker exec -u librenms "$LB_CONTAINER" python3 /opt/librenms/snmp-scan.py -v "$sn"
  done
  echo ""
  echo "[FIM] Scan concluido. Os switches descobertos aparecem no LibreNMS."
}

cmd_scan() {
  find_librenms
  echo "=== Scan de redes ==="
  echo "Communities registradas:"
  config_get snmp.community | python3 -c "import sys,json; [print(f'  - \$c') for c in json.load(sys.stdin)]"
  local SUBNETS="${1:-}"
  if [ -z "$SUBNETS" ]; then
    read -p "Subnets para scan (espaco separado; ex: 10.0.120.0/24 10.0.121.0/24): " SUBNETS
  fi
  [ -z "$SUBNETS" ] && { echo "[ERRO] Informe ao menos uma subnet."; exit 1; }
  scan_subnets "$SUBNETS"
}

# ---------- topologia ----------
cmd_topology() {
  find_librenms
  echo "[TOPOLOGIA] lnms device:discoverall ..."
  docker exec -u librenms "$LB_CONTAINER" sh -c "cd /opt/librenms && lnms device:discoverall"
  echo "[OK] Descoberta de topologia disparada."
}

# ---------- menu principal ----------
cmd_menu() {
  while true; do
    echo ""
    echo "=== Net Tools - Setup de Descoberta de Ativos (LibreNMS) ==="
    echo "  1) Communities SNMP"
    echo "  2) Redes de descoberta (nets)"
    echo "  3) Scan de redes (snmp-scan)"
    echo "  4) Forcar topologia (LLDP)"
    echo "  0) Sair"
    read -p "Opcao: " op
    case "$op" in
      1) cmd_communities ;;
      2) cmd_networks ;;
      3) cmd_scan ;;
      4) cmd_topology ;;
      0) exit 0 ;;
    esac
  done
}

# ---------- main ----------
case "${1:-menu}" in
  communities) cmd_communities ;;
  networks) cmd_networks ;;
  scan) cmd_scan "${2:-}" ;;
  topology) cmd_topology ;;
  menu|"") cmd_menu ;;
  *) echo "Uso: $0 [communities|networks|scan|topology]"; exit 1 ;;
esac
