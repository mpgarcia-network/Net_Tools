# Net Tools

Plataforma de **gestão de configuração de rede (NCM)** — push, backup/versionamento,
diff, aprovação, agendamento, auditoria e compliance, multi-vendor (Netmiko).

> Aplicação web (FastAPI + Netmiko) empacotada como stack Docker Swarm, autônoma
> (não depende de outras ferramentas). Conectores opcionais para LibreNMS e rConfig,
> configuráveis pela própria interface (Configurações → Conexões de API).

## Recursos

**Push / governança**
- Inventário (cadastro manual + import `.xlsx`/CSV), busca, paginação e **edição em massa** por vendor.
- Modelos de comando (templates) com `#[sleep N]` e seleção por driver.
- Execução em lote com **simulação (dry-run)** ou aplicação real; **diff antes/depois**.
- Aprovação, agendamento (cron/once), auditoria e RBAC.
- Credencial padrão global (TACACS/AAA) e/ou por device.
- **Papel no site** por device (Acesso / TOR / Distribuição / Core / Firewall) e
  **níveis de operador** (Básico / Médio / Avançado) com **alçada por hierarquia**
  (Core > Distribuição/TOR > Acesso; Firewall = avançado; não classificado = avançado).

**Conformidade / Drift (Golden config)**
- Políticas com regras **require** (deve existir), **forbid** (não pode existir) e
  **regex**; alvo por vendor/driver/tag e/ou lista de devices.
- Execução assíncrona lendo a config ao vivo (Netmiko), com **evidências** (linhas)
  por regra e **drift** (mudança desde a última coleta) via snapshot Git interno.

**Backup / versionamento (congelado)**
- Motor próprio (Netmiko + Git/`dulwich`) **implementado mas fora do menu** até a
  integração com o rConfig (fonte de backup) ser concluída. Segue acessível por URL.
- **Conectores opcionais**: **LibreNMS** (descoberta/inventário) e **rConfig**
  (inventário + status de backup + diff). Oxidized não é utilizado.

**Integrações**
- **Conexões de API** (LibreNMS/rConfig) editáveis em **Configurações** — URL, token
  (cifrado em repouso) e validação de TLS, com botão **Testar** e fallback para `.env`.

**Plataforma**
- Tema escuro/claro/automático, i18n PT/EN/ES, API e webhooks.

## Quickstart (Docker Swarm)

```bash
cd stacks/net-tools            # ou a raiz do repo
./manager-docker.sh init-env   # gera .env (SECRET_KEY, SESSION_SECRET, senha admin)
./manager-docker.sh start      # cria a rede, builda e sobe a stack
./manager-docker.sh status
```
Acesse `http://<host>:8090` e entre com `admin` + a senha do `init-env`.

## Variáveis principais (`.env`)

| Variável | Uso | Padrão |
|---|---|---|
| `APP_PORT` | Porta HTTP no host | `8090` |
| `SECRET_KEY` | Cifra segredos (nunca trocar depois) | gerado |
| `SESSION_SECRET` / `SESSION_MAX_AGE` / `SESSION_HTTPS_ONLY` | Sessão | gerado / 43200 / false |
| `ADMIN_USER` / `ADMIN_PASSWORD` | Admin inicial | `admin` / gerado |
| `REQUIRE_APPROVAL` | Exige aprovação para aplicar | `true` |
| `TIMEZONE` | Fuso (log/agenda) | `America/Sao_Paulo` |
| `NETMIKO_MAX_WORKERS` / `NETMIKO_CONN_TIMEOUT` | Concorrência/timeout | `10` / `30` |
| `SWARM_NODE_CONSTRAINT` | Nó do Swarm | hostname |

Integrações: `LIBRENMS_URL`/`LIBRENMS_TOKEN`/`LIBRENMS_VERIFY_TLS` e
`RCONFIG_URL`/`RCONFIG_TOKEN`/`RCONFIG_VERIFY_TLS` — opcionais; podem ser definidas
em **Configurações → Conexões de API** (o banco tem prioridade sobre o `.env`).

## Segurança

- Senhas (device e credencial padrão) cifradas em repouso (Fernet via `SECRET_KEY`).
- Sessão com expiração/revalidação, anti-CSRF, headers de segurança e rate-limit de login.
- Upload de imagem validado por conteúdo; duplicidade de IP/nome bloqueada.
- Recomendado rodar apenas em VPN ou atrás de HTTPS (`SESSION_HTTPS_ONLY=true`).

## Estrutura

```
app/
  main.py            # rotas + UI
  engine.py          # executor Netmiko (push, dry-run, diff, captura)
  backup.py          # motor de backup/versionamento (dulwich)
  compliance.py      # conformidade (golden) + drift
  catalog.py         # vendor/modelo -> driver Netmiko
  importer.py        # import xlsx/CSV
  i18n.py            # PT/EN/ES
  connectors/        # librenms, rconfig (opcionais)
  templates/ static/
```

## Roadmap

- [x] Push com governança, diff, agendamento, auditoria, i18n, edição em massa.
- [x] Motor de backup/versionamento (Git/dulwich) + diff.
- [x] Compliance/golden config (`require`/`forbid`/`regex`) + drift por device.
- [x] Conexões de API (LibreNMS/rConfig) editáveis na interface.
- [ ] Notificações de drift; API REST + tokens; SSO/2FA; trilha imutável.
- [ ] Instalador Windows.

## Licença

Proprietária — ver `LICENSE`.
