# Net Tools

Plataforma de **gestão de configuração de rede (NCM)** — push, backup/versionamento,
diff, aprovação, agendamento, auditoria e compliance, multi-vendor (Netmiko).

> Aplicação web (FastAPI + Netmiko) empacotada como stack Docker Swarm, autônoma
> (não depende de outras ferramentas). Conectores opcionais para LibreNMS e Oxidized.

## Recursos

**Push / governança**
- Inventário (cadastro manual + import `.xlsx`/CSV), busca, paginação e **edição em massa** por vendor.
- Modelos de comando (templates) com `#[sleep N]` e seleção por driver.
- Execução em lote com **simulação (dry-run)** ou aplicação real; **diff antes/depois**.
- Aprovação, agendamento (cron/once), auditoria e RBAC.
- Credencial padrão global (TACACS/AAA) e/ou por device.

**Backup / versionamento (núcleo próprio)**
- Coleta de config multi-vendor com Netmiko.
- Versionamento em **Git** (`dulwich`, Apache-2.0) por device.
- Histórico, **diff** entre versões e base para drift/rollback.

**Plataforma**
- Tema escuro/claro/automático, i18n PT/EN/ES, API e webhooks.
- **Conectores opcionais**: LibreNMS (descoberta), Oxidized (backup), rConfig (import).

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

Conectores opcionais: `LIBRENMS_URL`/`LIBRENMS_TOKEN`, `OXIDIZED_URL`/`OXIDIZED_TOKEN`,
`RCONFIG_URL`/`RCONFIG_TOKEN`.

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
  catalog.py         # vendor/modelo -> driver Netmiko
  importer.py        # import xlsx/CSV
  i18n.py            # PT/EN/ES
  connectors/        # librenms, oxidized, rconfig (opcionais)
  templates/ static/
```

## Roadmap

- [x] Push com governança, diff, agendamento, auditoria, i18n, edição em massa.
- [x] Motor de backup/versionamento (Git/dulwich) + diff.
- [ ] Compliance/golden config (checks `require`/`forbid`/`match`).
- [ ] Drift + notificações.
- [ ] API REST + tokens; SSO/2FA; trilha imutável.
- [ ] Instalador Windows.

## Licença

Proprietária — ver `LICENSE`.
