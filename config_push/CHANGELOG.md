# Changelog — Net Tools

## v0.1.0 — 2026-09-19

Primeira base do produto (derivada do motor interno de push + governança).

**Push / governança**
- Inventário (manual + import xlsx/CSV), busca, paginação, edição em massa (incl. usuário/senha).
- Modelos de comando, execução em lote, simulação (dry-run) e aplicação real com diff.
- Aprovação, agendamento, auditoria, RBAC, credencial padrão (TACACS/AAA).
- Multi-vendor: catalog `vendor/modelo -> driver`, autodetect (SSHDetect), suporte FortiOS.

**Backup / versionamento**
- Motor próprio de backup com Netmiko + versionamento Git (`dulwich`) por device.
- Histórico e diff entre versões.

**Plataforma**
- Tema escuro/claro/automático; i18n PT/EN/ES; webhook; `/healthz`.
- Conectores (opcionais) LibreNMS / Oxidized / rConfig (esqueleto).

**Pendências (roadmap)**
- Compliance/golden config e drift.
- API REST + tokens; SSO/2FA; trilha imutável.
- UI de Backup/Compliance; instalador Windows.
