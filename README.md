# Net Tools

Coleção de ferramentas de rede (NCM, backup/versionamento e monitoramento),
cada uma em sua pasta, com deploy Docker Swarm padronizado.

| Ferramenta | Pasta | O que é |
|---|---|---|
| **Config Push** | [`config_push/`](config_push/) | Gestão de configuração (push, dry-run/diff, aprovação, agendamento, auditoria, RBAC, backup/versionamento próprio) |
| **rConfig** | [`rconfig/`](rconfig/) | Coleta e versionamento de configuração (deploy Swarm + patch "keep unchanged" + retenção) |
| **LibreNMS** | [`librenms/`](librenms/) | Monitoramento/descoberta — deploy `docker compose` do projeto oficial (GPLv3), usado via API (conector) |
| **Scripts** | [`scripts/`](scripts/) | Descoberta no LibreNMS: communities SNMP, redes, scan agendado (`lnms-scan.sh`) e topologia (`setup-ativos.sh`) |

Cada pasta é **autônoma** (tem seu `docker-compose.yml`, `manager-docker.sh`,
`.env.example` e `README.md`). Sobe-se só o que o cliente precisa.

## Uso geral

```bash
cd <ferramenta>
./manager-docker.sh init-env
./manager-docker.sh start
./manager-docker.sh status
```

## Licença / dependências de terceiros

- O código deste repositório é proprietário — ver [`LICENSE`](LICENSE).
- `rconfig/` referencia o projeto rConfig (imagem oficial) e contém um patch
  derivado — revise a licença antes de distribuir (ver `rconfig/NOTICE.md`).
- `librenms/` é apenas documentação de integração com o projeto oficial (GPLv3).
