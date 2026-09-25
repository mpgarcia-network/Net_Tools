# LibreNMS — Topologia organizada (Device Groups + Custom Maps)

> Objetivo: deixar o mapa do LibreNMS **organizado e salvo** (não o "raio de
> bicicleta" com tudo amontoado). A estratégia é **agrupar** os devices
> (por **Site** e por **Camada**) e então **salvar mapas fixos** (Custom Maps)
> por grupo.
>
> Ambiente de referência: LibreNMS em `http://<host>:${APP_PORT:-8001}`.
> Token de API em **Settings → API**.

---

## 1. Conceito

O mapa nativo do LibreNMS (`/map`) mostra a **vizinhança LLDP/CDP** de tudo —
por isso fica amontoado. A organização se dá por **Device Groups**:

- **Site** (local físico): `Site: HU1`, `Site: ADM`, `Site: CB`, ...
- **Camada** (papel na rede): `Camada: Core`, `Camada: Distribuicao`,
  `Camada: TOR`, `Camada: Acesso`, `Camada: Firewall`.

Com os grupos criados, montamos **Custom Maps** (`/maps/custom`) — cada mapa
salvo mostrando **um grupo** (ou alguns) — e o resultado fica limpo e estável.

> Dica: a **fonte da verdade da Camada** é o campo **Camada** do nosso Config Push
> (`Device.site_role`). Ao classificar lá, dá pra manter os grupos do LibreNMS
> em sincronia (estático por lista de devices).

---

## 2. Criar os Device Groups via API (automatizado)

Endpoint: `POST /api/v0/devicegroups` (header `X-Auth-Token`).

- **Estático** (lista de devices):
```bash
curl -s -X POST -H "X-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Site: HU1","type":"static","desc":"Switches do site HU1","devices":[55,56,57]}' \
  "$BASE/api/v0/devicegroups"
```

- **Dinâmico** (regra por nome/sysName/etc.):
```bash
curl -s -X POST -H "X-Auth-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Camada: Core","type":"dynamic","desc":"Core",
       "rules":"{\"condition\":\"OR\",\"rules\":[
         {\"id\":\"sysName\",\"field\":\"sysName\",\"type\":\"string\",\"input\":\"text\",\"operator\":\"contains\",\"value\":\"-sw-core-\"},
         {\"id\":\"sysName\",\"field\":\"sysName\",\"type\":\"string\",\"input\":\"text\",\"operator\":\"contains\",\"value\":\"-cre-sw-\"}
       ],\"valid\":true}"}' \
  "$BASE/api/v0/devicegroups"
```

- **Atualizar regra**: `PATCH /api/v0/devicegroups/{nome}` com `{"rules": "..."}`.
- **Listar**: `GET /api/v0/devicegroups` · **Devices do grupo**:
  `GET /api/v0/devicegroups/{nome}`.

### Grupos criados no `100.120.0.41` (2026-09)

| Grupo | Tipo | Qtd | Regra / conteúdo |
|---|---|---|---|
| Site: ADM | estático | 30 | prefixo `adm-` |
| Site: HU1 | estático | 24 | prefixo `hu1-` |
| Site: CB | estático | 22 | prefixo `cb-` |
| Site: HU2 | estático | 12 | prefixo `hu2-` |
| Site: VVBP | estático | 6 | prefixo `vvbp-` |
| Site: TIE | estático | 3 | prefixo `tie-` |
| Site: UNLVP / RECOMESOUN / DCV / IPT / SCS | estático | 2 cada | prefixo |
| Camada: Core | dinâmico | 5 | sysName contém `-sw-core-` ou `-cre-sw-` |
| Camada: Distribuicao | dinâmico | 7 | sysName contém `-dist-` / `-agg-` |
| Camada: TOR | dinâmico | 1 | sysName contém `-tor-` |
| Camada: Acesso | dinâmico | 90 | sysName contém `sw-acs` / `sw-wlan` / `-acs-` |

> Servidores e hosts (prefixo `srv-`, `haproxy`, `.local`) **não** entram nos
> grupos de rede.

---

## 3. Criar os Custom Maps (interface do LibreNMS)

A API **não** cria Custom Maps — é pela UI:

1. Menu **Maps → Custom Maps → Create**.
2. Dê um nome (ex.: `Core`, `Site HU1`, `Distribuição`).
3. **Background**: em branco (ou use uma imagem do site, opcional).
4. **Add Group**: escolha o **Device Group** (ex.: `Camada: Core`).
   - Marque **Show neighbors** se quiser trazer a vizinhança; deixe **desligado**
     para ver só o grupo (mais limpo).
5. Ajuste **posições** dos nós (arraste) e **background size** se quiser.
6. **Save**. Repita por grupo (Site/Camada).
7. (Opcional) Compartilhe/fixe os mapas mais usados no NOC.

> Repare que o **layout é salvo por mapa** (posições dos nós) — é o "mapa fixo"
> que fica pronto no próprio LibreNMS, sem depender de Grafana.

---

## 4. Forçar descoberta de topologia (LLDP) imediatamente

Se um switch novo não aparecer nas conexões:

```bash
CONTAINER=$(docker ps -q -f name='^librenms$' | head -1)
docker exec -it -u librenms "$CONTAINER" lnms device:discoverall
```

> Sempre rode como **`-u librenms`** (não root) para não quebrar permissões de RRD.
> Confirme `$config['autodiscovery']['xdp'] = true;` (LLDP/CDP ativo).

---

## 5. Boas práticas

- **Habilite só LLDP** (evite CDP duplicando enlace, se não usar CDP).
- **Oculte nós desconhecidos/hosts** no mapa (opção do próprio mapa) para não poluir.
- Padronize o **sysName** (ex.: `<site>-<local>-<funcao>-<n>`). Isso melhora os
  grupos dinâmicos e os rótulos.
- Mantenha a **Camada** do Config Push alinhada com os grupos (é a fonte ideal).

---

## 6. Trobleshooting

| Sintoma | Causa | Solução |
|---|---|---|
| Mapa com tudo no centro | Muitos dispositivos num mesmo mapa | Quebre em **Custom Maps por grupo** |
| Enlace duplicado | LLDP + CDP no mesmo link | Desligue CDP ou filtre o protocolo |
| Grupo dinâmico pega device errado | Regra de nome frouxa (ex.: `cre` casa `acs`) | Prefira grupos **estáticos** pela Camada do Config Push |
| Switch novo não aparece | Descoberta LLDP não rodou | `lnms device:discoverall` (como `librenms`) |
| Sem permissão de escrita | Rodou como root | Use `-u librenms` |
