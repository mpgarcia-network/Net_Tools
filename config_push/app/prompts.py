"""Base de conhecimento do Assistente: perguntas/instrucoes prontas.

Os placeholders entre chaves sao substituidos pelo contexto do device
selecionado: ``{device} {vendor} {model} {driver} {site} {site_role}``.
Os ``{{ var.* }}`` sao mantidos de proposito (viram parte do modelo gerado).
"""

DEFAULT_PROMPTS = [
    # --- Sintaxe e comandos ---
    {"category": "Sintaxe e comandos", "title": "Criar VLAN",
     "body": "Como criar uma VLAN no {vendor} {model}? Mostre os comandos passo a passo."},
    {"category": "Sintaxe e comandos", "title": "Configurar NTP/SNTP",
     "body": "Como configurar o servidor NTP/SNTP no {vendor} {model}? Mostre os comandos."},
    {"category": "Sintaxe e comandos", "title": "Fuso horario",
     "body": "Como ajustar o fuso horario e a data/hora no {vendor} {model}?"},
    {"category": "Sintaxe e comandos", "title": "Community SNMP",
     "body": "Como configurar a community SNMP somente-leitura no {vendor} {model}?"},
    {"category": "Sintaxe e comandos", "title": "Salvar config",
     "body": "Como salvar a configuracao na startup no {vendor} {model} (driver {driver})?"},
    {"category": "Sintaxe e comandos", "title": "Rota default",
     "body": "Como criar uma rota default no {vendor} {model}?"},
    {"category": "Sintaxe e comandos", "title": "Trunk 802.1Q",
     "body": "Como configurar um trunk 802.1Q (uplink) no {vendor} {model}?"},
    {"category": "Sintaxe e comandos", "title": "Porta de acesso",
     "body": "Como configurar uma porta de acesso na VLAN X no {vendor} {model}?"},
    {"category": "Sintaxe e comandos", "title": "Desabilitar telnet/HTTP",
     "body": "Como desabilitar telnet e HTTP (acesso inseguro) no {vendor} {model}?"},

    # --- Meu ambiente ---
    {"category": "Meu ambiente", "title": "Resumo do site",
     "body": "Resuma os switches do site {site}: quantos sao, quais camadas (site_role) e vendors."},
    {"category": "Meu ambiente", "title": "Device atual",
     "body": "Descreva o device {device}: IP, vendor, modelo, driver, site e camada."},
    {"category": "Meu ambiente", "title": "Inventario por vendor",
     "body": "Liste os switches {vendor} {model} do inventario e o driver usado."},
    {"category": "Meu ambiente", "title": "Sem backup",
     "body": "Quais switches do site {site} nunca tiveram backup?"},
    {"category": "Meu ambiente", "title": "Camadas",
     "body": "Quais camadas (site_role) existem e como os switches estao distribuidas por elas?"},

    # --- Backups ---
    {"category": "Backups", "title": "Ultimo backup",
     "body": "Qual o ultimo backup do {device} e quando foi feito?"},
    {"category": "Backups", "title": "Backups atrasados",
     "body": "Quais devices estao com backup atrasado (stale)?"},

    # --- Gerar modelo ---
    {"category": "Gerar modelo", "title": "Modelo: VLAN",
     "body": "Gere um modelo de comando (snippet) para criar a VLAN {{ var.vlan_id }} chamada {{ var.vlan_name }} no {vendor} {model}."},
    {"category": "Gerar modelo", "title": "Modelo: NTP",
     "body": "Gere um modelo para configurar NTP no {vendor} {model} usando a variavel {{ var.ntp }}."},
    {"category": "Gerar modelo", "title": "Modelo: SNMP",
     "body": "Gere um modelo para configurar a community SNMP {{ var.snmp_ro }} no {vendor} {model}."},
    {"category": "Gerar modelo", "title": "Modelo: hostname/local",
     "body": "Gere um modelo de hostname ({{ name }}) e localizacao ({{ site }}) para {vendor} {model}."},

    # --- Explicar config ---
    {"category": "Explicar config", "title": "Explicar config atual",
     "body": "Explique a configuracao atual do {device} e aponte riscos ou pontos de atencao."},
    {"category": "Explicar config", "title": "VLANs e uplinks",
     "body": "Na config do {device}, liste as VLANs e identifique as interfaces de uplink/trunk."},
    {"category": "Explicar config", "title": "Auditoria de seguranca",
     "body": "A config do {device} tem algo inseguro (telnet, HTTP, SNMP v1/v2 sem ACL, senha fraca)?"},
    {"category": "Explicar config", "title": "Padronizacao",
     "body": "A config do {device} segue o padrao do site {site}? O que poderia ser padronizado?"},
]
