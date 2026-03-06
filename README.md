# 🔍 ReconForge

## Introdução

**ReconForge** é um framework de pentesting automatizado desenvolvido para operações **Red Team**. O fluxo atual foi simplificado para funcionar bem com poucos comandos: descobrir a superficie, mapear entradas reais, testar o que faz sentido e gerar relatorio.

### Por que ReconForge?

- **Simples de operar**: perfis prontos para os casos mais comuns
- **Modular**: Sistema de plugins extensivel
- **Completo**: Do reconhecimento a exploracao
- **Automatizado**: Execute scans completos com um comando

---

## Funcionalidades

### Capacidades Red Team

| Categoria | Descrição |
|-----------|-----------|
| **Reconnaissance** | DNS, subdominios, tecnologias web, mapeamento de rede |
| **Network Attack Surface** | Port scanning, Nmap NSE, SSL/TLS, exposicao de servicos |
| **Web Attack Vectors** | Crawling, mapeamento de formularios, requests reais e vulnerabilidades web |
| **Vulnerability Assessment** | Nuclei templates e scanners HTTP request-based |
| **Exploit Intelligence** | Busca automatica de exploits (Exploit-DB/CVE) |
| **Firewall/WAF Detection** | Identificação de proteções ativas |

### Perfis recomendados

Em vez de montar listas longas de plugins, prefira os perfis:

- `web-map`: mapeamento gentil de rotas, formularios, uploads e parametros
- `web-test`: `web-map` mais os scanners web request-based
- `infra`: portas, servicos, SSL, firewall e exposicao de infraestrutura

Os plugins continuam habilitaveis por YAML, mas o caminho padrao agora e por perfil.

**Integrações Externas**:
- `nmap` - Scanner de rede avançado
- `nuclei` - Scanner de vulnerabilidades
- `subfinder` - Enumeração de subdomínios
- `whatweb` - Detecção de tecnologias

---

## Instalação

### Requisitos do Sistema

```bash
# Debian/Ubuntu/Kali - Instalar dependências
./scripts/system_update.sh
```

### Requisitos Python

```bash
pip install -r requirements.txt
```

### Ferramentas Externas (Opcionais)

```bash
# Kali Linux já possui a maioria
sudo apt install nmap nuclei subfinder whatweb
```

---

## Uso

### Caminho oficial

O projeto agora usa um unico motor de execucao: o pipeline por estagios.

Se voce rodar apenas:

```bash
./run.sh example.com
```

o perfil padrao sera `web-test`.

### Perfis

```bash
# Perfil padrao para web
./run.sh example.com

# Mapear entradas web e requests observadas
./run.sh example.com --profile web-map

# Mapear e testar vetores web
./run.sh example.com --profile web-test

# Foco em infraestrutura
./run.sh example.com --profile infra

# Listar perfis
./run.sh --list-profiles

# Ver saude do ambiente e dependencias
./run.sh --healthcheck

# Mostrar rotas e parametros de um run ja executado
./run.sh --show-web-map 50

# Modo avancado do mesmo pipeline
./run.sh example.com --pipeline --recon-plugins PortScannerPlugin,WebFlowMapperPlugin
```

### Leitura pratica do web map

Depois de um `web-map` ou `web-test`, use:

```bash
./run.sh --show-web-map 50
```

Voce vai ver:

- formularios detectados no DOM
- requests observadas de verdade
- parametros por bucket
- acao UI associada a cada request

Quando houver divergencia entre DOM e request real, a request observada e a fonte de verdade.

#### Opcional: Usar Tor (Plugins Mais "Barulhentos")

Você pode rotear requests via Tor (proxy SOCKS5) quando estiver usando plugins com bruteforce/fuzzing (ex: `DirectoryScannerPlugin`) para reduzir risco de bloqueio do seu IP.

Config global em `config/default.yaml`:

```yaml
network:
  tor:
    enabled: false
    proxy_url: socks5h://127.0.0.1:9050
```

Ou habilitar por-plugin (recomendado para aplicar só onde faz sentido):

```yaml
plugins:
  config:
    DirectoryScannerPlugin:
      use_tor: true
```

Notas:
- O Tor precisa estar rodando localmente (porta SOCKS padrão `9050`).
- Para SOCKS funcionar com `requests`, a dependência `pysocks` precisa estar instalada (já incluída em `requirements.txt`).
- Você pode manter alguns plugins fora do Tor mesmo com `network.tor.enabled: true` definindo `use_tor: false` no plugin (ex: `ExploitSearcherPlugin`, `ReconnaissancePlugin`).
- Plugins baseados em ferramentas externas (ex: `nuclei`, `whatweb`, `subfinder`) tentam usar proxy via variáveis de ambiente (`ALL_PROXY`/`HTTP(S)_PROXY`) quando `use_tor` estiver habilitado, mas isso depende do suporte da ferramenta.

Ativar o serviço Tor (Debian/Kali):

```bash
sudo apt update
sudo apt install -y tor

# subir e iniciar no boot
sudo systemctl enable --now tor

# verificar se o SOCKS está ouvindo (padrão 9050)
ss -lntp | rg ':9050\\b' || netstat -lntp | rg ':9050\\b'
```

Nota (systemd): no Debian/Kali, o processo que fica rodando normalmente aparece como `tor@default.service`.
Você não precisa (e geralmente não consegue) dar `enable` diretamente nele; habilitar `tor.service` puxa o `tor@default.service` no boot.

Se a porta `9050` não estiver aberta, confira `/etc/tor/torrc` e garanta:

```text
SocksPort 9050
```

Opcional (Tor): tentar trocar circuito aproximadamente a cada 1 minuto.
Isso pode ajudar em alguns cenários, mas não garante IP novo a cada request e pode degradar performance/estabilidade.
Edite `/etc/tor/torrc`:

```text
MaxCircuitDirtiness 60
```

E reinicie o serviço:

```bash
sudo systemctl restart tor
```

### Ferramentas Extras (Opcional)

Alguns plugins usam ferramentas externas (se instaladas) para aumentar a cobertura sem brute force pesado:

- `KatanaCrawlerPlugin` (katana): crawler rapido para coletar endpoints
- `GauCollectorPlugin` (gau): coleta URLs historicas (Wayback/CommonCrawl)

Atalho recomendado: rode `scripts/system_update.sh` (agora ele instala `katana` e `gau` automaticamente, além das dependências de sistema).

Instalacao (via Go):

```bash
# katana
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# gau
go install -v github.com/lc/gau/v2/cmd/gau@latest

# garanta que o binario esta no PATH (geralmente ~/go/bin)
export PATH=\"$HOME/go/bin:$PATH\"
```

Nota sobre `httpx`:
- No Kali/Debian pode existir um binario `httpx` que e o CLI do Python HTTPX (cliente HTTP), nao o toolkit do ProjectDiscovery.
- Se voce instalar o `httpx` do ProjectDiscovery via Go, garanta que ele fique antes no `PATH` (ex: `~/go/bin` antes de `/usr/bin`), senao vai chamar o binario errado.

---

## Comandos do Menu Interativo

| Comando | Descrição |
|---------|-----------|
| `1-N` | Selecionar plugin por número |
| `nome` | Selecionar plugin por nome (busca parcial) |
| `r` | Ver resultados detalhados |
| `d` | Ver descobertas atuais |
| `s` | Ver serviços encontrados |
| `v` | Ver vulnerabilidades |
| `q` | Encerrar varredura |

---

## Relatórios

### Formato de Saída

Os relatórios são salvos em `dados/scan_YYYYMMDD_HHMMSS.json` contendo:

- **Metadados**: Alvo, duração, plugins executados
- **Descobertas**: Hosts, portas, serviços, tecnologias
- **Vulnerabilidades**: CVEs, severidade, descrições
- **Erros**: Falhas de execução

### Exemplo de Relatório

```json
{
  "metadata": {
    "target": "example.com",
    "duration_seconds": 45.2,
    "plugins_executed": ["PortScannerPlugin", "DirectoryScannerPlugin"]
  },
  "discoveries": {
    "hosts": ["192.168.1.1"],
    "open_ports": [22, 80, 443],
    "services": [{"port": 80, "service": "HTTP"}]
  },
  "vulnerabilities": [
    {"severity": "HIGH", "title": "SSL Certificate Expired"}
  ]
}
```

---

## Estrutura do Projeto

```
ReconForge/
├── scripts/
│   └── main.py              # Ponto de entrada
├── core/
│   ├── minimal_orchestrator.py  # Orquestrador principal
│   ├── plugin_manager.py        # Gerenciador de plugins
│   ├── plugin_base.py           # Classes base
│   └── config.py                # Configurações
├── plugins/                     # Plugins disponíveis
├── wordlists/                   # Wordlists para fuzzing
├── utils/                       # Utilitários
└── dados/                       # Relatórios gerados
```

---

## Gerenciamento de Plugins

```bash
# Listar plugins disponíveis
python scripts/manage_plugins.py list

# Habilitar plugin
python scripts/manage_plugins.py enable NomePlugin

# Desabilitar plugin
python scripts/manage_plugins.py disable NomePlugin
```

---

## Contribuindo

Contribuições são bem-vindas! Para adicionar um novo plugin:

1. Crie um arquivo em `plugins/`
2. Herde de `BasePlugin`, `WebPlugin` ou `NetworkPlugin`
3. Implemente o método `execute()`
4. O plugin será detectado automaticamente

---

## Licença

MIT License - Veja o arquivo [LICENSE](LICENSE) para detalhes.

---

<p align="center">
  <b>ReconForge</b> - Framework de Pentest Automatizado<br>
  Desenvolvido para operações Red Team
</p>
