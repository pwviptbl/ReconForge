# 🔍 ReconForge

## Introdução

**ReconForge** é um framework de pentesting automatizado desenvolvido para operações **Red Team**. Ele orquestra de forma inteligente plugins nativos e ferramentas externas, combinando varredura de rede, enumeração, detecção de vulnerabilidades e análise de exploits em um único workflow.

### Por que ReconForge?

- **Modular**: Sistema de plugins extensível
- **Flexível**: Funciona com ou sem IA
- **Completo**: Do reconhecimento à exploração
- **Interativo**: Menu intuitivo para seleção de plugins
- **Automatizado**: Execute scans completos com um comando

---

## Funcionalidades

### Capacidades Red Team

| Categoria | Descrição |
|-----------|-----------|
| **Reconnaissance** | DNS, subdomínios, tecnologias web, mapeamento de rede |
| **Network Attack Surface** | Port scanning, Nmap NSE, protocolos, SSL/TLS |
| **Web Attack Vectors** | Crawling, directory brute-force (estilo GoBuster/FFUF), vulnerabilidades web |
| **Vulnerability Assessment** | Nuclei templates, análise de misconfigurations |
| **Exploit Intelligence** | Busca automática de exploits (Exploit-DB/CVE) |
| **Firewall/WAF Detection** | Identificação de proteções ativas |

### Arsenal de Plugins

**Plugins Nativos (24+)**:
- Port Scanner, Network Mapper, Protocol Analyzer
- DNS Resolver, Subdomain Enumerator
- Directory Scanner (estilo GoBuster/FFUF)
- Web Crawler, Technology Detector, Header Analyzer
- SSL Analyzer, Firewall Detector
- Exploit Searcher, Exploit Suggester
- Nuclei Scanner, Misconfiguration Analyzer
- **Web Scanners Avançados**: XSS, LFI, SSRF, SSTI, IDOR, Open Redirect, Header Injection
- SSH Policy Check, Port Exposure Audit

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

### Modo Interativo (Sem IA)

```bash
# Iniciar menu interativo
./run.sh

# Ou diretamente
python scripts/main.py
```

**Fluxo**:
1. Digite o alvo (IP, domínio, URL ou CIDR)
2. Selecione os plugins no menu interativo
3. Execute e acompanhe os resultados em tempo real
4. Visualize o relatório final

### Modo CLI - Scans Automatizados

```bash
# Executar todos os plugins em um alvo
./run.sh example.com

# Executar plugins específicos por número
./run.sh example.com --plugins 1,2,4,5

# Excluir plugins específicos (ex: pular brute-force demorado)
./run.sh example.com --exclude-plugins DirectoryScanner,20

# Listar todos os plugins disponíveis
./run.sh --list-plugins

# Ignorar cache (forçar re-scan)
./run.sh example.com --no-cache
```

### Modo com IA

O modo com IA seleciona automaticamente os plugins baseado no objetivo informado.

#### Argumentos de IA

| Argumento | Descrição |
|-----------|-----------|
| `--ai` | Habilita o modo com IA |
| `-o`, `--orientacao` | Define o objetivo/orientação para a IA selecionar plugins |
| `--model` | Especifica o modelo de IA (padrão: gemini-2.5-flash-lite) |
| `--config` | Arquivo YAML de configuração customizado |

#### Exemplos

```bash
# Modo IA básico (executa plugins recomendados)
./run.sh example.com --ai

# IA com orientação específica
./run.sh example.com --ai -o "encontrar vulnerabilidades web"
./run.sh example.com --ai -o "scan de portas e serviços"
./run.sh example.com --ai -o "reconhecimento completo"

# Especificar modelo de IA
./run.sh example.com --ai -o "análise ssl" --model gemini-2.5-flash-lite

# Usar configuração customizada
./run.sh example.com --ai --config minha_config.yaml
```

#### Palavras-chave para Orientação

A IA interpreta estas palavras para selecionar plugins:

| Palavra-chave | Plugins Selecionados |
|---------------|---------------------|
| `web`, `diretório`, `crawl` | WebFlowMapper, Katana, Gau, Nuclei |
| `vuln`, `vulnerabilidade`, `cve` | Nuclei, ExploitSearcher |
| `rede`, `porta`, `scan`, `nmap` | PortScanner, Nmap, NetworkMapper |
| `ssl`, `https`, `certificado` | SSLAnalyzer |
| `dns`, `subdomínio` | DNSResolver, Subfinder |
| `firewall`, `waf` | FirewallDetector |
| `completo`, `tudo`, `full` | Todos os plugins |

#### Configuração de API Key

Edite `config/default.yaml`:

```yaml
ai:
  gemini:
    api_key: SUA_API_KEY_GEMINI
    enabled: true
    model: gemini-2.5-flash-lite
    temperature: 0.3
```

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
