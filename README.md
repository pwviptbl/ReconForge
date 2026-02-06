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
- Nuclei Scanner, Web Vuln Scanner
- SSH Policy Check, Port Exposure Audit
- Misconfiguration Analyzer

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

# Listar todos os plugins disponíveis
./run.sh --list-plugins

# Ignorar cache (forçar re-scan)
./run.sh example.com --no-cache
```

### Modo com IA (Em Desenvolvimento)

> O modo com IA utilizará um orquestrador inteligente que seleciona automaticamente os plugins baseado no tipo de alvo e descobertas anteriores.

```bash
# Futuro: Modo com IA habilitado
./run.sh example.com --ai

# Futuro: IA com objetivo específico
./run.sh example.com --ai --goal "encontrar vulnerabilidades web"
```

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
