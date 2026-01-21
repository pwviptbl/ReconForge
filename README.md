# ReconForge

**Framework de pentesting automatizado para operações Red Team** com orquestração inteligente de plugins nativos e ferramentas externas. Combine varredura de rede, enumeração, detecção de vulnerabilidades e análise de exploits em um único workflow interativo.

### 🎯 Capacidades Red Team
- **Reconnaissance**: DNS, subdomínios, tecnologias web, mapeamento de rede
- **Network Attack Surface**: Port scanning (nativo), Nmap NSE, protocolos, SSL/TLS
- **Web Attack Vectors**: Crawling, directory brute-force, detecção de vulnerabilidades web
- **Vulnerability Assessment**: Nuclei templates, análise de misconfigurations
- **Exploit Intelligence**: Busca automática de exploits (Exploit-DB/CVE) baseada em serviços detectados
- **Firewall/WAF Detection**: Identificação de proteções ativas

### 🔌 Arsenal
**Plugins Nativos**: Port Scanner, DNS Resolver, Web Crawler, Technology Detector, Subdomain Enum, Exploit Suggester, Protocol Analyzer, SSL Analyzer, Firewall Detector, Misconfiguration Analyzer, SSH Policy Check, Header Analyzer

**Integração Externa**: Nmap, Nuclei, Subfinder, WhatWeb

## 🚀 Início Rápido

```bash
# Ativar ambiente virtual
# Padrão: .venv (ou venv se já existir)
if [ -d ".venv" ]; then
	source .venv/bin/activate
else
	source venv/bin/activate
fi

# Executar
python main.py
```

## 📋 Como Funciona

1. **Digite o alvo** (IP, domínio, URL ou CIDR)
2. **Selecione os plugins** no menu interativo
3. **Execute** e acompanhe os resultados em tempo real
4. **Veja o relatório** final em formato JSON

## 🔌 Menu de Plugins

| Comando | Descrição |
|---------|-----------|
| `1-N` | Toggle plugin por número |
| `nome` | Toggle plugin por nome (busca parcial) |
| `cat:X` | Toggle todos de uma categoria (ex: `cat:network`) |
| `all` | Ativar todos os plugins |
| `none` | Desativar todos os plugins |
| `run` | Iniciar execução |
| `quit` | Sair sem executar |

## 📂 Categorias de Plugins

- **network**: Descoberta de rede, portas, serviços
- **web**: Análise de aplicações web
- **vulnerability**: Detecção de vulnerabilidades
- **reconnaissance**: Coleta de informações

## 📊 Relatórios

Os relatórios são salvos em `dados/scan_YYYYMMDD_HHMMSS.json` contendo:

- Metadados da varredura
- Plugins selecionados e executados
- Descobertas (hosts, portas, serviços, tecnologias)
- Vulnerabilidades encontradas
- Erros ocorridos

## 🛠️ Arquivos Principais

```
├── main.py                      # Ponto de entrada
├── core/
│   ├── minimal_orchestrator.py  # Orquestrador com menu interativo
│   ├── plugin_manager.py        # Gerenciador de plugins
│   ├── plugin_base.py           # Classe base para plugins
│   └── config.py                # Configurações
├── plugins/                     # Todos os plugins
├── utils/                       # Utilitários
└── dados/                       # Relatórios gerados
```

## 🔧 Gerenciamento de Plugins

```bash
# Listar plugins
python manage_plugins.py list

# Habilitar/Desabilitar
python manage_plugins.py enable NomePlguin
python manage_plugins.py disable NomePlugin
```

## 📦 Requisitos

```bash
pip install -r requirements.txt
```

### Ferramentas Externas (opcionais)

- `nmap` - Scanner de rede
- `nuclei` - Scanner de vulnerabilidades
- `subfinder` - Enumeração rápida de subdomínios
- `whatweb` - Detecção de tecnologias web
