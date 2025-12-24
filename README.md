# VarreduraIA

Sistema de pentest com **seleção manual de plugins** via menu interativo.

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
- `rustscan` - Scanner de portas rápido
- `sqlmap` - Detecção de SQL injection
