# VarreduraIA - Modo Minimalista

Sistema de pentest com **seleção manual de plugins** via menu interativo.

> ⚠️ **Branch Minimalista**: Esta versão remove a dependência da IA para tomada de decisões.
> O usuário tem controle total sobre quais plugins executar.

## 🚀 Início Rápido

```bash
# Ativar ambiente virtual
source venv/bin/activate

# Executar modo minimalista
python main_minimal.py
```

## 📋 Como Funciona

1. **Digite o alvo** (IP, domínio, URL ou CIDR)
2. **Selecione os plugins** no menu interativo
3. **Execute** e acompanhe os resultados em tempo real
4. **Veja o relatório** final em formato JSON

## 🔌 Menu de Plugins

O menu permite:

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

## 💡 Diferenças da Versão Completa

| Aspecto | Versão Completa | Versão Minimalista |
|---------|-----------------|-------------------|
| Decisão | Automática (IA Gemini) | Manual (Menu) |
| Complexidade | Maior | Menor |
| Dependências | Requer API Gemini | Sem IA |
| Controle | Sistema decide | Usuário decide |

## 📊 Relatórios

Os relatórios são salvos em `dados/minimal_scan_YYYYMMDD_HHMMSS.json` contendo:

- Metadados da varredura
- Plugins selecionados e executados
- Descobertas (hosts, portas, serviços, tecnologias)
- Vulnerabilidades encontradas
- Erros ocorridos

## 🛠️ Arquivos Principais

- `main_minimal.py` - Ponto de entrada do modo minimalista
- `core/minimal_orchestrator.py` - Orquestrador com menu interativo
- `core/plugin_manager.py` - Gerenciador de plugins (compartilhado)
- `plugins/` - Diretório com todos os plugins

## 📝 Uso com Versão Completa

Se quiser voltar para a versão com IA:

```bash
git checkout main
python main.py --target exemplo.com
```
