# VarreduraIA# Sistema de Pentest com Nmap e Análise IA

## Descrição

Sistema completo de pentesting que combina varreduras Nmap com análise inteligente usando Gemini AI. O sistema oferece:

- **Varreduras Nmap automatizadas** com scripts NSE
- **Análise inteligente** de resultados usando IA
- **Interface CLI completa** em português
- **Relatórios detalhados** em múltiplos formatos
- **Arquitetura modular** e extensível

## Características Principais

### 🎯 Tipos de Varredura
- **Básica**: Varredura rápida de portas
- **Completa**: Varredura com detecção de serviços e OS
- **Vulnerabilidades**: Foco em descoberta de vulnerabilidades
- **Web**: Especializada em serviços web
- **SMB**: Análise de serviços SMB/CIFS
- **Descoberta**: Mapeamento de rede

### 🤖 Análise IA
- Análise geral de segurança
- Identificação de vulnerabilidades
- Avaliação de serviços expostos
- Geração de planos de pentest
- Recomendações priorizadas

### 📊 Relatórios
- Formato texto resumido
- Relatórios HTML interativos
- Exportação JSON estruturada
- Logs detalhados com rotação

## Instalação

### Pré-requisitos

1. **Python 3.8+**
2. **Nmap** instalado no sistema
3. **Chave API do Gemini** (Google AI Studio)

### Instalação no Windows

```bash
# 1. Instalar Nmap
# Via Chocolatey:
choco install nmap

# Ou download manual de:
# https://nmap.org/download.html

# 2. Clonar repositório
git clone <repositorio>
cd "Pentest Web"

# 3. Instalar dependências Python
pip install -r requirements.txt

# 4. Configuração inicial
python main.py --configurar
```

### Obter Chave API Gemini

1. Acesse: https://aistudio.google.com/app/apikey
2. Faça login com conta Google
3. Clique em "Create API Key"
4. Copie a chave gerada
5. Configure no sistema durante a configuração inicial

## Uso

### Configuração Inicial

```bash
# Configuração interativa
python main.py --configurar
```

### Varreduras Simples

```bash
# Varredura básica
python main.py --alvo 192.168.1.1 --tipo basico

# Varredura completa com IA
python main.py --alvo scanme.nmap.org --tipo completo --ia

# Varredura de vulnerabilidades
python main.py --alvo 192.168.1.100 --tipo vulnerabilidades --ia --salvar resultado.json
```

### Interface CLI Completa

```bash
# Usar interface CLI completa
python main.py --cli

# Exemplos de comandos CLI:
python cli/comandos.py varrer --alvo 192.168.1.1 --tipo completo --relatorio
python cli/comandos.py configurar --validar
python cli/comandos.py diagnostico --sistema
python cli/comandos.py scripts --listar vuln
```

### Exemplos Avançados

```bash
# Varredura de rede com relatório HTML
python main.py --alvo 192.168.1.0/24 --tipo descoberta --ia --relatorio-html relatorio.html

# Varredura específica de portas
python cli/comandos.py varrer --alvo target.com --portas "80,443,8080,8443" --scripts "http-*"

# Análise focada em serviços web
python main.py --alvo webapp.example.com --tipo web --ia --salvar web_analysis.json
```

## Estrutura do Projeto

```
Pentest Web/
├── main.py                 # Script principal
├── cliente_gemini.py       # Cliente Gemini original
├── requirements.txt        # Dependências
├── README.md              # Documentação
│
├── core/                  # Módulos principais
│   ├── __init__.py
│   └── configuracao.py    # Gerenciamento de configuração
│
├── modulos/               # Módulos especializados
│   ├── __init__.py
│   ├── varredura_nmap.py  # Varreduras Nmap
│   └── analise_gemini.py  # Análise IA
│
├── utils/                 # Utilitários
│   ├── __init__.py
│   └── logger.py          # Sistema de logging
│
├── cli/                   # Interface CLI
│   ├── __init__.py
│   └── comandos.py        # Comandos CLI
│
├── config/                # Configurações
│   ├── __init__.py
│   └── default.yaml       # Configuração padrão
│
├── logs/                  # Arquivos de log
├── dados/                 # Banco de dados
├── relatorios/           # Relatórios gerados
└── testes/               # Testes automatizados
```

## Configuração

O sistema usa arquivo YAML para configuração com suporte a variáveis de ambiente:

```yaml
# config/default.yaml
api:
  gemini:
    modelo: "gemini-2.5-pro"
    chave_api: "${GEMINI_API_KEY}"
    timeout: 30

nmap:
  binario: "nmap"
  timeout_padrao: 300
  scripts_nse_padrao:
    - "default"
    - "vuln"
    - "discovery"
```

### Variáveis de Ambiente

```bash
# Definir chave API via variável de ambiente
set GEMINI_API_KEY=sua_chave_aqui

# Ou usar arquivo .env
echo GEMINI_API_KEY=sua_chave_aqui > .env
```

## Comandos CLI

### Varredura
```bash
# Sintaxe
python cli/comandos.py varrer --alvo <ALVO> [OPÇÕES]

# Opções:
--tipo {basico,completo,vulnerabilidades,web,smb,descoberta}
--portas <especificação>
--scripts <scripts_nse>
--opcoes <opcoes_nmap>
--salvar <arquivo.json>
--relatorio
```

### Configuração
```bash
# Configuração interativa
python cli/comandos.py configurar --interativo

# Listar configurações
python cli/comandos.py configurar --listar

# Definir configuração
python cli/comandos.py configurar --definir api.gemini.timeout 60

# Validar configurações
python cli/comandos.py configurar --validar
```

### Diagnóstico
```bash
# Diagnóstico completo do sistema
python cli/comandos.py diagnostico --sistema

# Verificar Nmap
python cli/comandos.py diagnostico --nmap

# Testar API Gemini
python cli/comandos.py diagnostico --api

# Estatísticas de logs
python cli/comandos.py diagnostico --logs
```

### Scripts NSE
```bash
# Listar todos os scripts
python cli/comandos.py scripts --listar

# Listar por categoria
python cli/comandos.py scripts --listar --categoria vuln

# Buscar scripts
python cli/comandos.py scripts --buscar http
```

## Formatos de Saída

### JSON
```json
{
  "timestamp_inicio": "2024-01-20T10:30:00",
  "alvo": "192.168.1.1",
  "tipo_varredura": "completo",
  "varredura_nmap": {
    "sucesso": true,
    "dados": {
      "resumo": {
        "hosts_ativos": 1,
        "portas_abertas": 5,
        "servicos_detectados": 3,
        "vulnerabilidades": 2
      },
      "hosts": [...]
    }
  },
  "analise_ia": {
    "analise_geral": {...},
    "vulnerabilidades": {...},
    "servicos": {...},
    "resumo_consolidado": {
      "nivel_risco_maximo": "Alto",
      "vulnerabilidades_criticas": 2,
      "proximos_passos": [...]
    }
  }
}
```

### Relatório HTML
O sistema gera relatórios HTML interativos com:
- Resumo executivo
- Detalhes técnicos por host
- Análise de vulnerabilidades
- Recomendações da IA
- Gráficos e métricas

## Recursos Avançados

### Logging Inteligente
- Rotação automática de arquivos
- Mascaramento de dados sensíveis
- Múltiplos níveis de log
- Logs especializados por módulo

### Análise IA Avançada
- Análise contextual de vulnerabilidades
- Geração de planos de pentest
- Priorização automática de riscos
- Recomendações específicas por ambiente

### Extensibilidade
- Arquitetura modular
- Plugins para novos tipos de varredura
- Templates personalizáveis
- API para integração

## Solução de Problemas

### Nmap não encontrado
```bash
# Windows - via Chocolatey
choco install nmap

# Windows - download manual
# https://nmap.org/download.html

# Verificar instalação
nmap --version
```

### Erro de API Gemini
```bash
# Verificar chave API
python cli/comandos.py diagnostico --api

# Reconfigurar
python main.py --configurar

# Definir via variável de ambiente
set GEMINI_API_KEY=sua_chave_aqui
```

### Problemas de Permissão
```bash
# Executar como administrador no Windows
# Ou verificar permissões de diretório

# Verificar logs
python cli/comandos.py diagnostico --logs
```

## Desenvolvimento

### Estrutura de Testes
```bash
# Executar testes
pytest testes/

# Testes com cobertura
pytest --cov=. testes/
```

### Contribuindo
1. Fork o projeto
2. Crie branch para feature (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova funcionalidade'`)
4. Push para branch (`git push origin feature/nova-funcionalidade`)
5. Crie Pull Request

## Licença

Este projeto está sob licença MIT. Veja arquivo LICENSE para detalhes.

## Avisos de Segurança

⚠️ **IMPORTANTE**: Este sistema é destinado para:
- Testes de penetração autorizados
- Auditorias de segurança legítimas
- Ambientes de teste e laboratório

❌ **NÃO USE** para:
- Atacar sistemas sem autorização
- Atividades ilegais ou maliciosas
- Violação de termos de serviço

## Suporte

- 📧 Email: [seu-email]
- 🐛 Issues: [link-do-repositorio]/issues
- 📖 Wiki: [link-da-wiki]
- 💬 Discussões: [link-das-discussoes]

---

**Desenvolvido com ❤️ para a comunidade de segurança cibernética**
