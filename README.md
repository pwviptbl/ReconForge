# Orquestrador Inteligente de Varreduras - Fase 1

## Descrição

**Fase 1: Resolução DNS** - Primeira etapa do Orquestrador Inteligente de Varreduras de Segurança.

Este sistema foca na resolução DNS como ponto de partida para varreduras de segurança, oferecendo:

- **Resolução DNS inteligente** (domínio ↔ IP)
- **Coleta de registros DNS** (A, AAAA, MX, CNAME, TXT)
- **Relatórios detalhados** em HTML e JSON
- **Logging completo** das operações
- **Base para próximas fases** do orquestrador

## Características da Fase 1

### 🎯 Resolução DNS
- **Resolução direta**: Domínio → IP(s)
- **Resolução reversa**: IP → Domínio(s)
- **Múltiplos registros**: A, AAAA, MX, CNAME, TXT
- **Validação automática** de tipos de alvo

### 📊 Relatórios
- **Console**: Resumo executivo
- **HTML**: Relatório visual completo
- **JSON**: Dados estruturados para próximas fases
- **Logs**: Rastreamento detalhado

## Instalação

### Pré-requisitos

1. **Python 3.8+**
2. **Biblioteca dnspython** (instalada automaticamente)

### Instalação

```bash
# 1. Clonar o repositório
git clone <repository-url>
cd VarreduraIA

# 2. Criar ambiente virtual
python -m venv venv

# 3. Ativar ambiente virtual
# Linux/Mac:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 4. Instalar dependências
pip install -r requirements.txt

```

## Uso - Fase 1: Resolução DNS

### Exemplos Básicos

```bash
# Resolver domínio para IP
python main.py --alvo google.com

# Resolver IP para domínio (resolução reversa)
python main.py --alvo 8.8.8.8

# Com saída verbosa
python main.py --alvo github.com --verbose
```

### Gerando Relatórios

```bash
# Salvar resultados em JSON (vai para dados/)
python main.py --alvo example.com --salvar resultado_dns.json

# Gerar relatório HTML (vai para relatorios/)
python main.py --alvo microsoft.com --relatorio-html relatorio.html

# Ambos os formatos
python main.py --alvo amazon.com --salvar dados.json --relatorio-html relatorio.html

# Especificar pastas completas (opcional)
python main.py --alvo github.com --salvar dados/github_dns.json --relatorio-html relatorios/github_relatorio.html
```

### Exemplos de Saída

**Resolução de Domínio:**
```
=== Orquestrador Inteligente - Fase 1: Resolução DNS ===
Alvo: google.com

✓ Resolução DNS concluída com sucesso!

Resumo:
  Tipo de alvo: Dominio
  IP principal: 142.250.219.142
  Total de IPs: 1
  IPs encontrados: 142.250.219.142
  Possui IPv6: Sim
  Possui MX: Sim

=== Próximos Passos ===
1. Executar varredura de portas nos IPs descobertos
2. Verificar subdomínios
3. Analisar registros DNS para informações adicionais
```

**Resolução de IP:**
```
=== Orquestrador Inteligente - Fase 1: Resolução DNS ===
Alvo: 8.8.8.8

✓ Resolução DNS concluída com sucesso!

Resumo:
  Tipo de alvo: Ip
  Hostname principal: dns.google
  Total de domínios: 1
  Domínios encontrados: dns.google
  Resolução reversa: Sim

=== Próximos Passos ===
1. Executar varredura de portas no IP
2. Investigar domínios associados
3. Verificar outros IPs na mesma rede
```

## Estrutura do Projeto - Fase 1

```
VarreduraIA/
├── main.py                    # Script principal - Fase 1
├── requirements.txt           # Dependências
├── README.md                 # Documentação
│
├── modulos/                  # Módulos ativos
│   ├── __init__.py
│   ├── resolucao_dns.py      # Resolução DNS (NOVO)
│   └── decisao_ia.py         # Decisão IA + Análise Gemini (UNIFICADO)
│
├── utils/                    # Utilitários
│   ├── __init__.py
│   └── logger.py             # Sistema de logging
│
├── core/                     # Configuração
│   ├── __init__.py
│   └── configuracao.py       # Gerenciamento de configuração
│
├── config/                   # Arquivos de configuração
│   ├── __init__.py
│   └── default.yaml          # Configuração padrão
│
├── relatorios/               # Relatórios HTML gerados
├── dados/                    # Arquivos JSON de resultados
├── logs/                     # Arquivos de log
├── modulos_backup/           # Módulos das próximas fases
├── cli_backup/               # Interface CLI (próximas fases)
└── .kiro/                    # Especificações do projeto
    └── specs/
        └── orquestrador-inteligente/
```

## Arquivos Gerados

### Relatório HTML
- **Localização**: `relatorios/`
- **Formato**: HTML responsivo com CSS
- **Conteúdo**: Resumo executivo, detalhes DNS, próximos passos

### Arquivo JSON
- **Localização**: `dados/`
- **Formato**: JSON estruturado
- **Conteúdo**: Dados completos para próximas fases

### Logs
- **Localização**: `logs/sistema.log`
- **Formato**: Texto estruturado com timestamps
- **Conteúdo**: Operações detalhadas, erros, métricas

## Próximas Fases

### Fase 2: Descoberta de Portas
- Integração com RustScan/Nmap
- Varredura inteligente baseada nos IPs da Fase 1

### Fase 3: Análise de Serviços  
- Identificação de serviços e versões
- Decisões IA para próximos módulos

### Fase 4: Varreduras Especializadas
- Módulos web (Nikto, Feroxbuster, WhatWeb)
- Módulos de vulnerabilidades (Nuclei, SearchSploit)

### Fase 5: Relatório Consolidado
- Integração de todos os resultados
- Análise IA completa
- Plano de pentest final

## Comandos Disponíveis

```bash
# Ajuda
python main.py --help

# Resolução DNS básica
python main.py --alvo <dominio_ou_ip>

# Com relatórios
python main.py --alvo <alvo> --salvar resultado.json --relatorio-html relatorio.html

# Modo verboso
python main.py --alvo <alvo> --verbose
```

## Formato de Saída JSON

```json
{
  "timestamp_inicio": "2025-08-26T11:53:04.311213",
  "alvo_original": "google.com",
  "fase": "resolucao_dns",
  "resolucao_dns": {
    "tipo_alvo": "dominio",
    "sucesso": true,
    "dados": {
      "dominio": "google.com",
      "ip_principal": "142.250.219.142",
      "ips_resolvidos": ["142.250.219.142"],
      "registros_dns": {
        "A": ["142.250.219.142"],
        "AAAA": ["2800:3f0:4004:c15::71"],
        "MX": ["10 smtp.google.com"]
      }
    }
  },
  "resumo": {
    "tipo_alvo": "dominio",
    "ip_principal": "142.250.219.142",
    "total_ips": 1,
    "possui_ipv6": true,
    "possui_mx": true
  },
  "sucesso_geral": true
}
```

## Solução de Problemas

### Erro de Resolução DNS
```bash
# Verificar conectividade
ping google.com

# Testar com IP conhecido
python main.py --alvo 8.8.8.8

# Verificar logs
tail -f logs/sistema.log
```

### Dependências
```bash
# Reinstalar dependências
pip install --upgrade -r requirements.txt

# Verificar dnspython
python -c "import dns.resolver; print('DNS OK')"
```

## Desenvolvimento

Esta é a **Fase 1** do Orquestrador Inteligente. O projeto está sendo desenvolvido incrementalmente:

1. ✅ **Fase 1**: Resolução DNS (atual)
2. 🔄 **Fase 2**: Descoberta de portas
3. 🔄 **Fase 3**: Análise de serviços
4. 🔄 **Fase 4**: Varreduras especializadas
5. 🔄 **Fase 5**: Relatório consolidado

## Licença

Este projeto está sob licença MIT.

---

**Orquestrador Inteligente - Construindo o futuro das varreduras de segurança** 🚀
