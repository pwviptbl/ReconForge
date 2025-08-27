# Orquestrador Inteligente de Varreduras - Pentest Inicial (DNS + Portas)

## Descrição

Pentest inicial automatizado com foco em:
- Resolução DNS inteligente (domínio ↔ IP)
- Scan de portas inicial (RustScan/Nmap básico)
- Decisão assistida por IA para próximos passos
- Nmap avançado opcional conforme recomendação
- Relatórios em HTML (Jinja2) e JSON
- Logging centralizado

Este repositório implementa a fase inicial do orquestrador: a partir de um alvo (domínio ou IP),
resolve DNS, executa varredura de portas, consolida resumos e utiliza IA para decidir se executa
varreduras Nmap avançadas. Mantém compatibilidade de CLI e caminhos de saída.

## Características do Pentest Inicial

### 🎯 Resolução DNS
- Resolução direta: Domínio → IP(s)
- Resolução reversa: IP → Domínio(s)
- Registros: A, AAAA, MX, CNAME, TXT
- Identificação do tipo de alvo

### 🔍 Scan de Portas
- Integração com RustScan (descoberta rápida)
- Resumo consolidado por host
- Total de portas e serviços expostos

### 🤖 Decisão IA (Gemini)
- Avalia os resultados do scan inicial
- Recomenda módulos Nmap avançados (básico, completo, vuln, web, smb, discovery)
- Define prioridade e portas de interesse
- Fallback local por regras quando IA indisponível

### 📡 Nmap Avançado (opcional)
- Execução por módulo com agregação de métricas
- Resumo por módulo e total de vulnerabilidades/serviços

### 📊 Relatórios e Logs
- HTML: templates Jinja2 com base e relatório DNS
- JSON: dump completo de resultados
- Logs: arquivo rotativo e console verboso opcional

## Instalação

### Pré-requisitos
- Python 3.8+
- Dependências de sistema opcionais (para módulos externos): nmap, rustscan, etc.

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

## Uso - Pentest Inicial: DNS + Scan de Portas

```bash
# Resolver domínio para IP (modo silencioso - padrão)
python main.py --alvo google.com

# Resolver IP para domínio (resolução reversa)
python main.py --alvo 8.8.8.8

# Com saída verbosa (detalhes no terminal)
python main.py --alvo github.com --verbose
```

### Arquivos Gerados Automaticamente
- JSON: dados/resultado_YYYYMMDD_HHMMSS.json
- HTML: relatorios/relatorio_YYYYMMDD_HHMMSS.html

Os diretórios são criados automaticamente, mantendo o comportamento anterior.

## Exemplos de Saída

Resolução de Domínio:
```
=== Orquestrador Inteligente - Pentest Inicial ===
Alvo: google.com

✓ Pentest inicial concluído com sucesso!

=== Resolução DNS ===
  Tipo de alvo: Dominio
  IP principal: 142.250.219.142
  Total de IPs: 1
  IPs encontrados: 142.250.219.142
  Possui IPv6: Sim
  Possui MX: Sim
```

Resolução de IP:
```
=== Orquestrador Inteligente - Pentest Inicial ===
Alvo: 8.8.8.8

✓ Pentest inicial concluído com sucesso!

=== Resolução DNS ===
  Tipo de alvo: Ip
  Hostname principal: dns.google
  Total de domínios: 1
  Domínios encontrados: dns.google
  Resolução reversa: Sim
```

## Estrutura do Projeto (refatorada)

```
VarreduraIA/
├── main.py
├── requirements.txt
├── README.md
│
├── core/
│   ├── __init__.py
│   ├── configuracao.py
│   └── orquestrador_pentest.py
│
├── infra/
│   └── persistencia.py
│
├── relatorios/
│   ├── __init__.py
│   └── gerador_html.py
│
├── templates/
│   └── relatorios/
│       ├── base.html
│       └── dns_relatorio.html
│
├── utils/
│   ├── __init__.py
│   ├── logger.py
│   ├── rede.py
│   └── resumo.py
│
├── modulos/
│   ├── __init__.py
│   ├── resolucao_dns.py
│   ├── varredura_rustscan.py
│   ├── varredura_nmap.py
│   └── decisao_ia.py
│
├── config/
│   ├── __init__.py
│   └── default.yaml
│
├── dados/
├── relatorios/        # arquivos HTML gerados (mesmo diretório do pacote)
└── logs/
```

Observação: o diretório relatorios/ serve tanto como pacote Python (código do gerador)
quanto como pasta de saída dos relatórios HTML, para manter compatibilidade de caminho.

## Arquitetura e Responsabilidades

- CLI fina: main.py
  - Parse de argumentos (--alvo, --verbose)
  - Configuração da verbosidade de console
  - Instancia módulos e delega execução ao orquestrador
  - Chama persistência e gerador de HTML

- Orquestração: core/orquestrador_pentest.py
  - Fluxo DNS → Scan de Portas → Decisão IA → Nmap Avançado (opcional)
  - Usa utils/rede.py para extrair/validar IPs
  - Usa utils/resumo.py para consolidar resumos
  - Loga sessão via utils/logger.py

- Relatórios HTML: relatorios/gerador_html.py
  - Renderização via Jinja2 usando templates/relatorios/*.html
  - Template base: templates/relatorios/base.html
  - Template DNS: templates/relatorios/dns_relatorio.html

- Persistência: infra/persistencia.py
  - salvar_json_resultados(resultados, arquivo)
  - garantir_diretorio(path)

- Configurações: core/configuracao.py + config/default.yaml
  - Chaves API do Gemini via variável de ambiente
  - Nível/arquivo de logging, diretórios padrão

- Logging: utils/logger.py
  - Console controlado pela flag --verbose
  - Arquivo com rotação e mascaramento de dados sensíveis

## Relatórios HTML (Jinja2)

O gerador utiliza o contexto "resultados" com os campos:
- resultados.alvo_original, resultados.timestamp_inicio, resultados.timestamp_fim, resultados.fase
- resultados.sucesso_geral, resultados.erro
- resultados.resumo_dns (tipo_alvo, ip_principal, total_ips, possui_ipv6, possui_mx, hostname_principal, total_dominios, possui_resolucao_reversa, ips_encontrados, dominios_encontrados)
- resultados.resolucao_dns.dados.registros_dns

## Comandos Disponíveis

```bash
# Ajuda
python main.py --help

# Execução padrão
python main.py --alvo <dominio_ou_ip>

# Modo verboso
python main.py --alvo <alvo> --verbose
```

## Formato de Saída JSON (exemplo)

```json
{
  "timestamp_inicio": "2025-08-26T11:53:04.311213",
  "alvo_original": "google.com",
  "fase": "pentest_inicial",
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
  "resumo_dns": {
    "tipo_alvo": "dominio",
    "ip_principal": "142.250.219.142",
    "total_ips": 1,
    "possui_ipv6": true,
    "possui_mx": true
  },
  "resumo_scan": {
    "total_ips_scaneados": 1,
    "hosts_ativos": 1,
    "total_portas_abertas": 3,
    "hosts_com_portas_abertas": [
      { "ip": "192.168.1.10", "portas_abertas": 3, "portas": [22,80,443] }
    ]
  },
  "sucesso_geral": true
}
```

## Solução de Problemas

- Confirme dependências externas (nmap, rustscan) se módulos avançados falharem.
- Verifique os logs em logs/sistema.log para detalhes de erros.
- Ajuste --verbose para inspecionar a saída de console.

## Desenvolvimento e Próximas Fases

1. Pentest inicial (esta fase) ✅
2. Enumeração de serviços e versões 🔄
3. Varreduras especializadas (web, vuln, etc.) 🔄
4. Relatório consolidado 🔄

## Licença

Este projeto está sob licença MIT.

---

Orquestrador Inteligente - Construindo o futuro das varreduras de segurança 🚀
