# Orquestrador Inteligente de Varreduras - Pentest com IA

## Descrição

Sistema completo de pentest automatizado com IA integrada:
- **Fase 1**: Resolução DNS + Scan inicial de portas
- **Fase 2**: Loop inteligente com IA decidindo próximos módulos
- **Fase 3**: Execução especializada (Web Scraping, Vuln Scan, etc.)
- **Fase 4**: Relatórios consolidados em HTML/JSON

**🆕 NOVO**: Módulo de Web Scraping com Autenticação!
- Descoberta de URLs, formulários e APIs
- Suporte a autenticação para áreas protegidas
- Detecção de vulnerabilidades web
- Integração completa com orquestrador IA

## Características Principais

### 🔍 Resolução DNS Inteligente
- Domínio → IPs e registros DNS
- IP → Domínios (resolução reversa)
- Detecção automática do tipo de alvo

### 📡 Scan de Portas
- RustScan para descoberta rápida
- Nmap para análise detalhada
- Detecção de serviços e versões

### 🤖 IA com Gemini
- Decisão inteligente de próximos passos
- Análise de contexto e risco
- Recomendações personalizadas
- Privacidade: IPs anonimizados antes do envio

### 🕷️ Web Scraping com Autenticação (NOVO!)
- **Spidering**: Descoberta automática de URLs
- **Formulários**: Detecção e análise de formulários
- **APIs**: Descoberta de endpoints REST/GraphQL
- **Autenticação**: Login automático com credenciais
- **Vulnerabilidades**: Testes de XSS, SQLi, LFI
- **Tecnologias**: Detecção de CMS, frameworks, linguagens

### �️ Testes de Vulnerabilidades (NOVO!)
- **Vulnerabilidades Web**: XSS, SQL Injection, LFI, Command Injection, CSRF, Open Redirect
- **Segurança de API**: Broken Authentication, Injection, IDOR, Rate Limiting, CORS, GraphQL
- **Segurança Mobile/Web**: SSL/TLS, PWA, Service Workers, Mobile Security, Hybrid Apps
- **Integração CLI**: Opções específicas para cada tipo de teste
- **Relatórios Detalhados**: Vulnerabilidades por criticidade e tipo

### �📊 Relatórios Avançados
- HTML responsivo com gráficos
- JSON estruturado para integração
- Logging centralizado com rotação

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

# 5. Configuração inicial
python setup.py --setup
```

### Configuração

O sistema usa um arquivo de configuração YAML único:

- **Automática**: Execute `python setup.py --setup` para configuração interativa
- **Manual**: Copie `config/default.yaml.example` para `config/default.yaml` e edite

 **Obrigatório**: Configure sua chave API do Gemini em `config/default.yaml`

Veja `config/README.md` para detalhes completos da configuração.

## Uso - Web Scraping com Autenticação (NOVO!)

```bash
# Estudo Web inicial (sem autenticação) → LOOP-IA
python main.py --web-scan --alvo https://exemplo.com

# Estudo Web com autenticação → LOOP-IA
python main.py --web-scan --alvo https://exemplo.com --usuario admin --senha minha_senha

# Modo verboso
python main.py --web-scan --alvo https://exemplo.com --verbose
```

### Funcionalidades do Web Scraping

#### 🕷️ Spidering Inteligente
- Descoberta automática de URLs no mesmo domínio
- Análise de links em HTML, JavaScript e formulários
- Controle de profundidade e limite de páginas
- Detecção de áreas autenticadas

#### 🔐 Autenticação Automática
- Detecção automática de formulários de login
- Tentativa de login com credenciais fornecidas
- Manutenção de sessão autenticada
- Spidering em áreas protegidas

#### 📝 Análise de Formulários
- Detecção de todos os formulários da página
- Classificação: login, busca, contato, etc.
- Análise de campos obrigatórios/opcionais
- Verificação de proteções CSRF

#### 🔗 Descoberta de APIs
- Detecção de endpoints REST/GraphQL
- Análise de JavaScript para APIs
- Extração de parâmetros de URL
- Mapeamento da superfície de ataque

#### 🛡️ Testes de Segurança
- SQL Injection básico
- XSS (Cross-Site Scripting)
- LFI (Local File Inclusion)
- Detecção de headers de segurança ausentes

#### 🔍 Detecção de Tecnologias
- CMS (WordPress, Joomla, Drupal)
- Frameworks (Laravel, Django, React, Vue)
- Servidores web (Apache, Nginx, IIS)
- Linguagens (PHP, ASP.NET, Java)

### Funcionalidades dos Testes de Vulnerabilidades

#### 🕷️ Vulnerabilidades Web
- **XSS (Cross-Site Scripting)**: Teste de injeção de scripts em formulários e parâmetros
- **SQL Injection**: Detecção de vulnerabilidades de injeção SQL
- **LFI (Local File Inclusion)**: Teste de inclusão de arquivos locais
- **Command Injection**: Verificação de execução de comandos remotos
- **CSRF (Cross-Site Request Forgery)**: Análise de proteção contra CSRF
- **Open Redirect**: Detecção de redirecionamentos abertos

#### 🔗 Segurança de API
- **Broken Authentication**: Teste de autenticação quebrada
- **API Injection**: Injeção em endpoints de API
- **IDOR (Insecure Direct Object References)**: Referências diretas inseguras
- **Rate Limiting**: Verificação de controle de taxa
- **CORS (Cross-Origin Resource Sharing)**: Análise de políticas CORS
- **GraphQL Security**: Segurança em APIs GraphQL

#### 📱 Segurança Mobile/Web
- **SSL/TLS Analysis**: Análise de certificados e configurações SSL
- **PWA (Progressive Web Apps)**: Verificação de manifestos PWA
- **Service Workers**: Análise de service workers
- **Mobile Security**: Segurança específica para aplicações móveis
- **Hybrid Security**: Segurança em aplicações híbridas

### Exemplo de Saída - Testes de Vulnerabilidades

```
=== Testes de Vulnerabilidades ===
Alvo: example.com
Testes a executar: Web=True, API=True, Mobile=True

🕷️ Executando testes de vulnerabilidades web...
✅ Web: 0 vulnerabilidades encontradas

🔗 Executando testes de segurança de API...
✅ API: 0 vulnerabilidades encontradas

📱 Executando testes de segurança mobile/web...
✅ Mobile/Web: 13 vulnerabilidades encontradas

✓ Testes de vulnerabilidades concluídos com sucesso!

=== Estatísticas Finais ===
  Total de vulnerabilidades: 13
  Tempo total: 26.10s
  Média: 0.5 vuln/segundo

✓ Arquivos salvos:
  JSON: dados/vulntest_20250829_000258.json
  HTML: relatorios/vulntest_20250829_000258.html
```

### Exemplo de Saída - Web Scraping

```
=== Varredura Web Específica ===
Alvo: httpbin.org
Tipo: basico
Autenticação: Desabilitada

🕷️ Iniciando scraping para: httpbin.org
🔍 Fase 1: Spider básico...
🔧 Fase 2: Detectando tecnologias...
📝 Fase 3: Analisando formulários...
🔗 Fase 4: Descobrindo APIs...

✅ Scraping concluído: 0 vulnerabilidades encontradas

=== Estatísticas Web ===
  URLs descobertas: 3
  Formulários: 1
  Endpoints API: 2
  Parâmetros: 0
  Vulnerabilidades: 0

=== Tecnologias Detectadas ===
  Frontend: React

✓ Arquivos salvos:
  JSON: dados/webscan_20250828_214513.json
  HTML: relatorios/webscan_20250828_214513.html
```

## Uso - Pentest Completo com IA

```bash
# Fluxo Redes (padrão): DNS → RustScan → LOOP-IA
python main.py --alvo exemplo.com

# Fluxo Web: Estudo com navegador → LOOP-IA
python main.py --web-scan --alvo https://exemplo.com [--usuario USER --senha PASS]

# Verbose
python main.py --alvo exemplo.com --verbose
```

### Funcionamento do Loop Inteligente

1. **Fase 1**: DNS + Scan inicial
2. **Fase 2**: IA analisa contexto e decide próximos módulos
3. **Fase 3**: Execução dos módulos escolhidos
4. **Fase 4**: Geração de relatório final

A IA pode escolher entre:
- `nmap_varredura_completa`
- `nmap_varredura_vulnerabilidades`
- `scanner_web_avancado`
- `scraper_auth` (novo módulo de web scraping)
- `feroxbuster_basico`
- E outros módulos especializados

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
├── main.py                          # CLI principal com argumentos web
├── requirements.txt
├── README.md
│
├── core/
│   ├── __init__.py
│   ├── configuracao.py
│   └── orquestrador_inteligente.py  # Orquestrador com IA
│
├── infra/
│   ├── __init__.py
│   └── persistencia.py
│
├── relatorios/
│   ├── __init__.py
│   └── gerador_html.py
│
├── modulos/
│   ├── __init__.py
│   ├── resolucao_dns.py
│   ├── varredura_rustscan.py
│   ├── varredura_nmap.py
│   ├── navegacao_web_ia.py             # 🆕 Módulo navegador Selenium/Playwright
│   ├── varredura_scraper_multi_engine.py  # 🆕 Multi-engine (Selenium/Playwright/Requests-HTML)
│   ├── varredura_scraper_auth.py    # 🆕 Web scraping com auth
│   ├── testador_vulnerabilidades_web.py    # 🆕 Testes web (XSS, SQLi, etc.)
│   ├── testador_seguranca_api.py           # 🆕 Segurança de APIs
│   ├── testador_seguranca_mobile_web.py    # 🆕 Segurança mobile/web
│   ├── scanner_web_avancado.py
│   ├── scanner_vulnerabilidades.py
│   └── decisao_ia.py
│
├── config/
│   ├── __init__.py
│   ├── default.yaml
│   └── default.yaml.example
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
│   ├── resumo.py
│   ├── anonimizador_ip.py
│   └── config_timeouts.py
│
├── dados/                          # Resultados JSON
├── relatorios/                     # Relatórios HTML
├── logs/                          # Logs do sistema
├── temp/                          # Arquivos temporários
└── wordlists/                     # Wordlists para brute force
```

Observação: o diretório relatorios/ serve tanto como pacote Python (código do gerador)
quanto como pasta de saída dos relatórios HTML, para manter compatibilidade de caminho.

## Arquitetura e Responsabilidades

- CLI fina: main.py
  - Parse de argumentos (--alvo, --verbose)
  - Configuração da verbosidade de console
  - Instancia módulos e delega execução ao orquestrador
  - Chama persistência e gerador de HTML

- Orquestração: core/orquestrador_inteligente.py
  - Fluxos: Redes (DNS → RustScan → LOOP-IA) e Web (Navegador → LOOP-IA)
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

# Redes (padrão): DNS → RustScan → LOOP-IA
python main.py --alvo ALVO [--verbose]

# Web: Estudo com navegador → LOOP-IA
python main.py --web-scan --alvo URL [--usuario USER --senha PASS] [--verbose]
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

## 🤖 Integração com IA (Gemini)

### Como a IA Decide os Próximos Passos

1. **Análise de Contexto**: A IA recebe informações sobre IPs descobertos, portas abertas e serviços detectados
2. **Anonimização**: Os IPs são anonimizados antes do envio para proteger privacidade
3. **Decisão Inteligente**: Baseado no contexto, a IA escolhe os módulos mais apropriados
4. **Mapeamento Automático**: Termos como "web scraping" são automaticamente mapeados para `navegador_web` ou `scraper_auth`

### Módulos que a IA Pode Escolher

- **Web Scraping**: `scraper_auth` (novo módulo)
- **Nmap Avançado**: `nmap_varredura_completa`, `nmap_varredura_vulnerabilidades`
- **Web Scanning**: `scanner_web_avancado`, `feroxbuster_basico`
- **Descoberta**: `subfinder_enum`, `sublist3r_enum`
- **Exploração**: `sqlmap_teste_url`, `searchsploit_check`

### Exemplo de Decisão IA

```
Contexto: Site com porta 80/443 aberta, suspeita de aplicação web
IA Decide: executar_modulo
Módulo: scraper_auth
Justificativa: Descobrir estrutura web e possíveis vulnerabilidades
```

## 🔒 Segurança e Privacidade

- **Anonimização de IPs**: Dados sensíveis são mascarados antes do envio para IA
- **Logs Seguros**: Informações sensíveis são mascaradas nos logs
- **Credenciais**: Tratamento seguro de senhas e tokens
- **HTTPS**: Preferência por conexões seguras quando disponíveis

## 📈 Desenvolvimento e Roadmap

### ✅ Implementado
- [x] Resolução DNS inteligente
- [x] Scan inicial de portas (RustScan)
- [x] Loop inteligente com IA
- [x] Web scraping com autenticação
- [x] Testes de vulnerabilidades web (XSS, SQLi, LFI, etc.)
- [x] Testes de segurança de API
- [x] Testes de segurança mobile/web
- [x] Relatórios HTML/JSON
- [x] Logging centralizado

### 🚧 Em Desenvolvimento
- [ ] Módulos adicionais (Nikto, Nuclei, etc.)
- [ ] Dashboard web para visualização
- [ ] Integração com ferramentas externas
- [ ] Análise de vulnerabilidades avançada

### 📋 Próximas Features
- [ ] Suporte a proxies
- [ ] Rate limiting inteligente
- [ ] Detecção de WAF
- [ ] Análise de JavaScript avançada
- [ ] Integração com Burp Suite

## 🐛 Solução de Problemas

### Erro de Conexão com IA
```bash
# Verificar chave API
grep "chave_api" config/default.yaml

# Testar conectividade
python -c "from modulos.decisao_ia import DecisaoIA; ia = DecisaoIA(); print(ia.conectar_gemini())"
```

### Módulo Web Scraping não Funciona
```bash
# Verificar instalação do BeautifulSoup
pip install beautifulsoup4 lxml

# Teste básico
python -c "from modulos.varredura_scraper_auth import VarreduraScraperAuth; s = VarreduraScraperAuth(); print('OK')"
```

### Erros de Permissão
```bash
# Verificar permissões dos diretórios
ls -la dados/ relatorios/ logs/

# Criar diretórios se necessário
mkdir -p dados relatorios logs
```

## 📝 Licença

Este projeto está sob licença MIT. Veja o arquivo LICENSE para detalhes.

---

**Orquestrador Inteligente** - Construindo o futuro das varreduras de segurança com IA 🤖
