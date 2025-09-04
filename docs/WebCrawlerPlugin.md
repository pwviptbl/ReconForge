# WebCrawlerPlugin - Navegação Web Avançada com Selenium

O **WebCrawlerPlugin** é um plugin avançado para o VarreduraIA que utiliza Selenium para navegação web automatizada, análise de formulários, tentativas de login automático e mapeamento completo de aplicações web.

## 🚀 Funcionalidades Principais

### 📝 Análise de Formulários
- **Detecção automática** de formulários em páginas web
- **Identificação de campos** (username, password, email, etc.)
- **Classificação automática** de formulários de login
- **Extração de tokens CSRF** e campos ocultos
- **Mapeamento de parâmetros** de entrada

### 🔐 Login Automático
- **Tentativas automáticas** com credenciais comuns
- **Detecção inteligente** de formulários de login
- **Verificação de sucesso** baseada em indicadores de resposta
- **Suporte a redirecionamentos** pós-login
- **Análise de respostas** para determinar falhas/sucessos

### 🕷️ Crawling Inteligente
- **Navegação em profundidade** configurável
- **Extração de links** e mapeamento de estrutura
- **Suporte a JavaScript** e SPAs
- **Análise de cookies** e sessões
- **Screenshots automáticos** em caso de erro

### 🛠️ Detecção de Tecnologias
- **Identificação automática** de frameworks (WordPress, Laravel, React, etc.)
- **Análise de JavaScript** e bibliotecas
- **Detecção de padrões** no código-fonte
- **Mapeamento de APIs** e endpoints

### 🔒 Análise de Segurança
- **Verificação de headers** de segurança
- **Análise de cookies** (HttpOnly, Secure, SameSite)
- **Detecção de vulnerabilidades** comuns
- **Mapeamento de superfície de ataque**

## 📋 Configurações Disponíveis

```yaml
WebCrawlerPlugin:
  headless: true                    # Executar sem interface gráfica
  timeout: 30                       # Timeout para operações
  page_load_timeout: 60            # Timeout para carregamento de páginas
  implicit_wait: 10                # Espera implícita do Selenium
  max_depth: 3                     # Profundidade máxima de crawling
  max_pages: 50                    # Número máximo de páginas a navegar
  screenshot_on_error: true        # Tirar screenshot em caso de erro
  follow_redirects: true           # Seguir redirecionamentos
  analyze_forms: true              # Analisar formulários encontrados
  attempt_login: true              # Tentar login automático
  common_credentials: true         # Usar credenciais comuns
  javascript_enabled: true         # Habilitar JavaScript
  user_agent: "Mozilla/5.0..."     # User-Agent para requisições
  window_size: [1920, 1080]       # Tamanho da janela do browser
  extract_apis: true               # Extrair endpoints de API
  analyze_cookies: true            # Analisar cookies
  check_security_headers: true     # Verificar headers de segurança
  detect_frameworks: true          # Detectar frameworks/tecnologias
```

## 🎯 Uso Básico

### Via Sistema Principal
```bash
# Executar varredura completa
python main.py https://exemplo.com

# O WebCrawlerPlugin será executado automaticamente se habilitado
```

### Via Plugin Manager
```bash
# Verificar status do plugin
python manage_plugins.py list

# Ver configuração atual
python manage_plugins.py config WebCrawlerPlugin

# Habilitar/desabilitar
python manage_plugins.py enable WebCrawlerPlugin
python manage_plugins.py disable WebCrawlerPlugin
```

### Via Código Python
```python
from plugins.web_crawler_plugin import WebCrawlerPlugin

# Criar instância do plugin
plugin = WebCrawlerPlugin()

# Configurar se necessário
plugin.config.update({
    'max_pages': 10,
    'attempt_login': True,
    'headless': False  # Mostrar browser para debug
})

# Executar
result = plugin.execute(
    target='https://exemplo.com',
    context={'test_mode': True}
)

# Verificar resultados
if result.success:
    data = result.data['web_crawling']
    print(f"Páginas navegadas: {data['statistics']['total_pages']}")
    print(f"Formulários encontrados: {data['statistics']['total_forms']}")
    print(f"Tentativas de login: {data['statistics']['login_attempts']}")
```

## 📊 Resultados Produzidos

### Estrutura de Dados
```json
{
  "web_crawling": {
    "target": "https://exemplo.com",
    "timestamp": 1234567890,
    "pages_crawled": [
      {
        "url": "https://exemplo.com",
        "title": "Título da Página",
        "depth": 0,
        "forms": [...],
        "links": [...],
        "inputs": [...],
        "cookies": [...],
        "technologies": [...]
      }
    ],
    "forms_found": [
      {
        "url": "https://exemplo.com/login",
        "method": "post",
        "action": "/authenticate",
        "is_login_form": true,
        "inputs": [...],
        "csrf_tokens": [...]
      }
    ],
    "login_attempts": [
      {
        "username": "admin",
        "password": "admin",
        "success": false,
        "final_url": "...",
        "url_changed": false
      }
    ],
    "frameworks_detected": ["WordPress", "jQuery", "Bootstrap"],
    "parameters_discovered": {
      "get_params": ["page", "id", "search"],
      "form_params": ["username", "password", "_token"],
      "cookie_names": ["PHPSESSID", "_session"]
    },
    "security_headers": {
      "headers_found": {"X-Frame-Options": "SAMEORIGIN"},
      "missing_headers": ["Content-Security-Policy"],
      "security_score": 0.375
    },
    "statistics": {
      "total_pages": 5,
      "total_forms": 2,
      "total_parameters": 15,
      "login_attempts": 3,
      "frameworks_detected": 3
    }
  }
}
```

## 🧪 Testes Disponíveis

### Teste Básico (Configuração)
```bash
python test_web_crawler_unit.py
```
- Verifica imports e configuração básica
- Testa validação de URLs
- Verifica detecção de frameworks
- Testa análise de formulários

### Teste Simples (Selenium)
```bash
python test_simple_crawler.py
```
- Navegação básica com Selenium
- Teste com site simples (httpbin.org)
- Verificação de funcionalidades principais

### Teste Avançado (Formulários)
```bash
python test_advanced_crawler.py
```
- Análise completa de formulários
- Tentativas de login automático
- Teste com sites reais
- Análise detalhada de resultados

## 🔧 Dependências

### Principais
- **selenium** (4.35.0+) - Automação do browser
- **webdriver-manager** - Gerenciamento automático do ChromeDriver

### Opcionais (mas recomendadas)
- **requests** - Para verificações HTTP adicionais
- **beautifulsoup4** - Parsing HTML adicional
- **lxml** - Parser XML/HTML rápido

## 📱 Requisitos do Sistema

### Browser
- **Google Chrome** ou **Chromium** instalado
- Versão recente (últimos 2 anos)

### Sistema Operacional
- **Linux** (testado no Ubuntu/Debian)
- **Windows** (com Chrome instalado)
- **macOS** (com Chrome instalado)

## ⚠️ Considerações Importantes

### Performance
- O plugin pode ser **lento** para sites grandes
- **Configure max_pages e max_depth** adequadamente
- Use **headless=true** para melhor performance

### Segurança
- **Não use em produção** com attempt_login=true
- As **credenciais testadas são comuns** e públicas
- **Respeite robots.txt** e termos de uso dos sites

### Rate Limiting
- O plugin **não implementa rate limiting automático**
- Para sites sensíveis, adicione delays manuais
- **Configure timeouts apropriados** para evitar bloqueios

## 🎁 Exemplos de Uso

### 1. Análise de Formulários Específica
```python
plugin = WebCrawlerPlugin()
plugin.config.update({
    'analyze_forms': True,
    'attempt_login': False,  # Só analisar, não tentar login
    'max_pages': 5
})
```

### 2. Teste de Login Controlado
```python
plugin.config.update({
    'attempt_login': True,
    'common_credentials': True,
    'screenshot_on_error': True,  # Debug visual
    'headless': False  # Ver o que está acontecendo
})
```

### 3. Mapeamento Completo de Site
```python
plugin.config.update({
    'max_depth': 5,
    'max_pages': 100,
    'extract_apis': True,
    'detect_frameworks': True,
    'analyze_cookies': True
})
```

## 🆘 Troubleshooting

### Chrome não encontrado
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install google-chrome-stable

# Ou usar Chromium
sudo apt install chromium-browser
```

### Timeout errors
- Aumente `page_load_timeout` e `timeout`
- Verifique conectividade de rede
- Use sites mais simples para teste

### Selenium errors
- Atualize Chrome para versão mais recente
- Reinstale webdriver-manager: `pip install --upgrade webdriver-manager`
- Verifique se tem permissões para criar arquivos temporários

---

**💡 Dica:** Para desenvolvimento e debug, configure `headless=false` para ver o browser em ação!
