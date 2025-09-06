# 🔌 Gerenciamento de Plugins - VarreduraIA

O VarreduraIA possui um sistema flexível de plugins que permite ativar/desativar funcionalidades específicas e configurar cada plugin individualmente.

## 📋 Visão Geral

### Tipos de Plugins Disponíveis

- **🔍 Plugins de Reconhecimento**: Reconnaissance (avançado)
- **🌐 Plugins de Rede**: DNS, Nmap, Port Scanner, RustScan, Subdomain Enumerator
- **🔗 Plugins Web**: Web Scanner, Technology Detector, Directory Scanner
- **🔍 Plugins de Vulnerabilidade**: Nuclei Scanner, SQLMap Scanner, Web Vuln Scanner

### Status Padrão dos Plugins

Por padrão, a maioria dos plugins está **habilitada**, exceto:
- `SQLMapScannerPlugin` - Desabilitado por ser muito agressivo
- `WebVulnScannerPlugin` - Desabilitado por ser potencialmente invasivo

#### ✅ **Habilitados por padrão (seguros):**
- **ReconnaissancePlugin v2.0.0** - 🔍 **ATUALIZADO!** Reconhecimento avançado + OSINT completo
- DNSResolverPlugin - Resolução DNS básica
- NmapScannerPlugin - Scanner Nmap completo
- PortScannerPlugin - Scanner de portas básico
- RustScanPlugin - Scanner de portas rápido
- SubdomainEnumeratorPlugin - Enumeração de subdomínios
- WebScannerPlugin - Scanner web básico
- TechnologyDetectorPlugin - Detector de tecnologias
- DirectoryScannerPlugin - Scanner de diretórios
- NucleiScannerPlugin - Scanner de vulnerabilidades

## 🛠️ Como Gerenciar Plugins

### 1. Listar Todos os Plugins

```bash
# Ativar o ambiente virtual
source venv/bin/activate

# Listar plugins e status
python manage_plugins.py list
```

### 2. Habilitar um Plugin

```bash
# Habilitar plugin específico
python manage_plugins.py enable NucleiScannerPlugin

# Exemplo: habilitar SQLMap (USE COM CUIDADO!)
python manage_plugins.py enable SQLMapScannerPlugin
```

### 3. Desabilitar um Plugin

```bash
# Desabilitar plugin específico
python manage_plugins.py disable PortScannerPlugin

# Exemplo: desabilitar scanner agressivo
python manage_plugins.py disable SQLMapScannerPlugin
```

### 4. Ver Configuração de um Plugin

```bash
# Mostrar configuração atual
python manage_plugins.py config DNSResolverPlugin
```

### 5. Configurar um Plugin

```bash
# Criar arquivo de configuração personalizada
cp config/plugins_example.yaml config/my_plugins.yaml

# Editar o arquivo conforme necessário
nano config/my_plugins.yaml

# Aplicar configuração personalizada
python manage_plugins.py config DNSResolverPlugin config/my_plugins.yaml
```

### 6. Ver Categorias de Plugins

```bash
# Listar categorias disponíveis
python manage_plugins.py categories
```

### 7. Exportar Configuração Atual

```bash
# Exportar configuração para backup
python manage_plugins.py export backup_plugins.yaml
```

## ⚙️ Configuração via Arquivo

### Usando Arquivo de Configuração Personalizado

1. **Copie o exemplo**:
   ```bash
   cp config/plugins_example.yaml config/custom_plugins.yaml
   ```

2. **Edite as configurações**:
   ```yaml
   plugins:
     enabled:
       DNSResolverPlugin: true
       NmapScannerPlugin: false  # Desabilitar Nmap
       SQLMapScannerPlugin: false # Manter SQLMap desabilitado
     
     config:
       DNSResolverPlugin:
         timeout: 20
         max_subdomains: 50
   ```

3. **Use no programa principal**:
   ```bash
   python main.py --target example.com --config config/custom_plugins.yaml
   ```

### Configurações Importantes por Plugin

#### 🔍 **ReconnaissancePlugin v2.0.0 - OSINT Expandido (NOVO!)**
**O plugin mais avançado para reconhecimento completo e OSINT!**

```yaml
ReconnaissancePlugin:
  # Servidores DNS para consultas
  dns_servers: ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
  
  # Enumeração de subdomínios
  subdomain_wordlist: "wordlists/subdomains.txt"
  max_subdomains: 200
  brute_force_subdomains: true
  
  # APIs externas (grátis)
  use_apis: true
  api_delay: 1.0
  crt_sh_api: true           # Certificate Transparency
  securitytrails_api: false  # Requer API key
  virustotal_api: false      # Requer API key
  
  # Recursos de reconhecimento básico
  check_email_patterns: true
  geoip_enabled: true
  whois_enabled: true
  asn_lookup: true
  
  # OSINT Intelligence Features (v2.0.0) 🆕
  social_media_scan: false          # Busca em redes sociais
  check_data_breaches: false        # Verificação de vazamentos
  threat_intelligence: false        # Threat intelligence
  advanced_email_harvesting: false  # Coleta avançada de emails
  
  # Performance
  max_threads: 50
  timeout: 15
```

**Funcionalidades Básicas:**
- 🌐 **Resolução DNS completa** (A, AAAA, MX, NS, TXT, CNAME)
- 🔄 **DNS reverso** para descobrir hostnames
- 🏢 **Informações ASN** e ranges de rede via IPWhois
- 🌍 **Enumeração de subdomínios** (brute-force + Certificate Transparency)
- 📧 **Descoberta de emails** com padrões comuns
- 🗺️ **Localização geográfica** via APIs gratuitas
- 📋 **Informações WHOIS** completas

**🆕 Funcionalidades OSINT v2.0.0:**
- 🔗 **Social Media Intelligence** (LinkedIn, Twitter, GitHub, Facebook)
- 🔓 **Data Breach Checking** (HaveIBeenPwned integration)
- ⚠️ **Threat Intelligence** (VirusTotal, AbuseIPDB, reputation scoring)
- 📧 **Advanced Email Harvesting** (Google Dorking, GitHub search, patterns)
- ⚡ **Multi-threading** para alta performance
- 🛡️ **Rate limiting** para respeitar APIs

**Configuração para OSINT Completo:**
```yaml
# Para pentesting agressivo com OSINT completo
ReconnaissancePlugin:
  # ... configurações básicas ...
  social_media_scan: true
  check_data_breaches: true
  threat_intelligence: true
  advanced_email_harvesting: true
```

**Exemplo de uso:**
```bash
# O plugin executa automaticamente no loop principal
python main.py --target example.com

# Testar especificamente o plugin
python test_reconnaissance.py
```

#### 🌐 DNSResolverPlugin
```yaml
DNSResolverPlugin:
  timeout: 30
  max_subdomains: 100
  dns_servers: ["8.8.8.8", "1.1.1.1"]
```

#### 🔍 NmapScannerPlugin
```yaml
NmapScannerPlugin:
  scan_type: "syn"        # syn, tcp, udp
  timing: "T4"           # T0-T5 (velocidade)
  script_scan: true      # Executar scripts NSE
  max_ports: 1000
```

#### ⚡ NucleiScannerPlugin
```yaml
NucleiScannerPlugin:
  severity_filter: ["medium", "high", "critical"]
  timeout: 300
  exclude_tags: ["intrusive", "dos"]
```

#### ⚠️ SQLMapScannerPlugin (CUIDADO!)
```yaml
SQLMapScannerPlugin:
  risk_level: 1          # 1=baixo, 2=médio, 3=alto
  level: 1               # 1=básico, 5=agressivo
  timeout: 300
```

## 🚨 Plugins Perigosos

### ⚠️ SQLMapScannerPlugin
- **Risco**: MUITO ALTO
- **Motivo**: Pode executar comandos SQL invasivos
- **Recomendação**: Use apenas em ambientes de teste que você possui

### ⚠️ WebVulnScannerPlugin
- **Risco**: MÉDIO-ALTO
- **Motivo**: Pode tentar exploits básicos
- **Recomendação**: Use com cuidado em produção

### ⚠️ NucleiScannerPlugin
- **Risco**: MÉDIO
- **Motivo**: Alguns templates podem ser invasivos
- **Recomendação**: Configure severity_filter e exclude_tags

## 🛡️ Boas Práticas de Segurança

### 1. Ambientes de Teste
- **SEMPRE** teste em ambientes controlados primeiro
- Use máquinas virtuais isoladas
- Tenha autorização explícita para todos os testes

### 2. Configuração Conservadora
```yaml
# Configuração conservadora recomendada
plugins:
  enabled:
    # Plugins seguros - sempre ligados
    DNSResolverPlugin: true
    SubdomainEnumeratorPlugin: true
    TechnologyDetectorPlugin: true
    
    # Plugins moderados - configurar cuidadosamente
    NmapScannerPlugin: true
    WebScannerPlugin: true
    NucleiScannerPlugin: true
    
    # Plugins agressivos - desabilitar por padrão
    SQLMapScannerPlugin: false
    WebVulnScannerPlugin: false
```

### 3. Logs e Monitoramento
- Sempre monitore os logs durante execução
- Use `--verbose` para mais detalhes
- Verifique se não há erros de conectividade

## 🔧 Desenvolvimento de Plugins

### Estrutura Básica
```python
from core.plugin_base import NetworkPlugin, PluginResult

class MeuPlugin(NetworkPlugin):
    def __init__(self):
        super().__init__()
        self.description = "Descrição do meu plugin"
        self.version = "1.0.0"
    
    def execute(self, target: str, context: dict, **kwargs) -> PluginResult:
        # Acessar configurações
        timeout = self.config.get('timeout', 30)
        
        # Sua lógica aqui
        
        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=1.0,
            data={'resultado': 'dados'}
        )
```

### Adicionando à Configuração
```yaml
plugins:
  enabled:
    MeuPlugin: true
  config:
    MeuPlugin:
      timeout: 60
      custom_option: "valor"
```

## 📝 Exemplos Práticos

### Scan Básico (Apenas Reconhecimento)
```bash
# Usar configuração conservadora
python main.py --target example.com --config config/scan_basic.yaml
```

### Scan Completo (Com Vulnerabilidades)
```bash
# Usar configuração completa
python main.py --target example.com --config config/scan_full.yaml
```

### Scan Específico (Apenas Web)
```bash
# Desabilitar plugins de rede, manter apenas web
python manage_plugins.py disable NmapScannerPlugin
python manage_plugins.py disable PortScannerPlugin
python main.py --target https://example.com
```

## ❓ Solução de Problemas

### Plugin Não Carrega
1. Verifique se está habilitado: `python manage_plugins.py list`
2. Verifique logs de erro no terminal
3. Confirme se dependências estão instaladas

### Plugin Falha na Execução
1. Use `--verbose` para mais detalhes
2. Verifique configurações específicas do plugin
3. Teste conectividade com o alvo

### Configuração Não Aplica
1. Verifique sintaxe YAML
2. Confirme caminho do arquivo de configuração
3. Reinicie o programa após mudanças

---

⚠️ **LEMBRE-SE**: Sempre use com responsabilidade e apenas em sistemas que você possui ou tem autorização explícita para testar!
