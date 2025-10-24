# 🔌 Gerenciamento de Plugins - VarreduraIA

O VarreduraIA possui um sistema flexível de plugins que permite ativar/desativar funcionalidades específicas e configurar cada plugin individualmente.

## 📋 Visão Geral

### Tipos de Plugins Disponíveis

- **🔍 Plugins de Reconhecimento**: Reconnaissance (avançado)
- **🌐 Plugins de Rede**: DNS, Nmap, Port Scanner, RustScan, Subdomain Enumerator
- **🔗 Plugins Web**: Web Scanner, Technology Detector, Directory Scanner
- **🛡️ Plugins de Análise de Vulnerabilidade**: Nuclei Scanner, SQLMap Scanner, Web Vuln Scanner, Misconfiguration Analyzer, Exploit Suggester

### Status Padrão dos Plugins

Por padrão, a maioria dos plugins está **habilitada**, exceto:
- `SQLMapScannerPlugin` - Desabilitado por ser muito agressivo
- `WebVulnScannerPlugin` - Desabilitado por ser potencialmente invasivo

#### ✅ **Habilitados por padrão (seguros):**
- **ReconnaissancePlugin v2.0.0** - 🔍 **ATUALIZADO!** Reconhecimento avançado + OSINT completo
- DNSResolverPlugin - Resolução DNS básica
- NmapScannerPlugin - Scanner Nmap completo (Agora com extração de CVEs!)
- PortScannerPlugin - Scanner de portas básico
- RustScanPlugin - Scanner de portas rápido
- SubdomainEnumeratorPlugin - Enumeração de subdomínios
- WebScannerPlugin - Scanner web básico
- TechnologyDetectorPlugin - Detector de tecnologias
- DirectoryScannerPlugin - Scanner de diretórios
- NucleiScannerPlugin - Scanner de vulnerabilidades
- **MisconfigurationAnalyzerPlugin (NOVO!)** - 🕵️ Analisa falhas de configuração em serviços de rede.
- **ExploitSuggesterPlugin (NOVO!)** - 💥 Sugere exploits públicos para as CVEs encontradas.

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
       MisconfigurationAnalyzerPlugin: true # Habilitar novo plugin
     
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
(conteúdo omitido para brevidade)

#### 🌐 DNSResolverPlugin
```yaml
DNSResolverPlugin:
  timeout: 30
  max_subdomains: 100
  dns_servers: ["8.8.8.8", "1.1.1.1"]
```

#### 🔍 NmapScannerPlugin (ATUALIZADO!)
- **O que há de novo?** Agora o plugin está otimizado para usar portas descobertas por outros scanners e extrai CVEs de forma estruturada.
```yaml
NmapScannerPlugin:
  scan_type: "syn"        # syn, tcp, udp
  timing: "T4"           # T0-T5 (velocidade)
  script_scan: true      # Executar scripts NSE
  max_ports: 1000        # Usado como fallback se nenhuma porta for descoberta antes
```

#### 🕵️ MisconfigurationAnalyzerPlugin (NOVO!)
**Este plugin foca em vulnerabilidades que não são CVEs, mas sim falhas de configuração.**
- **Funcionalidades:**
  - Verifica login anônimo em FTP (`ftp-anon`).
  - Enumera compartilhamentos SMB (`smb-enum-shares`).
  - Analisa cifras de criptografia fracas em SSL/TLS (`ssl-enum-ciphers`).
  - E mais...
- **Configuração:** Este plugin não possui configurações complexas, basta habilitá-lo.

#### 💥 ExploitSuggesterPlugin (NOVO!)
**Transforma dados em ação, sugerindo exploits para as vulnerabilidades encontradas.**
- **Funcionalidades:**
  - Consome os CVEs extraídos pelo `NmapScannerPlugin`.
  - Utiliza o `searchsploit` para encontrar exploits públicos no Exploit-DB.
  - Adiciona uma lista de exploits potenciais ao relatório final.
- **Pré-requisitos:** Requer que a ferramenta `searchsploit` (parte do Exploit-DB) esteja instalada.
- **Configuração:** Nenhuma configuração necessária, apenas habilitar.


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
(conteúdo omitido para brevidade)

## 🛡️ Boas Práticas de Segurança
(conteúdo omitido para brevidade)

## 🔧 Desenvolvimento de Plugins
(conteúdo omitido para brevidade)

## 📝 Exemplos Práticos
(conteúdo omitido para brevidade)

## ❓ Solução de Problemas
(conteúdo omitido para brevidade)

---

⚠️ **LEMBRE-SE**: Sempre use com responsabilidade e apenas em sistemas que você possui ou tem autorização explícita para testar!
