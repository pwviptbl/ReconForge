# 🔍 Plugin de Reconhecimento Avançado - ReconForge

## 🌟 Visão Geral

O **ReconnaissancePlugin** é o plugin mais avançado do ReconForge, combinando múltiplas técnicas de reconhecimento em uma única ferramenta poderosa. Ele automatiza a coleta de inteligência sobre alvos, fornecendo uma base sólida para testes de segurança.

## 🚀 Funcionalidades Principais

### 🌐 **Resolução DNS Completa**
- **Registros A/AAAA**: IPs IPv4 e IPv6
- **Registros MX**: Servidores de email
- **Registros NS**: Servidores DNS autoritativos
- **Registros TXT**: Informações adicionais (SPF, DMARC, etc.)
- **Registros CNAME**: Aliases de domínio
- **DNS Reverso**: Hostnames a partir de IPs

### 🏢 **Informações de Rede**
- **ASN (Autonomous System Number)**: Identificação da organização
- **Ranges de rede**: Blocos IP associados
- **Informações WHOIS**: Dados de registro
- **Localização geográfica**: País, cidade, ISP

### 🌍 **Enumeração de Subdomínios**
- **Brute-force**: Wordlists personalizáveis
- **Certificate Transparency**: Via API crt.sh
- **Multi-threading**: Até 50 threads simultâneas
- **Resolução automática**: Verifica quais subdomínios existem

### 📧 **Descoberta de Emails**
- **Padrões comuns**: admin@, info@, support@, etc.
- **Baseado em estrutura organizacional**
- **Preparado para integração com APIs** (Hunter.io, HaveIBeenPwned)

### 🗺️ **Inteligência Geográfica**
- **GeoIP via ip-api.com** (gratuito)
- **Localização física**: Coordenadas, cidade, país
- **Informações de ISP**: Provedor, organização
- **Detecção de proxy/VPN/hosting**

## 📊 **Exemplo de Resultados**

```json
{
  "target": "example.com",
  "statistics": {
    "total_ips": 15,
    "total_subdomains": 25,
    "total_emails": 20,
    "unique_asns": 2,
    "countries": 2
  },
  "dns_info": {
    "ips": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
    "mx_records": [
      {"preference": 10, "exchange": "mail.example.com"}
    ],
    "ns_records": ["ns1.example.com", "ns2.example.com"]
  },
  "subdomains": [
    {
      "domain": "www.example.com",
      "method": "brute_force",
      "resolved": true,
      "ips": ["93.184.216.34"]
    },
    {
      "domain": "api.example.com", 
      "method": "certificate_transparency",
      "resolved": true,
      "ips": ["93.184.216.35"]
    }
  ],
  "geo_info": {
    "93.184.216.34": {
      "country": "United States",
      "city": "Norwell",
      "isp": "Edgecast",
      "hosting": true
    }
  },
  "asn_info": {
    "93.184.216.34": {
      "asn": "15133",
      "asn_description": "EDGECAST, US",
      "network": "93.184.216.0/24"
    }
  }
}
```

## ⚙️ **Configuração Avançada**

### 🎯 **Configuração para Reconhecimento Passivo**
```yaml
ReconnaissancePlugin:
  # Apenas técnicas passivas (sem brute-force)
  brute_force_subdomains: false
  crt_sh_api: true
  use_apis: true
  max_threads: 10
  api_delay: 2.0
```

### ⚡ **Configuração para Reconhecimento Agressivo**
```yaml
ReconnaissancePlugin:
  # Máxima velocidade e descoberta
  max_subdomains: 500
  max_threads: 100
  brute_force_subdomains: true
  subdomain_wordlist: "wordlists/big_subdomains.txt"
  api_delay: 0.5
  timeout: 30
```

### 🛡️ **Configuração Corporativa (Stealth)**
```yaml
ReconnaissancePlugin:
  # Configuração discreta para ambientes corporativos
  max_threads: 5
  api_delay: 3.0
  timeout: 60
  max_subdomains: 50
  use_apis: false  # Não usar APIs externas
```

## 🔧 **Wordlists Personalizadas**

### Criar Wordlist Específica por Setor
```bash
# Para empresas de tecnologia
echo -e "api\napp\ndev\nstaging\nprod\ntest\nbeta\ncdn\nstatic" > wordlists/tech.txt

# Para organizações governamentais  
echo -e "portal\nservicos\ncidadao\ntransparencia\nlicitacoes" > wordlists/gov.txt

# Para e-commerce
echo -e "shop\nstore\ncart\npayment\ncheckout\napi\nmobile" > wordlists/ecommerce.txt
```

### Usar Wordlist Personalizada
```yaml
ReconnaissancePlugin:
  subdomain_wordlist: "wordlists/tech.txt"
```

## 🌐 **Integração com APIs Externas**

### APIs Gratuitas (Já Integradas)
- **crt.sh**: Certificate Transparency
- **ip-api.com**: GeoIP e informações de rede

### APIs Premium (Configuração Futura)
```yaml
ReconnaissancePlugin:
  # SecurityTrails (requer API key)
  securitytrails_api: true
  securitytrails_key: "sua_api_key_aqui"
  
  # VirusTotal (requer API key)
  virustotal_api: true
  virustotal_key: "sua_api_key_aqui"
```

## 📈 **Métricas e Performance**

### Benchmarks Típicos
- **Domínio simples**: 5-15 segundos
- **Domínio complexo**: 30-60 segundos
- **Subdomínios descobertos**: 10-100+ (dependendo do alvo)
- **IPs únicos**: 5-50+ (dependendo da infraestrutura)

### Otimização de Performance
```yaml
ReconnaissancePlugin:
  # Para alvos pequenos
  max_threads: 20
  max_subdomains: 50
  timeout: 10
  
  # Para alvos grandes
  max_threads: 100
  max_subdomains: 500
  timeout: 30
```

## 🛡️ **Considerações de Segurança**

### ✅ **Técnicas Passivas (Seguras)**
- Consultas DNS normais
- APIs públicas
- Certificate Transparency
- WHOIS públicos

### ⚠️ **Técnicas Semi-Ativas**
- Brute-force de subdomínios
- Múltiplas consultas DNS
- Pode ser detectado em logs

### 🔒 **Boas Práticas**
1. **Use rate limiting** adequado
2. **Respeite robots.txt** quando aplicável
3. **Monitore logs** durante execução
4. **Teste em ambientes próprios** primeiro

## 📝 **Casos de Uso**

### 🔍 **Reconhecimento Inicial**
```bash
# Descoberta básica de um domínio
python main.py --target example.com
```

### 🌐 **Mapeamento de Infraestrutura**
```bash
# Análise completa de subdomínios e IPs
python main.py --target corporation.com --config config/reconnaissance_full.yaml
```

### 🎯 **Inteligência Competitiva**
```bash
# Análise passiva (apenas APIs públicas)
python main.py --target competitor.com --config config/reconnaissance_passive.yaml
```

## 🚀 **Desenvolvimento Futuro**

### Funcionalidades Planejadas
- 📧 **Integração Hunter.io**: Descoberta de emails real
- 🔍 **Shodan Integration**: Descoberta de serviços expostos
- 🌐 **Amass Integration**: Enumeração de subdomínios avançada
- 📊 **Relatórios visuais**: Mapas de rede e gráficos
- 🔄 **Cache inteligente**: Evitar consultas duplicadas
- 🌍 **Múltiplas APIs GeoIP**: Redundância e precisão

### Como Contribuir
1. Fork do repositório
2. Implemente nova funcionalidade
3. Adicione testes
4. Envie Pull Request

---

⚠️ **AVISO LEGAL**: Use apenas em sistemas que você possui ou tem autorização explícita para testar. O reconhecimento deve ser feito de forma responsável e ética.
