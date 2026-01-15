# 🌐 Módulo de Análise de Rede - ReconForge

## 📋 Visão Geral

O **Módulo de Análise de Rede** adiciona capacidades avançadas de análise de infraestrutura e topologia de rede ao ReconForge. Este módulo complementa os scanners existentes com análises profundas de conectividade, protocolos e segurança de rede.

## 🔧 Plugins Implementados

### 1. **NetworkMapperPlugin** 🗺️
**Arquivo:** `network_mapper.py`

**Funcionalidade:**
- Mapeamento de topologia de rede
- Descoberta de hosts ativos
- Análise de roteamento (traceroute avançado)
- Identificação de infraestrutura de rede
- Análise de conectividade

**Configurações:**
```yaml
NetworkMapperPlugin:
  max_hops: 30                    # Máximo de hops para traceroute
  timeout: 5                      # Timeout para conexões
  parallel_threads: 10            # Threads para discovery paralelo
  enable_traceroute: true         # Habilitar traceroute
  enable_host_discovery: true     # Habilitar discovery de hosts
  enable_topology_mapping: true   # Habilitar mapeamento de topologia
```

**Exemplo de Output:**
```json
{
  "target_type": "external_ip",
  "traceroute": {
    "hops": [
      {"hop": 1, "ip": "192.168.1.1", "hostname": "gateway", "latency_ms": 1.2},
      {"hop": 2, "ip": "10.0.0.1", "hostname": "isp-router", "latency_ms": 15.8}
    ],
    "total_hops": 8,
    "target_reached": true
  },
  "topology": {
    "default_gateway": "192.168.1.1",
    "dns_servers": ["8.8.8.8", "1.1.1.1"]
  }
}
```

---

### 2. **SSLAnalyzerPlugin** 🔒
**Arquivo:** `ssl_analyzer.py`

**Funcionalidade:**
- Análise completa de certificados SSL/TLS
- Verificação de vulnerabilidades SSL (Heartbleed, POODLE, etc.)
- Análise de cifras e protocolos suportados
- Verificação de configurações de segurança
- Validação de cadeia de certificados

**Configurações:**
```yaml
SSLAnalyzerPlugin:
  check_vulnerabilities: true     # Verificar vulnerabilidades SSL
  verify_chain: true              # Verificar cadeia de certificados
  check_revocation: true          # Verificar revogação (OCSP/CRL)
  analyze_ciphers: true           # Analisar cifras suportadas
  check_hsts: true                # Verificar cabeçalho HSTS
```

**Exemplo de Output:**
```json
{
  "ssl_enabled": true,
  "certificate_analysis": {
    "subject": {"CN": "example.com"},
    "issuer": {"CN": "Let's Encrypt Authority"},
    "not_after": "Dec 15 23:59:59 2024 GMT",
    "validity_analysis": {
      "is_valid": true,
      "days_until_expiry": 45,
      "expires_soon": false
    }
  },
  "vulnerability_scan": {
    "heartbleed": {"vulnerable": false},
    "poodle": {"vulnerable": false},
    "summary": {"total_vulnerabilities": 0, "risk_level": "low"}
  }
}
```

---

### 3. **FirewallDetectorPlugin** 🛡️
**Arquivo:** `firewall_detector.py`

**Funcionalidade:**
- Detecção de firewalls de rede
- Identificação de WAFs (Web Application Firewalls)
- Análise de filtragem de portas
- Detecção de rate limiting
- Sugestões de técnicas de bypass

**Configurações:**
```yaml
FirewallDetectorPlugin:
  stealth_mode: true              # Modo stealth para evitar detecção
  timing_template: T3             # Template de timing (Nmap style)
  max_retries: 3                  # Máximo de tentativas
  detect_waf: true                # Habilitar detecção de WAF
  suggest_bypasses: true          # Sugerir técnicas de bypass
```

**WAFs Detectados:**
- CloudFlare
- AWS WAF
- Imperva/Incapsula
- F5 BIG-IP
- Akamai
- Sucuri
- Barracuda
- Fortinet
- Nginx WAF

**Exemplo de Output:**
```json
{
  "waf_detection": {
    "detected": true,
    "identified_wafs": ["cloudflare"],
    "confidence": "high",
    "blocking_behavior": {
      "blocked_requests": 3,
      "blocking_rate": 0.6,
      "aggressive_blocking": true
    }
  },
  "bypass_suggestions": {
    "specific_bypasses": {
      "cloudflare": [
        "Use real client IP headers",
        "Try different TLS/SSL versions"
      ]
    }
  }
}
```

---

### 4. **TrafficAnalyzerPlugin** 📊
**Arquivo:** `traffic_analyzer.py`

**Funcionalidade:**
- Análise de padrões de tráfego de rede
- Medição de latência e jitter
- Detecção de anomalias em tempo de resposta
- Análise de bandwidth e throughput
- Monitoramento de estabilidade de conexão

**Configurações:**
```yaml
TrafficAnalyzerPlugin:
  capture_duration: 60            # Duração da captura em segundos
  analysis_window: 300            # Janela de análise em segundos
  anomaly_threshold: 2.5          # Threshold para detecção de anomalias
  protocol_analysis: true         # Habilitar análise de protocolos
  bandwidth_measurement: true     # Habilitar medição de bandwidth
```

**Exemplo de Output:**
```json
{
  "latency_analysis": {
    "average_latency_ms": 45.2,
    "min_latency_ms": 38.1,
    "max_latency_ms": 67.9,
    "jitter_ms": 29.8,
    "connection_quality": "good"
  },
  "anomaly_detection": {
    "detected_anomalies": [],
    "anomaly_score": 5,
    "risk_level": "low"
  },
  "bandwidth_analysis": {
    "speed_kbps": 1250.5,
    "throughput_score": 8.5
  }
}
```

## 🚀 Como Usar

### 1. **Execução Individual**
```bash
# Análise completa de rede
python main.py --target example.com --plugins NetworkMapperPlugin,SSLAnalyzerPlugin,FirewallDetectorPlugin

# Apenas análise SSL
python main.py --target https://example.com --plugins SSLAnalyzerPlugin

# Detecção de firewall/WAF
python main.py --target example.com --plugins FirewallDetectorPlugin
```

### 2. **Integração no Workflow**
Os plugins são automaticamente carregados e podem ser habilitados/desabilitados no arquivo `config/default.yaml`.

### 3. **Configuração Personalizada**
```yaml
plugins:
  enabled:
    NetworkMapperPlugin: true
    SSLAnalyzerPlugin: true  
    FirewallDetectorPlugin: true
    TrafficAnalyzerPlugin: false  # Desabilitado por padrão
```

## 📊 Casos de Uso

### **Pentesting Externo**
```bash
python main.py --target company.com --plugins NetworkMapperPlugin,SSLAnalyzerPlugin,FirewallDetectorPlugin
```
- Mapeia rota até o alvo
- Analisa certificados SSL
- Detecta WAF/CDN
- Identifica pontos de entrada

### **Auditoria SSL/TLS**
```bash
python main.py --target https://api.company.com --plugins SSLAnalyzerPlugin
```
- Verifica configuração SSL
- Identifica vulnerabilidades
- Analisa força das cifras
- Valida certificados

### **Análise de Infraestrutura**
```bash
python main.py --target 192.168.1.0/24 --plugins NetworkMapperPlugin
```
- Descobre hosts ativos
- Mapeia topologia interna
- Identifica gateways e DNS
- Analisa conectividade

### **Bypass de WAF**
```bash
python main.py --target protected-site.com --plugins FirewallDetectorPlugin
```
- Identifica tipo de WAF
- Testa payloads maliciosos
- Sugere técnicas de bypass
- Analisa comportamento de bloqueio

## 🔧 Dependências

### **Dependências Python**
```bash
pip install scapy python-nmap pyshark cryptography netaddr ipwhois dnspython
```

### **Ferramentas do Sistema**
```bash
# Ubuntu/Debian
sudo apt-get install traceroute iputils-ping nmap

# CentOS/RHEL
sudo yum install traceroute iputils nmap
```

## ⚠️ Considerações de Segurança

### **Modo Stealth**
- Use `stealth_mode: true` para evitar detecção
- Configure delays apropriados entre requisições
- Limite o número de threads paralelas

### **Rate Limiting**
- Monitore responses 429/503
- Implemente backoff exponencial
- Use proxies rotativos se necessário

### **Permissões**
- Alguns recursos podem precisar de privilégios root
- Use `sudo` apenas quando necessário
- Configure firewall local apropriadamente

## 📈 Roadmap

### **Próximas Funcionalidades**
- [ ] Integração com Shodan/Censys
- [ ] Análise de DNS avançada
- [ ] Detecção de honeypots
- [ ] Machine Learning para detecção de anomalias
- [ ] Análise de tráfego em tempo real
- [ ] Suporte a IPv6
- [ ] Dashboard web para visualização

### **Melhorias Planejadas**
- [ ] Cache de resultados para otimização
- [ ] Exportação para formatos específicos
- [ ] Integração com threat intelligence feeds
- [ ] Análise de compliance automatizada

## 🤝 Contribuição

Para contribuir com o módulo de análise de rede:

1. Fork o repositório
2. Crie uma branch para sua feature
3. Implemente testes unitários
4. Envie um pull request

## 📝 Licença

Este módulo segue a mesma licença do projeto principal ReconForge.

---

*Desenvolvido com ❤️ para a comunidade de segurança cibernética*
