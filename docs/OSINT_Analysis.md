# 🔍 Expansão do Módulo de Reconhecimento (OSINT)

## 📋 Análise de Funcionalidades Existentes vs. Necessárias

### ✅ **JÁ IMPLEMENTADO no ReconnaissancePlugin:**

#### **Email Intelligence:**
```python
def _email_reconnaissance(self, domain: str):
    # Padrões comuns: admin@, info@, contact@, support@
    # TODO: Expandir com verificação real de existência
```

#### **Domain Intelligence:**
```python
def _dns_reconnaissance(self, domain: str):
    # DNS completo: A, AAAA, MX, NS, TXT, CNAME
def _subdomain_enumeration(self, domain: str):
    # Brute force + Certificate Transparency
def _whois_lookup(self, target: str):
    # WHOIS completo para domínios e IPs
```

#### **Network Intelligence:**
```python
def _asn_reconnaissance(self, ips: List[str]):
    # ASN, ranges de rede, informações de registry
def _geoip_lookup(self, ips: List[str]):
    # Localização geográfica via API
```

---

### 🚀 **FUNCIONALIDADES A ADICIONAR:**

#### **1. Social Media Intelligence**
```python
def _social_media_reconnaissance(self, domain: str, company_name: str) -> Dict[str, Any]:
    """Busca perfis em redes sociais relacionados ao domínio/empresa"""
    social_platforms = {
        'linkedin': f"https://www.linkedin.com/company/{company_name}",
        'twitter': f"https://twitter.com/{company_name}",
        'facebook': f"https://www.facebook.com/{company_name}",
        'instagram': f"https://www.instagram.com/{company_name}",
        'github': f"https://github.com/{company_name}",
        'youtube': f"https://www.youtube.com/c/{company_name}"
    }
    
    results = {}
    for platform, url in social_platforms.items():
        try:
            response = requests.head(url, timeout=10)
            results[platform] = {
                'url': url,
                'exists': response.status_code == 200,
                'status_code': response.status_code
            }
        except:
            results[platform] = {'url': url, 'exists': False, 'error': 'timeout'}
    
    return results
```

#### **2. Data Leak Checker**
```python
def _check_data_breaches(self, domain: str, emails: List[str]) -> Dict[str, Any]:
    """Verifica vazamentos de dados usando APIs públicas"""
    breach_results = {
        'domain_breaches': [],
        'email_breaches': {},
        'breach_summary': {}
    }
    
    # HaveIBeenPwned API (requer key para emails)
    # DeHashed API (pago)
    # Leak-Lookup (grátis, limitado)
    
    # Implementação básica com leak-lookup.com
    try:
        response = requests.get(
            f"https://leak-lookup.com/api/search",
            params={'query': domain, 'type': 'domain'},
            timeout=15
        )
        if response.status_code == 200:
            breach_results['domain_breaches'] = response.json()
    except:
        pass
    
    return breach_results
```

#### **3. Threat Intelligence Feeds**
```python
def _threat_intelligence_lookup(self, ips: List[str], domains: List[str]) -> Dict[str, Any]:
    """Consulta feeds de threat intelligence"""
    threat_results = {
        'malicious_ips': {},
        'malicious_domains': {},
        'reputation_scores': {},
        'threat_categories': {}
    }
    
    # APIs gratuitas de threat intelligence:
    
    # 1. AbuseIPDB (grátis com limitações)
    for ip in ips:
        try:
            response = requests.get(
                f"https://api.abuseipdb.com/api/v2/check",
                headers={'Key': 'YOUR_API_KEY', 'Accept': 'application/json'},
                params={'ipAddress': ip, 'maxAgeInDays': '90'},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                threat_results['malicious_ips'][ip] = {
                    'abuse_confidence': data.get('abuseConfidencePercentage', 0),
                    'is_malicious': data.get('abuseConfidencePercentage', 0) > 25,
                    'usage_type': data.get('usageType'),
                    'country': data.get('countryCode')
                }
        except:
            pass
    
    # 2. VirusTotal (grátis com limitações)
    # 3. URLVoid para domínios
    # 4. Shodan para informações de serviços
    
    return threat_results
```

#### **4. Advanced Email Harvesting**
```python
def _advanced_email_harvesting(self, domain: str) -> List[Dict[str, Any]]:
    """Coleta avançada de emails de múltiplas fontes"""
    emails = []
    
    # 1. Google Dorking (respeitando robots.txt)
    google_dorks = [
        f'site:{domain} "email" OR "@{domain}"',
        f'site:{domain} "contact" OR "contacto"',
        f'filetype:pdf site:{domain} "@{domain}"'
    ]
    
    # 2. GitHub repositories search
    try:
        github_api = f"https://api.github.com/search/code"
        params = {
            'q': f'"{domain}" email OR @{domain}',
            'per_page': 10
        }
        response = requests.get(github_api, params=params, timeout=15)
        if response.status_code == 200:
            # Parse GitHub results
            pass
    except:
        pass
    
    # 3. LinkedIn public profiles (cuidado com rate limiting)
    # 4. Company websites crawling
    # 5. Professional networks
    
    return emails
```

---

## 🔧 **Implementação Recomendada:**

### **Expandir ReconnaissancePlugin existente:**

```python
class ReconnaissancePlugin(NetworkPlugin):
    def __init__(self):
        super().__init__()
        # ... configurações existentes ...
        
        # Novas configurações OSINT
        self.config.update({
            'enable_social_media_scan': True,
            'enable_breach_check': True,
            'enable_threat_intelligence': True,
            'enable_advanced_email_harvest': True,
            'social_media_platforms': ['linkedin', 'twitter', 'github'],
            'threat_intel_apis': ['abuseipdb', 'virustotal'],
            'breach_check_apis': ['leak-lookup']
        })
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        # ... código existente ...
        
        # NOVAS funcionalidades OSINT
        if self.config.get('enable_social_media_scan', True):
            results['social_media'] = self._social_media_reconnaissance(domain, company_name)
        
        if self.config.get('enable_breach_check', True):
            results['data_breaches'] = self._check_data_breaches(domain, results['emails'])
        
        if self.config.get('enable_threat_intelligence', True):
            results['threat_intelligence'] = self._threat_intelligence_lookup(all_ips, [domain])
        
        if self.config.get('enable_advanced_email_harvest', True):
            advanced_emails = self._advanced_email_harvesting(domain)
            results['emails'].extend(advanced_emails)
        
        # ... resto do código ...
```

---

## ⚖️ **Opção 2: Módulo OSINT Separado (menos recomendado)**

Se preferir manter separado, criar apenas com funcionalidades **não duplicadas**:

```python
osint/
├── __init__.py
├── social_media_scanner.py     # ✅ NOVO - não existe no reconnaissance
├── leak_checker.py            # ✅ NOVO - não existe no reconnaissance  
├── threat_intelligence.py     # ⚠️ PARCIAL - expandir o que já existe
└── advanced_osint.py          # ✅ NOVO - técnicas avançadas
```

---

## 🎯 **Minha Recomendação Final:**

### **EXPANDIR o ReconnaissancePlugin** ao invés de criar módulo separado:

**✅ Vantagens:**
- Evita duplicação de código
- Mantém relacionamento lógico das funcionalidades
- Aproveita infraestrutura existente (DNS, WHOIS, ASN)
- Configuração centralizada
- Menos complexidade de manutenção

**❌ Desvantagens de módulo separado:**
- Duplicação de funcionalidades (DNS, email patterns, etc.)
- Necessidade de compartilhar dados entre plugins
- Maior complexidade de configuração
- Código fragmentado

---

## 🚀 **Proposta de Ação:**

1. **Manter** ReconnaissancePlugin como base
2. **Expandir** com funcionalidades OSINT avançadas:
   - Social Media Intelligence
   - Data Breach Checking  
   - Advanced Threat Intelligence
   - Enhanced Email Harvesting
3. **Adicionar** configurações granulares para cada funcionalidade
4. **Documentar** como "Módulo de Reconhecimento e OSINT"

**Que abordagem você prefere?** Expandir o plugin existente ou criar módulo separado mesmo com sobreposições?
