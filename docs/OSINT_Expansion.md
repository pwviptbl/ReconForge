# Expansão OSINT do ReconnaissancePlugin

## Visão Geral

O `ReconnaissancePlugin` foi expandido com funcionalidades avançadas de OSINT (Open Source Intelligence) para fornecer inteligência abrangente sobre alvos durante operações de pentesting. A versão 2.0.0 inclui quatro novas capacidades principais:

### 🔗 Social Media Intelligence
- **LinkedIn**: Verificação de páginas corporativas
- **Twitter/X**: Busca por handles oficiais da empresa
- **GitHub**: Detecção de organizações e repositórios
- **Facebook**: Verificação de páginas comerciais

### 🔓 Data Breach Intelligence
- **HaveIBeenPwned**: Integração com base de dados de vazamentos
- **Email Patterns**: Geração de emails comuns para verificação
- **Breach History**: Histórico de vazamentos relacionados ao domínio

### ⚠️ Threat Intelligence
- **VirusTotal**: Verificação de reputação de domínios
- **AbuseIPDB**: Análise de reputação de IPs
- **Basic Checks**: Verificações de indicadores suspeitos
- **Reputation Scoring**: Sistema de pontuação de confiabilidade

### 📧 Advanced Email Harvesting
- **Google Dorking**: Consultas otimizadas para busca de emails
- **GitHub Search**: Busca em repositórios públicos
- **Pattern Generation**: Geração de padrões comuns de email
- **Email Validation**: Verificação de padrões válidos

## Configuração

### Habilitando Funcionalidades OSINT

No arquivo `config/default.yaml`, configure as novas opções:

```yaml
plugins:
  ReconnaissancePlugin:
    # Configurações existentes...
    
    # OSINT Intelligence Features
    social_media_scan: true          # Habilitar busca em redes sociais
    check_data_breaches: true        # Verificar vazamentos de dados
    threat_intelligence: true        # Coletar threat intelligence
    advanced_email_harvesting: true  # Coleta avançada de emails
```

### Configurações Recomendadas

Para pentesting **passivo** (padrão):
```yaml
social_media_scan: false
check_data_breaches: false
threat_intelligence: false
advanced_email_harvesting: false
```

Para pentesting **agressivo**:
```yaml
social_media_scan: true
check_data_breaches: true
threat_intelligence: true
advanced_email_harvesting: true
```

## Exemplo de Uso

### Execução Básica

```python
from plugins.reconnaissance_plugin import ReconnaissancePlugin

# Criar instância
plugin = ReconnaissancePlugin()

# Configurar para OSINT completo
config = {
    'social_media_scan': True,
    'check_data_breaches': True,
    'threat_intelligence': True,
    'advanced_email_harvesting': True
}
plugin.set_config(config)

# Executar reconhecimento
result = await plugin.execute("target-domain.com")

# Acessar dados OSINT
osint_data = result.data['reconnaissance']['osint_intelligence']
```

### Estrutura dos Resultados OSINT

```json
{
  "reconnaissance": {
    "osint_intelligence": {
      "social_media": {
        "linkedin": {
          "url": "https://www.linkedin.com/company/target",
          "exists": true,
          "status_code": 200
        },
        "twitter": {
          "url": "https://twitter.com/target",
          "exists": false,
          "status_code": 404
        },
        "github": {
          "url": "https://github.com/target",
          "exists": true,
          "status_code": 200
        },
        "facebook": {
          "url": "https://www.facebook.com/target",
          "exists": false,
          "status_code": 404
        }
      },
      "data_breaches": {
        "haveibeenpwned": {
          "total_breaches": 585,
          "domain_breaches": 0,
          "breaches": []
        },
        "common_emails_to_check": [
          "admin@target-domain.com",
          "info@target-domain.com",
          "contact@target-domain.com"
        ]
      },
      "threat_intel": {
        "virustotal": {
          "domain": "target-domain.com",
          "url": "https://www.virustotal.com/gui/domain/target-domain.com",
          "note": "Manual verification recommended"
        },
        "abuseipdb": {
          "ip": "192.168.1.1",
          "url": "https://www.abuseipdb.com/check/192.168.1.1",
          "note": "Manual verification recommended"
        },
        "basic_checks": [],
        "reputation_score": 100
      },
      "advanced_emails": {
        "google_dorking": {
          "queries": [
            "site:target-domain.com \"email\"",
            "site:target-domain.com \"@target-domain.com\""
          ],
          "note": "Manual Google search recommended with these queries"
        },
        "github_search": {
          "total_results": 42,
          "note": "Check GitHub manually for email addresses in code"
        },
        "common_patterns": [
          "admin@target-domain.com",
          "contact@target-domain.com",
          "info@target-domain.com"
        ],
        "unique_emails": 10,
        "total_emails": 10
      }
    }
  }
}
```

## Funcionalidades Técnicas

### Rate Limiting
- Implementado delay entre requisições para evitar bloqueios
- Timeouts configuráveis para cada operação
- Tratamento de erros de conectividade

### Segurança
- User-Agent rotativo para evitar detecção
- Verificação de status codes HTTP
- Tratamento seguro de exceções

### Escalabilidade
- Execução não-bloqueante
- Configurações granulares por funcionalidade
- Compatibilidade com execução paralela

## Dependências

As funcionalidades OSINT utilizam bibliotecas padrão do Python:
- `requests`: Para requisições HTTP
- `re`: Para expressões regulares
- `socket`: Para validação de endereços

## Limitações e Considerações

### APIs Públicas
- **HaveIBeenPwned**: Limitado à API pública (sem chave)
- **VirusTotal**: Requer chave API para funcionalidade completa
- **GitHub**: Rate limit de 60 requisições/hora sem autenticação

### Rate Limiting
- Implementado delay padrão de 1 segundo entre requisições
- Recomenda-se configurar `api_delay` adequadamente

### Detecção
- Uso de User-Agent padrão pode ser detectado
- Recomenda-se rotação de User-Agents em ambiente de produção

## Próximas Melhorias

### v2.1.0 (Planejado)
- [ ] Integração com APIs autenticadas (VirusTotal, SecurityTrails)
- [ ] Suporte a proxy/Tor para anonimato
- [ ] Cache de resultados para otimização
- [ ] Exportação de relatórios OSINT

### v2.2.0 (Planejado)
- [ ] Integração com Shodan API
- [ ] Análise de certificados SSL históricos
- [ ] Monitoramento de mudanças de DNS
- [ ] Timeline de eventos de segurança

## Conclusão

A expansão OSINT do `ReconnaissancePlugin` transforma-o em uma ferramenta completa de inteligência, fornecendo informações valiosas sobre presença digital, histórico de segurança e superficie de ataque de organizações-alvo. As funcionalidades são projetadas para serem discretas e respeitosas com rate limits, adequadas para uso profissional em pentesting ético.
