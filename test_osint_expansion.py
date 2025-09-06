#!/usr/bin/env python3
"""
Teste do ReconnaissancePlugin expandido com funcionalidades OSINT
"""

import asyncio
import sys
import os
import yaml

# Adicionar o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from plugins.reconnaissance_plugin import ReconnaissancePlugin
from utils.logger import Logger

async def test_osint_expansion():
    """Testa as novas funcionalidades OSINT"""
    
    # Configurar logging
    logger = Logger("test_osint")
    
    print("🔍 Testando ReconnaissancePlugin expandido com OSINT...")
    
    # Carregar configuração
    with open('config/default.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Ativar recursos OSINT para teste
    osint_config = config['plugins']['ReconnaissancePlugin'].copy()
    osint_config.update({
        'social_media_scan': True,
        'check_data_breaches': True,
        'threat_intelligence': True,
        'advanced_email_harvesting': True
    })
    
    # Criar instância do plugin
    plugin = ReconnaissancePlugin()
    plugin.set_config(osint_config)
    
    # Domínio de teste
    test_domain = "google.com"
    
    print(f"\n📊 Testando reconhecimento OSINT para: {test_domain}")
    print("=" * 60)
    
    try:
        # Executar reconhecimento completo
        result = await plugin.execute(test_domain)
        
        if result.success:
            print("✅ Plugin executado com sucesso!")
            
            # Exibir estatísticas
            if 'reconnaissance' in result.data:
                recon_data = result.data['reconnaissance']
                
                # Estatísticas básicas
                if 'statistics' in recon_data:
                    stats = recon_data['statistics']
                    print(f"\n📈 Estatísticas:")
                    print(f"   • IPs encontrados: {stats.get('total_ips', 0)}")
                    print(f"   • Subdomínios: {stats.get('total_subdomains', 0)}")
                    print(f"   • Emails: {stats.get('total_emails', 0)}")
                
                # Funcionalidades OSINT
                if 'osint_intelligence' in recon_data:
                    osint_data = recon_data['osint_intelligence']
                    print(f"\n🕵️ Resultados OSINT:")
                    
                    # Social Media
                    if 'social_media' in osint_data:
                        social = osint_data['social_media']
                        print(f"   🔗 Social Media:")
                        for platform, data in social.items():
                            if platform != 'error' and data:
                                if isinstance(data, dict) and 'exists' in data:
                                    status = "✅" if data['exists'] else "❌"
                                    print(f"     • {platform.capitalize()}: {status}")
                    
                    # Data Breaches
                    if 'data_breaches' in osint_data:
                        breaches = osint_data['data_breaches']
                        print(f"   🔓 Data Breaches:")
                        if 'common_emails_to_check' in breaches:
                            print(f"     • Emails para verificar: {len(breaches['common_emails_to_check'])}")
                    
                    # Threat Intelligence
                    if 'threat_intel' in osint_data:
                        threat = osint_data['threat_intel']
                        print(f"   ⚠️ Threat Intelligence:")
                        print(f"     • Score de reputação: {threat.get('reputation_score', 'N/A')}")
                        if 'basic_checks' in threat:
                            checks = threat['basic_checks']
                            print(f"     • Indicadores: {len(checks)} encontrados")
                    
                    # Advanced Email Harvesting
                    if 'advanced_emails' in osint_data:
                        emails = osint_data['advanced_emails']
                        print(f"   📧 Email Harvesting:")
                        print(f"     • Total de emails: {emails.get('total_emails', 0)}")
                        if 'common_patterns' in emails:
                            print(f"     • Padrões comuns: {len(emails['common_patterns'])}")
                
                print(f"\n⏱️ Tempo de execução: {result.execution_time:.2f}s")
                
        else:
            print(f"❌ Erro na execução: {result.error}")
            
    except Exception as e:
        print(f"❌ Erro no teste: {str(e)}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("✅ Teste concluído!")

async def test_individual_methods():
    """Testa os métodos OSINT individualmente"""
    
    print("\n🧪 Testando métodos OSINT individuais...")
    
    plugin = ReconnaissancePlugin()
    test_domain = "example.com"
    
    # Teste Social Media
    print(f"\n🔗 Testando Social Media para {test_domain}:")
    social_result = plugin._social_media_reconnaissance(test_domain)
    print(f"   Resultado: {len(social_result)} plataformas verificadas")
    
    # Teste Data Breaches
    print(f"\n🔓 Testando Data Breaches para {test_domain}:")
    breach_result = plugin._check_data_breaches(test_domain)
    if 'common_emails_to_check' in breach_result:
        print(f"   Emails para verificar: {len(breach_result['common_emails_to_check'])}")
    
    # Teste Threat Intelligence
    print(f"\n⚠️ Testando Threat Intelligence para {test_domain}:")
    threat_result = plugin._threat_intelligence_lookup(test_domain, "93.184.216.34")
    print(f"   Score de reputação: {threat_result.get('reputation_score', 'N/A')}")
    
    # Teste Advanced Email Harvesting
    print(f"\n📧 Testando Advanced Email Harvesting para {test_domain}:")
    email_result = plugin._advanced_email_harvesting(test_domain)
    print(f"   Total de emails: {email_result.get('total_emails', 0)}")

if __name__ == "__main__":
    print("🚀 Iniciando teste do ReconnaissancePlugin expandido...")
    
    asyncio.run(test_osint_expansion())
    asyncio.run(test_individual_methods())
    
    print("\n🎉 Todos os testes concluídos!")
