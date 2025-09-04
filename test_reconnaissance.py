#!/usr/bin/env python3
"""
Teste básico do plugin de reconhecimento
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from plugins.reconnaissance_plugin import ReconnaissancePlugin
import json
import time

def test_reconnaissance_plugin():
    """Testa o plugin de reconhecimento com um domínio de exemplo"""
    
    plugin = ReconnaissancePlugin()
    
    print("🔍 Testando Plugin de Reconhecimento Avançado")
    print("=" * 50)
    
    # Mostrar informações do plugin
    info = plugin.get_info()
    print(f"📋 Plugin: {info['name']}")
    print(f"📝 Descrição: {info['description']}")
    print(f"🏷️ Versão: {info['version']}")
    print(f"📂 Categoria: {info['category']}")
    
    # Verificar dependências
    dependencies = info.get('dependencies', {})
    print("\n🔧 Dependências:")
    for dep, available in dependencies.items():
        status = "✅" if available else "❌"
        print(f"  {status} {dep}")
    
    # Teste com domínio real (usar um domínio seguro para teste)
    test_domain = "google.com"  # Domínio público e seguro para teste
    
    print(f"\n🎯 Testando com domínio: {test_domain}")
    print("⏳ Executando reconhecimento... (pode demorar alguns segundos)")
    
    start_time = time.time()
    
    context = {}  # Contexto vazio para o teste
    result = plugin.execute(test_domain, context)
    
    execution_time = time.time() - start_time
    
    print(f"\n⏱️ Tempo de execução: {execution_time:.2f} segundos")
    print(f"✅ Sucesso: {result.success}")
    
    if result.success:
        data = result.data
        recon = data.get('reconnaissance', {})
        
        print("\n📊 Resultados do Reconhecimento:")
        print(f"  🌐 IPs encontrados: {len(data.get('hosts', []))}")
        print(f"  🔗 Domínios descobertos: {len(data.get('domains', []))}")
        print(f"  📧 Emails encontrados: {len(recon.get('emails', []))}")
        print(f"  🌍 Subdomínios: {len(recon.get('subdomains', []))}")
        
        # Mostrar alguns IPs encontrados
        hosts = data.get('hosts', [])
        if hosts:
            print(f"\n🖥️ IPs encontrados:")
            for ip in hosts[:5]:  # Mostrar apenas os primeiros 5
                print(f"  • {ip}")
            if len(hosts) > 5:
                print(f"  ... e mais {len(hosts) - 5} IPs")
        
        # Mostrar alguns subdomínios encontrados
        subdomains = recon.get('subdomains', [])
        if subdomains:
            print(f"\n🌐 Subdomínios encontrados:")
            for sub in subdomains[:5]:  # Mostrar apenas os primeiros 5
                domain = sub.get('domain', 'N/A')
                method = sub.get('method', 'N/A')
                print(f"  • {domain} (método: {method})")
            if len(subdomains) > 5:
                print(f"  ... e mais {len(subdomains) - 5} subdomínios")
        
        # Informações geográficas
        geo_info = recon.get('geo_info', {})
        if geo_info:
            print(f"\n🌍 Informações Geográficas:")
            for ip, geo in list(geo_info.items())[:3]:  # Mostrar apenas 3
                if 'country' in geo:
                    country = geo.get('country', 'N/A')
                    city = geo.get('city', 'N/A')
                    isp = geo.get('isp', 'N/A')
                    print(f"  • {ip}: {city}, {country} ({isp})")
        
        # Informações ASN
        asn_info = recon.get('asn_info', {})
        if asn_info:
            print(f"\n🏢 Informações ASN:")
            for ip, asn in list(asn_info.items())[:3]:  # Mostrar apenas 3
                asn_num = asn.get('asn', 'N/A')
                asn_desc = asn.get('asn_description', 'N/A')
                if asn_num and asn_num != 'N/A':
                    print(f"  • {ip}: {asn_num} - {asn_desc}")
        
        # Estatísticas
        stats = recon.get('statistics', {})
        if stats:
            print(f"\n📈 Estatísticas:")
            print(f"  • Total de IPs únicos: {stats.get('total_ips', 0)}")
            print(f"  • Total de subdomínios: {stats.get('total_subdomains', 0)}")
            print(f"  • Total de emails: {stats.get('total_emails', 0)}")
            print(f"  • ASNs únicos: {stats.get('unique_asns', 0)}")
            print(f"  • Países únicos: {stats.get('countries', 0)}")
    
    else:
        print(f"❌ Erro: {result.error}")
    
    print("\n" + "=" * 50)
    print("✅ Teste concluído!")

if __name__ == "__main__":
    test_reconnaissance_plugin()
