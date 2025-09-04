#!/usr/bin/env python3
"""
Demonstração integrada do WebCrawlerPlugin com o sistema VarreduraIA
Mostra como o plugin funciona junto com outros plugins
"""

import sys
import asyncio
from pathlib import Path

# Adicionar diretório raiz ao path
sys.path.append(str(Path(__file__).parent))

from core.config import Config
from core.orchestrator import Orchestrator
from utils.logger import setup_logger
import json
import time

async def demo_integrated_scan():
    """Demonstra varredura integrada com WebCrawlerPlugin"""
    print("🚀 Demonstração Integrada - VarreduraIA + WebCrawlerPlugin")
    print("="*65)
    
    # Configurar logger
    logger = setup_logger()
    
    # Carregar configuração
    config = Config()
    # config.load_config() # Já carrega automaticamente
    
    # Configurar para usar apenas alguns plugins relevantes
    # (para demonstração mais rápida)
    demo_plugins = {
        'DNSResolverPlugin': True,
        'WebCrawlerPlugin': True,
        'TechnologyDetectorPlugin': True,
        'WebScannerPlugin': False,  # Desabilitar para evitar sobreposição
        'PortScannerPlugin': False,  # Desabilitar para demo mais rápida
        'NmapScannerPlugin': False,
        'NucleiScannerPlugin': False,
        'DirectoryScannerPlugin': False,
        'WebVulnScannerPlugin': False,
        'ReconnaissancePlugin': False,
        'RustscanPlugin': False,
        'SubdomainEnumeratorPlugin': False,
        'SQLMapPlugin': False
    }
    
    # Atualizar configuração temporariamente
    original_config = config.get('plugins.enabled', {}).copy()
    config._config['plugins']['enabled'].update(demo_plugins)
    
    # Configurar WebCrawlerPlugin para demo
    config._config['plugins']['config']['WebCrawlerPlugin'] = {
        'headless': True,
        'timeout': 20,
        'max_pages': 3,
        'max_depth': 2,
        'attempt_login': True,
        'analyze_forms': True,
        'detect_frameworks': True,
        'screenshot_on_error': False  # Para demo
    }
    
    # Inicializar orquestrador
    orchestrator = Orchestrator(config=config)
    
    # Alvo de teste
    target = "https://httpbin.org"
    
    print(f"🎯 Alvo: {target}")
    print(f"📋 Plugins habilitados para demo:")
    for plugin, enabled in demo_plugins.items():
        if enabled:
            print(f"   ✅ {plugin}")
    
    print(f"\n⏳ Iniciando varredura integrada...")
    
    try:
        start_time = time.time()
        
        # Executar varredura
        results = await orchestrator.execute_scan(target)
        
        execution_time = time.time() - start_time
        
        print(f"\n📊 Varredura concluída em {execution_time:.2f}s")
        
        # Analisar resultados por plugin
        for plugin_name, result in results.items():
            print(f"\n{'='*50}")
            print(f"🔌 Plugin: {plugin_name}")
            
            if result.get('success'):
                data = result.get('data', {})
                
                if plugin_name == 'WebCrawlerPlugin':
                    # Análise detalhada do WebCrawlerPlugin
                    web_data = data.get('web_crawling', {})
                    stats = web_data.get('statistics', {})
                    
                    print(f"   📄 Páginas navegadas: {stats.get('total_pages', 0)}")
                    print(f"   📝 Formulários encontrados: {stats.get('total_forms', 0)}")
                    print(f"   🔐 Tentativas de login: {stats.get('login_attempts', 0)}")
                    print(f"   🛠️  Frameworks detectados: {stats.get('frameworks_detected', 0)}")
                    
                    # Mostrar frameworks encontrados
                    frameworks = web_data.get('frameworks_detected', [])
                    if frameworks:
                        print(f"   Tecnologias: {', '.join(frameworks)}")
                    
                    # Mostrar formulários
                    forms = web_data.get('forms_found', [])
                    if forms:
                        print(f"   Formulários:")
                        for i, form in enumerate(forms):
                            print(f"     {i+1}. {form['method'].upper()} {form['action']} " +
                                  f"({'Login' if form['is_login_form'] else 'Outro'})")
                
                elif plugin_name == 'DNSResolverPlugin':
                    # Análise do DNS
                    ips = data.get('ips', [])
                    if ips:
                        print(f"   🌐 IPs resolvidos: {len(ips)}")
                        for ip in ips[:3]:
                            print(f"     • {ip}")
                        if len(ips) > 3:
                            print(f"     ... e mais {len(ips)-3}")
                
                elif plugin_name == 'TechnologyDetectorPlugin':
                    # Análise de tecnologias
                    techs = data.get('technologies', [])
                    if techs:
                        print(f"   🔧 Tecnologias detectadas: {len(techs)}")
                        for tech in techs[:5]:
                            print(f"     • {tech}")
                
                print(f"   ✅ Sucesso - Tempo: {result.get('execution_time', 0):.2f}s")
                
            else:
                error = result.get('error', 'Erro desconhecido')
                print(f"   ❌ Falha: {error}")
        
        # Salvar resultados completos
        output_file = f"data/demo_integrated_{int(time.time())}.json"
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n💾 Resultados completos salvos em: {output_file}")
        
        # Mostrar resumo final
        print(f"\n📈 Resumo Final:")
        successful_plugins = sum(1 for r in results.values() if r.get('success'))
        total_plugins = len(results)
        print(f"   • Plugins executados: {total_plugins}")
        print(f"   • Sucessos: {successful_plugins}")
        print(f"   • Falhas: {total_plugins - successful_plugins}")
        print(f"   • Taxa de sucesso: {successful_plugins/total_plugins:.1%}")
        
    except Exception as e:
        print(f"\n❌ Erro durante a varredura: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Restaurar configuração original
        config._config['plugins']['enabled'] = original_config

def main():
    """Função principal"""
    print("🌟 Demonstração do WebCrawlerPlugin Integrado ao VarreduraIA")
    print("Esta demo mostra como o WebCrawlerPlugin funciona junto com outros plugins")
    print("para fornecer uma análise completa de aplicações web.\n")
    
    try:
        asyncio.run(demo_integrated_scan())
        print("\n✅ Demonstração concluída com sucesso!")
    except KeyboardInterrupt:
        print("\n👋 Demo cancelada pelo usuário")
    except Exception as e:
        print(f"\n💥 Erro na demonstração: {e}")

if __name__ == "__main__":
    main()
