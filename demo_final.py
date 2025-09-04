#!/usr/bin/env python3
"""
Demonstração final simples do WebCrawlerPlugin
Mostra uso direto do plugin para análise web
"""

import sys
from pathlib import Path
import json
import time

# Adicionar diretório raiz ao path
sys.path.append(str(Path(__file__).parent))

from plugins.web_crawler_plugin import WebCrawlerPlugin

def demo_web_analysis():
    """Demonstração de análise web completa"""
    print("🕷️  DEMONSTRAÇÃO FINAL - WebCrawlerPlugin")
    print("="*55)
    print("📋 Funcionalidades demonstradas:")
    print("   • Navegação automatizada com Selenium")
    print("   • Análise completa de formulários")
    print("   • Detecção de tecnologias/frameworks")
    print("   • Extração de parâmetros e endpoints")
    print("   • Análise de cookies e segurança")
    print("   • Tentativas de login automático")
    
    # Configurar plugin
    plugin = WebCrawlerPlugin()
    
    # Configurações para demo
    plugin.config.update({
        'headless': True,              # Sem interface gráfica
        'max_pages': 3,               # Limitar páginas para demo
        'max_depth': 2,               # Profundidade reduzida
        'timeout': 20,                # Timeout razoável
        'attempt_login': True,        # Demonstrar login automático
        'analyze_forms': True,        # Analisar formulários
        'detect_frameworks': True,    # Detectar tecnologias
        'extract_apis': True,         # Extrair APIs
        'analyze_cookies': True,      # Analisar cookies
        'check_security_headers': True, # Verificar segurança
        'screenshot_on_error': False  # Sem screenshots para demo
    })
    
    # Sites para demonstração
    demo_sites = [
        {
            'name': 'Site com Formulários',
            'url': 'https://httpbin.org/forms/post',
            'description': 'Demonstra análise de formulários complexos'
        },
        {
            'name': 'Site Principal HTTPBin',
            'url': 'https://httpbin.org',
            'description': 'Demonstra navegação e detecção de tecnologias'
        }
    ]
    
    all_results = {}
    
    for i, site in enumerate(demo_sites, 1):
        print(f"\n📍 TESTE {i}/{len(demo_sites)}: {site['name']}")
        print(f"🌐 URL: {site['url']}")
        print(f"📝 {site['description']}")
        print("-" * 50)
        
        try:
            start_time = time.time()
            
            # Executar análise
            print("⏳ Analisando...")
            result = plugin.execute(
                target=site['url'],
                context={'demo_mode': True}
            )
            
            execution_time = time.time() - start_time
            
            if result.success:
                data = result.data.get('web_crawling', {})
                stats = data.get('statistics', {})
                
                # Resumo dos resultados
                print(f"✅ Análise concluída em {execution_time:.1f}s")
                print(f"\n📊 Resultados:")
                print(f"   📄 Páginas navegadas: {stats.get('total_pages', 0)}")
                print(f"   📝 Formulários: {stats.get('total_forms', 0)}")
                print(f"   🔧 Tecnologias: {stats.get('frameworks_detected', 0)}")
                print(f"   📋 Parâmetros: {stats.get('total_parameters', 0)}")
                print(f"   🔗 Endpoints: {stats.get('total_endpoints', 0)}")
                
                # Detalhes interessantes
                frameworks = data.get('frameworks_detected', [])
                if frameworks:
                    print(f"\n🛠️  Tecnologias detectadas:")
                    for fw in frameworks:
                        print(f"      • {fw}")
                
                forms = data.get('forms_found', [])
                if forms:
                    print(f"\n📝 Formulários encontrados:")
                    for j, form in enumerate(forms):
                        login_status = "🔐 Login" if form['is_login_form'] else "📋 Formulário"
                        print(f"      {j+1}. {login_status} - {form['method'].upper()} {form['action']}")
                        print(f"         Campos: {len(form['inputs'])}")
                
                login_attempts = data.get('login_attempts', [])
                if login_attempts:
                    print(f"\n🔐 Tentativas de login ({len(login_attempts)}):")
                    for attempt in login_attempts:
                        status = "✅" if attempt.get('success') else "❌"
                        print(f"      {status} {attempt.get('username', 'N/A')}")
                
                # Armazenar resultado
                all_results[site['name']] = {
                    'url': site['url'],
                    'success': True,
                    'execution_time': execution_time,
                    'stats': stats,
                    'frameworks': frameworks,
                    'forms_count': len(forms),
                    'login_attempts': len(login_attempts)
                }
                
            else:
                print(f"❌ Falha: {result.error}")
                all_results[site['name']] = {
                    'url': site['url'],
                    'success': False,
                    'error': result.error
                }
            
        except KeyboardInterrupt:
            print("\n⏹️  Demo interrompida")
            break
        except Exception as e:
            print(f"❌ Erro: {e}")
            all_results[site['name']] = {
                'url': site['url'],
                'success': False,
                'error': str(e)
            }
        
        if i < len(demo_sites):
            print("\n⏸️  Pausa...")
            time.sleep(2)
    
    # Resumo final
    print(f"\n{'='*55}")
    print("📈 RESUMO FINAL DA DEMONSTRAÇÃO")
    print(f"{'='*55}")
    
    successful_tests = sum(1 for r in all_results.values() if r.get('success'))
    total_tests = len(all_results)
    
    print(f"🎯 Testes executados: {total_tests}")
    print(f"✅ Sucessos: {successful_tests}")
    print(f"❌ Falhas: {total_tests - successful_tests}")
    print(f"📊 Taxa de sucesso: {successful_tests/total_tests:.1%}")
    
    if successful_tests > 0:
        total_pages = sum(r.get('stats', {}).get('total_pages', 0) for r in all_results.values() if r.get('success'))
        total_forms = sum(r.get('forms_count', 0) for r in all_results.values() if r.get('success'))
        total_frameworks = sum(len(r.get('frameworks', [])) for r in all_results.values() if r.get('success'))
        
        print(f"\n📋 Totais agregados:")
        print(f"   📄 Páginas analisadas: {total_pages}")
        print(f"   📝 Formulários encontrados: {total_forms}")
        print(f"   🛠️  Tecnologias detectadas: {total_frameworks}")
    
    # Salvar resultados
    output_file = f"data/demo_final_{int(time.time())}.json"
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"\n💾 Resultados salvos em: {output_file}")
    
    print(f"\n🎉 Demonstração concluída!")
    print("🔧 Para usar o plugin:")
    print("   • python main.py <url>  # Uso integrado")
    print("   • python manage_plugins.py config WebCrawlerPlugin  # Configurar")
    print("   • Consulte docs/WebCrawlerPlugin.md para detalhes")

def main():
    """Função principal da demo"""
    try:
        demo_web_analysis()
    except KeyboardInterrupt:
        print("\n👋 Demo cancelada")
    except Exception as e:
        print(f"\n💥 Erro: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
