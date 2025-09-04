#!/usr/bin/env python3
"""
Teste avançado do WebCrawlerPlugin com análise de formulários
Testa com sites que têm formulários de login reais
"""

import sys
from pathlib import Path
import json
import time

# Adicionar diretório raiz ao path
sys.path.append(str(Path(__file__).parent))

from plugins.web_crawler_plugin import WebCrawlerPlugin

def test_form_analysis():
    """Teste focado em análise de formulários"""
    print("📝 Testando análise avançada de formulários...")
    
    # Configurar plugin
    plugin = WebCrawlerPlugin()
    plugin.config.update({
        'headless': True,
        'max_pages': 5,
        'max_depth': 2,
        'timeout': 20,
        'attempt_login': True,
        'common_credentials': True,
        'analyze_forms': True,
        'extract_apis': True
    })
    
    # Sites com formulários interessantes para teste
    test_sites = [
        {
            'name': 'HTTPBin Forms',
            'url': 'https://httpbin.org/forms/post',
            'description': 'Site com formulário POST simples'
        },
        {
            'name': 'TestPhp VulnWeb',
            'url': 'http://testphp.vulnweb.com/login.php',
            'description': 'Site de teste com formulário de login'
        }
    ]
    
    for site in test_sites:
        print(f"\n{'='*60}")
        print(f"🎯 Testando: {site['name']}")
        print(f"🌐 URL: {site['url']}")
        print(f"📋 Descrição: {site['description']}")
        
        try:
            start_time = time.time()
            
            # Executar plugin
            result = plugin.execute(
                target=site['url'],
                context={'test_mode': True}
            )
            
            execution_time = time.time() - start_time
            
            if result.success:
                data = result.data.get('web_crawling', {})
                stats = data.get('statistics', {})
                
                print(f"\n📊 Estatísticas:")
                print(f"   ✅ Sucesso em {execution_time:.2f}s")
                print(f"   📄 Páginas: {stats.get('total_pages', 0)}")
                print(f"   📝 Formulários: {stats.get('total_forms', 0)}")
                print(f"   🔐 Tentativas de login: {stats.get('login_attempts', 0)}")
                print(f"   🛠️  Frameworks: {stats.get('frameworks_detected', 0)}")
                print(f"   🔗 Endpoints: {stats.get('total_endpoints', 0)}")
                
                # Análise detalhada de formulários
                forms = data.get('forms_found', [])
                if forms:
                    print(f"\n📝 Formulários Encontrados ({len(forms)}):")
                    for i, form in enumerate(forms):
                        print(f"\n   📋 Formulário {i+1}:")
                        print(f"      URL: {form['url']}")
                        print(f"      Método: {form['method'].upper()}")
                        print(f"      Action: {form['action']}")
                        print(f"      É login?: {'✅' if form['is_login_form'] else '❌'}")
                        print(f"      Inputs: {len(form['inputs'])}")
                        
                        if form['inputs']:
                            print(f"      Campos encontrados:")
                            for inp in form['inputs']:
                                field_type = inp.get('type', 'unknown')
                                field_name = inp.get('name', 'sem nome')
                                field_placeholder = inp.get('placeholder', '')
                                print(f"        • {field_type}: {field_name} {f'({field_placeholder})' if field_placeholder else ''}")
                        
                        if form['csrf_tokens']:
                            print(f"      🔒 CSRF Tokens: {len(form['csrf_tokens'])}")
                            for token in form['csrf_tokens']:
                                print(f"        • {token.get('name', 'unnamed')}: {token.get('value', 'no value')[:20]}...")
                
                # Tentativas de login
                login_attempts = data.get('login_attempts', [])
                if login_attempts:
                    print(f"\n🔐 Tentativas de Login ({len(login_attempts)}):")
                    for attempt in login_attempts:
                        status = "✅ SUCESSO" if attempt.get('success') else "❌ FALHOU"
                        username = attempt.get('username', 'N/A')
                        print(f"   • {username}: {status}")
                        
                        if attempt.get('success'):
                            print(f"     🎯 URL final: {attempt.get('final_url', 'N/A')}")
                            print(f"     🔄 URL mudou: {'Sim' if attempt.get('url_changed') else 'Não'}")
                        
                        if attempt.get('error'):
                            print(f"     ❌ Erro: {attempt['error']}")
                
                # Frameworks detectados
                frameworks = data.get('frameworks_detected', [])
                if frameworks:
                    print(f"\n🛠️  Tecnologias Detectadas:")
                    for framework in frameworks:
                        print(f"   • {framework}")
                
                # Parâmetros descobertos
                params = data.get('parameters_discovered', {})
                if params:
                    print(f"\n📋 Parâmetros Descobertos:")
                    for param_type, param_list in params.items():
                        if param_list:
                            print(f"   • {param_type}: {len(param_list)} parâmetros")
                            if len(param_list) <= 5:
                                for param in param_list:
                                    print(f"     - {param}")
                            else:
                                for param in param_list[:3]:
                                    print(f"     - {param}")
                                print(f"     ... e mais {len(param_list)-3}")
                
                # Salvar resultado
                safe_name = site['name'].lower().replace(' ', '_').replace('/', '_')
                output_file = f"data/form_test_{safe_name}_{int(time.time())}.json"
                Path(output_file).parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(result.to_dict(), f, indent=2, ensure_ascii=False, default=str)
                
                print(f"\n💾 Resultado salvo em: {output_file}")
                
            else:
                print(f"❌ Falha: {result.error}")
        
        except KeyboardInterrupt:
            print("\n⏹️  Teste interrompido")
            break
        except Exception as e:
            print(f"❌ Erro: {e}")
            import traceback
            traceback.print_exc()
        
        print("\n⏸️  Pausa entre testes...")
        time.sleep(3)

def main():
    """Função principal"""
    print("🔍 Teste Avançado do WebCrawlerPlugin - Análise de Formulários")
    print("="*70)
    print("⚠️  Este teste analisará formulários reais e tentará logins automáticos")
    print("🕒 Pode levar alguns minutos para completar")
    
    try:
        test_form_analysis()
        print("\n" + "="*70)
        print("✅ Teste avançado concluído!")
    except KeyboardInterrupt:
        print("\n👋 Teste cancelado pelo usuário")
    except Exception as e:
        print(f"\n💥 Erro fatal: {e}")

if __name__ == "__main__":
    main()
