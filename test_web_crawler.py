#!/usr/bin/env python3
"""
Script de teste para o WebCrawlerPlugin
Testa navegação web, análise de formulários e login automático
"""

import sys
import asyncio
from pathlib import Path

# Adicionar diretório raiz ao path
sys.path.append(str(Path(__file__).parent))

from core.config import ConfigManager
from core.plugin_manager import PluginManager
from utils.logger import setup_logger
import json
import time

def print_separator(title: str = ""):
    """Imprime separador visual"""
    if title:
        print(f"\n{'='*20} {title} {'='*20}")
    else:
        print("="*60)

def print_results(results: dict, section_title: str):
    """Imprime resultados de forma organizada"""
    print_separator(section_title)
    
    if results.get('success'):
        data = results.get('data', {})
        web_crawling = data.get('web_crawling', {})
        
        # Estatísticas gerais
        stats = web_crawling.get('statistics', {})
        print(f"📊 Estatísticas:")
        print(f"   • Páginas navegadas: {stats.get('total_pages', 0)}")
        print(f"   • Formulários encontrados: {stats.get('total_forms', 0)}")
        print(f"   • Parâmetros descobertos: {stats.get('total_parameters', 0)}")
        print(f"   • Endpoints encontrados: {stats.get('total_endpoints', 0)}")
        print(f"   • Tentativas de login: {stats.get('login_attempts', 0)}")
        print(f"   • Frameworks detectados: {stats.get('frameworks_detected', 0)}")
        print(f"   • Profundidade máxima: {stats.get('max_depth_reached', 0)}")
        print(f"   • Erros encontrados: {stats.get('errors_encountered', 0)}")
        
        # Formulários detalhados
        forms = web_crawling.get('forms_found', [])
        if forms:
            print(f"\n📝 Formulários Analisados ({len(forms)}):")
            for i, form in enumerate(forms):
                print(f"   {i+1}. URL: {form['url']}")
                print(f"      • Método: {form['method'].upper()}")
                print(f"      • Action: {form['action']}")
                print(f"      • É login?: {'✅' if form['is_login_form'] else '❌'}")
                print(f"      • Inputs: {len(form['inputs'])}")
                if form['csrf_tokens']:
                    print(f"      • CSRF tokens: {len(form['csrf_tokens'])}")
        
        # Tentativas de login
        login_attempts = web_crawling.get('login_attempts', [])
        if login_attempts:
            print(f"\n🔐 Tentativas de Login ({len(login_attempts)}):")
            for attempt in login_attempts:
                status = "✅ SUCESSO" if attempt.get('success') else "❌ FALHOU"
                print(f"   • {attempt['username']}:{attempt.get('password', '')} - {status}")
                if attempt.get('final_url'):
                    print(f"     URL final: {attempt['final_url']}")
        
        # Frameworks detectados
        frameworks = web_crawling.get('frameworks_detected', [])
        if frameworks:
            print(f"\n🛠️  Tecnologias Detectadas:")
            for framework in frameworks:
                print(f"   • {framework}")
        
        # APIs descobertas
        apis = web_crawling.get('apis_discovered', [])
        if apis:
            print(f"\n🔗 APIs Descobertas ({len(apis)}):")
            for api in apis[:10]:  # Mostrar apenas as primeiras 10
                print(f"   • {api['endpoint']}")
        
        # Análise de cookies
        cookies_analysis = web_crawling.get('cookies_analysis', {})
        if cookies_analysis:
            print(f"\n🍪 Análise de Cookies:")
            print(f"   • Total: {cookies_analysis.get('total_cookies', 0)}")
            print(f"   • Sessão: {cookies_analysis.get('session_cookies', 0)}")
            print(f"   • Persistentes: {cookies_analysis.get('persistent_cookies', 0)}")
            print(f"   • Seguros: {cookies_analysis.get('secure_cookies', 0)}")
            print(f"   • HttpOnly: {cookies_analysis.get('httponly_cookies', 0)}")
        
        # Headers de segurança
        security_headers = web_crawling.get('security_headers', {})
        if security_headers:
            print(f"\n🔒 Headers de Segurança:")
            headers_found = security_headers.get('headers_found', {})
            missing_headers = security_headers.get('missing_headers', [])
            score = security_headers.get('security_score', 0)
            
            print(f"   • Score de segurança: {score:.2%}")
            print(f"   • Headers presentes: {len(headers_found)}")
            print(f"   • Headers ausentes: {len(missing_headers)}")
        
        # Parâmetros descobertos
        params = web_crawling.get('parameters_discovered', {})
        if params:
            print(f"\n📋 Parâmetros Descobertos:")
            for param_type, param_list in params.items():
                if param_list:
                    print(f"   • {param_type}: {len(param_list)} parâmetros")
                    if len(param_list) <= 10:
                        print(f"     {', '.join(param_list)}")
                    else:
                        print(f"     {', '.join(param_list[:10])}... (+{len(param_list)-10} mais)")
        
        # Erros encontrados
        errors = web_crawling.get('errors', [])
        if errors:
            print(f"\n⚠️  Erros Encontrados ({len(errors)}):")
            for error in errors[:5]:  # Mostrar apenas os primeiros 5
                print(f"   • {error['url']}: {error['error']}")
        
        print(f"\n✅ Navegação web concluída com sucesso!")
        print(f"⏱️  Tempo de execução: {results.get('execution_time', 0):.2f}s")
        
    else:
        print(f"❌ Erro: {results.get('error', 'Erro desconhecido')}")

async def test_web_crawler():
    """Testa o plugin WebCrawler"""
    print("🕷️  Testando WebCrawlerPlugin")
    
    # Configurar logger
    logger = setup_logger()
    
    # Carregar configuração
    config = ConfigManager()
    config.load_config()
    
    # Inicializar plugin manager
    plugin_manager = PluginManager(config=config)
    plugin_manager.load_plugins()
    
    # Obter plugin
    plugin = plugin_manager.get_plugin('WebCrawlerPlugin')
    if not plugin:
        print("❌ Plugin WebCrawlerPlugin não encontrado!")
        return
    
    print(f"✅ Plugin carregado: {plugin.name} v{plugin.version}")
    print(f"📝 Descrição: {plugin.description}")
    
    # Testar com diferentes alvos
    test_targets = [
        {
            'name': 'Site de teste com formulários',
            'url': 'https://httpbin.org/forms/post',
            'description': 'Site simples com formulário de teste'
        },
        {
            'name': 'Site WordPress (testphp.vulnweb.com)',
            'url': 'http://testphp.vulnweb.com',
            'description': 'Site de teste com vulnerabilidades conhecidas'
        }
    ]
    
    for target_info in test_targets:
        print_separator(f"Testando: {target_info['name']}")
        print(f"🎯 URL: {target_info['url']}")
        print(f"📖 Descrição: {target_info['description']}")
        
        try:
            # Executar plugin
            start_time = time.time()
            result = plugin.execute(
                target=target_info['url'],
                context={
                    'test_mode': True,
                    'max_pages': 10,  # Limitar para teste
                    'max_depth': 2
                }
            )
            
            # Mostrar resultados
            print_results(result.to_dict(), f"Resultados - {target_info['name']}")
            
            # Salvar resultados detalhados
            output_file = f"data/web_crawler_test_{target_info['name'].lower().replace(' ', '_')}_{int(time.time())}.json"
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, indent=2, ensure_ascii=False, default=str)
            
            print(f"💾 Resultados salvos em: {output_file}")
            
        except KeyboardInterrupt:
            print("\n⏹️  Teste interrompido pelo usuário")
            break
        except Exception as e:
            print(f"❌ Erro durante o teste: {e}")
            import traceback
            traceback.print_exc()
        
        print("\n" + "="*60)
        time.sleep(2)  # Pausa entre testes

def main():
    """Função principal"""
    print("🚀 Iniciando testes do WebCrawlerPlugin")
    print("⚠️  Este teste usará Selenium e pode levar alguns minutos")
    print("📱 Certifique-se de ter o Chrome/Chromium instalado")
    
    try:
        asyncio.run(test_web_crawler())
    except KeyboardInterrupt:
        print("\n👋 Teste cancelado pelo usuário")
    except Exception as e:
        print(f"\n💥 Erro fatal: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
