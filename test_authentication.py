#!/usr/bin/env python3
"""
Teste do WebCrawlerPlugin com autenticação por cookies/sessão
Demonstra como acessar páginas autenticadas usando cookies existentes
"""

import sys
from pathlib import Path
import json
import time

# Adicionar diretório raiz ao path
sys.path.append(str(Path(__file__).parent))

from plugins.web_crawler_plugin import WebCrawlerPlugin

def test_cookie_authentication():
    """Testa autenticação usando cookies"""
    print("🍪 Testando WebCrawlerPlugin com Autenticação por Cookies")
    print("="*60)
    
    # Configurar plugin
    plugin = WebCrawlerPlugin()
    plugin.config.update({
        'headless': True,
        'max_pages': 3,
        'max_depth': 2,
        'timeout': 20,
        'attempt_login': False,  # Desabilitar login automático (já temos cookies)
        'analyze_forms': True,
        'detect_frameworks': True,
        'screenshot_on_error': False
    })
    
    # Exemplo 1: Cookies como lista de dicionários
    print("\n📋 TESTE 1: Cookies como lista de dicionários")
    print("-" * 50)
    
    custom_cookies = [
        {
            "name": "session_id",
            "value": "abc123def456",
            "domain": "httpbin.org",
            "path": "/",
            "secure": False,
            "httpOnly": True
        },
        {
            "name": "user_preference",
            "value": "dark_mode",
            "domain": "httpbin.org",
            "path": "/"
        },
        {
            "name": "csrf_token",
            "value": "xyz789token",
            "domain": "httpbin.org"
        }
    ]
    
    try:
        result = plugin.execute(
            target="https://httpbin.org/cookies",
            context={'test_mode': True},
            cookies=custom_cookies
        )
        
        if result.success:
            data = result.data.get('web_crawling', {})
            auth_details = data.get('authentication_details', {})
            
            print(f"✅ Teste 1 concluído com sucesso!")
            print(f"   🍪 Cookies aplicados: {auth_details.get('custom_cookies_count', 0)}")
            print(f"   📄 Páginas navegadas: {data.get('statistics', {}).get('total_pages', 0)}")
            print(f"   🔧 Tecnologias detectadas: {len(data.get('frameworks_detected', []))}")
            
            # Verificar se cookies foram aplicados corretamente
            pages = data.get('pages_crawled', [])
            if pages:
                page_cookies = pages[0].get('cookies', [])
                print(f"   🔍 Cookies encontrados na página: {len(page_cookies)}")
                for cookie in page_cookies[:3]:  # Mostrar primeiros 3
                    print(f"      • {cookie.get('name', 'N/A')}: {cookie.get('value', 'N/A')[:20]}...")
        else:
            print(f"❌ Teste 1 falhou: {result.error}")
    
    except Exception as e:
        print(f"❌ Erro no Teste 1: {e}")
    
    print("\n⏸️  Pausa entre testes...")
    time.sleep(3)
    
    # Exemplo 2: Cookie string (formato tradicional)
    print("\n📄 TESTE 2: Cookie string (formato tradicional)")
    print("-" * 50)
    
    # Exemplo baseado no cookie fornecido pelo usuário
    cookie_string = "ECIDADEWINDOWMAIN=923c3bf1505e3e05a6213d23d413dec3f1aac8ed; session_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9; _csrf=MTc1Njk1NjI3MnxJbmRzVVd4WE4yOVVOWFpVWkhoSlZYQk1LMUpPT0d0MVUxUTlWbnB2YlVoalVGUXdWVGhMVTBSc1FVMDlJZ289; _pk_id=d8f684d5466f394d; preferences=dark_mode; accept_cookies=yes"
    
    try:
        result = plugin.execute(
            target="https://httpbin.org/cookies",
            context={'test_mode': True},
            cookie_string=cookie_string
        )
        
        if result.success:
            data = result.data.get('web_crawling', {})
            auth_details = data.get('authentication_details', {})
            
            print(f"✅ Teste 2 concluído com sucesso!")
            print(f"   📄 Cookie string fornecida: {'Sim' if auth_details.get('cookie_string_provided') else 'Não'}")
            print(f"   📄 Páginas navegadas: {data.get('statistics', {}).get('total_pages', 0)}")
            
            # Mostrar cookies aplicados
            pages = data.get('pages_crawled', [])
            if pages:
                page_cookies = pages[0].get('cookies', [])
                print(f"   🔍 Total de cookies na página: {len(page_cookies)}")
                
                # Procurar pelos cookies que aplicamos
                applied_cookies = []
                for cookie in page_cookies:
                    cookie_name = cookie.get('name', '')
                    if any(name in cookie_name for name in ['ECIDADE', 'session', 'csrf', '_pk']):
                        applied_cookies.append(cookie_name)
                
                if applied_cookies:
                    print(f"   ✅ Cookies aplicados encontrados: {', '.join(applied_cookies[:3])}")
                    if len(applied_cookies) > 3:
                        print(f"      ... e mais {len(applied_cookies)-3}")
        else:
            print(f"❌ Teste 2 falhou: {result.error}")
    
    except Exception as e:
        print(f"❌ Erro no Teste 2: {e}")
    
    print("\n⏸️  Pausa entre testes...")
    time.sleep(3)
    
    # Exemplo 3: Combinação de cookies + dados de sessão
    print("\n🔑 TESTE 3: Cookies + dados de sessão localStorage")
    print("-" * 50)
    
    session_data = {
        "user_id": "12345",
        "user_role": "admin",
        "theme": "dark",
        "language": "pt-br",
        "last_activity": str(int(time.time()))
    }
    
    simple_cookies = [
        {
            "name": "auth_token",
            "value": "Bearer_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "domain": "httpbin.org"
        }
    ]
    
    try:
        result = plugin.execute(
            target="https://httpbin.org",
            context={'test_mode': True},
            cookies=simple_cookies,
            session=session_data
        )
        
        if result.success:
            data = result.data.get('web_crawling', {})
            auth_details = data.get('authentication_details', {})
            
            print(f"✅ Teste 3 concluído com sucesso!")
            print(f"   🍪 Cookies: {auth_details.get('custom_cookies_count', 0)}")
            print(f"   🔑 Dados de sessão: {'Sim' if auth_details.get('session_data_provided') else 'Não'}")
            print(f"   📄 Páginas navegadas: {data.get('statistics', {}).get('total_pages', 0)}")
            
            # Verificar localStorage
            pages = data.get('pages_crawled', [])
            if pages:
                local_storage = pages[0].get('local_storage', {})
                if local_storage:
                    print(f"   💾 Dados no localStorage: {len(local_storage)} itens")
                    for key in list(local_storage.keys())[:3]:
                        print(f"      • {key}: {local_storage[key][:30]}...")
        else:
            print(f"❌ Teste 3 falhou: {result.error}")
    
    except Exception as e:
        print(f"❌ Erro no Teste 3: {e}")

def test_portainer_example():
    """Teste com exemplo real do Portainer (formato do usuário)"""
    print("\n🐳 TESTE ESPECIAL: Exemplo Portainer (formato do usuário)")
    print("="*60)
    
    plugin = WebCrawlerPlugin()
    plugin.config.update({
        'headless': True,
        'max_pages': 2,
        'timeout': 15,
        'attempt_login': False
    })
    
    # Cookies do exemplo fornecido pelo usuário
    portainer_cookie_string = "ECIDADEWINDOWMAIN=923c3bf1505e3e05a6213d23d413dec3f1aac8ed; portainer_api_key=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOjEsInNjb3BlIjoiZGVmYXVsdCIsImZvcmNlQ2hhbmdlUGFzc3dvcmQiOmZhbHNlLCJleHAiOjE3NTY5ODUwNzIsImp0aSI6ImViZTE3NmUyLWZjN2MtNGY4NS1hMDMzLWE0NTZmOTkxODFjOCIsImlhdCI6MTc1Njk1NjI3Mn0.JECPLL8rgEepbfuiVcDnlWphFwzm1c2q6ueQosTXPzI; _gorilla_csrf=MTc1Njk1NjI3MnxJbmRzVVd4WE4yOVVOWFpVWkhoSlZYQk1LMUpPT0d0MVUxUTVWbnB2YlVoalVGUXdWVGhMVTBSc1FVMDlJZ289fGt5YjM7VMTNWaW5V7c4NWLLLM3rPUGMXxPtxBaQAi0O; _pk_id.1.1fff=d8f684d5466f394d.1756956273.; _pk_ses.1.1fff=1; ecidade_skin=default; aceita_cookie=sim"
    
    print(f"🎯 Simulando acesso autenticado ao sistema...")
    print(f"🍪 Usando cookies do Portainer/eCidade fornecidos")
    
    try:
        # Para demonstração, vamos usar httpbin que aceita qualquer cookie
        result = plugin.execute(
            target="https://httpbin.org/cookies",
            context={'portainer_test': True},
            cookie_string=portainer_cookie_string
        )
        
        if result.success:
            data = result.data.get('web_crawling', {})
            
            print(f"✅ Simulação bem-sucedida!")
            print(f"   🔐 Autenticação aplicada: {'Sim' if data.get('authentication_used') else 'Não'}")
            
            # Mostrar cookies aplicados
            pages = data.get('pages_crawled', [])
            if pages:
                page_cookies = pages[0].get('cookies', [])
                print(f"   🍪 Cookies aplicados: {len(page_cookies)}")
                
                # Procurar cookies específicos do Portainer
                portainer_cookies = []
                for cookie in page_cookies:
                    name = cookie.get('name', '')
                    if any(key in name for key in ['portainer', 'ECIDADE', 'gorilla', 'ecidade']):
                        portainer_cookies.append(name)
                
                if portainer_cookies:
                    print(f"   🐳 Cookies do sistema encontrados:")
                    for cookie_name in portainer_cookies:
                        print(f"      • {cookie_name}")
                
                print(f"\n   💡 Em um ambiente real, este plugin poderia:")
                print(f"      • Navegar nas páginas autenticadas do Portainer")
                print(f"      • Analisar formulários administrativos")
                print(f"      • Mapear funcionalidades disponíveis")
                print(f"      • Extrair informações de configuração")
        else:
            print(f"❌ Simulação falhou: {result.error}")
    
    except Exception as e:
        print(f"❌ Erro na simulação: {e}")

def main():
    """Função principal"""
    print("🚀 Teste de Autenticação do WebCrawlerPlugin")
    print("Este teste demonstra como usar o plugin com cookies/sessões existentes")
    print("para acessar páginas autenticadas.\n")
    
    try:
        test_cookie_authentication()
        test_portainer_example()
        
        print(f"\n{'='*60}")
        print("✅ Todos os testes de autenticação concluídos!")
        print("\n📖 Como usar em produção:")
        print("   1. Obtenha cookies de uma sessão autenticada")
        print("   2. Formate como lista de dicts ou string")
        print("   3. Passe como parâmetro cookies= ou cookie_string=")
        print("   4. O plugin navegará como usuário autenticado")
        print("\n💡 Exemplo de uso:")
        print('   plugin.execute("https://app.com", {}, cookie_string="session=abc123")')
        
    except KeyboardInterrupt:
        print("\n👋 Teste cancelado")
    except Exception as e:
        print(f"\n💥 Erro: {e}")

if __name__ == "__main__":
    main()
