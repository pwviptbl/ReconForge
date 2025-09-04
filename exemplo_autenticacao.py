#!/usr/bin/env python3
"""
Exemplo prático de uso do WebCrawlerPlugin com autenticação
Demonstra diferentes formas de passar cookies/sessões
"""

import sys
from pathlib import Path

# Adicionar diretório raiz ao path
sys.path.append(str(Path(__file__).parent))

from plugins.web_crawler_plugin import WebCrawlerPlugin

def exemplo_uso_basico():
    """Exemplo básico de uso com cookies"""
    print("📚 EXEMPLO PRÁTICO - Uso do WebCrawlerPlugin com Autenticação")
    print("="*65)
    
    # Criar instância do plugin
    plugin = WebCrawlerPlugin()
    
    # Configurar para exemplo rápido
    plugin.config.update({
        'headless': True,
        'max_pages': 2,
        'timeout': 15,
        'attempt_login': False  # Já temos autenticação
    })
    
    print("🎯 Método 1: Lista de cookies (recomendado para controle fino)")
    print("-" * 50)
    
    cookies_lista = [
        {
            "name": "session_id",
            "value": "abc123session",
            "domain": "httpbin.org",
            "path": "/",
            "secure": False,
            "httpOnly": True
        },
        {
            "name": "user_token",
            "value": "token_xyz789",
            "domain": "httpbin.org"
        }
    ]
    
    print("Código de exemplo:")
    print("""
    cookies = [
        {
            "name": "session_id",
            "value": "abc123session",
            "domain": "httpbin.org",
            "httpOnly": True
        }
    ]
    
    result = plugin.execute(
        target="https://httpbin.org/cookies",
        context={},
        cookies=cookies
    )
    """)
    
    try:
        result = plugin.execute(
            target="https://httpbin.org/cookies",
            context={},
            cookies=cookies_lista
        )
        
        if result.success:
            data = result.data['web_crawling']
            print(f"✅ Sucesso! Cookies aplicados: {data['authentication_details']['custom_cookies_count']}")
        else:
            print(f"❌ Erro: {result.error}")
    except Exception as e:
        print(f"❌ Exceção: {e}")
    
    print(f"\n🎯 Método 2: String de cookies (mais simples)")
    print("-" * 50)
    
    cookie_string = "session=abc123; user_id=456; role=admin; csrf_token=xyz789"
    
    print("Código de exemplo:")
    print("""
    # Copie cookies diretamente do browser (F12 > Application > Cookies)
    cookie_string = "session=abc123; user_id=456; role=admin"
    
    result = plugin.execute(
        target="https://app.com/dashboard",
        context={},
        cookie_string=cookie_string
    )
    """)
    
    try:
        result = plugin.execute(
            target="https://httpbin.org/cookies",
            context={},
            cookie_string=cookie_string
        )
        
        if result.success:
            data = result.data['web_crawling']
            print(f"✅ Sucesso! String de cookies aplicada")
        else:
            print(f"❌ Erro: {result.error}")
    except Exception as e:
        print(f"❌ Exceção: {e}")

def exemplo_portainer():
    """Exemplo específico com os cookies do Portainer/eCidade"""
    print(f"\n🐳 EXEMPLO ESPECÍFICO - Portainer/eCidade")
    print("="*50)
    
    plugin = WebCrawlerPlugin()
    plugin.config.update({'headless': True, 'max_pages': 1, 'timeout': 10})
    
    # Cookies exatos fornecidos pelo usuário
    portainer_cookies = "ECIDADEWINDOWMAIN=923c3bf1505e3e05a6213d23d413dec3f1aac8ed; portainer_api_key=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOjEsInNjb3BlIjoiZGVmYXVsdCIsImZvcmNlQ2hhbmdlUGFzc3dvcmQiOmZhbHNlLCJleHAiOjE3NTY5ODUwNzIsImp0aSI6ImViZTE3NmUyLWZjN2MtNGY4NS1hMDMzLWE0NTZmOTkxODFjOCIsImlhdCI6MTc1Njk1NjI3Mn0.JECPLL8rgEepbfuiVcDnlWphFwzm1c2q6ueQosTXPzI; _gorilla_csrf=MTc1Njk1NjI3MnxJbmRzVVd4WE4yOVVOWFpVWkhoSlZYQk1LMUpPT0d0MVUxUTVWbnB2YlVoalVGUXdWVGhMVTBSc1FVMDlJZ285fGt5YjM7VMTNWaW5V7c4NWLLLM3rPUGMXxPtxBaQAi0O; aceita_cookie=sim"
    
    print("📝 Para usar com seu sistema real:")
    print("""
    # 1. Faça login normalmente no Portainer/eCidade
    # 2. Abra F12 > Application > Cookies
    # 3. Copie todos os cookies
    # 4. Use desta forma:
    
    result = plugin.execute(
        target="https://seu-portainer.com/#!/dashboard",
        context={},
        cookie_string="ECIDADEWINDOWMAIN=...; portainer_api_key=...; ..."
    )
    """)
    
    print(f"✅ Pronto! O plugin irá:")
    print(f"   • Aplicar todos os cookies de autenticação")
    print(f"   • Navegar como usuário autenticado")
    print(f"   • Analisar formulários disponíveis")
    print(f"   • Mapear funcionalidades administrativas")
    print(f"   • Extrair endpoints e parâmetros")

def exemplo_integracao():
    """Exemplo de integração com o sistema principal"""
    print(f"\n🔧 INTEGRAÇÃO COM O SISTEMA PRINCIPAL")
    print("="*50)
    
    print("📝 Via linha de comando (futuro):")
    print("""
    # Opção 1: Arquivo de cookies
    python main.py https://app.com --cookies cookies.json
    
    # Opção 2: String direta
    python main.py https://app.com --cookie-string "session=abc123; token=xyz"
    """)
    
    print("📝 Via código Python:")
    print("""
    from core.orchestrator import Orchestrator
    from core.config import Config
    
    config = Config()
    orchestrator = Orchestrator(config)
    
    # Executar varredura autenticada
    results = await orchestrator.execute_scan(
        "https://app.com/dashboard",
        cookies="session=abc123; user_id=456; role=admin"
    )
    """)
    
    print("📝 Via plugin diretamente:")
    print("""
    from plugins.web_crawler_plugin import WebCrawlerPlugin
    
    plugin = WebCrawlerPlugin()
    result = plugin.execute(
        target="https://app.com",
        context={},
        cookie_string="session=abc123; csrf_token=xyz789"
    )
    
    # Analisar resultados
    if result.success:
        web_data = result.data['web_crawling']
        print(f"Páginas: {web_data['statistics']['total_pages']}")
        print(f"Formulários: {web_data['statistics']['total_forms']}")
        print(f"Autenticado: {web_data['authentication_used']}")
    """)

def main():
    """Função principal"""
    print("🎓 GUIA DE USO - WebCrawlerPlugin com Autenticação")
    print("Este guia mostra como usar cookies/sessões para acessar páginas autenticadas\n")
    
    try:
        exemplo_uso_basico()
        exemplo_portainer()
        exemplo_integracao()
        
        print(f"\n{'='*65}")
        print("🎉 RESUMO DOS RECURSOS DE AUTENTICAÇÃO")
        print("="*65)
        print("✅ Suporte a cookies individuais (lista de dicionários)")
        print("✅ Suporte a string de cookies (formato do browser)")
        print("✅ Suporte a dados de sessão (localStorage)")
        print("✅ Aplicação automática antes da navegação")
        print("✅ Refresh automático para ativar cookies")
        print("✅ Detecção de autenticação nos resultados")
        print("✅ Compatível com qualquer sistema web")
        
        print(f"\n💡 DICAS DE USO:")
        print("• Use F12 > Application > Cookies para obter cookies")
        print("• Teste com cookie_string para simplicidade")
        print("• Use lista de cookies para controle fino")
        print("• Cookies são aplicados antes de qualquer navegação")
        print("• Funciona com qualquer sistema: Portainer, eCidade, etc.")
        
    except KeyboardInterrupt:
        print("\n👋 Guia interrompido")

if __name__ == "__main__":
    main()
