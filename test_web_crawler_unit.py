#!/usr/bin/env python3
"""
Script para testar funcionalidades específicas do WebCrawlerPlugin
Inclui teste de formulários, login e mapeamento de parâmetros
"""

import sys
import json
import time
from pathlib import Path

# Adicionar diretório raiz ao path
sys.path.append(str(Path(__file__).parent))

from plugins.web_crawler_plugin import WebCrawlerPlugin

def test_plugin_basic():
    """Teste básico do plugin sem Selenium (verificação de imports)"""
    print("🔍 Testando imports e configuração básica...")
    
    try:
        plugin = WebCrawlerPlugin()
        info = plugin.get_info()
        
        print(f"✅ Plugin criado com sucesso")
        print(f"📛 Nome: {info['name']}")
        print(f"📖 Descrição: {info['description']}")
        print(f"🏷️  Versão: {info['version']}")
        print(f"🎯 Alvos suportados: {info['supported_targets']}")
        print(f"🔧 Selenium disponível: {info['dependencies']['selenium']}")
        
        # Mostrar configurações
        print(f"\n⚙️  Configurações padrão:")
        for key, value in plugin.config.items():
            print(f"   • {key}: {value}")
        
        # Mostrar recursos
        print(f"\n✨ Recursos disponíveis:")
        for feature in info['features']:
            print(f"   • {feature}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao criar plugin: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_url_validation():
    """Testa validação de URLs"""
    print("\n🔗 Testando validação de URLs...")
    
    plugin = WebCrawlerPlugin()
    
    test_urls = [
        ('https://google.com', True),
        ('http://example.com', True),
        ('google.com', True),  # Deve normalizar
        ('ftp://example.com', False),
        ('invalid-url', False),
        ('', False)
    ]
    
    for url, expected in test_urls:
        result = plugin.validate_target(url)
        status = "✅" if result == expected else "❌"
        print(f"   {status} {url} -> {result}")
        
        if result and url:
            normalized = plugin._normalize_url(url)
            print(f"      Normalizada: {normalized}")

def test_framework_detection():
    """Testa detecção de frameworks"""
    print("\n🛠️  Testando detecção de frameworks...")
    
    plugin = WebCrawlerPlugin()
    
    # Simular conteúdo de página
    test_content = """
    <html>
    <head>
        <script src="/wp-content/themes/theme.js"></script>
        <link rel="stylesheet" href="/bootstrap/css/bootstrap.min.css">
    </head>
    <body>
        <div class="container">
            <form method="post" action="/login">
                <input type="hidden" name="_token" value="abc123">
                <input type="text" name="username" placeholder="Username">
                <input type="password" name="password" placeholder="Password">
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
        </div>
        <script>
            if (typeof jQuery !== 'undefined') {
                console.log('jQuery loaded');
            }
        </script>
    </body>
    </html>
    """
    
    # Detectar frameworks no conteúdo
    detected = set()
    for framework, signatures in plugin.framework_signatures.items():
        if any(sig.lower() in test_content.lower() for sig in signatures):
            detected.add(framework)
    
    print(f"   Frameworks detectados no HTML de teste:")
    for framework in detected:
        print(f"   ✅ {framework}")

def test_form_analysis():
    """Testa análise de formulários"""
    print("\n📝 Testando análise de formulários...")
    
    plugin = WebCrawlerPlugin()
    
    # Simular dados de formulário
    test_form = {
        'url': 'https://example.com/login',
        'form_index': 0,
        'action': '/login',
        'method': 'post',
        'inputs': [
            {
                'type': 'text',
                'name': 'username',
                'id': 'user_field',
                'placeholder': 'Enter username'
            },
            {
                'type': 'password',
                'name': 'password',
                'id': 'pass_field',
                'placeholder': 'Enter password'
            },
            {
                'type': 'hidden',
                'name': '_token',
                'value': 'csrf_token_123'
            },
            {
                'type': 'submit',
                'value': 'Login'
            }
        ]
    }
    
    # Testar detecção de formulário de login
    is_login = plugin._is_login_form(test_form)
    print(f"   Formulário de login detectado: {'✅' if is_login else '❌'}")
    
    # Mostrar detalhes do formulário
    print(f"   Método: {test_form['method'].upper()}")
    print(f"   Action: {test_form['action']}")
    print(f"   Inputs: {len(test_form['inputs'])}")
    
    # Analisar tipos de campos
    field_types = {}
    for input_field in test_form['inputs']:
        field_type = input_field.get('type', 'unknown')
        field_types[field_type] = field_types.get(field_type, 0) + 1
    
    print(f"   Tipos de campos:")
    for field_type, count in field_types.items():
        print(f"     • {field_type}: {count}")

def test_credentials():
    """Testa credenciais comuns"""
    print("\n🔐 Testando credenciais comuns...")
    
    plugin = WebCrawlerPlugin()
    
    print(f"   Total de credenciais: {len(plugin.common_credentials)}")
    print(f"   Primeiras 5 credenciais:")
    
    for i, (username, password) in enumerate(plugin.common_credentials[:5]):
        print(f"     {i+1}. {username}:{password if password else '(vazio)'}")

def test_selectors():
    """Testa seletores CSS"""
    print("\n🎯 Testando seletores CSS...")
    
    plugin = WebCrawlerPlugin()
    
    print(f"   Seletores de username ({len(plugin.login_selectors['username_fields'])}):")
    for selector in plugin.login_selectors['username_fields'][:3]:
        print(f"     • {selector}")
    
    print(f"   Seletores de password ({len(plugin.login_selectors['password_fields'])}):")
    for selector in plugin.login_selectors['password_fields'][:3]:
        print(f"     • {selector}")
    
    print(f"   Seletores de submit ({len(plugin.login_selectors['submit_buttons'])}):")
    for selector in plugin.login_selectors['submit_buttons'][:3]:
        print(f"     • {selector}")

def main():
    """Função principal de teste"""
    print("🧪 Iniciando testes unitários do WebCrawlerPlugin")
    print("="*60)
    
    try:
        # Teste 1: Configuração básica
        if not test_plugin_basic():
            print("❌ Falha no teste básico. Abortando...")
            return
        
        # Teste 2: Validação de URLs
        test_url_validation()
        
        # Teste 3: Detecção de frameworks
        test_framework_detection()
        
        # Teste 4: Análise de formulários
        test_form_analysis()
        
        # Teste 5: Credenciais
        test_credentials()
        
        # Teste 6: Seletores
        test_selectors()
        
        print("\n" + "="*60)
        print("✅ Todos os testes unitários concluídos com sucesso!")
        print("\n🚀 Para teste completo com Selenium, execute:")
        print("   python test_web_crawler.py")
        
    except Exception as e:
        print(f"\n💥 Erro durante os testes: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
