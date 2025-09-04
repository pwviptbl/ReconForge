#!/usr/bin/env python3
"""
Teste simples do WebCrawlerPlugin com um site real
"""

import sys
from pathlib import Path
import json
import time

# Adicionar diretório raiz ao path
sys.path.append(str(Path(__file__).parent))

from plugins.web_crawler_plugin import WebCrawlerPlugin

def test_simple_navigation():
    """Teste simples de navegação"""
    print("🌐 Testando navegação simples com Selenium...")
    
    # Configurar plugin com configurações limitadas para teste
    plugin = WebCrawlerPlugin()
    plugin.config.update({
        'headless': True,
        'max_pages': 5,
        'max_depth': 1,
        'timeout': 15,
        'attempt_login': False,  # Desabilitar login para teste simples
        'common_credentials': False
    })
    
    # Testar com httpbin (site de teste simples)
    target = "https://httpbin.org"
    
    print(f"🎯 Testando com: {target}")
    print(f"⚙️  Configurações: headless={plugin.config['headless']}, max_pages={plugin.config['max_pages']}")
    
    try:
        start_time = time.time()
        
        # Executar o plugin
        result = plugin.execute(
            target=target,
            context={'test_mode': True}
        )
        
        execution_time = time.time() - start_time
        
        print(f"\n📊 Resultado:")
        print(f"   • Sucesso: {'✅' if result.success else '❌'}")
        print(f"   • Tempo: {execution_time:.2f}s")
        
        if result.success:
            data = result.data.get('web_crawling', {})
            stats = data.get('statistics', {})
            
            print(f"   • Páginas: {stats.get('total_pages', 0)}")
            print(f"   • Formulários: {stats.get('total_forms', 0)}")
            print(f"   • Frameworks: {stats.get('frameworks_detected', 0)}")
            
            # Mostrar algumas páginas navegadas
            pages = data.get('pages_crawled', [])
            if pages:
                print(f"\n📄 Páginas navegadas:")
                for page in pages[:3]:
                    print(f"   • {page['url']} (título: {page.get('title', 'N/A')[:50]})")
            
            # Mostrar frameworks detectados
            frameworks = data.get('frameworks_detected', [])
            if frameworks:
                print(f"\n🛠️  Frameworks detectados:")
                for framework in frameworks:
                    print(f"   • {framework}")
            
            # Salvar resultado
            output_file = f"data/simple_test_{int(time.time())}.json"
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, indent=2, ensure_ascii=False, default=str)
            
            print(f"\n💾 Resultado salvo em: {output_file}")
            
        else:
            print(f"   • Erro: {result.error}")
        
        return result.success
        
    except KeyboardInterrupt:
        print("\n⏹️  Teste interrompido")
        return False
    except Exception as e:
        print(f"\n❌ Erro: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Função principal"""
    print("🚀 Teste simples do WebCrawlerPlugin")
    print("="*50)
    
    success = test_simple_navigation()
    
    if success:
        print("\n✅ Teste concluído com sucesso!")
        print("\n💡 Para teste mais completo, execute:")
        print("   python test_web_crawler.py")
    else:
        print("\n❌ Teste falhou")

if __name__ == "__main__":
    main()
