#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wrapper de compatibilidade - Fase 1 da Refatoração

Mantém compatibilidade com o main.py original enquanto
permite transição gradual para o sistema refatorado.
"""

import os
import sys
from pathlib import Path

# Garantir diretório raiz no path
sys.path.insert(0, str(Path(__file__).parent))


def should_use_refactored_version() -> bool:
    """
    Decide se deve usar versão refatorada baseado em:
    - Variável de ambiente
    - Arquivo de configuração
    - Argumentos da linha de comando
    """
    # Verificar variável de ambiente
    if os.environ.get('VARREDURA_USE_REFACTORED', '').lower() in ['true', '1', 'yes']:
        return True
    
    # Verificar se existe arquivo marker
    marker_file = Path(__file__).parent / '.use_refactored'
    if marker_file.exists():
        return True
    
    # Verificar argumentos da linha de comando
    if '--use-refactored' in sys.argv:
        # Remover o argumento para não afetar o parser
        sys.argv.remove('--use-refactored')
        return True
    
    return False


def run_original_main():
    """Executa versão original do main.py"""
    try:
        print("🔄 Executando versão original (compatibilidade)")
        
        # Importar e executar main original
        import importlib.util
        
        # Carregar main.py original dinamicamente
        main_path = Path(__file__).parent / 'main_original.py'
        if not main_path.exists():
            # Se não existe main_original.py, usar o main.py atual
            main_path = Path(__file__).parent / 'main.py'
        
        spec = importlib.util.spec_from_file_location("main_original", main_path)
        main_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(main_module)
        
        # Executar função main
        return main_module.main()
        
    except Exception as e:
        print(f"❌ Erro na versão original: {e}")
        print("🔄 Tentando versão refatorada como fallback...")
        return run_refactored_main()


def run_refactored_main():
    """Executa versão refatorada do main.py"""
    try:
        print("🚀 Executando versão refatorada (Fase 1)")
        
        from main_refatorado import main
        return main()
        
    except Exception as e:
        print(f"❌ Erro na versão refatorada: {e}")
        
        # Se falhou, tentar versão original como fallback
        if 'main_original' not in str(e):  # Evitar loop infinito
            print("🔄 Tentando versão original como fallback...")
            return run_original_main()
        else:
            print("❌ Ambas as versões falharam")
            return 1


def enable_refactored_version():
    """Habilita versão refatorada criando arquivo marker"""
    marker_file = Path(__file__).parent / '.use_refactored'
    try:
        marker_file.write_text(f"Versão refatorada habilitada em {sys.version}\n")
        print("✅ Versão refatorada habilitada")
        print("   Use 'python main.py --disable-refactored' para desabilitar")
    except Exception as e:
        print(f"❌ Erro ao habilitar versão refatorada: {e}")


def disable_refactored_version():
    """Desabilita versão refatorada removendo arquivo marker"""
    marker_file = Path(__file__).parent / '.use_refactored'
    try:
        if marker_file.exists():
            marker_file.unlink()
            print("✅ Versão refatorada desabilitada")
        else:
            print("ℹ️  Versão refatorada já estava desabilitada")
    except Exception as e:
        print(f"❌ Erro ao desabilitar versão refatorada: {e}")


def show_version_info():
    """Mostra informações sobre as versões disponíveis"""
    print("=== VarreduraIA - Informações de Versão ===")
    
    # Verificar arquivos disponíveis
    main_original = Path(__file__).parent / 'main_original.py'
    main_refatorado = Path(__file__).parent / 'main_refatorado.py'
    marker_file = Path(__file__).parent / '.use_refactored'
    
    print(f"📁 Versão original disponível: {'✅' if main_original.exists() else '❌'}")
    print(f"📁 Versão refatorada disponível: {'✅' if main_refatorado.exists() else '❌'}")
    print(f"🔧 Versão refatorada ativa: {'✅' if marker_file.exists() else '❌'}")
    
    # Mostrar configuração atual
    current_version = "refatorada" if should_use_refactored_version() else "original"
    print(f"🚀 Versão atual: {current_version}")
    
    print("\n=== Como alternar versões ===")
    print("  Habilitar refatorada: python main.py --enable-refactored")
    print("  Desabilitar refatorada: python main.py --disable-refactored")
    print("  Usar refatorada uma vez: python main.py --use-refactored <args>")
    print("  Variável de ambiente: VARREDURA_USE_REFACTORED=true")


def main():
    """Fun��o principal do wrapper - DEPRECATED"""
    print("??  AVISO: main_wrapper.py est� obsoleto!")
    print("   Use diretamente: python main.py <argumentos>")
    print("   Para vers�o legada: python main_wrapper.py --legacy")
    
    # Verificar se quer vers�o legada
    if '--legacy' in sys.argv:
        sys.argv.remove('--legacy')
        return run_legacy_version()
    else:
        return run_current_main()


if __name__ == "__main__":
    sys.exit(main())
