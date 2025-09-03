#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Teste de Integração da Fase 2 - Strategy Pattern

Este script testa a integração das estratégias com o sistema existente,
verificando se o container DI está registrando corretamente as estratégias
e se o StrategyManager está funcionando.
"""

import sys
from pathlib import Path

# Garantir que o diretório raiz está no path
sys.path.insert(0, str(Path(__file__).parent))

def test_container_registration():
    """Testa se o container consegue registrar as estratégias"""
    print("🧪 Teste 1: Registro de Estratégias no Container")
    
    try:
        from core.dependency_container import DependencyContainer
        
        # Criar container
        container = DependencyContainer()
        print("   ✅ Container criado")
        
        # Registrar estratégias
        container.register_strategies()
        print("   ✅ Estratégias registradas")
        
        # Verificar se StrategyManager está disponível
        strategy_manager = container.get_strategy_manager()
        if strategy_manager:
            print(f"   ✅ StrategyManager obtido: {type(strategy_manager).__name__}")
            
            # Verificar estratégias registradas
            strategies = strategy_manager._strategies
            print(f"   ✅ {len(strategies)} estratégias no manager:")
            for strategy_name, strategy in strategies.items():
                try:
                    name = strategy.name if hasattr(strategy, 'name') else str(type(strategy).__name__)
                    description = strategy.description if hasattr(strategy, 'description') else "Sem descrição"
                    print(f"      - {name}: {description}")
                except Exception as e:
                    print(f"      - {type(strategy).__name__}: Erro ao obter info ({e})")
            
            return True
        else:
            print("   ❌ StrategyManager não disponível")
            return False
            
    except Exception as e:
        print(f"   ❌ Erro no teste 1: {e}")
        return False

def test_scan_context_creation():
    """Testa criação de ScanContext"""
    print("\n🧪 Teste 2: Criação de ScanContext")
    
    try:
        from core.dependency_container import DependencyContainer
        
        container = DependencyContainer()
        container.register_strategies()
        
        # Criar contexto
        context = container.create_scan_context("example.com")
        
        # Adicionar preferências após criação
        context.user_preferences = {'verbose': True}
        
        print(f"   ✅ ScanContext criado para: {context.initial_target}")
        print(f"   ✅ Preferências: {context.user_preferences}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Erro no teste 2: {e}")
        return False

def test_strategy_execution():
    """Testa execução de uma estratégia simples"""
    print("\n🧪 Teste 3: Execução de Estratégia")
    
    try:
        from core.dependency_container import DependencyContainer
        from strategies import DNSResolutionStrategy
        
        container = DependencyContainer()
        container.register_strategies()
        
        # Obter StrategyManager
        strategy_manager = container.get_strategy_manager()
        context = container.create_scan_context("8.8.8.8")
        
        # Verificar se DNS strategy pode executar
        dns_strategy = None
        print(f"   📋 Verificando {len(strategy_manager._strategies)} estratégias:")
        for i, (strategy_name, strategy) in enumerate(strategy_manager._strategies.items()):
            print(f"      {i}: {type(strategy).__name__} - {strategy_name}")
            if strategy_name == 'dns_resolution':
                dns_strategy = strategy
                break
        
        if dns_strategy:
            print(f"   ✅ DNS Strategy encontrada: {type(dns_strategy)}")
            try:
                can_execute = dns_strategy.can_execute(context)
                print(f"   ✅ DNS Strategy pode executar: {can_execute}")
                
                if can_execute:
                    # Tentar execução rápida (sem módulos externos por enquanto)
                    estimated_time = dns_strategy.estimate_execution_time("8.8.8.8", context)
                    print(f"   ✅ Tempo estimado: {estimated_time}s")
                
                return True
            except Exception as e:
                print(f"   ❌ Erro ao testar DNS Strategy: {e}")
                return False
        else:
            print("   ❌ DNS Strategy não encontrada")
            return False
            
    except Exception as e:
        print(f"   ❌ Erro no teste 3: {e}")
        return False

def test_main_integration():
    """Testa integração com main.py"""
    print("\n🧪 Teste 4: Integração com Main")
    
    try:
        from core.service_configuration import create_configured_container
        
        # Criar container configurado como no main
        container = create_configured_container()
        print("   ✅ Container configurado criado")
        
        # Registrar estratégias
        container.register_strategies()
        print("   ✅ Estratégias registradas via main")
        
        # Verificar disponibilidade
        strategy_manager = container.get_strategy_manager()
        if strategy_manager:
            print(f"   ✅ StrategyManager disponível com {len(strategy_manager._strategies)} estratégias")
            return True
        else:
            print("   ❌ StrategyManager não disponível")
            return False
            
    except Exception as e:
        print(f"   ❌ Erro no teste 4: {e}")
        return False

def main():
    """Executa todos os testes"""
    print("🚀 Teste de Integração - Fase 2 Strategy Pattern")
    print("=" * 60)
    
    tests = [
        test_container_registration,
        test_scan_context_creation,
        test_strategy_execution,
        test_main_integration
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 60)
    print(f"📊 Resultado: {passed}/{total} testes passaram")
    
    if passed == total:
        print("🎉 Todos os testes passaram! Integração da Fase 2 bem-sucedida!")
        return 0
    else:
        print("⚠️  Alguns testes falharam. Verificar implementação.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
