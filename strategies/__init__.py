#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de Estratégias - Fase 2 da Refatoração VarreduraIA

Este módulo contém todas as implementações de estratégias do padrão Strategy Pattern.
Cada estratégia encapsula um conjunto específico de funcionalidades de scanning
e pode ser executada de forma independente ou coordenada pelo StrategyManager.

Estratégias Implementadas:
- dns_resolution_strategy: Resolução DNS abrangente
- port_scan_strategy: Varredura de portas com RustScan
- service_detection_strategy: Detecção de serviços com Nmap
- technology_detection_strategy: Detecção de tecnologias web
- web_analysis_strategy: Análise abrangente de aplicações web
- vulnerability_analysis_strategy: Análise de vulnerabilidades
- subdomain_enumeration_strategy: Enumeração de subdomínios

Uso:
    from strategies import DNSResolutionStrategy, PortScanStrategy
    from core.strategy_manager import StrategyManager
    
    # Registrar estratégias
    manager = StrategyManager()
    manager.register_strategy(DNSResolutionStrategy())
    manager.register_strategy(PortScanStrategy())
    
    # Executar
    results = manager.execute_strategies(target, context)
"""

# Importações das estratégias implementadas
from .dns_resolution_strategy import DNSResolutionStrategy
from .port_scan_strategy import PortScanStrategy
from .service_detection_strategy import ServiceDetectionStrategy
from .technology_detection_strategy import TechnologyDetectionStrategy
from .web_analysis_strategy import WebAnalysisStrategy
from .vulnerability_analysis_strategy import VulnerabilityAnalysisStrategy
from .subdomain_enumeration_strategy import SubdomainEnumerationStrategy

# Lista de todas as estratégias disponíveis
ALL_STRATEGIES = [
    DNSResolutionStrategy,
    SubdomainEnumerationStrategy,
    PortScanStrategy,
    ServiceDetectionStrategy,
    TechnologyDetectionStrategy,
    WebAnalysisStrategy,
    VulnerabilityAnalysisStrategy
]

# Mapeamento por nome
STRATEGY_REGISTRY = {
    strategy().name: strategy for strategy in ALL_STRATEGIES
}

# Mapeamento por fase de execução
from interfaces.scanner_strategy import ExecutionPhase

STRATEGIES_BY_PHASE = {
    ExecutionPhase.RECONNAISSANCE: [
        DNSResolutionStrategy,
        SubdomainEnumerationStrategy
    ],
    ExecutionPhase.DISCOVERY: [
        PortScanStrategy,
        ServiceDetectionStrategy
    ],
    ExecutionPhase.ENUMERATION: [
        TechnologyDetectionStrategy,
        WebAnalysisStrategy
    ],
    ExecutionPhase.VULNERABILITY_ANALYSIS: [
        VulnerabilityAnalysisStrategy
    ]
}

def get_strategy_by_name(name: str):
    """
    Obtém uma classe de estratégia pelo nome
    
    Args:
        name: Nome da estratégia
        
    Returns:
        Classe da estratégia ou None se não encontrada
    """
    return STRATEGY_REGISTRY.get(name)

def get_strategies_for_phase(phase: ExecutionPhase):
    """
    Obtém todas as estratégias para uma fase específica
    
    Args:
        phase: Fase de execução
        
    Returns:
        Lista de classes de estratégias
    """
    return STRATEGIES_BY_PHASE.get(phase, [])

def create_default_strategy_set(logger=None):
    """
    Cria um conjunto padrão de estratégias com dependências básicas
    
    Args:
        logger: Logger opcional
        
    Returns:
        Lista de instâncias de estratégias
    """
    strategies = []
    
    # Instanciar estratégias na ordem correta de dependências
    strategies.append(DNSResolutionStrategy(logger=logger))
    strategies.append(SubdomainEnumerationStrategy(logger=logger))
    strategies.append(PortScanStrategy(logger=logger))
    strategies.append(ServiceDetectionStrategy(logger=logger))
    strategies.append(TechnologyDetectionStrategy(logger=logger))
    strategies.append(WebAnalysisStrategy(logger=logger))
    strategies.append(VulnerabilityAnalysisStrategy(logger=logger))
    
    return strategies

__all__ = [
    'DNSResolutionStrategy',
    'PortScanStrategy', 
    'ServiceDetectionStrategy',
    'TechnologyDetectionStrategy',
    'WebAnalysisStrategy',
    'VulnerabilityAnalysisStrategy',
    'SubdomainEnumerationStrategy',
    'ALL_STRATEGIES',
    'STRATEGY_REGISTRY',
    'STRATEGIES_BY_PHASE',
    'get_strategy_by_name',
    'get_strategies_for_phase',
    'create_default_strategy_set'
]
