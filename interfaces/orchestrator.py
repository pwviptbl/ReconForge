#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interface para orquestrador - Fase 1 da Refatoração

Define contrato para orquestradores permitindo diferentes
estratégias de execução e coordenação de módulos.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from enum import Enum

from .scanner_module import IScannerModule


class ExecutionMode(Enum):
    """Modos de execução"""
    SEQUENTIAL = "sequential"    # Execução sequencial
    PARALLEL = "parallel"       # Execução paralela
    ADAPTIVE = "adaptive"       # Adaptativo baseado em IA
    PIPELINE = "pipeline"       # Pipeline de módulos


class ExecutionStatus(Enum):
    """Status de execução"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class IOrchestrator(ABC):
    """Interface para orquestradores de pentest"""
    
    @property
    @abstractmethod
    def execution_mode(self) -> ExecutionMode:
        """Modo de execução atual"""
        pass
    
    @property
    @abstractmethod
    def available_modules(self) -> List[IScannerModule]:
        """Módulos disponíveis para execução"""
        pass
    
    @abstractmethod
    def register_module(self, module: IScannerModule):
        """
        Registra um módulo no orquestrador
        
        Args:
            module: Módulo a registrar
        """
        pass
    
    @abstractmethod
    def unregister_module(self, module_name: str):
        """
        Remove um módulo do orquestrador
        
        Args:
            module_name: Nome do módulo a remover
        """
        pass
    
    @abstractmethod
    def execute_pentest(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executa pentest completo no alvo
        
        Args:
            target: Alvo do pentest
            config: Configuração da execução
            
        Returns:
            Resultado consolidado do pentest
        """
        pass
    
    @abstractmethod
    def execute_module(self, module_name: str, target: str, 
                      context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executa módulo específico
        
        Args:
            module_name: Nome do módulo
            target: Alvo do módulo
            context: Contexto de execução
            
        Returns:
            Resultado da execução
        """
        pass
    
    @abstractmethod
    def pause_execution(self) -> bool:
        """
        Pausa execução atual
        
        Returns:
            True se pausado com sucesso
        """
        pass
    
    @abstractmethod
    def resume_execution(self) -> bool:
        """
        Resume execução pausada
        
        Returns:
            True se retomado com sucesso
        """
        pass
    
    @abstractmethod
    def cancel_execution(self) -> bool:
        """
        Cancela execução atual
        
        Returns:
            True se cancelado com sucesso
        """
        pass
    
    @abstractmethod
    def get_execution_status(self) -> ExecutionStatus:
        """
        Retorna status atual da execução
        
        Returns:
            Status da execução
        """
        pass
    
    @abstractmethod
    def get_execution_progress(self) -> Dict[str, Any]:
        """
        Retorna progresso da execução atual
        
        Returns:
            Informações de progresso (percentual, módulo atual, etc.)
        """
        pass


class IExecutionStrategy(ABC):
    """Interface para estratégias de execução"""
    
    @abstractmethod
    def plan_execution(self, modules: List[IScannerModule], 
                      target: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Planeja ordem de execução dos módulos
        
        Args:
            modules: Módulos disponíveis
            target: Alvo do pentest
            context: Contexto atual
            
        Returns:
            Plano de execução ordenado
        """
        pass
    
    @abstractmethod
    def should_continue(self, current_results: Dict[str, Any], 
                       context: Dict[str, Any]) -> bool:
        """
        Decide se deve continuar execução
        
        Args:
            current_results: Resultados até agora
            context: Contexto atual
            
        Returns:
            True se deve continuar, False para parar
        """
        pass
    
    @abstractmethod
    def adapt_plan(self, current_plan: List[Dict[str, Any]], 
                  new_findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Adapta plano baseado em novos achados
        
        Args:
            current_plan: Plano atual
            new_findings: Novos achados que podem influenciar o plano
            
        Returns:
            Plano adaptado
        """
        pass


class IDecisionEngine(ABC):
    """Interface para engines de decisão (IA)"""
    
    @abstractmethod
    def decide_next_action(self, context: Dict[str, Any], 
                          available_modules: List[str]) -> Dict[str, Any]:
        """
        Decide próxima ação baseada no contexto
        
        Args:
            context: Contexto atual com resultados e estado
            available_modules: Módulos disponíveis para execução
            
        Returns:
            Decisão sobre próxima ação
        """
        pass
    
    @abstractmethod
    def evaluate_risk_score(self, findings: Dict[str, Any]) -> int:
        """
        Avalia pontuação de risco baseada nos achados
        
        Args:
            findings: Achados do pentest
            
        Returns:
            Pontuação de risco (0-100)
        """
        pass
    
    @abstractmethod
    def generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """
        Gera recomendações baseadas nos resultados
        
        Args:
            results: Resultados consolidados
            
        Returns:
            Lista de recomendações
        """
        pass
