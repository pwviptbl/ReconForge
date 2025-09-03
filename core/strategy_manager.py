#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Strategy Manager - Fase 2 da Refatoração

Gerencia registro, seleção e execução de estratégias de scanner,
implementando o padrão Strategy com:
- Registro dinâmico de estratégias
- Seleção baseada em contexto e prioridade
- Execução ordenada e controle de fluxo
- Gestão de dependências entre estratégias
- Execução paralela quando apropriado
"""

import threading
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from interfaces.scanner_strategy import (
    IScannerStrategy, StrategyPriority, ExecutionPhase, StrategyResult
)
from core.scan_context import ScanContext, ScanPhase


class ExecutionStatus(Enum):
    """Status de execução de uma estratégia"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


@dataclass
class StrategyExecution:
    """Informações sobre uma execução de estratégia"""
    strategy: IScannerStrategy
    target: str
    status: ExecutionStatus
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    result: Optional[StrategyResult] = None
    future: Optional[Future] = None
    error: Optional[str] = None
    retry_count: int = 0


class StrategyManager:
    """
    Gerenciador de estratégias de scanner
    
    Responsável por:
    - Registrar estratégias disponíveis
    - Selecionar estratégias baseado no contexto
    - Executar estratégias em ordem apropriada
    - Gerenciar dependências
    - Controlar execução paralela
    """
    
    def __init__(self, logger=None, max_workers: int = 3):
        self._logger = logger
        self._strategies: Dict[str, IScannerStrategy] = {}
        self._strategy_dependencies: Dict[str, Set[str]] = {}
        self._execution_history: List[StrategyExecution] = []
        self._current_executions: Dict[str, StrategyExecution] = {}
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="strategy")
        self._lock = threading.RLock()
        
        # Configurações
        self.max_retries = 3
        self.retry_delay = 5.0  # segundos
        self.execution_timeout = 300  # 5 minutos
        self.enable_parallel_execution = True
        
        self._log("INFO", "StrategyManager inicializado")
    
    def register_strategy(self, strategy: IScannerStrategy) -> None:
        """
        Registra uma estratégia
        
        Args:
            strategy: Estratégia a registrar
        """
        with self._lock:
            name = strategy.name
            if name in self._strategies:
                self._log("WARNING", f"Estratégia {name} já registrada, substituindo")
            
            self._strategies[name] = strategy
            self._strategy_dependencies[name] = set(strategy.get_dependencies())
            
            self._log("INFO", f"Estratégia registrada: {name}")
    
    def unregister_strategy(self, strategy_name: str) -> bool:
        """
        Remove uma estratégia
        
        Args:
            strategy_name: Nome da estratégia a remover
            
        Returns:
            True se removida, False se não encontrada
        """
        with self._lock:
            if strategy_name not in self._strategies:
                return False
            
            del self._strategies[strategy_name]
            del self._strategy_dependencies[strategy_name]
            
            # Remover das dependências de outras estratégias
            for deps in self._strategy_dependencies.values():
                deps.discard(strategy_name)
            
            self._log("INFO", f"Estratégia removida: {strategy_name}")
            return True
    
    def get_registered_strategies(self) -> List[str]:
        """
        Lista estratégias registradas
        
        Returns:
            Lista de nomes de estratégias
        """
        with self._lock:
            return list(self._strategies.keys())
    
    def get_strategy(self, name: str) -> Optional[IScannerStrategy]:
        """
        Recupera uma estratégia por nome
        
        Args:
            name: Nome da estratégia
            
        Returns:
            Estratégia ou None se não encontrada
        """
        with self._lock:
            return self._strategies.get(name)
    
    def select_strategies(self, context: ScanContext, target: str, 
                         phase: Optional[ExecutionPhase] = None,
                         exclude_executed: bool = True) -> List[IScannerStrategy]:
        """
        Seleciona estratégias apropriadas para o contexto atual
        
        Args:
            context: Contexto do scan
            target: Alvo específico
            phase: Fase de execução desejada (opcional)
            exclude_executed: Se deve excluir estratégias já executadas
            
        Returns:
            Lista de estratégias ordenadas por prioridade
        """
        with self._lock:
            suitable_strategies = []
            
            for strategy in self._strategies.values():
                # Filtrar por fase se especificada
                if phase and strategy.execution_phase != phase:
                    continue
                
                # Verificar se pode executar no contexto atual
                if not strategy.can_execute(context):
                    continue
                
                # Validar alvo
                if not strategy.validate_target(target):
                    continue
                
                # Excluir já executadas se solicitado
                if exclude_executed and strategy.name in context.executed_strategies:
                    continue
                
                # Verificar dependências
                if not self._are_dependencies_satisfied(strategy.name, context):
                    continue
                
                suitable_strategies.append(strategy)
            
            # Ordenar por prioridade (critical primeiro)
            suitable_strategies.sort(key=lambda s: s.priority.value)
            
            self._log("INFO", f"Selecionadas {len(suitable_strategies)} estratégias para {target}")
            return suitable_strategies
    
    def execute_strategy(self, strategy_name: str, target: str, context: ScanContext,
                        parallel: bool = None) -> StrategyResult:
        """
        Executa uma estratégia específica
        
        Args:
            strategy_name: Nome da estratégia
            target: Alvo para execução
            context: Contexto do scan
            parallel: Se deve executar em paralelo (None para auto-detectar)
            
        Returns:
            Resultado da execução
            
        Raises:
            ValueError: Se estratégia não estiver registrada
        """
        with self._lock:
            if strategy_name not in self._strategies:
                raise ValueError(f"Estratégia não registrada: {strategy_name}")
            
            strategy = self._strategies[strategy_name]
            
            # Determinar se deve executar em paralelo
            if parallel is None:
                parallel = (self.enable_parallel_execution and 
                           strategy.supports_parallel_execution())
            
            execution = StrategyExecution(
                strategy=strategy,
                target=target,
                status=ExecutionStatus.PENDING
            )
            
            self._execution_history.append(execution)
            
            if parallel:
                return self._execute_strategy_parallel(execution, context)
            else:
                return self._execute_strategy_sync(execution, context)
    
    def execute_multiple_strategies(self, strategy_names: List[str], targets: List[str],
                                   context: ScanContext, parallel: bool = True) -> Dict[str, StrategyResult]:
        """
        Executa múltiplas estratégias
        
        Args:
            strategy_names: Lista de nomes de estratégias
            targets: Lista de alvos
            context: Contexto do scan
            parallel: Se deve executar em paralelo
            
        Returns:
            Dicionário com resultados por estratégia
        """
        results = {}
        
        if parallel and self.enable_parallel_execution:
            # Execução paralela
            futures = {}
            
            for strategy_name in strategy_names:
                for target in targets:
                    key = f"{strategy_name}_{target}"
                    try:
                        future = self._executor.submit(
                            self._execute_strategy_with_context,
                            strategy_name, target, context
                        )
                        futures[key] = future
                    except Exception as e:
                        self._log("ERROR", f"Erro ao submeter {strategy_name} para {target}: {e}")
            
            # Aguardar conclusão
            for key, future in futures.items():
                try:
                    result = future.result(timeout=self.execution_timeout)
                    results[key] = result
                except Exception as e:
                    self._log("ERROR", f"Erro na execução paralela {key}: {e}")
                    results[key] = self._create_error_result(str(e))
        else:
            # Execução sequencial
            for strategy_name in strategy_names:
                for target in targets:
                    key = f"{strategy_name}_{target}"
                    try:
                        result = self.execute_strategy(strategy_name, target, context, parallel=False)
                        results[key] = result
                    except Exception as e:
                        self._log("ERROR", f"Erro na execução sequencial {key}: {e}")
                        results[key] = self._create_error_result(str(e))
        
        return results
    
    def execute_strategy_chain(self, context: ScanContext, targets: List[str],
                              max_iterations: int = 10) -> Dict[str, Any]:
        """
        Executa cadeia de estratégias baseada em dependências e contexto
        
        Args:
            context: Contexto do scan
            targets: Lista de alvos
            max_iterations: Máximo de iterações para evitar loops infinitos
            
        Returns:
            Relatório de execução
        """
        iteration = 0
        total_executed = 0
        
        self._log("INFO", f"Iniciando cadeia de estratégias para {len(targets)} alvos")
        
        while iteration < max_iterations and not context.is_completed:
            iteration += 1
            executed_in_iteration = 0
            
            self._log("INFO", f"Iteração {iteration} da cadeia de estratégias")
            
            for target in targets:
                # Selecionar estratégias apropriadas
                strategies = self.select_strategies(context, target)
                
                if not strategies:
                    continue
                
                # Executar estratégias em ordem de prioridade
                for strategy in strategies:
                    try:
                        context.start_strategy(strategy.name)
                        
                        result = self._execute_strategy_with_retry(strategy, target, context)
                        
                        # Processar resultado
                        if result.success:
                            self._process_strategy_result(result, context)
                            executed_in_iteration += 1
                            context.complete_strategy(strategy.name, True, result.execution_time)
                        else:
                            context.complete_strategy(strategy.name, False, result.execution_time, 
                                                    "; ".join(result.errors))
                        
                    except Exception as e:
                        error_msg = f"Erro na execução de {strategy.name}: {e}"
                        self._log("ERROR", error_msg)
                        context.complete_strategy(strategy.name, False, 0.0, error_msg)
            
            total_executed += executed_in_iteration
            
            # Se nenhuma estratégia foi executada nesta iteração, sair
            if executed_in_iteration == 0:
                self._log("INFO", "Nenhuma estratégia executada nesta iteração, finalizando")
                break
        
        # Relatório final
        return {
            "iterations": iteration,
            "total_strategies_executed": total_executed,
            "final_context": context.to_dict(),
            "execution_summary": self._generate_execution_summary()
        }
    
    def validate_dependencies(self) -> Dict[str, List[str]]:
        """
        Valida dependências de todas as estratégias
        
        Returns:
            Dicionário com problemas de dependência por estratégia
        """
        problems = {}
        
        with self._lock:
            for strategy_name, dependencies in self._strategy_dependencies.items():
                strategy_problems = []
                
                for dep in dependencies:
                    if dep not in self._strategies:
                        strategy_problems.append(f"Dependência não registrada: {dep}")
                
                # Verificar dependências circulares
                if self._has_circular_dependency(strategy_name):
                    strategy_problems.append("Dependência circular detectada")
                
                if strategy_problems:
                    problems[strategy_name] = strategy_problems
        
        return problems
    
    def get_execution_statistics(self) -> Dict[str, Any]:
        """
        Retorna estatísticas de execução
        
        Returns:
            Estatísticas detalhadas
        """
        with self._lock:
            total_executions = len(self._execution_history)
            successful = sum(1 for ex in self._execution_history if ex.status == ExecutionStatus.COMPLETED)
            failed = sum(1 for ex in self._execution_history if ex.status == ExecutionStatus.FAILED)
            
            # Tempo médio de execução por estratégia
            strategy_times = {}
            for execution in self._execution_history:
                if execution.status == ExecutionStatus.COMPLETED and execution.result:
                    name = execution.strategy.name
                    if name not in strategy_times:
                        strategy_times[name] = []
                    strategy_times[name].append(execution.result.execution_time)
            
            avg_times = {
                name: sum(times) / len(times) 
                for name, times in strategy_times.items()
            }
            
            return {
                "total_executions": total_executions,
                "successful_executions": successful,
                "failed_executions": failed,
                "success_rate": successful / total_executions if total_executions > 0 else 0,
                "registered_strategies": len(self._strategies),
                "average_execution_times": avg_times,
                "currently_running": len(self._current_executions)
            }
    
    def shutdown(self) -> None:
        """Finaliza o gerenciador e libera recursos"""
        self._log("INFO", "Finalizando StrategyManager")
        
        # Cancelar execuções em andamento
        with self._lock:
            for execution in self._current_executions.values():
                if execution.future:
                    execution.future.cancel()
        
        # Finalizar executor
        self._executor.shutdown(wait=True)
        
        self._log("INFO", "StrategyManager finalizado")
    
    # Métodos privados
    
    def _execute_strategy_sync(self, execution: StrategyExecution, context: ScanContext) -> StrategyResult:
        """Executa estratégia de forma síncrona"""
        execution.status = ExecutionStatus.RUNNING
        execution.start_time = datetime.now()
        
        try:
            self._current_executions[execution.strategy.name] = execution
            
            result = execution.strategy.execute(execution.target, context)
            
            execution.status = ExecutionStatus.COMPLETED
            execution.result = result
            
        except Exception as e:
            execution.status = ExecutionStatus.FAILED
            execution.error = str(e)
            result = self._create_error_result(str(e))
        
        finally:
            execution.end_time = datetime.now()
            self._current_executions.pop(execution.strategy.name, None)
        
        return result
    
    def _execute_strategy_parallel(self, execution: StrategyExecution, context: ScanContext) -> StrategyResult:
        """Executa estratégia de forma paralela"""
        try:
            future = self._executor.submit(
                self._execute_strategy_with_context,
                execution.strategy.name, execution.target, context
            )
            execution.future = future
            execution.status = ExecutionStatus.RUNNING
            
            result = future.result(timeout=self.execution_timeout)
            execution.status = ExecutionStatus.COMPLETED
            execution.result = result
            
            return result
            
        except Exception as e:
            execution.status = ExecutionStatus.FAILED
            execution.error = str(e)
            return self._create_error_result(str(e))
    
    def _execute_strategy_with_context(self, strategy_name: str, target: str, context: ScanContext) -> StrategyResult:
        """Wrapper para execução com contexto"""
        strategy = self._strategies[strategy_name]
        return strategy.execute(target, context)
    
    def _execute_strategy_with_retry(self, strategy: IScannerStrategy, target: str, 
                                   context: ScanContext) -> StrategyResult:
        """Executa estratégia com retry automático"""
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                result = strategy.execute(target, context)
                if result.success or attempt == self.max_retries:
                    return result
                
                last_error = "; ".join(result.errors) if result.errors else "Falha sem detalhes"
                
            except Exception as e:
                last_error = str(e)
                if attempt == self.max_retries:
                    break
            
            # Aguardar antes do próximo retry
            if attempt < self.max_retries:
                self._log("WARNING", f"Retry {attempt + 1}/{self.max_retries} para {strategy.name}")
                time.sleep(self.retry_delay)
        
        return self._create_error_result(f"Falha após {self.max_retries} tentativas: {last_error}")
    
    def _are_dependencies_satisfied(self, strategy_name: str, context: ScanContext) -> bool:
        """Verifica se dependências de uma estratégia estão satisfeitas"""
        dependencies = self._strategy_dependencies.get(strategy_name, set())
        
        for dep in dependencies:
            if dep not in context.executed_strategies:
                return False
        
        return True
    
    def _has_circular_dependency(self, strategy_name: str, visited: Set[str] = None) -> bool:
        """Verifica dependência circular"""
        if visited is None:
            visited = set()
        
        if strategy_name in visited:
            return True
        
        visited.add(strategy_name)
        
        dependencies = self._strategy_dependencies.get(strategy_name, set())
        for dep in dependencies:
            if self._has_circular_dependency(dep, visited.copy()):
                return True
        
        return False
    
    def _process_strategy_result(self, result: StrategyResult, context: ScanContext) -> None:
        """Processa resultado de uma estratégia e atualiza contexto"""
        # Adicionar novos alvos descobertos
        for target in result.discovered_targets:
            context.add_target(target, "discovered", result.data.get("strategy_name", "unknown"))
        
        # Adicionar serviços descobertos
        for host, services in result.discovered_services.items():
            if isinstance(services, list):
                for service in services:
                    if isinstance(service, dict):
                        from core.scan_context import ServiceInfo
                        service_info = ServiceInfo(
                            host=host,
                            port=service.get("port", 0),
                            service_name=service.get("name", "unknown"),
                            version=service.get("version"),
                            banner=service.get("banner"),
                            detected_by=result.data.get("strategy_name", "unknown")
                        )
                        context.add_service(service_info)
        
        # Adicionar vulnerabilidades
        for vuln in result.vulnerabilities:
            if isinstance(vuln, dict):
                from core.scan_context import VulnerabilityInfo
                vuln_info = VulnerabilityInfo(
                    vuln_id=vuln.get("id", f"vuln_{len(context.vulnerabilities)}"),
                    name=vuln.get("name", "Unknown Vulnerability"),
                    description=vuln.get("description", ""),
                    severity=vuln.get("severity", "info"),
                    cvss_score=vuln.get("cvss_score"),
                    cve_id=vuln.get("cve_id"),
                    discovered_by=result.data.get("strategy_name", "unknown"),
                    confidence=vuln.get("confidence", 1.0)
                )
                context.add_vulnerability(vuln_info)
    
    def _create_error_result(self, error_message: str) -> StrategyResult:
        """Cria resultado de erro padronizado"""
        return StrategyResult(
            success=False,
            execution_time=0.0,
            data={},
            errors=[error_message],
            warnings=[],
            discovered_targets=[],
            discovered_services={},
            vulnerabilities=[],
            next_strategies=[],
            confidence_score=0.0,
            timestamp=datetime.now().isoformat()
        )
    
    def _generate_execution_summary(self) -> Dict[str, Any]:
        """Gera resumo da execução"""
        with self._lock:
            summary = {
                "strategies_executed": len(self._execution_history),
                "successful_strategies": [],
                "failed_strategies": [],
                "execution_times": {}
            }
            
            for execution in self._execution_history:
                if execution.status == ExecutionStatus.COMPLETED:
                    summary["successful_strategies"].append(execution.strategy.name)
                    if execution.result:
                        summary["execution_times"][execution.strategy.name] = execution.result.execution_time
                elif execution.status == ExecutionStatus.FAILED:
                    summary["failed_strategies"].append({
                        "strategy": execution.strategy.name,
                        "error": execution.error
                    })
            
            return summary
    
    def _log(self, level: str, message: str) -> None:
        """Log interno com fallback"""
        if self._logger and hasattr(self._logger, level.lower()):
            getattr(self._logger, level.lower())(f"[StrategyManager] {message}")
        elif level.upper() in ['ERROR', 'WARNING']:
            print(f"[{level}] StrategyManager: {message}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
