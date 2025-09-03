#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interface Strategy Base para Módulos de Scanner - Fase 2 da Refatoração

Define o padrão Strategy para módulos de scanner, permitindo:
- Execução dinâmica baseada em contexto
- Gestão de dependências entre estratégias
- Extensibilidade sem modificar código existente
- Estimativas de tempo e priorização
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from enum import Enum
from dataclasses import dataclass
from datetime import datetime


class StrategyPriority(Enum):
    """Prioridades de execução das estratégias"""
    CRITICAL = 1    # Executar sempre primeiro (ex: DNS, scan inicial)
    HIGH = 2        # Alta prioridade (ex: detecção de serviços)
    MEDIUM = 3      # Prioridade média (ex: enumeração de subdomínios)
    LOW = 4         # Baixa prioridade (ex: análises complementares)
    OPTIONAL = 5    # Opcional, apenas se solicitado


class ExecutionPhase(Enum):
    """Fases de execução do pentest"""
    RECONNAISSANCE = "reconnaissance"     # Reconhecimento
    DISCOVERY = "discovery"              # Descoberta
    ENUMERATION = "enumeration"          # Enumeração
    VULNERABILITY_ANALYSIS = "vuln_analysis"  # Análise de vulnerabilidades
    EXPLOITATION = "exploitation"        # Exploração
    POST_EXPLOITATION = "post_exploit"   # Pós-exploração


@dataclass
class StrategyResult:
    """Resultado padronizado de uma estratégia"""
    success: bool
    execution_time: float
    data: Dict[str, Any]
    errors: List[str]
    warnings: List[str]
    discovered_targets: List[str]
    discovered_services: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    next_strategies: List[str]  # Sugestões de próximas estratégias
    confidence_score: float     # Confiança no resultado (0-1)
    timestamp: str


class IScannerStrategy(ABC):
    """Interface base para estratégias de scanner"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Nome identificador único da estratégia"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Descrição do que a estratégia faz"""
        pass
    
    @property
    @abstractmethod
    def priority(self) -> StrategyPriority:
        """Prioridade de execução da estratégia"""
        pass
    
    @property
    @abstractmethod
    def execution_phase(self) -> ExecutionPhase:
        """Fase de execução apropriada para esta estratégia"""
        pass
    
    @abstractmethod
    def can_execute(self, context: 'ScanContext') -> bool:
        """
        Verifica se a estratégia pode ser executada no contexto atual
        
        Args:
            context: Contexto atual do scan
            
        Returns:
            True se pode executar, False caso contrário
        """
        pass
    
    @abstractmethod
    def execute(self, target: str, context: 'ScanContext') -> StrategyResult:
        """
        Executa a estratégia no alvo especificado
        
        Args:
            target: Alvo a ser escaneado (IP, URL, etc.)
            context: Contexto de execução
            
        Returns:
            Resultado da execução
        """
        pass
    
    @abstractmethod
    def get_dependencies(self) -> List[str]:
        """
        Lista de estratégias que devem executar antes desta
        
        Returns:
            Lista de nomes de estratégias dependentes
        """
        pass
    
    @abstractmethod
    def estimate_execution_time(self, target: str, context: 'ScanContext') -> float:
        """
        Estima tempo de execução em segundos
        
        Args:
            target: Alvo a ser escaneado
            context: Contexto de execução
            
        Returns:
            Tempo estimado em segundos
        """
        pass
    
    def validate_target(self, target: str) -> bool:
        """
        Valida se o alvo é compatível com esta estratégia
        
        Args:
            target: Alvo a validar
            
        Returns:
            True se válido, False caso contrário
        """
        return True  # Implementação padrão aceita qualquer alvo
    
    def get_required_tools(self) -> List[str]:
        """
        Lista de ferramentas/dependências necessárias
        
        Returns:
            Lista de nomes de ferramentas necessárias
        """
        return []  # Implementação padrão não requer ferramentas específicas
    
    def get_configuration_schema(self) -> Dict[str, Any]:
        """
        Schema de configuração específica desta estratégia
        
        Returns:
            Schema JSON para validação de configuração
        """
        return {}  # Implementação padrão não requer configuração
    
    def supports_parallel_execution(self) -> bool:
        """
        Indica se esta estratégia pode ser executada em paralelo
        
        Returns:
            True se suporta execução paralela, False caso contrário
        """
        return True  # Implementação padrão suporta paralelização
    
    def get_output_artifacts(self) -> List[str]:
        """
        Lista de artefatos que esta estratégia produz
        
        Returns:
            Lista de tipos de artefatos (ex: ["ports", "services", "vulnerabilities"])
        """
        return []


class IDNSStrategy(IScannerStrategy):
    """Interface para estratégias de resolução DNS"""
    
    @abstractmethod
    def resolve_domain(self, domain: str, context: 'ScanContext') -> StrategyResult:
        """
        Resolve informações DNS do domínio
        
        Args:
            domain: Domínio a resolver
            context: Contexto de execução
            
        Returns:
            Resultado com informações DNS
        """
        pass


class IPortScanStrategy(IScannerStrategy):
    """Interface para estratégias de scan de portas"""
    
    @abstractmethod
    def scan_ports(self, target: str, ports: Optional[List[int]], context: 'ScanContext') -> StrategyResult:
        """
        Escaneia portas do alvo
        
        Args:
            target: IP ou hostname a escanear
            ports: Lista de portas específicas (None para faixa padrão)
            context: Contexto de execução
            
        Returns:
            Resultado com portas abertas
        """
        pass


class IServiceDetectionStrategy(IScannerStrategy):
    """Interface para estratégias de detecção de serviços"""
    
    @abstractmethod
    def detect_services(self, target: str, ports: List[int], context: 'ScanContext') -> StrategyResult:
        """
        Detecta serviços rodando nas portas especificadas
        
        Args:
            target: IP ou hostname
            ports: Lista de portas abertas para analisar
            context: Contexto de execução
            
        Returns:
            Informações sobre serviços detectados
        """
        pass


class IVulnerabilityAnalysisStrategy(IScannerStrategy):
    """Interface para estratégias de análise de vulnerabilidades"""
    
    @abstractmethod
    def analyze_vulnerabilities(self, target: str, services: Dict[str, Any], context: 'ScanContext') -> StrategyResult:
        """
        Analisa vulnerabilidades baseado nos serviços detectados
        
        Args:
            target: Alvo a analisar
            services: Serviços previamente detectados
            context: Contexto de execução
            
        Returns:
            Lista de vulnerabilidades encontradas
        """
        pass


class IWebAnalysisStrategy(IScannerStrategy):
    """Interface para estratégias de análise web"""
    
    @abstractmethod
    def analyze_web_application(self, url: str, credentials: Optional[Dict[str, str]], context: 'ScanContext') -> StrategyResult:
        """
        Analisa aplicação web
        
        Args:
            url: URL base da aplicação
            credentials: Credenciais opcionais para autenticação
            context: Contexto de execução
            
        Returns:
            Resultado da análise web
        """
        pass


class ISubdomainEnumerationStrategy(IScannerStrategy):
    """Interface para estratégias de enumeração de subdomínios"""
    
    @abstractmethod
    def enumerate_subdomains(self, domain: str, context: 'ScanContext') -> StrategyResult:
        """
        Enumera subdomínios do domínio principal
        
        Args:
            domain: Domínio principal
            context: Contexto de execução
            
        Returns:
            Lista de subdomínios encontrados
        """
        pass


class IDirectoryScanStrategy(IScannerStrategy):
    """Interface para estratégias de scan de diretórios"""
    
    @abstractmethod
    def scan_directories(self, base_url: str, wordlist: Optional[str], context: 'ScanContext') -> StrategyResult:
        """
        Escaneia diretórios e arquivos web
        
        Args:
            base_url: URL base para scanning
            wordlist: Wordlist personalizada (opcional)
            context: Contexto de execução
            
        Returns:
            Diretórios e arquivos encontrados
        """
        pass


class ITechnologyDetectionStrategy(IScannerStrategy):
    """Interface para estratégias de detecção de tecnologia"""
    
    @abstractmethod
    def detect_technologies(self, url: str, context: 'ScanContext') -> StrategyResult:
        """
        Detecta tecnologias utilizadas no site
        
        Args:
            url: URL a analisar
            context: Contexto de execução
            
        Returns:
            Tecnologias detectadas
        """
        pass


class IExploitSearchStrategy(IScannerStrategy):
    """Interface para estratégias de busca de exploits"""
    
    @abstractmethod
    def search_exploits(self, service_info: Dict[str, Any], context: 'ScanContext') -> StrategyResult:
        """
        Busca exploits para serviços/vulnerabilidades encontradas
        
        Args:
            service_info: Informações sobre serviços e versões
            context: Contexto de execução
            
        Returns:
            Lista de exploits disponíveis
        """
        pass


# Classes auxiliares para implementação de estratégias

class BaseStrategy(IScannerStrategy):
    """Classe base abstrata com implementações padrão"""
    
    def __init__(self, logger=None):
        self._logger = logger
        self._start_time = None
        self._execution_stats = {}
    
    def _log(self, level: str, message: str):
        """Log interno com fallback"""
        if self._logger and hasattr(self._logger, level.lower()):
            getattr(self._logger, level.lower())(f"[{self.name}] {message}")
        elif level.upper() in ['ERROR', 'WARNING']:
            print(f"[{level}] {self.name}: {message}")
    
    def _start_execution_timer(self):
        """Inicia timer de execução"""
        self._start_time = datetime.now()
    
    def _get_execution_time(self) -> float:
        """Retorna tempo de execução em segundos"""
        if self._start_time:
            return (datetime.now() - self._start_time).total_seconds()
        return 0.0
    
    def _create_result(self, success: bool = True, data: Dict[str, Any] = None, 
                      errors: List[str] = None, warnings: List[str] = None,
                      discovered_targets: List[str] = None, discovered_services: Dict[str, Any] = None,
                      vulnerabilities: List[Dict[str, Any]] = None, next_strategies: List[str] = None,
                      confidence_score: float = 1.0) -> StrategyResult:
        """
        Cria resultado padronizado
        
        Args:
            success: Se a execução foi bem-sucedida
            data: Dados retornados
            errors: Lista de erros
            warnings: Lista de avisos
            discovered_targets: Novos alvos descobertos
            discovered_services: Serviços descobertos
            vulnerabilities: Vulnerabilidades encontradas
            next_strategies: Próximas estratégias sugeridas
            confidence_score: Confiança no resultado
            
        Returns:
            Resultado padronizado
        """
        return StrategyResult(
            success=success,
            execution_time=self._get_execution_time(),
            data=data or {},
            errors=errors or [],
            warnings=warnings or [],
            discovered_targets=discovered_targets or [],
            discovered_services=discovered_services or {},
            vulnerabilities=vulnerabilities or [],
            next_strategies=next_strategies or [],
            confidence_score=confidence_score,
            timestamp=datetime.now().isoformat()
        )
    
    def validate_target(self, target: str) -> bool:
        """Validação básica de alvo"""
        if not target or not isinstance(target, str):
            return False
        return len(target.strip()) > 0
    
    def supports_parallel_execution(self) -> bool:
        """Por padrão, suporta execução paralela"""
        return True
    
    def get_required_tools(self) -> List[str]:
        """Por padrão, não requer ferramentas específicas"""
        return []
    
    def get_configuration_schema(self) -> Dict[str, Any]:
        """Schema básico de configuração"""
        return {
            "type": "object",
            "properties": {
                "timeout": {
                    "type": "number",
                    "description": "Timeout em segundos",
                    "default": 300
                },
                "max_retries": {
                    "type": "integer",
                    "description": "Número máximo de tentativas",
                    "default": 3
                }
            }
        }
    
    def get_output_artifacts(self) -> List[str]:
        """Por padrão, produz dados genéricos"""
        return ["scan_data"]
