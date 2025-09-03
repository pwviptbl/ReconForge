#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Context Object para Estratégias de Scanner - Fase 2 da Refatoração

Define o contexto compartilhado entre estratégias durante a execução,
incluindo estado do scan, dados descobertos e configurações.
"""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ScanMode(Enum):
    """Modos de execução do scan"""
    NETWORK = "network"           # Scan de rede tradicional
    WEB = "web"                  # Scan focado em aplicações web
    WEB_GEMINI = "web_gemini"    # Scan web com IA Gemini
    HYBRID = "hybrid"            # Combinação de modos


class ScanPhase(Enum):
    """Fases do scan"""
    INITIALIZATION = "initialization"
    RECONNAISSANCE = "reconnaissance"
    DISCOVERY = "discovery"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"


@dataclass
class ScanTarget:
    """Informações sobre um alvo de scan"""
    identifier: str                    # IP, URL, ou domínio
    target_type: str                   # "ip", "domain", "url"
    discovered_by: str                 # Nome da estratégia que descobriu
    confidence: float = 1.0            # Confiança na validade do alvo
    metadata: Dict[str, Any] = field(default_factory=dict)  # Metadados adicionais


@dataclass
class ServiceInfo:
    """Informações sobre um serviço detectado"""
    host: str
    port: int
    service_name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    state: str = "open"
    confidence: float = 1.0
    detected_by: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityInfo:
    """Informações sobre uma vulnerabilidade encontrada"""
    vuln_id: str                       # ID único da vulnerabilidade
    name: str                          # Nome da vulnerabilidade
    description: str                   # Descrição
    severity: str                      # "critical", "high", "medium", "low", "info"
    cvss_score: Optional[float] = None # Score CVSS se disponível
    cve_id: Optional[str] = None       # CVE ID se aplicável
    affected_service: Optional[ServiceInfo] = None
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    discovered_by: str = ""
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionMetrics:
    """Métricas de execução das estratégias"""
    total_strategies_executed: int = 0
    successful_strategies: int = 0
    failed_strategies: int = 0
    total_execution_time: float = 0.0
    strategy_times: Dict[str, float] = field(default_factory=dict)
    strategy_results: Dict[str, bool] = field(default_factory=dict)


class ScanContext:
    """
    Contexto compartilhado entre estratégias durante execução do scan
    
    Contém todo o estado acumulativo do scan, incluindo alvos descobertos,
    serviços detectados, vulnerabilidades encontradas e configurações.
    """
    
    def __init__(self, initial_target: str, scan_mode: ScanMode = ScanMode.NETWORK):
        # Identificação do scan
        self.scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.initial_target = initial_target
        self.scan_mode = scan_mode
        self.current_phase = ScanPhase.INITIALIZATION
        
        # Timestamps
        self.start_time = datetime.now()
        self.last_update = datetime.now()
        self.end_time: Optional[datetime] = None
        
        # Eventos e logs (inicializar antes de add_target)
        self.events: List[Dict[str, Any]] = []
        self.execution_log: List[str] = []
        
        # Alvos descobertos
        self.targets: Dict[str, ScanTarget] = {}
        self.add_target(initial_target, "initial", "user_input")
        
        # Descobertas
        self.discovered_hosts: Set[str] = set()
        self.open_ports: Dict[str, List[int]] = {}  # host -> [portas]
        self.services: Dict[str, List[ServiceInfo]] = {}  # host -> [serviços]
        self.vulnerabilities: List[VulnerabilityInfo] = []
        self.technologies: Dict[str, Dict[str, Any]] = {}  # host -> {tech: version}
        self.subdomains: Set[str] = set()
        self.web_directories: Dict[str, List[str]] = {}  # host -> [paths]
        
        # Estado de execução
        self.executed_strategies: List[str] = []
        self.current_strategy: Optional[str] = None
        self.strategy_queue: List[str] = []
        self.failed_strategies: Dict[str, str] = {}  # strategy -> error
        
        # Configurações e preferências
        self.config: Dict[str, Any] = {}
        self.user_preferences: Dict[str, Any] = {}
        self.resource_limits: Dict[str, Any] = {
            "max_execution_time": 3600,  # 1 hora
            "max_concurrent_strategies": 3,
            "memory_limit_mb": 1024
        }
        
        # Métricas
        self.metrics = ExecutionMetrics()
        
        # Dados específicos por estratégia
        self.strategy_data: Dict[str, Dict[str, Any]] = {}
        
        # Estados de conclusão
        self.is_completed = False
        self.completion_reason = ""
        
        # Cache para evitar reexecução desnecessária
        self.cache: Dict[str, Any] = {}
    
    def add_target(self, identifier: str, target_type: str, discovered_by: str, 
                  confidence: float = 1.0, metadata: Dict[str, Any] = None) -> bool:
        """
        Adiciona um novo alvo ao contexto
        
        Args:
            identifier: Identificador do alvo (IP, URL, domínio)
            target_type: Tipo do alvo ("ip", "domain", "url")
            discovered_by: Nome da estratégia que descobriu
            confidence: Confiança na validade (0-1)
            metadata: Metadados adicionais
            
        Returns:
            True se adicionado, False se já existia
        """
        if identifier in self.targets:
            return False
            
        self.targets[identifier] = ScanTarget(
            identifier=identifier,
            target_type=target_type,
            discovered_by=discovered_by,
            confidence=confidence,
            metadata=metadata or {}
        )
        
        # Adicionar aos conjuntos específicos conforme o tipo
        if target_type == "ip":
            self.discovered_hosts.add(identifier)
        elif target_type == "domain":
            self.subdomains.add(identifier)
        
        self._update_timestamp()
        self._log_event("target_discovered", {
            "target": identifier,
            "type": target_type,
            "discovered_by": discovered_by
        })
        
        return True
    
    def add_open_ports(self, host: str, ports: List[int], discovered_by: str = "") -> None:
        """
        Adiciona portas abertas para um host
        
        Args:
            host: Host/IP
            ports: Lista de portas abertas
            discovered_by: Estratégia que descobriu
        """
        if host not in self.open_ports:
            self.open_ports[host] = []
        
        new_ports = []
        for port in ports:
            if port not in self.open_ports[host]:
                self.open_ports[host].append(port)
                new_ports.append(port)
        
        if new_ports:
            self._update_timestamp()
            self._log_event("ports_discovered", {
                "host": host,
                "ports": new_ports,
                "discovered_by": discovered_by
            })
    
    def add_service(self, service: ServiceInfo) -> None:
        """
        Adiciona informações de um serviço
        
        Args:
            service: Informações do serviço
        """
        if service.host not in self.services:
            self.services[service.host] = []
        
        # Verificar se serviço já existe (mesmo host e porta)
        for existing in self.services[service.host]:
            if existing.port == service.port:
                # Atualizar informações se a nova é mais confiável
                if service.confidence > existing.confidence:
                    self.services[service.host].remove(existing)
                    self.services[service.host].append(service)
                return
        
        # Adicionar novo serviço
        self.services[service.host].append(service)
        self._update_timestamp()
        self._log_event("service_discovered", {
            "host": service.host,
            "port": service.port,
            "service": service.service_name,
            "discovered_by": service.detected_by
        })
    
    def add_vulnerability(self, vulnerability: VulnerabilityInfo) -> None:
        """
        Adiciona uma vulnerabilidade encontrada
        
        Args:
            vulnerability: Informações da vulnerabilidade
        """
        # Verificar duplicatas baseado no ID
        for existing in self.vulnerabilities:
            if existing.vuln_id == vulnerability.vuln_id:
                # Atualizar se a nova é mais confiável
                if vulnerability.confidence > existing.confidence:
                    self.vulnerabilities.remove(existing)
                    self.vulnerabilities.append(vulnerability)
                return
        
        self.vulnerabilities.append(vulnerability)
        self._update_timestamp()
        self._log_event("vulnerability_discovered", {
            "vuln_id": vulnerability.vuln_id,
            "name": vulnerability.name,
            "severity": vulnerability.severity,
            "discovered_by": vulnerability.discovered_by
        })
    
    def set_technologies(self, host: str, technologies: Dict[str, Any], discovered_by: str = "") -> None:
        """
        Define tecnologias detectadas para um host
        
        Args:
            host: Host/URL
            technologies: Dicionário com tecnologias detectadas
            discovered_by: Estratégia que detectou
        """
        self.technologies[host] = technologies
        self._update_timestamp()
        self._log_event("technologies_detected", {
            "host": host,
            "technologies": list(technologies.keys()),
            "discovered_by": discovered_by
        })
    
    def add_web_directories(self, host: str, directories: List[str], discovered_by: str = "") -> None:
        """
        Adiciona diretórios web descobertos
        
        Args:
            host: Host/URL
            directories: Lista de diretórios/arquivos
            discovered_by: Estratégia que descobriu
        """
        if host not in self.web_directories:
            self.web_directories[host] = []
        
        new_dirs = []
        for directory in directories:
            if directory not in self.web_directories[host]:
                self.web_directories[host].append(directory)
                new_dirs.append(directory)
        
        if new_dirs:
            self._update_timestamp()
            self._log_event("directories_discovered", {
                "host": host,
                "directories": new_dirs,
                "discovered_by": discovered_by
            })
    
    def start_strategy(self, strategy_name: str) -> None:
        """
        Marca o início da execução de uma estratégia
        
        Args:
            strategy_name: Nome da estratégia
        """
        self.current_strategy = strategy_name
        if strategy_name not in self.executed_strategies:
            self.executed_strategies.append(strategy_name)
        
        self._update_timestamp()
        self._log_event("strategy_started", {
            "strategy": strategy_name,
            "phase": self.current_phase.value
        })
    
    def complete_strategy(self, strategy_name: str, success: bool, execution_time: float = 0.0, error: str = "") -> None:
        """
        Marca a conclusão de uma estratégia
        
        Args:
            strategy_name: Nome da estratégia
            success: Se foi bem-sucedida
            execution_time: Tempo de execução em segundos
            error: Mensagem de erro se aplicável
        """
        self.current_strategy = None
        
        # Atualizar métricas
        self.metrics.total_strategies_executed += 1
        self.metrics.strategy_times[strategy_name] = execution_time
        self.metrics.strategy_results[strategy_name] = success
        self.metrics.total_execution_time += execution_time
        
        if success:
            self.metrics.successful_strategies += 1
        else:
            self.metrics.failed_strategies += 1
            if error:
                self.failed_strategies[strategy_name] = error
        
        self._update_timestamp()
        self._log_event("strategy_completed", {
            "strategy": strategy_name,
            "success": success,
            "execution_time": execution_time,
            "error": error if error else None
        })
    
    def set_strategy_data(self, strategy_name: str, data: Dict[str, Any]) -> None:
        """
        Armazena dados específicos de uma estratégia
        
        Args:
            strategy_name: Nome da estratégia
            data: Dados a armazenar
        """
        self.strategy_data[strategy_name] = data
        self._update_timestamp()
    
    def get_strategy_data(self, strategy_name: str) -> Dict[str, Any]:
        """
        Recupera dados de uma estratégia
        
        Args:
            strategy_name: Nome da estratégia
            
        Returns:
            Dados da estratégia ou dicionário vazio
        """
        return self.strategy_data.get(strategy_name, {})
    
    def update_phase(self, new_phase: ScanPhase) -> None:
        """
        Atualiza a fase atual do scan
        
        Args:
            new_phase: Nova fase
        """
        old_phase = self.current_phase
        self.current_phase = new_phase
        self._update_timestamp()
        self._log_event("phase_changed", {
            "old_phase": old_phase.value,
            "new_phase": new_phase.value
        })
    
    def complete_scan(self, reason: str = "completed") -> None:
        """
        Marca o scan como completo
        
        Args:
            reason: Motivo da conclusão
        """
        self.is_completed = True
        self.completion_reason = reason
        self.end_time = datetime.now()
        self.current_phase = ScanPhase.COMPLETED
        
        self._log_event("scan_completed", {
            "reason": reason,
            "total_time": self.get_total_execution_time(),
            "strategies_executed": len(self.executed_strategies)
        })
    
    def get_total_execution_time(self) -> float:
        """
        Retorna tempo total de execução em segundos
        
        Returns:
            Tempo em segundos
        """
        end_time = self.end_time or datetime.now()
        return (end_time - self.start_time).total_seconds()
    
    def get_discovered_targets_by_type(self, target_type: str) -> List[ScanTarget]:
        """
        Retorna alvos descobertos de um tipo específico
        
        Args:
            target_type: Tipo do alvo ("ip", "domain", "url")
            
        Returns:
            Lista de alvos do tipo especificado
        """
        return [target for target in self.targets.values() if target.target_type == target_type]
    
    def get_services_by_host(self, host: str) -> List[ServiceInfo]:
        """
        Retorna serviços de um host específico
        
        Args:
            host: Host a consultar
            
        Returns:
            Lista de serviços do host
        """
        return self.services.get(host, [])
    
    def get_vulnerabilities_by_severity(self, severity: str) -> List[VulnerabilityInfo]:
        """
        Retorna vulnerabilidades de uma severidade específica
        
        Args:
            severity: Severidade ("critical", "high", "medium", "low", "info")
            
        Returns:
            Lista de vulnerabilidades da severidade especificada
        """
        return [vuln for vuln in self.vulnerabilities if vuln.severity == severity]
    
    def has_capability_data(self, capability: str) -> bool:
        """
        Verifica se há dados para uma capacidade específica
        
        Args:
            capability: Nome da capacidade ("ports", "services", "vulnerabilities", etc.)
            
        Returns:
            True se há dados, False caso contrário
        """
        capability_checks = {
            "hosts": bool(self.discovered_hosts),
            "ports": bool(self.open_ports),
            "services": bool(self.services),
            "vulnerabilities": bool(self.vulnerabilities),
            "technologies": bool(self.technologies),
            "subdomains": bool(self.subdomains),
            "directories": bool(self.web_directories)
        }
        
        return capability_checks.get(capability, False)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte contexto para dicionário serializável
        
        Returns:
            Representação em dicionário
        """
        return {
            "scan_id": self.scan_id,
            "initial_target": self.initial_target,
            "scan_mode": self.scan_mode.value,
            "current_phase": self.current_phase.value,
            "start_time": self.start_time.isoformat(),
            "last_update": self.last_update.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "discovered_hosts": list(self.discovered_hosts),
            "open_ports": self.open_ports,
            "services_count": sum(len(services) for services in self.services.values()),
            "vulnerabilities_count": len(self.vulnerabilities),
            "technologies_count": sum(len(techs) for techs in self.technologies.values()),
            "subdomains_count": len(self.subdomains),
            "executed_strategies": self.executed_strategies,
            "metrics": {
                "total_strategies_executed": self.metrics.total_strategies_executed,
                "successful_strategies": self.metrics.successful_strategies,
                "failed_strategies": self.metrics.failed_strategies,
                "total_execution_time": self.metrics.total_execution_time
            },
            "is_completed": self.is_completed,
            "completion_reason": self.completion_reason
        }
    
    def _update_timestamp(self) -> None:
        """Atualiza timestamp da última modificação"""
        self.last_update = datetime.now()
    
    def _log_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        Registra um evento no contexto
        
        Args:
            event_type: Tipo do evento
            data: Dados do evento
        """
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "data": data
        }
        self.events.append(event)
        
        # Manter apenas os últimos 1000 eventos para evitar uso excessivo de memória
        if len(self.events) > 1000:
            self.events = self.events[-1000:]
