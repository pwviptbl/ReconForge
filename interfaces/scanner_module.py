#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interfaces base para módulos de scanner - Fase 1 da Refatoração

Define contratos claros para todos os módulos de scanner,
permitindo implementações intercambiáveis e testabilidade.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from enum import Enum


class ScannerCapability(Enum):
    """Capacidades que um scanner pode ter"""
    PORT_SCANNING = "port_scanning"
    SERVICE_DETECTION = "service_detection"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    WEB_SCANNING = "web_scanning"
    DNS_RESOLUTION = "dns_resolution"
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    DIRECTORY_SCANNING = "directory_scanning"
    TECHNOLOGY_DETECTION = "technology_detection"
    EXPLOIT_SEARCH = "exploit_search"


class ScannerPriority(Enum):
    """Prioridades de execução"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    OPTIONAL = 5


class IScannerModule(ABC):
    """Interface base para todos os módulos de scanner"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Nome identificador do módulo"""
        pass
    
    @property
    @abstractmethod
    def capabilities(self) -> List[ScannerCapability]:
        """Lista de capacidades que este módulo oferece"""
        pass
    
    @property
    @abstractmethod
    def priority(self) -> ScannerPriority:
        """Prioridade de execução deste módulo"""
        pass
    
    @abstractmethod
    def can_execute(self, context: Dict[str, Any]) -> bool:
        """
        Verifica se o módulo pode ser executado no contexto atual
        
        Args:
            context: Contexto de execução com informações sobre o alvo
            
        Returns:
            True se pode executar, False caso contrário
        """
        pass
    
    @abstractmethod
    def execute(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executa o scanner no alvo especificado
        
        Args:
            target: Alvo a ser escaneado (IP, URL, etc.)
            context: Contexto de execução
            
        Returns:
            Resultado da execução com formato padronizado
        """
        pass
    
    @abstractmethod
    def get_dependencies(self) -> List[ScannerCapability]:
        """
        Lista dependências necessárias de outros módulos
        
        Returns:
            Lista de capacidades que devem estar disponíveis antes da execução
        """
        pass
    
    @abstractmethod
    def estimate_time(self, target: str, context: Dict[str, Any]) -> int:
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
        Valida se o alvo é compatível com este módulo
        
        Args:
            target: Alvo a validar
            
        Returns:
            True se válido, False caso contrário
        """
        return True  # Implementação padrão aceita qualquer alvo
    
    def get_configuration_schema(self) -> Dict[str, Any]:
        """
        Retorna schema de configuração para este módulo
        
        Returns:
            Schema JSON descrevendo configurações aceitas
        """
        return {}  # Implementação padrão não requer configuração


class IPortScanner(IScannerModule):
    """Interface para scanners de porta"""
    
    @abstractmethod
    def scan_ports(self, target: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Escaneia portas específicas ou faixa padrão
        
        Args:
            target: IP ou hostname a escanear
            ports: Lista de portas específicas (None para faixa padrão)
            
        Returns:
            Resultado com portas abertas e informações detectadas
        """
        pass


class IServiceDetector(IScannerModule):
    """Interface para detectores de serviço"""
    
    @abstractmethod
    def detect_services(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """
        Detecta serviços rodando nas portas especificadas
        
        Args:
            target: IP ou hostname
            ports: Lista de portas abertas para analisar
            
        Returns:
            Informações sobre serviços detectados
        """
        pass


class IVulnerabilityScanner(IScannerModule):
    """Interface para scanners de vulnerabilidade"""
    
    @abstractmethod
    def scan_vulnerabilities(self, target: str, services: Dict[str, Any]) -> Dict[str, Any]:
        """
        Escaneia vulnerabilidades baseado nos serviços detectados
        
        Args:
            target: Alvo a escanear
            services: Serviços previamente detectados
            
        Returns:
            Lista de vulnerabilidades encontradas
        """
        pass


class IWebScanner(IScannerModule):
    """Interface para scanners web"""
    
    @abstractmethod
    def scan_web_application(self, url: str, credentials: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Escaneia aplicação web
        
        Args:
            url: URL base da aplicação
            credentials: Credenciais opcionais para autenticação
            
        Returns:
            Resultado da análise web
        """
        pass


class IDNSResolver(IScannerModule):
    """Interface para resolvedores DNS"""
    
    @abstractmethod
    def resolve_dns(self, domain: str) -> Dict[str, Any]:
        """
        Resolve informações DNS do domínio
        
        Args:
            domain: Domínio a resolver
            
        Returns:
            Informações DNS incluindo IPs, registros MX, etc.
        """
        pass


class ISubdomainEnumerator(IScannerModule):
    """Interface para enumeradores de subdomínio"""
    
    @abstractmethod
    def enumerate_subdomains(self, domain: str) -> Dict[str, Any]:
        """
        Enumera subdomínios do domínio principal
        
        Args:
            domain: Domínio principal
            
        Returns:
            Lista de subdomínios encontrados
        """
        pass


class IDirectoryScanner(IScannerModule):
    """Interface para scanners de diretório"""
    
    @abstractmethod
    def scan_directories(self, base_url: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """
        Escaneia diretórios e arquivos web
        
        Args:
            base_url: URL base para scanning
            wordlist: Wordlist personalizada (opcional)
            
        Returns:
            Diretórios e arquivos encontrados
        """
        pass


class ITechnologyDetector(IScannerModule):
    """Interface para detectores de tecnologia"""
    
    @abstractmethod
    def detect_technologies(self, url: str) -> Dict[str, Any]:
        """
        Detecta tecnologias utilizadas no site
        
        Args:
            url: URL a analisar
            
        Returns:
            Tecnologias detectadas (frameworks, CMS, etc.)
        """
        pass


class IExploitSearcher(IScannerModule):
    """Interface para buscadores de exploit"""
    
    @abstractmethod
    def search_exploits(self, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Busca exploits para serviços/vulnerabilidades encontradas
        
        Args:
            service_info: Informações sobre serviços e versões
            
        Returns:
            Lista de exploits disponíveis
        """
        pass
