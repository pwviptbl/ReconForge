#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interface para sistema de logging - Fase 1 da Refatoração

Define contrato para logger permitindo implementações
intercambiáveis e testabilidade.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from enum import Enum


class LogLevel(Enum):
    """Níveis de log"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ILogger(ABC):
    """Interface para sistema de logging"""
    
    @abstractmethod
    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log mensagem de debug"""
        pass
    
    @abstractmethod
    def info(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log mensagem informativa"""
        pass
    
    @abstractmethod
    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log mensagem de aviso"""
        pass
    
    @abstractmethod
    def error(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log mensagem de erro"""
        pass
    
    @abstractmethod
    def critical(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log mensagem crítica"""
        pass
    
    @abstractmethod
    def log(self, level: LogLevel, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log com nível específico"""
        pass
    
    @abstractmethod
    def set_level(self, level: LogLevel):
        """Define nível mínimo de log"""
        pass
    
    @abstractmethod
    def get_level(self) -> LogLevel:
        """Retorna nível atual de log"""
        pass


class ILoggerFactory(ABC):
    """Interface para factory de loggers"""
    
    @abstractmethod
    def create_logger(self, name: str) -> ILogger:
        """
        Cria um logger com nome específico
        
        Args:
            name: Nome do logger
            
        Returns:
            Instância do logger
        """
        pass
    
    @abstractmethod
    def configure(self, config: Dict[str, Any]):
        """
        Configura a factory com parâmetros específicos
        
        Args:
            config: Configuração do sistema de log
        """
        pass
