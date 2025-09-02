#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interface para camada de persistência - Fase 1 da Refatoração

Define contrato para persistência de dados permitindo
diferentes implementações (arquivo, banco, etc.).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from enum import Enum
from datetime import datetime


class StorageBackend(Enum):
    """Tipos de backend de armazenamento"""
    FILE_JSON = "file_json"
    FILE_PICKLE = "file_pickle"
    SQLITE = "sqlite"
    MONGODB = "mongodb"
    POSTGRESQL = "postgresql"
    REDIS = "redis"


class DataFormat(Enum):
    """Formatos de dados suportados"""
    JSON = "json"
    PICKLE = "pickle"
    BINARY = "binary"
    TEXT = "text"


class IPersistenceLayer(ABC):
    """Interface para camada de persistência"""
    
    @property
    @abstractmethod
    def backend_type(self) -> StorageBackend:
        """Tipo de backend utilizado"""
        pass
    
    @abstractmethod
    def save_scan_result(self, scan_id: str, data: Dict[str, Any], 
                        metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Salva resultado de um scan
        
        Args:
            scan_id: Identificador único do scan
            data: Dados do resultado
            metadata: Metadados opcionais
            
        Returns:
            True se salvou com sucesso, False caso contrário
        """
        pass
    
    @abstractmethod
    def load_scan_result(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Carrega resultado de um scan
        
        Args:
            scan_id: Identificador do scan
            
        Returns:
            Dados do scan ou None se não encontrado
        """
        pass
    
    @abstractmethod
    def delete_scan_result(self, scan_id: str) -> bool:
        """
        Remove resultado de um scan
        
        Args:
            scan_id: Identificador do scan
            
        Returns:
            True se removeu com sucesso, False caso contrário
        """
        pass
    
    @abstractmethod
    def list_scan_results(self, target: Optional[str] = None, 
                         start_date: Optional[datetime] = None,
                         end_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Lista resultados de scans com filtros opcionais
        
        Args:
            target: Filtrar por alvo específico
            start_date: Data inicial
            end_date: Data final
            
        Returns:
            Lista de metadados dos scans encontrados
        """
        pass
    
    @abstractmethod
    def save_configuration(self, config_name: str, config_data: Dict[str, Any]) -> bool:
        """
        Salva configuração
        
        Args:
            config_name: Nome da configuração
            config_data: Dados da configuração
            
        Returns:
            True se salvou com sucesso
        """
        pass
    
    @abstractmethod
    def load_configuration(self, config_name: str) -> Optional[Dict[str, Any]]:
        """
        Carrega configuração
        
        Args:
            config_name: Nome da configuração
            
        Returns:
            Dados da configuração ou None se não encontrado
        """
        pass
    
    @abstractmethod
    def backup_data(self, backup_path: str) -> bool:
        """
        Cria backup dos dados
        
        Args:
            backup_path: Caminho para salvar backup
            
        Returns:
            True se backup criado com sucesso
        """
        pass
    
    @abstractmethod
    def restore_data(self, backup_path: str) -> bool:
        """
        Restaura dados de um backup
        
        Args:
            backup_path: Caminho do backup
            
        Returns:
            True se restaurado com sucesso
        """
        pass
    
    @abstractmethod
    def get_storage_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas do armazenamento
        
        Returns:
            Estatísticas como tamanho, número de registros, etc.
        """
        pass
    
    def is_available(self) -> bool:
        """
        Verifica se o backend está disponível
        
        Returns:
            True se disponível, False caso contrário
        """
        return True  # Implementação padrão


class ICacheLayer(ABC):
    """Interface para camada de cache"""
    
    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """
        Recupera valor do cache
        
        Args:
            key: Chave do cache
            
        Returns:
            Valor armazenado ou None se não encontrado
        """
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Armazena valor no cache
        
        Args:
            key: Chave do cache
            value: Valor a armazenar
            ttl: Tempo de vida em segundos (None para permanente)
            
        Returns:
            True se armazenado com sucesso
        """
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """
        Remove valor do cache
        
        Args:
            key: Chave a remover
            
        Returns:
            True se removido com sucesso
        """
        pass
    
    @abstractmethod
    def clear(self) -> bool:
        """
        Limpa todo o cache
        
        Returns:
            True se limpo com sucesso
        """
        pass
    
    @abstractmethod
    def exists(self, key: str) -> bool:
        """
        Verifica se chave existe no cache
        
        Args:
            key: Chave a verificar
            
        Returns:
            True se existe, False caso contrário
        """
        pass
