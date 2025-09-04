"""
Interface base para plugins do VarreduraIA
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
import time


@dataclass
class PluginResult:
    """Resultado da execução de um plugin"""
    success: bool
    plugin_name: str
    execution_time: float
    data: Dict[str, Any]
    error: Optional[str] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte o resultado para dicionário"""
        return {
            'success': self.success,
            'plugin_name': self.plugin_name,
            'execution_time': self.execution_time,
            'data': self.data,
            'error': self.error,
            'timestamp': self.timestamp
        }


class BasePlugin(ABC):
    """Classe base para todos os plugins"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.description = ""
        self.version = "1.0.0"
        self.author = "VarreduraIA"
        self.category = "general"
        self.requirements = []  # Lista de dependências
        self.supported_targets = ["ip", "domain", "url"]  # Tipos de alvo suportados
        self.config = {}  # Configurações específicas do plugin
        
    @abstractmethod
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """
        Executa o plugin no alvo especificado
        
        Args:
            target: Alvo da varredura (IP, domínio, URL, etc.)
            context: Contexto atual da varredura (dados de outros plugins)
            **kwargs: Parâmetros adicionais
            
        Returns:
            PluginResult com os resultados da execução
        """
        pass
    
    def validate_target(self, target: str) -> bool:
        """
        Valida se o plugin pode ser executado no alvo
        
        Args:
            target: Alvo da varredura
            
        Returns:
            True se o plugin pode ser executado
        """
        return True
    
    def get_info(self) -> Dict[str, Any]:
        """Retorna informações sobre o plugin"""
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'author': self.author,
            'category': self.category,
            'requirements': self.requirements,
            'supported_targets': self.supported_targets
        }
    
    def _measure_execution_time(self, func, *args, **kwargs):
        """Mede tempo de execução de uma função"""
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            return result, execution_time, None
        except Exception as e:
            execution_time = time.time() - start_time
            return None, execution_time, str(e)


class NetworkPlugin(BasePlugin):
    """Plugin base para varreduras de rede"""
    
    def __init__(self):
        super().__init__()
        self.category = "network"
        self.supported_targets = ["ip", "cidr", "domain"]
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Implementação padrão - deve ser sobrescrita por plugins filhos"""
        return PluginResult(
            success=False,
            plugin_name=self.name,
            execution_time=0.0,
            data={},
            error="Plugin não implementou método execute()"
        )


class WebPlugin(BasePlugin):
    """Plugin base para varreduras web"""
    
    def __init__(self):
        super().__init__()
        self.category = "web"
        self.supported_targets = ["url", "domain"]
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Implementação padrão - deve ser sobrescrita por plugins filhos"""
        return PluginResult(
            success=False,
            plugin_name=self.name,
            execution_time=0.0,
            data={},
            error="Plugin não implementou método execute()"
        )


class VulnerabilityPlugin(BasePlugin):
    """Plugin base para detecção de vulnerabilidades"""
    
    def __init__(self):
        super().__init__()
        self.category = "vulnerability"
        self.supported_targets = ["ip", "domain", "url"]
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Implementação padrão - deve ser sobrescrita por plugins filhos"""
        return PluginResult(
            success=False,
            plugin_name=self.name,
            execution_time=0.0,
            data={},
            error="Plugin não implementou método execute()"
        )
