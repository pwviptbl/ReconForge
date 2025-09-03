"""
Gerenciador de plugins para VarreduraIA
Carrega, gerencia e executa plugins de forma dinâmica
"""

import os
import sys
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Type
import inspect

from .plugin_base import BasePlugin, PluginResult, NetworkPlugin, WebPlugin, VulnerabilityPlugin
from .config import get_config
from utils.logger import get_logger


class PluginManager:
    """Gerenciador de plugins"""
    
    def __init__(self, plugins_dir: Optional[str] = None):
        self.logger = get_logger('PluginManager')
        self.plugins_dir = Path(plugins_dir or get_config('plugins.directory', 'plugins'))
        self.plugins: Dict[str, BasePlugin] = {}
        self.plugin_classes: Dict[str, Type[BasePlugin]] = {}
        
        # Criar diretório de plugins se não existir
        self.plugins_dir.mkdir(exist_ok=True)
        
        # Carregar plugins
        self._load_plugins()
    
    def _load_plugins(self):
        """Carrega todos os plugins do diretório"""
        self.logger.info(f"🔍 Carregando plugins de: {self.plugins_dir}")
        
        # Adicionar diretório de plugins ao path
        sys.path.insert(0, str(self.plugins_dir))
        
        plugin_files = list(self.plugins_dir.glob("*.py"))
        
        for plugin_file in plugin_files:
            if plugin_file.name.startswith('_'):
                continue  # Pular arquivos que começam com _
                
            try:
                self._load_plugin_file(plugin_file)
            except Exception as e:
                self.logger.error(f"❌ Erro ao carregar {plugin_file.name}: {e}")
        
        self.logger.info(f"✅ {len(self.plugins)} plugins carregados")
    
    def _load_plugin_file(self, plugin_file: Path):
        """Carrega um arquivo de plugin específico"""
        module_name = plugin_file.stem
        
        # Importar módulo
        spec = importlib.util.spec_from_file_location(module_name, plugin_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Encontrar classes que herdam de BasePlugin (mas não são classes base)
        base_classes = {BasePlugin, NetworkPlugin, WebPlugin, VulnerabilityPlugin}
        
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj) and 
                issubclass(obj, BasePlugin) and 
                obj not in base_classes):
                
                # Instanciar plugin
                plugin_instance = obj()
                plugin_name = plugin_instance.name
                
                self.plugins[plugin_name] = plugin_instance
                self.plugin_classes[plugin_name] = obj
                
                self.logger.debug(f"  📦 {plugin_name} ({plugin_instance.category})")
    
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Obtém plugin pelo nome"""
        return self.plugins.get(name)
    
    def list_plugins(self, category: Optional[str] = None) -> List[BasePlugin]:
        """Lista plugins disponíveis, opcionalmente filtrados por categoria"""
        plugins = list(self.plugins.values())
        
        if category:
            plugins = [p for p in plugins if p.category == category]
        
        return plugins
    
    def get_plugin_info(self, name: str) -> Optional[Dict]:
        """Obtém informações detalhadas de um plugin"""
        plugin = self.get_plugin(name)
        return plugin.get_info() if plugin else None
    
    def execute_plugin(self, name: str, target: str, context: Dict, **kwargs) -> PluginResult:
        """
        Executa um plugin específico
        
        Args:
            name: Nome do plugin
            target: Alvo da varredura
            context: Contexto atual
            **kwargs: Parâmetros adicionais
            
        Returns:
            PluginResult com resultado da execução
        """
        plugin = self.get_plugin(name)
        
        if not plugin:
            return PluginResult(
                success=False,
                plugin_name=name,
                execution_time=0.0,
                data={},
                error=f"Plugin '{name}' não encontrado"
            )
        
        # Validar alvo
        if not plugin.validate_target(target):
            return PluginResult(
                success=False,
                plugin_name=name,
                execution_time=0.0,
                data={},
                error=f"Alvo '{target}' não é válido para o plugin '{name}'"
            )
        
        # Executar plugin
        self.logger.info(f"🚀 Executando plugin: {name}")
        
        try:
            result = plugin.execute(target, context, **kwargs)
            
            if result.success:
                self.logger.info(f"✅ {name} executado com sucesso ({result.execution_time:.2f}s)")
            else:
                self.logger.warning(f"⚠️ {name} falhou: {result.error}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"💥 Erro na execução de {name}: {e}")
            return PluginResult(
                success=False,
                plugin_name=name,
                execution_time=0.0,
                data={},
                error=str(e)
            )
    
    def get_suitable_plugins(self, target: str, context: Dict) -> List[str]:
        """
        Retorna lista de plugins adequados para o alvo e contexto
        
        Args:
            target: Alvo da varredura
            context: Contexto atual
            
        Returns:
            Lista de nomes de plugins adequados
        """
        suitable = []
        
        for name, plugin in self.plugins.items():
            if plugin.validate_target(target):
                suitable.append(name)
        
        return suitable
    
    def get_plugins_by_category(self, category: str) -> List[str]:
        """Retorna plugins de uma categoria específica"""
        return [
            name for name, plugin in self.plugins.items()
            if plugin.category == category
        ]
    
    def reload_plugins(self):
        """Recarrega todos os plugins"""
        self.logger.info("🔄 Recarregando plugins...")
        self.plugins.clear()
        self.plugin_classes.clear()
        self._load_plugins()
    
    def get_plugin_categories(self) -> List[str]:
        """Retorna todas as categorias de plugins disponíveis"""
        categories = set()
        for plugin in self.plugins.values():
            categories.add(plugin.category)
        return sorted(list(categories))
