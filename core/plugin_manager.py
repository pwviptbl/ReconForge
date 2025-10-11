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
                
                # Verificar se o plugin está habilitado na configuração
                plugin_class_name = obj.__name__
                is_enabled = get_config(f'plugins.enabled.{plugin_class_name}')
                
                # Se não está definido na configuração, usar True como padrão
                # Mas se está explicitamente definido como False, respeitar
                if is_enabled is False:
                    self.logger.info(f"  ⏭️ {plugin_class_name} desabilitado na configuração")
                    continue
                elif is_enabled is None:
                    # Plugin não configurado, usar padrão True
                    is_enabled = True
                
                # Instanciar plugin
                plugin_instance = obj()

                # Verificar dependências
                if not self._check_dependencies(plugin_instance):
                    continue

                plugin_name = plugin_instance.name
                
                # Aplicar configurações específicas do plugin se existirem
                plugin_config = get_config(f'plugins.config.{plugin_class_name}', {})
                if plugin_config:
                    plugin_instance.config.update(plugin_config)
                
                self.plugins[plugin_name] = plugin_instance
                self.plugin_classes[plugin_name] = obj
                
                self.logger.debug(f"  📦 {plugin_name} ({plugin_instance.category})")

    def _check_dependencies(self, plugin: BasePlugin) -> bool:
        """Verifica se as dependências de um plugin estão instaladas."""
        if not plugin.requirements:
            return True

        for requirement in plugin.requirements:
            try:
                if importlib.util.find_spec(requirement) is None:
                    self.logger.warning(
                        f"  ⏭️ Plugin '{plugin.name}' desabilitado: "
                        f"dependência '{requirement}' não encontrada."
                    )
                    return False
            except ModuleNotFoundError:
                self.logger.warning(
                    f"  ⏭️ Plugin '{plugin.name}' desabilitado: "
                    f"dependência '{requirement}' não encontrada."
                )
                return False

        return True
    
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
    
    def list_enabled_plugins(self) -> Dict[str, bool]:
        """Retorna dicionário com status de todos os plugins (habilitado/desabilitado)"""
        enabled_status = {}
        
        # Verificar plugins carregados (habilitados)
        for plugin_name, plugin in self.plugins.items():
            plugin_class_name = plugin.__class__.__name__
            enabled_status[plugin_class_name] = True
        
        # Verificar plugins desabilitados na configuração
        all_plugin_configs = get_config('plugins.enabled', {})
        for plugin_class_name, is_enabled in all_plugin_configs.items():
            if not is_enabled and plugin_class_name not in [p.__class__.__name__ for p in self.plugins.values()]:
                enabled_status[plugin_class_name] = False
        
        return enabled_status
    
    def enable_plugin(self, plugin_class_name: str) -> bool:
        """
        Habilita um plugin específico (atualiza configuração e recarrega)
        
        Args:
            plugin_class_name: Nome da classe do plugin
            
        Returns:
            True se foi habilitado com sucesso
        """
        try:
            # Atualizar configuração global (isso requer acesso à instância de Config)
            from .config import _config
            if _config:
                _config.set(f'plugins.enabled.{plugin_class_name}', True)
                _config.save_config()  # Salvar no arquivo
                self.logger.info(f"✅ Plugin {plugin_class_name} habilitado")
                return True
            return False
        except Exception as e:
            self.logger.error(f"❌ Erro ao habilitar plugin {plugin_class_name}: {e}")
            return False
    
    def disable_plugin(self, plugin_class_name: str) -> bool:
        """
        Desabilita um plugin específico (atualiza configuração e recarrega)
        
        Args:
            plugin_class_name: Nome da classe do plugin
            
        Returns:
            True se foi desabilitado com sucesso
        """
        try:
            # Atualizar configuração global
            from .config import _config
            if _config:
                _config.set(f'plugins.enabled.{plugin_class_name}', False)
                _config.save_config()  # Salvar no arquivo
                
                # Remover plugin dos plugins carregados se estiver presente
                plugin_to_remove = None
                for plugin_name, plugin in self.plugins.items():
                    if plugin.__class__.__name__ == plugin_class_name:
                        plugin_to_remove = plugin_name
                        break
                
                if plugin_to_remove:
                    del self.plugins[plugin_to_remove]
                    del self.plugin_classes[plugin_to_remove]
                
                self.logger.info(f"❌ Plugin {plugin_class_name} desabilitado")
                return True
            return False
        except Exception as e:
            self.logger.error(f"❌ Erro ao desabilitar plugin {plugin_class_name}: {e}")
            return False
    
    def get_plugin_config(self, plugin_class_name: str) -> Dict:
        """Obtém configuração específica de um plugin"""
        return get_config(f'plugins.config.{plugin_class_name}', {})
    
    def update_plugin_config(self, plugin_class_name: str, config_updates: Dict) -> bool:
        """
        Atualiza configuração específica de um plugin
        
        Args:
            plugin_class_name: Nome da classe do plugin
            config_updates: Dicionário com as atualizações de configuração
            
        Returns:
            True se foi atualizado com sucesso
        """
        try:
            from .config import _config
            if _config:
                current_config = self.get_plugin_config(plugin_class_name)
                current_config.update(config_updates)
                _config.set(f'plugins.config.{plugin_class_name}', current_config)
                
                # Atualizar configuração do plugin se estiver carregado
                for plugin in self.plugins.values():
                    if plugin.__class__.__name__ == plugin_class_name:
                        plugin.config.update(config_updates)
                        break
                
                self.logger.info(f"🔧 Configuração do plugin {plugin_class_name} atualizada")
                return True
            return False
        except Exception as e:
            self.logger.error(f"❌ Erro ao atualizar configuração do plugin {plugin_class_name}: {e}")
            return False
