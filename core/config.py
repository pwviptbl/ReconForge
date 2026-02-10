"""
Configuração do sistema ReconForge simplificado
Integra variáveis de ambiente (.env) com configuração YAML
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

# Carrega variáveis do arquivo .env automaticamente
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).parent.parent / ".env"
    load_dotenv(_env_path, override=False)
except ImportError:
    pass  # python-dotenv opcional — funciona sem ele


# Mapeamento de variáveis de ambiente para caminhos na configuração YAML
# Formato: NOME_DA_VARIAVEL -> caminho.dotado.no.yaml
_ENV_OVERRIDES = {
    'GEMINI_API_KEY': 'ai.gemini.api_key',
    'LOG_LEVEL': 'logging.level',
    'LOG_DIR': 'logging.file',
}


class Config:
    """Classe de configuração centralizada"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_dir = Path(__file__).parent.parent / "config"  # Pasta config/ na raiz
        self.default_config_file = self.config_dir / "default.yaml"
        self.user_config_file = config_file
        self._config = {}
        self._load_config()
        self._apply_env_overrides()
    
    def _load_config(self):
        """Carrega configuração dos arquivos"""
        # Carregar configuração padrão
        if self.default_config_file.exists():
            with open(self.default_config_file, 'r', encoding='utf-8') as f:
                self._config = yaml.safe_load(f) or {}
        
        # Sobrescrever com configuração do usuário se especificada
        if self.user_config_file and Path(self.user_config_file).exists():
            with open(self.user_config_file, 'r', encoding='utf-8') as f:
                user_config = yaml.safe_load(f) or {}
                self._merge_configs(self._config, user_config)
    
    def _apply_env_overrides(self):
        """Aplica variáveis de ambiente sobre a configuração YAML"""
        for env_var, config_path in _ENV_OVERRIDES.items():
            value = os.environ.get(env_var)
            if value:
                self.set(config_path, value)
    
    def _merge_configs(self, base: Dict, override: Dict):
        """Merge recursivo de configurações"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_configs(base[key], value)
            else:
                base[key] = value
    
    def get(self, path: str, default=None):
        """
        Obtém valor da configuração usando notação de ponto
        Ex: config.get('ai.gemini.api_key')
        """
        keys = path.split('.')
        value = self._config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, path: str, value: Any):
        """Define valor na configuração"""
        keys = path.split('.')
        config = self._config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
    
    def save_config(self, config_file: Optional[str] = None):
        """Salva configuração atual em arquivo"""
        target_file = config_file or self.default_config_file
        
        with open(target_file, 'w', encoding='utf-8') as f:
            yaml.dump(self._config, f, default_flow_style=False, allow_unicode=True)
    
    @property
    def all(self) -> Dict[str, Any]:
        """Retorna toda a configuração"""
        return self._config.copy()


# Instância global
_config = None

def get_config(path: str = None, default=None, config_file: Optional[str] = None):
    """Função para acessar configuração globalmente"""
    global _config
    
    if _config is None:
        _config = Config(config_file)
    
    if path is None:
        return _config.all
    
    return _config.get(path, default)

