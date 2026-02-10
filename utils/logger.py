"""
Sistema de logging com rotação automática de arquivos
"""

import logging
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


def setup_logger(
    name: str,
    verbose: bool = False,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Configura e retorna um logger com console e arquivo rotativo
    
    Args:
        name: Nome do logger
        verbose: Se True, mostra logs DEBUG
        log_file: Arquivo de log opcional (sobrescreve config YAML)
    
    Returns:
        Logger configurado
    """
    logger = logging.getLogger(name)
    
    # Evitar duplicação de handlers
    if logger.handlers:
        return logger
    
    # Nível de log
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    
    # Formato
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Handler para console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Handler para arquivo com rotação automática
    _target_file = log_file
    if not _target_file:
        # Tentar carregar da config YAML (importação tardia para evitar circular)
        try:
            from core.config import get_config
            _target_file = get_config('logging.file', None)
        except Exception:
            pass
    
    if _target_file:
        try:
            log_path = Path(_target_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Carregar limites da config ou usar padrões
            max_bytes = 10 * 1024 * 1024  # 10 MB padrão
            backup_count = 5
            try:
                from core.config import get_config
                max_bytes = int(get_config('logging.max_size_mb', 10)) * 1024 * 1024
                backup_count = int(get_config('logging.backup_count', 5))
            except Exception:
                pass
            
            file_handler = RotatingFileHandler(
                log_path,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception:
            pass  # Se falhar, segue apenas com console
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Obtém logger existente ou cria um básico"""
    logger = logging.getLogger(name)
    if not logger.handlers:
        return setup_logger(name)
    return logger

