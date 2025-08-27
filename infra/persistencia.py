#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Camada de persistência para resultados e utilidades de arquivos.
"""

import json
from pathlib import Path
from typing import Dict, Any

from utils.logger import obter_logger


logger = obter_logger("Persistencia")


def garantir_diretorio(caminho_arquivo: str) -> Path:
    """
    Garante que o diretório pai do arquivo exista.
    Args:
        caminho_arquivo: Caminho do arquivo (string)
    Returns:
        Path: Objeto Path para o arquivo
    """
    p = Path(caminho_arquivo)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def salvar_json_resultados(resultados: Dict[str, Any], arquivo: str) -> bool:
    """
    Salva resultados em arquivo JSON.
    Mantém compatibilidade com a versão anterior: se o caminho não começar com 'dados/',
    salva automaticamente dentro de dados/ com o nome base do arquivo.
    Args:
        resultados: Dicionário com os resultados
        arquivo: Caminho do arquivo alvo
    Returns:
        bool: True em caso de sucesso
    """
    try:
        # Compatibilidade com comportamento anterior do main
        if not arquivo.startswith('dados/'):
            arquivo = f"dados/{Path(arquivo).name}"

        caminho = garantir_diretorio(arquivo)
        with caminho.open('w', encoding='utf-8') as f:
            json.dump(resultados, f, indent=2, ensure_ascii=False)

        logger.info(f"Resultados salvos em: {caminho}")
        return True
    except Exception as e:
        logger.error(f"Erro ao salvar resultados: {str(e)}")
        return False