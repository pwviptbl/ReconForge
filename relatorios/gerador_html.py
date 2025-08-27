#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gerador de relatórios HTML usando Jinja2.

Responsável por renderizar templates HTML com base nos resultados produzidos
pelo orquestrador. Mantém compatibilidade com a estrutura atual de saída.
"""

from pathlib import Path
from typing import Dict, Any

from jinja2 import Environment, FileSystemLoader, select_autoescape, TemplateNotFound

from utils.logger import obter_logger


TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "relatorios"


def _criar_ambiente() -> Environment:
    """Cria e configura o ambiente Jinja2."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env


def gerar_relatorio_dns(resultados: Dict[str, Any], arquivo_saida: str) -> bool:
    """
    Gera relatório HTML específico para Resolução DNS.
    Args:
        resultados: Dicionário com resultados completos do fluxo.
        arquivo_saida: Caminho do arquivo HTML de saída (será criado se não existir).
    Returns:
        bool: True se gerou com sucesso.
    """
    logger = obter_logger("GeradorRelatorioHTML")

    try:
        # Preparar ambiente e template
        env = _criar_ambiente()
        try:
            template = env.get_template("dns_relatorio.html")
        except TemplateNotFound:
            logger.error(f"Template não encontrado: {TEMPLATE_DIR / 'dns_relatorio.html'}")
            return False

        # Garantir diretório de saída
        saida_path = Path(arquivo_saida)
        saida_path.parent.mkdir(parents=True, exist_ok=True)

        # Renderizar com contexto
        html = template.render(resultados=resultados)

        # Escrever arquivo
        saida_path.write_text(html, encoding="utf-8")

        logger.info(f"Relatório HTML gerado: {saida_path}")
        return True

    except Exception as e:
        logger.error(f"Erro ao gerar relatório HTML: {str(e)}")
        return False


def gerar_relatorio_completo(resultados: Dict[str, Any], arquivo_saida: str) -> bool:
    """
    Gera relatório HTML completo de pentest incluindo DNS, scan de portas, análise IA e nmap avançado.
    Args:
        resultados: Dicionário com resultados completos do fluxo.
        arquivo_saida: Caminho do arquivo HTML de saída (será criado se não existir).
    Returns:
        bool: True se gerou com sucesso.
    """
    logger = obter_logger("GeradorRelatorioHTML")

    try:
        # Preparar ambiente e template
        env = _criar_ambiente()
        try:
            template = env.get_template("pentest_completo.html")
        except TemplateNotFound:
            logger.error(f"Template não encontrado: {TEMPLATE_DIR / 'pentest_completo.html'}")
            return False

        # Garantir diretório de saída
        saida_path = Path(arquivo_saida)
        saida_path.parent.mkdir(parents=True, exist_ok=True)

        # Renderizar com contexto
        html = template.render(resultados=resultados)

        # Escrever arquivo
        saida_path.write_text(html, encoding="utf-8")

        logger.info(f"Relatório HTML completo gerado: {saida_path}")
        return True

    except Exception as e:
        logger.error(f"Erro ao gerar relatório HTML completo: {str(e)}")
        return False


def gerar_relatorio_automatico(resultados: Dict[str, Any], arquivo_saida: str) -> bool:
    """
    Gera relatório HTML automaticamente escolhendo o template adequado baseado nos dados disponíveis.
    Args:
        resultados: Dicionário com resultados completos do fluxo.
        arquivo_saida: Caminho do arquivo HTML de saída (será criado se não existir).
    Returns:
        bool: True se gerou com sucesso.
    """
    logger = obter_logger("GeradorRelatorioHTML")
    
    # Verificar quais dados estão disponíveis
    tem_scan_portas = 'scan_portas' in resultados or 'resumo_scan' in resultados
    tem_decisao_ia = 'decisao_ia' in resultados
    tem_nmap_avancado = 'nmap_avancado' in resultados
    
    # Se tem dados além de DNS, usar template completo
    if tem_scan_portas or tem_decisao_ia or tem_nmap_avancado:
        logger.info("Dados de pentest completos detectados, usando template completo")
        return gerar_relatorio_completo(resultados, arquivo_saida)
    else:
        logger.info("Apenas dados DNS detectados, usando template DNS")
        return gerar_relatorio_dns(resultados, arquivo_saida)