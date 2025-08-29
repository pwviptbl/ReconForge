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


def _adaptar_resultados_para_template(resultados: Dict[str, Any]) -> Dict[str, Any]:
    """
    Adapta a estrutura de 'resultados' produzida pelo OrquestradorInteligente para o
    formato esperado pelos templates atuais (compatibilidade).
    - Gera 'resumo_scan' a partir de contexto_execucao.portas_abertas
    - Copia 'scan_portas' a partir de resultados_por_modulo.scan_inicial (quando existir)
    - Gera 'resumo_dns' a partir de resultados_por_modulo.resolucao_dns (quando existir)
    - Gera 'decisao_ia' com base no último item de 'decisoes_ia' (quando existir)
    - Extrai 'web_estudo' a partir de resultados_por_modulo.navegador_web (quando existir)
    """
    try:
        dados: Dict[str, Any] = dict(resultados) if isinstance(resultados, dict) else {}
        contexto = dados.get('contexto_execucao', {})
        resultados_mod = dados.get('resultados_por_modulo', {}) or {}

        # 1) Resumo de scan (rede)
        portas_abertas = contexto.get('portas_abertas', {}) or {}
        ips_descobertos = contexto.get('ips_descobertos', []) or []
        hosts_ativos = len([ip for ip, portas in portas_abertas.items() if portas])
        total_portas = sum(len(portas) for portas in portas_abertas.values())
        hosts_com_portas_abertas = [
            {
                'ip': ip,
                'portas_abertas': len(sorted(set(portas))),
                'portas': sorted(set(portas)),
            }
            for ip, portas in portas_abertas.items() if portas
        ]
        if portas_abertas or ips_descobertos:
            dados['resumo_scan'] = {
                'total_ips_scaneados': len(ips_descobertos) or len(portas_abertas.keys()),
                'hosts_ativos': hosts_ativos,
                'total_portas_abertas': total_portas,
                'hosts_com_portas_abertas': hosts_com_portas_abertas,
            }

        # 2) Scan de portas detalhado (bruto) se existir no contexto
        if 'scan_inicial' in resultados_mod and isinstance(resultados_mod['scan_inicial'], dict):
            dados['scan_portas'] = resultados_mod['scan_inicial']

        # 3) Resumo DNS (melhor esforço)
        if 'resolucao_dns' in resultados_mod and isinstance(resultados_mod['resolucao_dns'], dict):
            rdns = resultados_mod['resolucao_dns'].get('dados', {}) or {}
            # Heurística simples
            if isinstance(rdns.get('ips_resolvidos'), list) or 'dns' in rdns:
                ips_res = rdns.get('ips_resolvidos', rdns.get('ips', [])) or []
                dados['resumo_dns'] = {
                    'tipo_alvo': 'dominio',
                    'ip_principal': ips_res[0] if ips_res else 'N/A',
                    'total_ips': len(ips_res),
                    'possui_ipv6': bool(rdns.get('ipv6')),
                    'possui_mx': bool(rdns.get('mx')),
                    'ips_encontrados': ips_res,
                }
            else:
                doms = rdns.get('dominios', []) or []
                dados['resumo_dns'] = {
                    'tipo_alvo': 'ip',
                    'ip': rdns.get('ip', dados.get('alvo_original', 'N/A')),
                    'hostname_principal': rdns.get('hostname', ''),
                    'total_dominios': len(doms),
                    'possui_resolucao_reversa': bool(doms),
                    'dominios_encontrados': doms,
                }

        # 4) Decisão IA (última)
        if isinstance(dados.get('decisoes_ia'), list) and dados['decisoes_ia']:
            di = dados['decisoes_ia'][-1]
            dados['decisao_ia'] = {
                'prioridade': di.get('prioridade'),
                'justificativa_ia': di.get('justificativa'),
                'modulos_recomendados': [di.get('modulo')] if di.get('modulo') else [],
                'portas_prioritarias': (di.get('parametros') or {}).get('portas_prioritarias', []),
                'fonte_decisao': 'Gemini',
            }

        # 5) Estudo Web Inicial (navegador_web)
        nav_mod = resultados_mod.get('navegador_web')
        if isinstance(nav_mod, dict):
            # Pode ser formato normalizado (resultados_por_alvo) ou direto (dados)
            dados_nav = None
            if 'dados' in nav_mod and isinstance(nav_mod['dados'], dict):
                dados_nav = nav_mod['dados']
            else:
                rpa = nav_mod.get('resultados_por_alvo', {}) or {}
                if rpa:
                    primeiro_alvo = next(iter(rpa))
                    dados_nav = (rpa.get(primeiro_alvo) or {}).get('dados', {})

            if isinstance(dados_nav, dict):
                dados['web_estudo'] = {
                    'url': dados_nav.get('url_base') or dados_nav.get('url'),
                    'titulo': dados_nav.get('titulo'),
                    'status_code': dados_nav.get('status_code'),
                    'total_formularios': dados_nav.get('total_formularios', len(dados_nav.get('formularios', []) or [])),
                    'total_links': dados_nav.get('total_links', len(dados_nav.get('links', []) or [])),
                    'tecnologias': dados_nav.get('tecnologias', {}) or {},
                    'screenshot_path': dados_nav.get('screenshot_path'),
                    'engine_usada': dados_nav.get('engine_usado') or dados_nav.get('engine_usada') or '',
                    'formularios': dados_nav.get('formularios', []) or [],
                    'links': dados_nav.get('links', []) or [],
                }

        return dados
    except Exception:
        # Em caso de erro, retorna o original para não quebrar geração
        return resultados if isinstance(resultados, dict) else {}


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

        # Renderizar com contexto (adaptado para compatibilidade de templates)
        dados_render = _adaptar_resultados_para_template(resultados)
        html = template.render(resultados=dados_render)

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
    
    # Verificar quais dados estão disponíveis (compatível com novo orquestrador)
    tem_scan_portas = (
        ('scan_portas' in resultados) or
        ('resumo_scan' in resultados) or
        ('contexto_execucao' in resultados) or
        ('resultados_por_modulo' in resultados and 'scan_inicial' in (resultados.get('resultados_por_modulo') or {}))
    )
    tem_decisao_ia = ('decisao_ia' in resultados) or bool(resultados.get('decisoes_ia'))
    tem_nmap_avancado = (
        ('nmap_avancado' in resultados) or
        any('nmap' in k for k in (resultados.get('resultados_por_modulo') or {}).keys())
    )
    
    # Se tem dados além de DNS, usar template completo
    if tem_scan_portas or tem_decisao_ia or tem_nmap_avancado:
        logger.info("Dados de pentest completos detectados, usando template completo")
        return gerar_relatorio_completo(resultados, arquivo_saida)
    else:
        logger.info("Apenas dados DNS detectados, usando template DNS")
        return gerar_relatorio_dns(resultados, arquivo_saida)