#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utilitários para geração de resumos de resultados de varreduras.
Extrai e consolida informações de:
- Scans de portas (RustScan/Nmap básico) por host
- Nmap avançado (múltiplos módulos), agregando métricas
"""

from typing import Dict, Any

from utils.logger import obter_logger

logger = obter_logger("UtilsResumo")


def gerar_resumo_scan_completo(resultados_scan: Dict[str, Any], scanner_portas) -> Dict[str, Any]:
    """
    Gera resumo completo dos scans de portas.
    Observa a estrutura de resultados por IP e utiliza scanner_portas.gerar_resumo(resultado)
    para normalizar cada host, mantendo compatibilidade com a lógica atual.

    Args:
        resultados_scan: dicionário { ip: resultado_scan_individual }
        scanner_portas: instância que expõe gerar_resumo(resultado_individual) -> Dict

    Returns:
        Resumo consolidado com total de IPs, hosts ativos, portas abertas e detalhes por host.
    """
    resumo = {
        "total_ips_scaneados": len(resultados_scan),
        "hosts_ativos": 0,
        "total_portas_abertas": 0,
        "hosts_com_portas_abertas": [],
        "resumo_por_host": {},
    }

    for ip, resultado in resultados_scan.items():
        if resultado.get("sucesso"):
            resumo_host = scanner_portas.gerar_resumo(resultado)
            resumo["resumo_por_host"][ip] = resumo_host

            if resumo_host.get("hosts_ativos", 0) > 0:
                resumo["hosts_ativos"] += 1

            portas_abertas = resumo_host.get("portas_abertas", 0)
            resumo["total_portas_abertas"] += portas_abertas

            if portas_abertas > 0:
                host_info = {
                    "ip": ip,
                    "portas_abertas": portas_abertas,
                    "portas": [],
                }

                # Extrair portas abertas
                for host_detalhe in resumo_host.get("hosts_detalhes", []):
                    if host_detalhe.get("portas_abertas"):
                        host_info["portas"] = host_detalhe["portas_abertas"]
                        break

                resumo["hosts_com_portas_abertas"].append(host_info)

    return resumo


def gerar_resumo_nmap_avancado(resultados_nmap: Dict[str, Any]) -> Dict[str, Any]:
    """
    Gera resumo agregado dos resultados do Nmap avançado (múltiplos módulos).
    Mantém o mesmo formato consolidado utilizado anteriormente no main.

    Estrutura esperada (parcial):
    resultados_nmap = {
      'modulos_executados': [...],
      'ips_analisados': [...],
      'resultados_por_modulo': {
          'nome_modulo': {
              'ip1': { 'sucesso': bool, 'dados': { 'resumo': {...} }, ... },
              ...
          }
      }
    }

    Args:
        resultados_nmap: dicionário completo da execução avançada do Nmap

    Returns:
        Dicionário com métricas agregadas por módulo e totais.
    """
    resumo = {
        "modulos_executados": len(resultados_nmap.get("modulos_executados", [])),
        "ips_analisados": len(resultados_nmap.get("ips_analisados", [])),
        "total_vulnerabilidades": 0,
        "total_servicos_detectados": 0,
        "hosts_com_vulnerabilidades": [],
        "servicos_criticos_encontrados": [],
        "resumo_por_modulo": {},
    }

    for modulo, resultados_modulo in resultados_nmap.get("resultados_por_modulo", {}).items():
        resumo_modulo = {
            "ips_processados": 0,
            "sucessos": 0,
            "falhas": 0,
            "vulnerabilidades_encontradas": 0,
            "servicos_encontrados": 0,
        }

        for ip, resultado in resultados_modulo.items():
            resumo_modulo["ips_processados"] += 1

            if resultado.get("sucesso"):
                resumo_modulo["sucessos"] += 1

                dados = resultado.get("dados", {})
                resumo_dados = dados.get("resumo", {})

                vulns = resumo_dados.get("vulnerabilidades", 0)
                servicos = resumo_dados.get("servicos_detectados", 0)

                resumo_modulo["vulnerabilidades_encontradas"] += vulns
                resumo_modulo["servicos_encontrados"] += servicos

                resumo["total_vulnerabilidades"] += vulns
                resumo["total_servicos_detectados"] += servicos

                # Identificar hosts com vulnerabilidades
                if vulns > 0 and ip not in resumo["hosts_com_vulnerabilidades"]:
                    resumo["hosts_com_vulnerabilidades"].append(ip)
            else:
                resumo_modulo["falhas"] += 1

        resumo["resumo_por_modulo"][modulo] = resumo_modulo

    return resumo