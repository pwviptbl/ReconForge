#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utilitários de rede: validação e extração de IPs a partir de resultados DNS.
"""

import socket
from typing import Dict, Any, List

from utils.logger import obter_logger

logger = obter_logger("UtilsRede")


def validar_ip(ip: str) -> bool:
    """
    Valida se é um IPv4 válido.
    Args:
        ip: endereço IP em string
    Returns:
        bool: True se válido
    """
    try:
        socket.inet_aton(ip)
        return True
    except OSError:
        return False


def extrair_ips_para_scan(resultado_dns: Dict[str, Any]) -> List[str]:
    """
    Extrai IPs do resultado DNS para scan de portas.
    Estrutura esperada (compatível com [class OrquestradorPentest](main.py:20)):
      - resultado_dns['tipo_alvo'] em {'dominio', 'ip', ...}
      - resultado_dns['dados'] contendo:
          se domínio: 'ips_resolvidos': List[str]
          se ip: 'ip': str
    Args:
        resultado_dns: dicionário de resultado da resolução DNS
    Returns:
        Lista de IPs válidos e únicos
    """
    ips: List[str] = []
    dados = resultado_dns.get("dados", {})
    tipo_alvo = resultado_dns.get("tipo_alvo", "desconhecido")

    if tipo_alvo == "dominio":
        ips_resolvidos = dados.get("ips_resolvidos", [])
        ips.extend(ips_resolvidos)
    else:
        ip_original = dados.get("ip")
        if ip_original:
            ips.append(ip_original)

    # Remover duplicatas e IPs inválidos
    ips_unicos = list(set(ips))
    ips_validos = [ip for ip in ips_unicos if validar_ip(ip)]

    logger.info(f"IPs extraídos para scan: {ips_validos}")
    return ips_validos