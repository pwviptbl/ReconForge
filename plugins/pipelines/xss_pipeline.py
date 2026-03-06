"""
XssPipeline — Pipeline de exploração de Cross-Site Scripting (Fase 3)

Verifica se o payload é refletido no contexto correto (HTML_BODY,
ATTRIBUTE, JS_STRING, URL) sem precisar de browser.

Para DOM XSS e casos autenticados → BrowserAttackEngine (Fase 4).
"""

from __future__ import annotations

import re
from typing import List, Tuple

from core.browser_attack_engine import BrowserAttackConfig, BrowserAttackEngine
from core.config import get_config
from core.payload_engine import PayloadEngine
from core.models import QueueItem
from plugins.pipelines import BasePipeline, _HttpResult, _http_send


_BROWSER_CONTEXTS = {"DOM", "JS_TEMPLATE", "CSS", "JSON"}


class XssPipeline(BasePipeline):
    name = "XssPipeline"
    MAX_ATTEMPTS = 5

    def __init__(self):
        super().__init__()
        self.payload_engine = PayloadEngine()
        self.browser_engine = BrowserAttackEngine(
            BrowserAttackConfig.from_mapping(get_config("browser_attack", {}))
        )

    def _get_payloads(self, item: QueueItem) -> List[str]:
        return self.payload_engine.get_payloads(
            context=item.context,
            category="xss",
            candidate_payload=item.candidate_payload,
            max_payloads=self.MAX_ATTEMPTS,
        )

    def run_attempt(self, item: QueueItem, attempt_num: int):
        payload = self._select_payload(item, attempt_num)
        if self._needs_browser(item):
            attempt = self.browser_engine.run_attack(
                item=item,
                payload=payload,
                attempt_number=attempt_num,
                mode="xss",
            )
            attempt.executor = f"{self.name}/Browser"
            return attempt
        return super().run_attempt(item, attempt_num)

    def _execute(self, item: QueueItem, payload: str) -> Tuple[str, _HttpResult]:
        url = item.endpoint or item.target
        param = item.parameter

        if item.method.upper() == "POST":
            return _http_send(url, method="POST", data={param: payload} if param else {})
        else:
            params = {param: payload} if param else {}
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

    @staticmethod
    def _needs_browser(item: QueueItem) -> bool:
        return (item.context or "").upper() in _BROWSER_CONTEXTS
