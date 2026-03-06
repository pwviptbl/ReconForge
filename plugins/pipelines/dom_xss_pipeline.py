"""
DomXssPipeline — Fase 4

Executa XSS orientado a browser para sinks DOM, templates JS e SPAs.
"""

from __future__ import annotations

from typing import List, Tuple

from core.browser_attack_engine import BrowserAttackConfig, BrowserAttackEngine
from core.config import get_config
from core.models import ExploitAttempt, QueueItem
from core.payload_engine import PayloadEngine
from plugins.pipelines import BasePipeline, _HttpResult


class DomXssPipeline(BasePipeline):
    name = "DomXssPipeline"
    MAX_ATTEMPTS = 6

    def __init__(self):
        super().__init__()
        self.payload_engine = PayloadEngine()
        self.browser_engine = BrowserAttackEngine(
            BrowserAttackConfig.from_mapping(get_config("browser_attack", {}))
        )

    def run_attempt(self, item: QueueItem, attempt_num: int) -> ExploitAttempt:
        payload = self._select_payload(item, attempt_num)
        attempt = self.browser_engine.run_attack(
            item=item,
            payload=payload,
            attempt_number=attempt_num,
            mode="xss",
        )
        attempt.executor = self.name
        return attempt

    def _get_payloads(self, item: QueueItem) -> List[str]:
        return self.payload_engine.get_payloads(
            context=item.context or "DOM",
            category="dom_xss",
            candidate_payload=item.candidate_payload,
            max_payloads=self.MAX_ATTEMPTS,
        )

    def _execute(self, item: QueueItem, payload: str) -> Tuple[str, _HttpResult]:
        raise NotImplementedError("DomXssPipeline usa BrowserAttackEngine diretamente.")

    def _verify(self, result: _HttpResult, payload: str, item: QueueItem) -> str:
        raise NotImplementedError("DomXssPipeline usa BrowserAttackEngine diretamente.")
