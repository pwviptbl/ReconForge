"""
PayloadMutator — Fase 4

Aplica mutações simples e determinísticas para aumentar cobertura de filtros,
WAFs e contextos de rendering sem depender de ML ou geração dinâmica.
"""

from __future__ import annotations

from html import escape
from typing import Iterable, List
from urllib.parse import quote


class PayloadMutator:
    """Gera variantes de evasão de payloads preservando a ordem original."""

    def __init__(self, max_variants_per_payload: int = 6):
        self.max_variants_per_payload = max(1, int(max_variants_per_payload))

    def mutate(self, payloads: List[str], category: str) -> List[str]:
        mutated = []
        for payload in payloads:
            mutated.append(payload)
            mutated.extend(self._variants_for_payload(payload, category))
        return self._unique(mutated)

    def _variants_for_payload(self, payload: str, category: str) -> List[str]:
        variants = [
            self._url_encode(payload),
            self._html_entities(payload),
            self._case_variation(payload),
            self._double_encode(payload),
        ]

        if category in {"xss", "dom_xss"}:
            variants.extend(
                [
                    self._null_byte_variant(payload),
                    self._comment_injection(payload),
                ]
            )
        elif category in {"ssrf", "open_redirect"}:
            variants.append(self._protocol_relative(payload))

        unique_variants = self._unique(v for v in variants if v and v != payload)
        return unique_variants[: self.max_variants_per_payload]

    @staticmethod
    def _url_encode(payload: str) -> str:
        return quote(payload, safe="")

    @staticmethod
    def _double_encode(payload: str) -> str:
        return quote(quote(payload, safe=""), safe="")

    @staticmethod
    def _html_entities(payload: str) -> str:
        return escape(payload, quote=True)

    @staticmethod
    def _case_variation(payload: str) -> str:
        result = []
        upper = True
        for char in payload:
            if char.isalpha():
                result.append(char.upper() if upper else char.lower())
                upper = not upper
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def _null_byte_variant(payload: str) -> str:
        if "<script" in payload.lower():
            return payload.replace("script", "scr\x00ipt")
        return payload.replace("alert", "al\x00ert", 1)

    @staticmethod
    def _comment_injection(payload: str) -> str:
        if "<script" in payload.lower():
            return payload.replace("script", "s/**/cript")
        return payload.replace("onerror", "on/**/error")

    @staticmethod
    def _protocol_relative(payload: str) -> str:
        if payload.startswith("http://"):
            return "//" + payload[len("http://") :]
        if payload.startswith("https://"):
            return "//" + payload[len("https://") :]
        return payload

    @staticmethod
    def _unique(values: Iterable[str]) -> List[str]:
        seen = set()
        result = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result
