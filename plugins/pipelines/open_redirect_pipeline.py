"""
OpenRedirectPipeline — Pipeline de exploração de Open Redirect (Fase 3)

Verifica se o servidor redireciona para domínio arbitrário controlado.
Confirma por:
1. Location header apontando para destino externo arbitrário.
2. Resposta 3xx com destino que não pertence ao domínio alvo.
3. Meta-refresh ou JS redirect para domínio externo.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import List, Tuple

from core.models import QueueItem
from plugins.pipelines import BasePipeline, _HttpResult, _http_send


# Domínios de teste para redirect
_REDIRECT_TARGETS = [
    "https://reconforge-test.example.com/",
    "//reconforge-test.example.com/",
    "https://evil.com/",
    "//evil.com/",
    r"\/\/evil.com/",
    r"\\/\\/evil.com/",
    "%2F%2Fevil.com%2F",
    "https:evil.com",
]

_MARKER_DOMAIN = "reconforge-test.example.com"


class OpenRedirectPipeline(BasePipeline):
    name = "OpenRedirectPipeline"
    MAX_ATTEMPTS = 5

    def _get_payloads(self, item: QueueItem) -> List[str]:
        return _REDIRECT_TARGETS

    def _execute(self, item: QueueItem, payload: str) -> Tuple[str, _HttpResult]:
        url = item.endpoint or item.target
        param = item.parameter

        if item.method.upper() == "POST":
            return _http_send(url, method="POST",
                              data={param: payload} if param else {"redirect": payload},
                              timeout=10)
        else:
            params = {param: payload} if param else {"redirect": payload}
            return _http_send(url, method="GET", params=params, timeout=10)

    def _verify(self, result: _HttpResult, payload: str, item: QueueItem) -> str:
        if result.status == 0:
            return "failed"

        # Verificar Location header em respostas 3xx
        if result.status in (301, 302, 303, 307, 308):
            location = result.headers.get("Location", result.headers.get("location", ""))
            if location and self._is_external_redirect(location, item.target):
                return "impact_proven"
            if location and _MARKER_DOMAIN in location:
                return "impact_proven"

        # Verificar meta-refresh ou window.location no body
        body = result.body
        meta_refresh = re.search(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\'][^"\']*url=([^"\']+)',
            body, re.IGNORECASE
        )
        if meta_refresh:
            target = meta_refresh.group(1)
            if self._is_external_redirect(target, item.target):
                return "partial"
            if _MARKER_DOMAIN in target:
                return "impact_proven"

        js_redirect = re.search(
            r'(window\.location|location\.href)\s*=\s*["\']([^"\']+)["\']',
            body, re.IGNORECASE
        )
        if js_redirect:
            target = js_redirect.group(2)
            if self._is_external_redirect(target, item.target):
                return "partial"

        # Payload refletido como link no body (potencial redirect)
        if _MARKER_DOMAIN in body or "evil.com" in body:
            return "partial"

        return "failed"

    def _is_external_redirect(self, location: str, original_target: str) -> bool:
        """Verifica se o redirect vai para um domínio diferente do alvo."""
        try:
            loc_parsed = urllib.parse.urlparse(location)
            tgt_parsed = urllib.parse.urlparse(
                original_target if "://" in original_target else f"https://{original_target}"
            )
            loc_host = loc_parsed.netloc.lower().lstrip("/")
            tgt_host = tgt_parsed.netloc.lower()

            if loc_host and tgt_host and loc_host != tgt_host:
                return True
            # Protocolo-relative (//evil.com)
            if location.startswith("//") and tgt_host not in location:
                return True
        except Exception:
            pass
        return False
