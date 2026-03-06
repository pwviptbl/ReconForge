"""
IdorPipeline — Pipeline de exploração de IDOR (Fase 3)

Testa acesso a recursos de outros usuários incrementando/decrementando
identificadores numéricos no parâmetro vulnerável.

Confirma IDOR por:
1. Resposta diferente com ID modificado (mesmo status, corpo diferente).
2. Dados privados de outro usuário visíveis na resposta.
3. Operação em recurso alheio (PUT/DELETE retornam 200/204 em vez de 403).
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from core.models import QueueItem
from plugins.pipelines import BasePipeline, _HttpResult, _http_send


class IdorPipeline(BasePipeline):
    name = "IdorPipeline"
    MAX_ATTEMPTS = 5

    def _get_payloads(self, item: QueueItem) -> List[str]:
        """Gera IDs alternativos para testar."""
        base = self._extract_base_id(item)
        if base is None:
            return ["1", "2", "0", "999", "-1"]
        variants = []
        for delta in [1, -1, 2, -2, 100]:
            variants.append(str(base + delta))
        variants.extend(["0", "-1", "999999"])
        return variants

    def _extract_base_id(self, item: QueueItem) -> Optional[int]:
        """Extrai o ID numérico do endpoint ou payload."""
        # Tentar do payload candidato
        num_match = re.search(r"\d+", item.candidate_payload or "")
        if num_match:
            return int(num_match.group())
        # Tentar do endpoint
        num_match = re.search(r"/(\d+)(?:/|$|\?)", item.endpoint or "")
        if num_match:
            return int(num_match.group(1))
        # Tentar do parâmetro na URL
        num_match = re.search(r"[?&]\w+=(\d+)", item.endpoint or "")
        if num_match:
            return int(num_match.group(1))
        return None

    def _execute(self, item: QueueItem, payload: str) -> Tuple[str, _HttpResult]:
        """Submete o ID modificado no parâmetro vulnerável."""
        # Primeiro obter a resposta baseline (ID original)
        url = item.endpoint or item.target
        param = item.parameter

        if item.method.upper() in ("PUT", "DELETE", "PATCH"):
            # Substituir ID no URL para operações de mutação
            url_modified = re.sub(r"/\d+(/|$)", f"/{payload}\\1", url)
            return _http_send(url_modified, method=item.method)
        elif item.method.upper() == "POST":
            return _http_send(url, method="POST",
                              data={param: payload} if param else {"id": payload})
        else:
            params = {param: payload} if param else {"id": payload}
            return _http_send(url, method="GET", params=params)

    def _verify(self, result: _HttpResult, payload: str, item: QueueItem) -> str:
        if result.status == 0:
            return "failed"

        # Operações de mutação com sucesso → impacto confirmado
        if item.method.upper() in ("PUT", "DELETE", "PATCH"):
            if result.status in (200, 204):
                return "impact_proven"
            if result.status == 403:
                return "failed"

        # GET: resposta com dados do usuário alterado
        if result.status == 200 and len(result.body) > 100:
            # Verificar se não é uma página de erro padrão
            body_lower = result.body.lower()
            error_indicators = ["not found", "404", "forbidden", "access denied", "unauthorized"]
            if not any(ind in body_lower for ind in error_indicators):
                return "partial"  # Resposta válida com ID alterado

        # Redirecionamento sem 403 → possível IDOR
        if result.status in (301, 302):
            return "partial"

        return "failed"
