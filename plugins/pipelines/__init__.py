"""
Pipelines de exploração por categoria — Fase 3

Cada pipeline encapsula:
1. Seleção/mutação de payload para o contexto específico.
2. Execução da requisição HTTP com timeout.
3. Verificação da resposta para confirmar impacto.
4. Retorno de ExploitAttempt com snapshot completo.

Todos os pipelines compartilham a interface BasePipeline.
"""

from __future__ import annotations

import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from core.models import ExploitAttempt, QueueItem, _new_id, _now_iso
from utils.logger import get_logger


# ---------------------------------------------------------------------------
# Constantes globais de timeout
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 15   # segundos por tentativa


# ---------------------------------------------------------------------------
# HTTP helper mínimo (sem dependência de requests/httpx para compatibilidade)
# ---------------------------------------------------------------------------

class _HttpResult:
    def __init__(self, status: int, body: str, headers: Dict[str, str], raw_request: str):
        self.status = status
        self.body = body
        self.headers = headers
        self.raw_request = raw_request


def _http_send(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[str, _HttpResult]:
    """
    Envia uma requisição HTTP e retorna (raw_request, HttpResult).
    Usa urllib puro — nenhuma dependência externa.
    """
    default_headers = {
        "User-Agent": "ReconForge/3.0 (pipeline exploit)",
        "Accept": "*/*",
    }
    if headers:
        default_headers.update(headers)

    # Monta URL com query string para GET
    final_url = url
    if method.upper() == "GET" and params:
        qs = urllib.parse.urlencode(params)
        sep = "&" if "?" in url else "?"
        final_url = f"{url}{sep}{qs}"

    # Monta body para POST
    body_bytes: Optional[bytes] = None
    if method.upper() == "POST" and data:
        body_bytes = urllib.parse.urlencode(data).encode("utf-8")
        default_headers["Content-Type"] = "application/x-www-form-urlencoded"

    # Snapshot da requisição enviada
    raw_req = f"{method.upper()} {final_url}\n"
    raw_req += "\n".join(f"{k}: {v}" for k, v in default_headers.items())
    if body_bytes:
        raw_req += f"\n\n{body_bytes.decode('utf-8', errors='replace')}"

    req = urllib.request.Request(
        final_url,
        data=body_bytes,
        headers=default_headers,
        method=method.upper(),
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read(65536).decode("utf-8", errors="replace")
            resp_headers = {k: v for k, v in resp.headers.items()}
            return raw_req, _HttpResult(
                status=resp.status,
                body=resp_body,
                headers=resp_headers,
                raw_request=raw_req,
            )
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode("utf-8", errors="replace") if e.fp else ""
        return raw_req, _HttpResult(
            status=e.code,
            body=body,
            headers={k: v for k, v in e.headers.items()},
            raw_request=raw_req,
        )
    except Exception as exc:
        return raw_req, _HttpResult(
            status=0,
            body=f"[ERRO: {exc}]",
            headers={},
            raw_request=raw_req,
        )


def _build_response_snapshot(result: _HttpResult) -> str:
    headers_str = "\n".join(f"{k}: {v}" for k, v in result.headers.items())
    return f"HTTP/1.1 {result.status}\n{headers_str}\n\n{result.body[:4096]}"


# ---------------------------------------------------------------------------
# Interface base de pipeline
# ---------------------------------------------------------------------------

class BasePipeline(ABC):
    """
    Interface comum para todos os pipelines de exploração por categoria.
    """

    #: Nome do pipeline (ex: "XssPipeline")
    name: str = "BasePipeline"

    #: Máximo de tentativas por item de queue
    MAX_ATTEMPTS: int = 5

    def __init__(self):
        self.logger = get_logger(self.__class__.__name__)

    def run_attempt(
        self, item: QueueItem, attempt_num: int
    ) -> ExploitAttempt:
        """
        Executa uma tentativa de exploração e retorna ExploitAttempt.
        Implementação padrão que seleciona payload e chama _execute.
        """
        payload = self._select_payload(item, attempt_num)

        try:
            raw_req, result = self._execute(item, payload)
            status = self._verify(result, payload, item)
            resp_snap = _build_response_snapshot(result)
        except Exception as exc:
            raw_req = f"ERRO ao executar tentativa: {exc}"
            resp_snap = ""
            status = "failed"
            self.logger.warning(f"{self.name} tentativa {attempt_num} falhou: {exc}")

        return ExploitAttempt(
            queue_item_id=item.id,
            attempt_number=attempt_num,
            payload_used=payload,
            executor=self.name,
            request_snapshot=raw_req,
            response_snapshot=resp_snap,
            status=status,
        )

    @abstractmethod
    def _get_payloads(self, item: QueueItem) -> List[str]:
        """Retorna lista de payloads para este pipeline."""
        pass

    def _select_payload(self, item: QueueItem, attempt_num: int) -> str:
        """Seleciona payload baseado no número da tentativa (round-robin)."""
        payloads = self._get_payloads(item)
        if not payloads:
            return item.candidate_payload or ""
        # Tentativa 1 → índice 0, tentativa 2 → índice 1, etc.
        idx = (attempt_num - 1) % len(payloads)
        return payloads[idx]

    @abstractmethod
    def _execute(
        self, item: QueueItem, payload: str
    ) -> Tuple[str, _HttpResult]:
        """Executa a requisição com o payload dado."""
        pass

    @abstractmethod
    def _verify(
        self, result: _HttpResult, payload: str, item: QueueItem
    ) -> str:
        """
        Verifica se o impacto foi confirmado.
        Retorna: "impact_proven", "partial" ou "failed".
        """
        pass
