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
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

import requests

from core.models import ExploitAttempt, QueueItem, _new_id, _now_iso
from utils.auth_session import apply_session_profile_to_prepared_request
from utils.http_session import create_requests_session
from utils.logger import get_logger
from utils.request_utils import rebuild_attack_request


# ---------------------------------------------------------------------------
# Constantes globais de timeout
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 15   # segundos por tentativa


# ---------------------------------------------------------------------------
# HTTP helper minimo para envio consistente via configuracao central.
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
    Envia uma requisicao HTTP e retorna (raw_request, HttpResult).
    Usa requests.Session centralizada para respeitar Tor quando habilitado.
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
        qs = requests.models.RequestEncodingMixin._encode_params(params)
        sep = "&" if "?" in url else "?"
        final_url = f"{url}{sep}{qs}"

    # Monta body para POST
    body_bytes: Optional[bytes] = None
    if method.upper() == "POST" and data:
        body_bytes = requests.models.RequestEncodingMixin._encode_params(data).encode("utf-8")
        default_headers["Content-Type"] = "application/x-www-form-urlencoded"

    # Snapshot da requisição enviada
    raw_req = f"{method.upper()} {final_url}\n"
    raw_req += "\n".join(f"{k}: {v}" for k, v in default_headers.items())
    if body_bytes:
        raw_req += f"\n\n{body_bytes.decode('utf-8', errors='replace')}"

    session = create_requests_session(headers=default_headers)
    try:
        response = session.request(
            method.upper(),
            final_url,
            data=body_bytes,
            timeout=timeout,
            allow_redirects=True,
        )
        return raw_req, _HttpResult(
            status=response.status_code,
            body=response.text[:65536],
            headers=dict(response.headers),
            raw_request=raw_req,
        )
    except requests.RequestException as exc:
        return raw_req, _HttpResult(
            status=0,
            body=f"[ERRO: {exc}]",
            headers={},
            raw_request=raw_req,
        )


def _build_response_snapshot(result: _HttpResult) -> str:
    headers_str = "\n".join(f"{k}: {v}" for k, v in result.headers.items())
    return f"HTTP/1.1 {result.status}\n{headers_str}\n\n{result.body[:4096]}"


def _prepared_to_raw_request(prepared: requests.PreparedRequest) -> str:
    lines = [f"{prepared.method} {prepared.url}"]
    for key, value in prepared.headers.items():
        lines.append(f"{key}: {value}")
    body = prepared.body
    if body:
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        lines.extend(["", str(body)])
    return "\n".join(lines)


def _http_send_prepared(
    prepared: requests.PreparedRequest,
    timeout: int = DEFAULT_TIMEOUT,
    session_file: str = "",
    session_profile: Optional[Dict[str, Any]] = None,
) -> Tuple[str, _HttpResult]:
    apply_session_profile_to_prepared_request(
        prepared,
        session_file=session_file or None,
        session_profile=session_profile,
    )
    raw_req = _prepared_to_raw_request(prepared)
    session = create_requests_session()
    try:
        response = session.send(prepared, timeout=timeout, allow_redirects=True)
        body = response.text[:65536]
        headers = dict(response.headers)
        return raw_req, _HttpResult(
            status=response.status_code,
            body=body,
            headers=headers,
            raw_request=raw_req,
        )
    except requests.RequestException as exc:
        return raw_req, _HttpResult(
            status=0,
            body=f"[ERRO: {exc}]",
            headers={},
            raw_request=raw_req,
        )


def _http_send_item(
    item: QueueItem,
    payload: str,
    *,
    fallback_param: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[str, _HttpResult]:
    request_node = getattr(item, "request_node", None)
    injection_point = getattr(item, "injection_point", None)
    session_profile = getattr(item, "auth_session", None) or {}
    session_file = str(getattr(item, "auth_session_file", "") or "")

    if request_node and injection_point:
        prepared = rebuild_attack_request(request_node, injection_point, payload)
        return _http_send_prepared(
            prepared,
            timeout=timeout,
            session_file=session_file,
            session_profile=session_profile,
        )

    url = item.endpoint or item.target
    method = (item.method or "GET").upper()
    parameter = item.parameter or fallback_param
    headers = dict(session_profile.get("headers") or {})
    cookie_header = str(session_profile.get("cookie_string") or "").strip()
    if cookie_header and "Cookie" not in headers and "cookie" not in headers:
        headers["Cookie"] = cookie_header

    if method == "POST":
        data = {parameter: payload} if parameter else {}
        return _http_send(url, method="POST", data=data, headers=headers or None, timeout=timeout)

    params = {parameter: payload} if parameter else {}
    return _http_send(url, method="GET", params=params, headers=headers or None, timeout=timeout)


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
