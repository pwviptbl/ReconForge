"""
Plugin de Scanner de CSRF (Cross-Site Request Forgery)

Diferente dos outros scanners parametrizados (XSS/LFI/SSRF/...), CSRF não é
detectado por reflexão de payload, e sim por ausência/ineficácia de proteção
em requests que alteram estado (POST/PUT/PATCH/DELETE) autenticadas por
cookie de sessão. Por isso este plugin não herda de
`ParameterizedVulnerabilityPlugin` e implementa seu próprio fluxo:

1. Para cada request_node com método "unsafe" e sessão via cookie:
   a. Se não existe nenhum parâmetro com cara de anti-CSRF token
      (nome ou header) -> finding "Missing CSRF Token".
   b. Se existe um token, reenvia a mesma request com o valor do token
      adulterado; se o servidor ainda aceitar (mesmo status de sucesso da
      baseline) -> finding "CSRF token not validated server-side".
"""

import re
from typing import Any, Dict, List, Optional

import requests

from core.models import Vulnerability
from core.plugin_base import PluginResult, VulnerabilityPlugin
from utils.http_session import build_request_node_headers, create_requests_session
from utils.probe_logger import ProbeLogger
from utils.rate_limiter import RateLimiter
from utils.request_utils import rebuild_attack_request
from utils.web_discovery import build_request_nodes, iter_request_node_parameters
from utils.logger import get_logger

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_TOKEN_PARAM_PATTERN = re.compile(
    r"csrf|xsrf|_token$|^token$|authenticity_token|verification_token|nonce", re.IGNORECASE
)
_TOKEN_HEADER_PATTERN = re.compile(r"csrf|xsrf", re.IGNORECASE)


class CsrfScannerPlugin(VulnerabilityPlugin):
    """
    Scanner de CSRF para requests autenticadas por cookie de sessão.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        super().__init__(config)
        self.config = config
        self.logger = get_logger(self.__class__.__name__)
        self.timeout = self.config.get("timeout", 10)
        self.verify_ssl = self.config.get("verify_ssl", True)
        self.rate_limiter = RateLimiter.from_config(self.config)

    def get_info(self) -> Dict[str, Any]:
        info = super().get_info()
        info["category"] = "vulnerability"
        info["requires"] = ["WebFlowMapperPlugin"]
        return info

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        import time

        start_time = time.time()
        vulns: List[Vulnerability] = []
        tested_count = 0
        probe_logger = ProbeLogger()

        actual_target = context.get("original_target", target)
        self.logger.info(f"🚀 Iniciando varredura {self.name} em: {actual_target}")

        discoveries = context.get("discoveries", {})
        session = create_requests_session(
            plugin_config=self.config,
            session_file=context.get("auth_session_file"),
        )
        session.verify = self.verify_ssl

        request_nodes = build_request_nodes(
            discoveries,
            actual_target,
            default_headers=build_request_node_headers(session),
        )

        # Sem cookie de sessão não há o que um CSRF cross-site exploraria.
        has_session_cookie = bool(session.cookies) or any(
            request_node.get("cookies") for request_node in request_nodes
        )

        try:
            if has_session_cookie:
                for request_node in request_nodes:
                    method = (request_node.get("method") or "GET").upper()
                    if method not in _UNSAFE_METHODS:
                        continue
                    tested_count += 1
                    try:
                        vuln = self._test_request_node(session, request_node, probe_logger)
                        if vuln:
                            vulns.append(vuln)
                    except Exception as e:
                        self.logger.debug(
                            f"Erro ao testar CSRF em {request_node.get('url')}: {e}"
                        )
            else:
                self.logger.info(
                    f"{self.name}: nenhuma sessão autenticada por cookie detectada — pulando"
                )
        finally:
            session.close()

        execution_time = time.time() - start_time
        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=execution_time,
            data={
                "vulnerabilities": [v.to_dict() for v in vulns],
                "tested_count": tested_count,
                "probe_log": probe_logger.to_list(),
                "probe_summary": {
                    "total": probe_logger.total,
                    "hits": len(probe_logger.hits),
                },
            },
        )

    def _find_token_point(self, request_node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Procura um parâmetro (query/body) com cara de anti-CSRF token."""
        for injection_point in iter_request_node_parameters(request_node):
            name = injection_point.get("parameter_name") or ""
            if _TOKEN_PARAM_PATTERN.search(name):
                return injection_point
        return None

    def _has_token_header(self, request_node: Dict[str, Any]) -> bool:
        headers = request_node.get("headers") or {}
        return any(_TOKEN_HEADER_PATTERN.search(h) for h in headers.keys())

    def _test_request_node(
        self, session: requests.Session, request_node: Dict[str, Any], probe_logger: ProbeLogger
    ) -> Optional[Vulnerability]:
        url = request_node.get("url", "")
        method = request_node.get("method", "POST")
        token_point = self._find_token_point(request_node)

        # Caso 1: nenhum token em parâmetro nem em header dedicado.
        if not token_point and not self._has_token_header(request_node):
            probe_logger.record(
                url=url, method=method, param="", location="",
                payload="(sem token)", response=None,
                indicator="missing_csrf_token", hit=True,
            )
            return Vulnerability(
                name="CSRF — Ausência de Token Anti-CSRF",
                severity="Medium",
                description=(
                    f"Request {method} para '{url}' altera estado e usa sessão via "
                    "cookie, mas não envia nenhum token anti-CSRF (parâmetro ou header)."
                ),
                url=url,
                evidence=f"Método: {method}; nenhum parâmetro/header de token encontrado.",
                cve="CWE-352",
                remediation=(
                    "Implementar token anti-CSRF (synchronizer token ou double-submit "
                    "cookie) validado no servidor, e/ou cookies com SameSite=Strict/Lax."
                ),
                plugin_source=self.name,
            )

        # Caso 2: existe parâmetro de token — testar se o servidor realmente o valida.
        if token_point:
            self.rate_limiter.wait()
            baseline = session.send(
                rebuild_attack_request(
                    request_node, token_point, token_point.get("value") or "baseline"
                ),
                timeout=self.timeout,
            )
            self.rate_limiter.record_request()

            self.rate_limiter.wait()
            tampered = session.send(
                rebuild_attack_request(request_node, token_point, "reconforge-invalid-token"),
                timeout=self.timeout,
            )
            self.rate_limiter.record_request()

            hit = (
                baseline.status_code < 400
                and tampered.status_code == baseline.status_code
            )
            probe_logger.record(
                url=url, method=method, param=token_point.get("parameter_name"),
                location=token_point.get("location"),
                payload="reconforge-invalid-token", response=tampered,
                indicator=f"baseline={baseline.status_code}", hit=hit,
            )
            if hit:
                return Vulnerability(
                    name="CSRF — Token Anti-CSRF Não Validado",
                    severity="High",
                    description=(
                        f"Request {method} para '{url}' aceita o parâmetro "
                        f"'{token_point.get('parameter_name')}' com qualquer valor "
                        f"(status {tampered.status_code} igual à baseline {baseline.status_code})."
                    ),
                    url=url,
                    evidence=(
                        f"Baseline status={baseline.status_code}; "
                        f"tampered status={tampered.status_code}"
                    ),
                    cve="CWE-352",
                    remediation=(
                        "Validar o token anti-CSRF no servidor (comparação contra o "
                        "valor emitido na sessão), rejeitando requests com token "
                        "ausente, reutilizado ou adulterado."
                    ),
                    plugin_source=self.name,
                )
        return None
