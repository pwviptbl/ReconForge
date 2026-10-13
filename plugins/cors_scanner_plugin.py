"""
Plugin de Scanner de CORS (Cross-Origin Resource Sharing) mal configurado

Para cada URL em escopo já descoberta, envia requests com um header
`Origin` forjado e inspeciona a resposta:

- ACAO reflete o Origin arbitrário que enviamos  -> origin reflection
- ACAO reflete `null`                            -> confiança em origin null
- ACAO: *  com Access-Control-Allow-Credentials  -> combinação inválida/perigosa
- ACAO reflete um sufixo/prefixo do domínio       -> regex de match frouxo

A severidade sobe quando `Access-Control-Allow-Credentials: true` acompanha o
reflexo (permite exfiltrar dados autenticados cross-origin).

Herda de VulnerabilityPlugin (não injeta payload em parâmetro; manipula o
header Origin). Reaproveita sessão, rate limiter e política de Tor.
"""

import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from core.models import Vulnerability
from core.plugin_base import PluginResult, VulnerabilityPlugin
from utils.http_session import build_request_node_headers, create_requests_session
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

_ATTACKER_ORIGIN = "https://evil-reconforge-probe.com"


class CorsScannerPlugin(VulnerabilityPlugin):
    """Scanner de configuração incorreta de CORS."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        super().__init__(config)
        self.config = config
        self.logger = get_logger(self.__class__.__name__)
        self.timeout = self.config.get("timeout", 10)
        self.verify_ssl = self.config.get("verify_ssl", True)
        self.max_urls = self.config.get("max_urls", 100)
        self.rate_limiter = RateLimiter.from_config(self.config)

    def get_info(self) -> Dict[str, Any]:
        info = super().get_info()
        info["category"] = "vulnerability"
        return info

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()
        vulns: List[Vulnerability] = []

        actual_target = context.get("original_target", target)
        self.logger.info(f"🚀 Iniciando varredura {self.name} em: {actual_target}")

        discoveries = context.get("discoveries", {})
        candidates = self._collect_candidates(discoveries, actual_target)
        self.logger.info(f"🔍 {len(candidates)} URLs candidatas para teste de CORS")

        session = create_requests_session(
            plugin_config=self.config,
            session_file=context.get("auth_session_file"),
        )
        session.verify = self.verify_ssl

        tested = 0
        try:
            for url in candidates:
                try:
                    vuln = self._test_url(session, url)
                    tested += 1
                    if vuln:
                        vulns.append(vuln)
                except Exception as e:
                    self.logger.debug(f"Erro ao testar CORS em {url}: {e}")
        finally:
            session.close()

        execution_time = time.time() - start_time
        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=execution_time,
            data={
                "vulnerabilities": [v.to_dict() for v in vulns],
                "tested_urls": tested,
                "candidate_urls": len(candidates),
            },
            summary=f"{self.name}: {len(vulns)} endpoint(s) com CORS inseguro em {tested} testado(s).",
        )

    def _collect_candidates(self, discoveries: Dict[str, Any], actual_target: str) -> List[str]:
        """URLs de endpoints + request_nodes, dedup e em escopo."""
        target_netloc = urlparse(
            actual_target if "://" in actual_target else f"https://{actual_target}"
        ).netloc.lower()

        urls: List[str] = []
        if actual_target.startswith(("http://", "https://")):
            urls.append(actual_target)
        for ep in discoveries.get("endpoints", []) or []:
            if isinstance(ep, str):
                urls.append(ep)
            elif isinstance(ep, dict) and ep.get("url"):
                urls.append(ep["url"])
        for node in discoveries.get("request_nodes", []) or []:
            if isinstance(node, dict) and node.get("url"):
                urls.append(node["url"])

        seen: set = set()
        result: List[str] = []
        for url in urls:
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue
            host = (urlparse(url).hostname or "").lower()
            if target_netloc and host and host != target_netloc and not host.endswith("." + target_netloc):
                continue
            if url in seen:
                continue
            seen.add(url)
            result.append(url)
            if len(result) >= self.max_urls:
                break
        return result

    def _probe_origins(self, actual_host: str) -> List[str]:
        # Origins forjados: arbitrário, null, e um sufixo-trick baseado no host.
        origins = [_ATTACKER_ORIGIN, "null"]
        if actual_host:
            origins.append(f"https://{actual_host}.evil-reconforge-probe.com")
        return origins

    def _test_url(self, session: requests.Session, url: str) -> Optional[Vulnerability]:
        host = (urlparse(url).hostname or "").lower()
        best: Optional[Vulnerability] = None
        best_rank = -1
        severity_rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

        for origin in self._probe_origins(host):
            self.rate_limiter.wait()
            resp = session.get(url, headers={"Origin": origin}, timeout=self.timeout)
            self.rate_limiter.record_request()
            if self.rate_limiter.handle_rate_limit(resp.status_code):
                self.rate_limiter.wait()
                resp = session.get(url, headers={"Origin": origin}, timeout=self.timeout)
                self.rate_limiter.record_request()

            acao = resp.headers.get("Access-Control-Allow-Origin")
            acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").strip().lower()
            if not acao:
                continue

            creds = acac == "true"
            finding = self._evaluate(url, origin, acao.strip(), creds)
            if finding:
                rank = severity_rank.get(finding.severity, 0)
                if rank > best_rank:
                    best, best_rank = finding, rank
        return best

    def _evaluate(self, url: str, origin: str, acao: str, creds: bool) -> Optional[Vulnerability]:
        # Reflexão do Origin arbitrário que enviamos.
        if acao == origin and origin != "null":
            sev = "High" if creds else "Medium"
            kind = "reflete o Origin arbitrário enviado"
        elif acao == "null" and origin == "null":
            sev = "High" if creds else "Medium"
            kind = "confia no Origin 'null'"
        elif acao == "*" and creds:
            # Navegadores rejeitam * + credentials, mas indica config incorreta.
            sev = "Medium"
            kind = "retorna '*' com Allow-Credentials: true (combinação inválida)"
        else:
            return None

        return Vulnerability(
            name="CORS Mal Configurado",
            severity=sev,
            description=(
                f"Endpoint '{url}' {kind}"
                + (" com credenciais permitidas" if creds else "") + "."
            ),
            url=url,
            evidence=(
                f"Origin enviado: {origin}\n"
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {str(creds).lower()}"
            ),
            cve="CWE-942",
            remediation=(
                "Validar o header Origin contra uma allowlist estrita de origens "
                "confiáveis; nunca refletir o Origin recebido nem usar '*' em "
                "conjunto com Access-Control-Allow-Credentials: true."
            ),
            plugin_source=self.name,
        )
