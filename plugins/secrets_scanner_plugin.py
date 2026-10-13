"""
Plugin de Scanner de Secrets (credenciais/chaves expostas)

Baixa os conteúdos já descobertos (endpoints do gau/katana, URLs de
request_nodes e arquivos .js referenciados) e faz grep por padrões de
segredos — chaves de API, tokens, chaves privadas, credenciais em URL.

Diferente dos scanners de injeção, não envia payloads: apenas lê respostas.
Por isso herda de VulnerabilityPlugin (e não de
ParameterizedVulnerabilityPlugin). Reaproveita a sessão, o rate limiter e a
política de Tor já existentes.

Os valores detectados são REDIGIDOS no evidence (apenas um prefixo é
mostrado) para não despejar o segredo em claro nos relatórios.
"""

import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from core.models import Vulnerability
from core.plugin_base import PluginResult, VulnerabilityPlugin
from utils.http_session import build_request_node_headers, create_requests_session
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

# (nome_legível, regex compilada, severidade)
# Padrões escolhidos para minimizar falso-positivo (prefixos bem específicos).
_SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]", str]] = [
    ("AWS Access Key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "High"),
    ("AWS Secret Access Key", re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"), "Critical"),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "High"),
    ("Google OAuth Token", re.compile(r"\bya29\.[0-9A-Za-z_\-]+\b"), "High"),
    ("GitHub Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b"), "Critical"),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b"), "High"),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_\-/]+"), "Medium"),
    ("Stripe Secret Key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"), "Critical"),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "Critical"),
    ("JSON Web Token (JWT)", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "Low"),
    ("Credential in URL", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@"), "Medium"),
    ("Generic API Key assignment", re.compile(r"(?i)(?:api[_\-]?key|apikey|secret|token|password|passwd)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]"), "Medium"),
]


class SecretsScannerPlugin(VulnerabilityPlugin):
    """Scanner passivo de segredos expostos em respostas HTTP/JS."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        super().__init__(config)
        self.config = config
        self.logger = get_logger(self.__class__.__name__)
        self.timeout = self.config.get("timeout", 10)
        self.verify_ssl = self.config.get("verify_ssl", True)
        self.max_urls = self.config.get("max_urls", 200)
        self.max_body_bytes = self.config.get("max_body_bytes", 2_000_000)  # 2 MB por resposta
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
        self.logger.info(f"🔍 {len(candidates)} URLs candidatas para varredura de secrets")

        session = create_requests_session(
            plugin_config=self.config,
            session_file=context.get("auth_session_file"),
        )
        session.verify = self.verify_ssl

        scanned = 0
        # Dedup por (url, tipo, valor-redigido) para não repetir o mesmo achado.
        seen_findings: set = set()

        try:
            for url in candidates:
                try:
                    body = self._fetch_body(session, url)
                    if not body:
                        continue
                    scanned += 1
                    for vuln in self._scan_body(url, body, seen_findings):
                        vulns.append(vuln)
                except Exception as e:
                    self.logger.debug(f"Erro ao varrer {url}: {e}")
        finally:
            session.close()

        execution_time = time.time() - start_time
        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=execution_time,
            data={
                "vulnerabilities": [v.to_dict() for v in vulns],
                "scanned_urls": scanned,
                "candidate_urls": len(candidates),
            },
            summary=f"{self.name}: {len(vulns)} segredo(s) em {scanned} resposta(s).",
        )

    def _collect_candidates(self, discoveries: Dict[str, Any], actual_target: str) -> List[str]:
        """Reúne URLs de endpoints + request_nodes, dedup e em escopo."""
        target_host = (urlparse(
            actual_target if "://" in actual_target else f"https://{actual_target}"
        ).hostname or "").lower()

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
            if target_host and host and host != target_host and not host.endswith("." + target_host):
                continue
            if url in seen:
                continue
            seen.add(url)
            result.append(url)
            if len(result) >= self.max_urls:
                break
        return result

    def _fetch_body(self, session: requests.Session, url: str) -> Optional[str]:
        self.rate_limiter.wait()
        response = session.get(url, timeout=self.timeout, stream=True)
        self.rate_limiter.record_request()

        if self.rate_limiter.handle_rate_limit(response.status_code):
            self.rate_limiter.wait()
            response = session.get(url, timeout=self.timeout, stream=True)
            self.rate_limiter.record_request()

        content = response.content[: self.max_body_bytes]
        return content.decode("utf-8", errors="ignore")

    def _scan_body(self, url: str, body: str, seen_findings: set) -> List[Vulnerability]:
        found: List[Vulnerability] = []
        for label, pattern, severity in _SECRET_PATTERNS:
            for match in pattern.finditer(body):
                raw = match.group(0)
                key = (url, label, raw)
                if key in seen_findings:
                    continue
                seen_findings.add(key)
                found.append(
                    Vulnerability(
                        name=f"Segredo Exposto — {label}",
                        severity=severity,
                        description=(
                            f"Possível {label} exposto na resposta de '{url}'."
                        ),
                        url=url,
                        evidence=f"Tipo: {label}\nTrecho (redigido): {self._redact(raw)}",
                        cve="CWE-200",
                        remediation=(
                            "Remover o segredo do conteúdo servido ao cliente, revogar/rotacionar "
                            "a credencial exposta e movê-la para variável de ambiente ou cofre."
                        ),
                        plugin_source=self.name,
                    )
                )
        return found

    @staticmethod
    def _redact(value: str) -> str:
        """Mostra apenas um prefixo do segredo para evitar vazamento no relatório."""
        value = value.replace("\n", " ").strip()
        if len(value) <= 8:
            return value[:2] + "***"
        return value[:6] + "***" + f"({len(value)} chars)"
