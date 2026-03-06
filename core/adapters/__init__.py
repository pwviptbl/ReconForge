"""
Adaptadores de PluginResult → Finding — Fase 2

Cada adaptador converte a saída livre (Dict) de um plugin de detecção em
Finding padronizado com confidence_score calculado por heurística específica
do plugin.

Hierarquia:
    PluginFindingAdapter          ← classe principal (facade)
        ├── XssAdapter
        ├── LfiAdapter
        ├── SsrfAdapter
        ├── IdorAdapter
        ├── HeaderInjectionAdapter
        ├── OpenRedirectAdapter
        ├── SstiAdapter
        ├── NucleiAdapter
        ├── MisconfigAdapter
        └── GenericAdapter        ← fallback para plugins não mapeados
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from core.models import Finding, _new_id, _now_iso
from utils.logger import get_logger

logger = get_logger("adapters")


# ---------------------------------------------------------------------------
# Helpers compartilhados
# ---------------------------------------------------------------------------

_SEVERITY_SCORE: Dict[str, float] = {
    "critical": 0.90,
    "high":     0.80,
    "medium":   0.65,
    "low":      0.45,
    "info":     0.30,
    "unknown":  0.40,
}


def _severity_to_score(severity: str) -> float:
    return _SEVERITY_SCORE.get(str(severity).lower(), 0.40)


def _extract_param(url: str, payload: str) -> str:
    """Infere parâmetro vulnerável a partir de URL ou payload."""
    # Tentar extrair da URL
    qs_match = re.search(r"[?&]([^=&]+)=", url or "")
    if qs_match:
        return qs_match.group(1)
    # Tentar extrair do payload (ex: param=value)
    eq_match = re.match(r"([a-zA-Z_][a-zA-Z0-9_]*)=", payload or "")
    if eq_match:
        return eq_match.group(1)
    return ""


def _safe_str(v: Any) -> str:
    return str(v) if v is not None else ""


# ---------------------------------------------------------------------------
# Adaptadores por plugin
# ---------------------------------------------------------------------------

class GenericAdapter:
    """
    Adaptador genérico para plugins não mapeados explicitamente.
    Tenta extrair o máximo de informação disponível do PluginResult.data.
    """
    category = "unknown"

    def convert(
        self,
        plugin_name: str,
        target: str,
        data: Dict[str, Any],
        run_id: Optional[int] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Caso 1: data contém lista de vulnerabilidades
        vulns = data.get("vulnerabilities") or data.get("findings") or []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            f = self._vuln_dict_to_finding(v, plugin_name, target, run_id)
            if f:
                findings.append(f)

        # Caso 2: data tem flag "vulnerable" direta
        if not findings and data.get("vulnerable"):
            url = _safe_str(data.get("url") or target)
            payload = _safe_str(data.get("payload") or data.get("parameter") or "")
            f = Finding(
                category=self._infer_category(plugin_name),
                target=target,
                endpoint=url,
                method=_safe_str(data.get("method", "GET")),
                parameter=_extract_param(url, payload),
                detection_source=plugin_name,
                candidate_payload=payload,
                raw_evidence=_safe_str(data.get("evidence") or data.get("snippet") or ""),
                confidence_score=_severity_to_score(data.get("severity", "medium")),
                run_id=run_id,
            )
            findings.append(f)

        return findings

    def _vuln_dict_to_finding(
        self,
        v: Dict[str, Any],
        plugin_name: str,
        target: str,
        run_id: Optional[int],
    ) -> Optional[Finding]:
        url = _safe_str(v.get("url") or v.get("endpoint") or target)
        payload = _safe_str(v.get("payload") or v.get("parameter") or "")
        severity = _safe_str(v.get("severity", "medium"))
        name_str = _safe_str(v.get("name") or v.get("type") or "")

        # Confidence base por severidade + bônus se tem evidência
        base_score = _severity_to_score(severity)
        evidence = _safe_str(v.get("evidence") or v.get("snippet") or v.get("description") or "")
        if evidence:
            base_score = min(1.0, base_score + 0.05)

        return Finding(
            category=self._infer_category(name_str or plugin_name),
            target=target,
            endpoint=url,
            method=_safe_str(v.get("method", "GET")),
            parameter=_extract_param(url, payload) or _safe_str(v.get("parameter") or ""),
            detection_source=plugin_name,
            candidate_payload=payload,
            raw_evidence=evidence,
            confidence_score=base_score,
            run_id=run_id,
        )

    @staticmethod
    def _infer_category(name: str) -> str:
        name_lower = name.lower()
        category_keywords: Dict[str, str] = {
            "dom xss": "dom_xss",
            "xss": "xss", "cross-site scripting": "xss",
            "sql": "sqli", "injection": "sqli",
            "ssrf": "ssrf", "server-side request": "ssrf",
            "lfi": "lfi", "local file": "lfi", "path traversal": "lfi",
            "idor": "idor", "insecure direct": "idor",
            "csrf": "csrf", "cross-site request forgery": "csrf",
            "ssti": "ssti", "template injection": "ssti",
            "open redirect": "open_redirect",
            "header injection": "header_injection",
            "auth": "auth", "authentication": "auth",
            "rce": "rce", "remote code": "rce",
            "xxe": "xxe", "xml external": "xxe",
            "misconfig": "misconfiguration", "misconfiguration": "misconfiguration",
        }
        for keyword, cat in category_keywords.items():
            if keyword in name_lower:
                return cat
        return "unknown"


class XssAdapter(GenericAdapter):
    category = "xss"

    def convert(self, plugin_name, target, data, run_id=None):
        findings = super().convert(plugin_name, target, data, run_id)
        for f in findings:
            evidence_lower = f.raw_evidence.lower()
            payload_lower = f.candidate_payload.lower()

            if any(marker in evidence_lower for marker in ["dom", "innerhtml", "document.write", "location.hash"]):
                f.category = "dom_xss"
                f.context = "DOM"
                continue

            f.category = "xss"
            # XSS: contexto importa para seleção de payload
            if "${" in payload_lower or "template literal" in evidence_lower:
                f.context = "JS_TEMPLATE"
            elif "attribute" in evidence_lower:
                f.context = "ATTRIBUTE"
            elif "javascript" in evidence_lower or "js" in f.endpoint.lower():
                f.context = "JS_STRING"
            elif "url" in evidence_lower:
                f.context = "URL"
            else:
                f.context = "HTML_BODY"
        return findings


class LfiAdapter(GenericAdapter):
    category = "lfi"

    def convert(self, plugin_name, target, data, run_id=None):
        findings = super().convert(plugin_name, target, data, run_id)
        for f in findings:
            f.category = "lfi"
            # LFI confirmado por conteúdo (ex: root:x:0:0) → score mais alto
            evidence = f.raw_evidence.lower()
            if any(marker in evidence for marker in ["root:", "/etc/passwd", "win.ini", "[windows]"]):
                f.confidence_score = min(1.0, f.confidence_score + 0.20)
                f.raw_evidence = f"[FILE_CONTENT_CONFIRMED]\n{f.raw_evidence}"
        return findings


class SsrfAdapter(GenericAdapter):
    category = "ssrf"

    def convert(self, plugin_name, target, data, run_id=None):
        findings = super().convert(plugin_name, target, data, run_id)
        for f in findings:
            f.category = "ssrf"
            # SSRF: marcar contexto como URL
            f.context = "URL"
            # Callback confirmado → score máximo
            evidence = f.raw_evidence.lower()
            if any(m in evidence for m in ["callback", "dns lookup", "oob", "interaction"]):
                f.confidence_score = min(1.0, f.confidence_score + 0.15)
        return findings


class IdorAdapter(GenericAdapter):
    category = "idor"

    def convert(self, plugin_name, target, data, run_id=None):
        findings = super().convert(plugin_name, target, data, run_id)
        for f in findings:
            f.category = "idor"
            # IDOR: sem parâmetro numérico → score penalizado
            if f.parameter and re.search(r"\d+", f.parameter):
                f.confidence_score = min(1.0, f.confidence_score + 0.05)
            elif not f.parameter:
                f.confidence_score = max(0.0, f.confidence_score - 0.10)
        return findings


class HeaderInjectionAdapter(GenericAdapter):
    category = "header_injection"

    def convert(self, plugin_name, target, data, run_id=None):
        findings = super().convert(plugin_name, target, data, run_id)
        for f in findings:
            f.category = "header_injection"
            f.context = "HEADER"
        return findings


class OpenRedirectAdapter(GenericAdapter):
    category = "open_redirect"

    def convert(self, plugin_name, target, data, run_id=None):
        findings = super().convert(plugin_name, target, data, run_id)
        for f in findings:
            f.category = "open_redirect"
            f.context = "URL"
        return findings


class SstiAdapter(GenericAdapter):
    category = "ssti"

    def convert(self, plugin_name, target, data, run_id=None):
        findings = super().convert(plugin_name, target, data, run_id)
        for f in findings:
            f.category = "ssti"


class NucleiAdapter(GenericAdapter):
    """
    Adapter especializado para NucleiScannerPlugin.
    O Nuclei reporta resultados com campos padronizados: template-id, severity, matched-at.
    """

    def convert(self, plugin_name, target, data, run_id=None):
        findings: List[Finding] = []
        vulns = data.get("vulnerabilities") or data.get("findings") or []

        for v in vulns:
            if not isinstance(v, dict):
                continue
            template_id = _safe_str(v.get("template_id") or v.get("name") or "")
            matched_at = _safe_str(v.get("matched_at") or v.get("url") or target)
            severity = _safe_str(v.get("severity", "medium"))
            evidence = _safe_str(v.get("description") or v.get("evidence") or "")

            category = self._infer_category(template_id)
            base_score = _severity_to_score(severity)
            # Nuclei templates têm alta confiança quando matched_at não é o alvo raiz
            if matched_at and matched_at != target:
                base_score = min(1.0, base_score + 0.08)

            f = Finding(
                category=category,
                target=target,
                endpoint=matched_at,
                method="GET",
                parameter=_extract_param(matched_at, ""),
                detection_source=plugin_name,
                candidate_payload=_safe_str(v.get("payload") or ""),
                raw_evidence=evidence,
                confidence_score=base_score,
                run_id=run_id,
            )
            findings.append(f)

        return findings


class MisconfigAdapter(GenericAdapter):
    category = "misconfiguration"

    def convert(self, plugin_name, target, data, run_id=None):
        findings = super().convert(plugin_name, target, data, run_id)
        for f in findings:
            f.category = "misconfiguration"
        return findings


# ---------------------------------------------------------------------------
# Facade principal
# ---------------------------------------------------------------------------

_ADAPTER_MAP: Dict[str, type] = {
    "XssScannerPlugin":            XssAdapter,
    "LfiScannerPlugin":            LfiAdapter,
    "SsrfScannerPlugin":           SsrfAdapter,
    "IdorScannerPlugin":           IdorAdapter,
    "HeaderInjectionScannerPlugin": HeaderInjectionAdapter,
    "OpenRedirectScannerPlugin":   OpenRedirectAdapter,
    "SstiScannerPlugin":           SstiAdapter,
    "NucleiScannerPlugin":         NucleiAdapter,
    "MisconfigurationAnalyzerPlugin": MisconfigAdapter,
}


class PluginFindingAdapter:
    """
    Facade que seleciona o adaptador correto para cada plugin e
    converte PluginResult.data → List[Finding].

    Uso:
        adapter = PluginFindingAdapter()
        findings = adapter.adapt(plugin_result, target, run_id)
    """

    def __init__(self):
        # Instanciar adaptadores uma vez
        self._adapters = {k: cls() for k, cls in _ADAPTER_MAP.items()}
        self._generic = GenericAdapter()

    def adapt(
        self,
        plugin_name: str,
        data: Dict[str, Any],
        target: str,
        run_id: Optional[int] = None,
    ) -> List[Finding]:
        """
        Converte saída de um plugin em Findings padronizados.

        Args:
            plugin_name: Nome da classe do plugin (ex: "XssScannerPlugin").
            data: PluginResult.data (dicionário livre).
            target: Alvo original do run.
            run_id: ID do run atual.

        Returns:
            Lista de Finding padronizados.
        """
        adapter = self._adapters.get(plugin_name, self._generic)
        try:
            return adapter.convert(plugin_name, target, data, run_id)
        except Exception as exc:
            logger.warning(f"Adapter falhou para {plugin_name}: {exc}")
            return []
