"""
Estágio de detecção de vulnerabilidades (stage_detect).

Executa os plugins de varredura de vulnerabilidades e converte seus
resultados (PluginResult) em Findings padronizados usando o
PluginFindingAdapter. Os Findings ficam em state.findings prontos
para o ValidationGate (Fase 2).

Plugins típicos deste estágio:
- XssScannerPlugin
- LfiScannerPlugin
- SsrfScannerPlugin
- IdorScannerPlugin
- HeaderInjectionScannerPlugin
- OpenRedirectScannerPlugin
- SstiScannerPlugin
- WebVulnScannerPlugin
- NucleiScannerPlugin
- MisconfigurationAnalyzerPlugin
- HeaderAnalyzerPlugin
- DirectoryScannerPlugin
- SSLAnalyzerPlugin
"""

from typing import Any, Dict, List, Optional

from core.models import Finding, Vulnerability, _new_id, _now_iso
from core.stage_base import ReconStageBase
from core.workflow_state import WorkflowState


# Plugins que pertencem ao estágio de detecção
DETECT_PLUGIN_NAMES = [
    "XssScannerPlugin",
    "LfiScannerPlugin",
    "SsrfScannerPlugin",
    "IdorScannerPlugin",
    "HeaderInjectionScannerPlugin",
    "OpenRedirectScannerPlugin",
    "SstiScannerPlugin",
    "WebVulnScannerPlugin",
    "WebScannerPlugin",
    "NucleiScannerPlugin",
    "MisconfigurationAnalyzerPlugin",
    "HeaderAnalyzerPlugin",
    "DirectoryScannerPlugin",
    "SSLAnalyzerPlugin",
    "ExploitSearcherPlugin",
    "ExploitSuggesterPlugin",
    "KatanaCrawlerPlugin",
    "GauCollectorPlugin",
    "WebCrawlerPlugin",
]

# Mapeamento de nome de plugin para categoria de finding
_PLUGIN_CATEGORY_MAP = {
    "XssScannerPlugin":              "xss",
    "LfiScannerPlugin":              "lfi",
    "SsrfScannerPlugin":             "ssrf",
    "IdorScannerPlugin":             "idor",
    "HeaderInjectionScannerPlugin":  "header_injection",
    "OpenRedirectScannerPlugin":     "open_redirect",
    "SstiScannerPlugin":             "ssti",
    "WebVulnScannerPlugin":          "web_vuln",
    "WebScannerPlugin":              "web_vuln",
    "NucleiScannerPlugin":           "nuclei",
    "MisconfigurationAnalyzerPlugin": "misconfiguration",
    "HeaderAnalyzerPlugin":          "header",
    "SSLAnalyzerPlugin":             "ssl",
    "ExploitSearcherPlugin":         "exploit",
    "ExploitSuggesterPlugin":        "exploit",
}

# Mapeamento de severidade legada para confidence_score estimado
_SEVERITY_CONFIDENCE = {
    "critical": 0.90,
    "high":     0.80,
    "medium":   0.65,
    "low":      0.45,
    "info":     0.30,
}


class StageDetect(ReconStageBase):
    """
    Estágio 2: Detecção de vulnerabilidades.

    Executa plugins de scan de vulnerabilidades e transforma seus resultados
    em Findings padronizados (core/models.py). Também mantém compatibilidade
    com o modelo legado de Vulnerability em state.vulnerabilities.

    Gate: passa se ao menos 1 finding foi gerado. Se nenhum plugin de detecção
    encontrou nada, não faz sentido continuar o pipeline de exploração.
    """

    name = "stage_detect"
    timeout_seconds = 900   # Nuclei + múltiplos scanners podem demorar

    def __init__(
        self,
        plugin_manager=None,
        plugin_names: Optional[List[str]] = None,
    ):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.plugin_names = plugin_names or DETECT_PLUGIN_NAMES

    def execute(self, state: WorkflowState) -> WorkflowState:
        if not self.plugin_manager:
            self.logger.warning("plugin_manager não configurado em StageDetect — pulando")
            return state

        available = set(self.plugin_manager.plugins.keys())
        to_run = [n for n in self.plugin_names if n in available]

        if not to_run:
            self.logger.info("Nenhum plugin de detecção disponível para execução")
            return state

        self.logger.info(f"Plugins de detecção a executar: {to_run}")

        for plugin_name in to_run:
            if state.aborted:
                break
            self._run_plugin(plugin_name, state)

        self.logger.info(
            f"Stage detect: {len(state.findings)} findings gerados | "
            f"{len(state.vulnerabilities)} vulnerabilidades legadas"
        )
        return state

    def _run_plugin(self, plugin_name: str, state: WorkflowState):
        """Executa um plugin de detecção e converte resultados em Findings."""
        try:
            result = self.plugin_manager.execute_plugin(
                plugin_name,
                state.original_target or state.target,
                state.to_context_dict(),
            )
            if not result:
                return

            state.executed_plugins.append(plugin_name)
            state.plugin_results[plugin_name] = result.to_dict() if hasattr(result, "to_dict") else result

            # Converter para Findings padronizados
            new_findings = self._adapt_to_findings(plugin_name, result, state)
            for f in new_findings:
                state.add_finding(f)

            # Manter compatibilidade legada com state.vulnerabilities
            self._merge_legacy_vulns(result, state)

        except Exception as exc:
            self.logger.error(f"Erro ao executar {plugin_name}: {exc}")
            state.errors.append(f"[{self.name}] {plugin_name}: {exc}")

    def _adapt_to_findings(
        self,
        plugin_name: str,
        result: Any,
        state: WorkflowState,
    ) -> List[Finding]:
        """
        Converte o PluginResult de um plugin de detecção em uma lista de Findings.

        Na Fase 2, cada plugin terá um adapter dedicado em core/adapters/.
        Aqui usamos um adapter genérico que extrai informação dos campos
        mais comuns dos result.data.
        """
        findings: List[Finding] = []
        data: Dict = {}

        if hasattr(result, "data") and isinstance(result.data, dict):
            data = result.data
        elif isinstance(result, dict):
            data = result

        default_category = _PLUGIN_CATEGORY_MAP.get(plugin_name, "unknown")
        target = state.original_target or state.target

        # ---- Caso 1: result.data tem lista "vulnerabilities" ----
        vuln_list = data.get("vulnerabilities", [])
        if vuln_list and isinstance(vuln_list, list):
            for vuln in vuln_list:
                if not isinstance(vuln, dict):
                    continue
                f = self._vuln_dict_to_finding(
                    vuln, plugin_name, default_category, target, state.run_id
                )
                if f:
                    findings.append(f)
            return findings

        # ---- Caso 2: result.data tem lista "findings" (alguns plugins já usam) ----
        raw_findings = data.get("findings", [])
        if raw_findings and isinstance(raw_findings, list):
            for item in raw_findings:
                if not isinstance(item, dict):
                    continue
                f = self._vuln_dict_to_finding(
                    item, plugin_name, default_category, target, state.run_id
                )
                if f:
                    findings.append(f)
            return findings

        # ---- Caso 3: o próprio result representa uma vulnerabilidade ----
        if data.get("vulnerable") or data.get("is_vulnerable"):
            f = Finding(
                category=default_category,
                target=target,
                endpoint=str(data.get("url", data.get("endpoint", target))),
                method=str(data.get("method", "GET")),
                parameter=str(data.get("parameter", data.get("param", ""))),
                context=str(data.get("context", "HTML_BODY")),
                candidate_payload=str(data.get("payload", data.get("evidence", ""))),
                detection_source=plugin_name,
                raw_evidence=str(data.get("evidence", data.get("detail", ""))),
                confidence_score=self._estimate_confidence(data, plugin_name),
                externally_exploitable=bool(data.get("externally_exploitable", True)),
                run_id=state.run_id,
            )
            findings.append(f)

        return findings

    def _vuln_dict_to_finding(
        self,
        vuln: Dict,
        plugin_name: str,
        default_category: str,
        target: str,
        run_id: Optional[int],
    ) -> Optional[Finding]:
        """Converte um dicionário de vulnerabilidade em Finding."""
        # Pular entradas sem informação mínima
        if not vuln.get("name") and not vuln.get("url") and not vuln.get("endpoint"):
            return None

        severity = str(vuln.get("severity", "medium")).lower()
        category = self._infer_category(vuln, default_category)
        confidence = _SEVERITY_CONFIDENCE.get(severity, 0.5)

        # Alguns plugins incluem confidence própria
        if "confidence" in vuln:
            try:
                confidence = float(vuln["confidence"])
                if confidence > 1.0:
                    confidence = confidence / 100.0
            except (ValueError, TypeError):
                pass

        return Finding(
            category=category,
            target=str(vuln.get("host", vuln.get("target", target))),
            endpoint=str(vuln.get("url", vuln.get("endpoint", target))),
            method=str(vuln.get("method", "GET")),
            parameter=str(vuln.get("parameter", vuln.get("param", ""))),
            context=str(vuln.get("context", "HTML_BODY")),
            candidate_payload=str(vuln.get("payload", vuln.get("evidence", ""))),
            detection_source=plugin_name,
            raw_evidence=str(vuln.get("evidence", vuln.get("description", ""))),
            confidence_score=confidence,
            externally_exploitable=bool(vuln.get("externally_exploitable", True)),
            run_id=run_id,
        )

    def _infer_category(self, vuln: Dict, default: str) -> str:
        """Tenta inferir a categoria de um achado a partir de seus campos."""
        name = str(vuln.get("name", "")).lower()
        cat_map = {
            "dom xss": "dom_xss",
            "xss": "xss",
            "cross-site": "xss",
            "sql": "sqli",
            "injection": "sqli",
            "lfi": "lfi",
            "local file": "lfi",
            "ssrf": "ssrf",
            "server-side request": "ssrf",
            "csrf": "csrf",
            "idor": "idor",
            "insecure direct": "idor",
            "open redirect": "open_redirect",
            "redirect": "open_redirect",
            "header injection": "header_injection",
            "ssti": "ssti",
            "template injection": "ssti",
            "ssl": "ssl",
            "tls": "ssl",
            "misconfig": "misconfiguration",
            "rce": "rce",
            "command": "rce",
        }
        for keyword, category in cat_map.items():
            if keyword in name:
                return category
        return vuln.get("category", default)

    def _estimate_confidence(self, data: Dict, plugin_name: str) -> float:
        """Estima score de confiança quando o plugin não fornece explicitamente."""
        severity = str(data.get("severity", "medium")).lower()
        base = _SEVERITY_CONFIDENCE.get(severity, 0.5)
        # Plugins com maior precisão histórica recebem boost
        precise_plugins = {"NucleiScannerPlugin", "XssScannerPlugin", "SsrfScannerPlugin"}
        if plugin_name in precise_plugins:
            base = min(1.0, base + 0.10)
        return base

    def _merge_legacy_vulns(self, result: Any, state: WorkflowState):
        """
        Mantém compatibilidade com state.vulnerabilities para plugins e
        relatórios que ainda consomem o modelo legado de Vulnerability.
        """
        data: Dict = {}
        if hasattr(result, "data") and isinstance(result.data, dict):
            data = result.data
        elif isinstance(result, dict):
            data = result

        vuln_list = data.get("vulnerabilities", [])
        if not vuln_list:
            return

        for v in vuln_list:
            if isinstance(v, dict):
                state.vulnerabilities.append(v)
            elif hasattr(v, "to_dict"):
                state.vulnerabilities.append(v)

    def gate_passes(self, state: WorkflowState) -> bool:
        """
        Passa se ao menos 1 finding foi gerado.
        Sem findings, não há o que validar ou explorar.
        """
        total = len(state.findings) + len(state.vulnerabilities)
        if total == 0:
            self.logger.info(
                "Gate detect: nenhum finding encontrado — pipeline de exploração será pulado"
            )
        return total > 0
