"""
Plugin de Scanner de Header Injection (HTTP Response Splitting)
Detecta injeção de novos cabeçalhos na resposta HTTP.
"""

import requests
from typing import List, Dict, Any, Optional, Tuple

from core.parameterized_vulnerability_plugin import ParameterizedVulnerabilityPlugin
from core.models import Vulnerability


class HeaderInjectionScannerPlugin(ParameterizedVulnerabilityPlugin):
    """
    Scanner de Header Injection.
    """

    def get_default_payloads(self) -> List[str]:
        return [
            "test\r\nX-Injected-Header: ReconForge",
            "test%0d%0aX-Injected-Header: ReconForge",
        ]

    def evaluate_hit(
        self, response: requests.Response, payload: Any, injection_point: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        hit = 'X-Injected-Header' in response.headers
        return hit, ("X-Injected-Header" if hit else None)

    def build_vulnerability(
        self,
        request_node: Dict[str, Any],
        injection_point: Dict[str, Any],
        payload: Any,
        response: requests.Response,
        indicator: str,
    ) -> Vulnerability:
        param_name = injection_point.get("parameter_name")
        return Vulnerability(
            name="HTTP Header Injection",
            severity="Medium",
            description=f"Possivel Header Injection no parametro '{param_name}'.",
            url=request_node.get("url"),
            evidence=f"Payload: {payload}\nInjected header found in response.",
            cve="CWE-113",
            plugin_source=self.name,
        )
