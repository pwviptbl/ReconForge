"""
Plugin de Scanner de XSS Refletido
Detecta vulnerabilidades de Cross-Site Scripting (Refletido) em parâmetros GET e formulários.
"""

import re
import requests
from typing import List, Dict, Any, Optional, Tuple

from core.parameterized_vulnerability_plugin import ParameterizedVulnerabilityPlugin
from core.models import Vulnerability


class XSSScannerPlugin(ParameterizedVulnerabilityPlugin):
    """
    Scanner de XSS Refletido.
    Analisa formulários e parâmetros de URL descobertos pelo WebCrawler.
    """

    def get_default_payloads(self) -> List[str]:
        return [
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "'><svg/onload=alert(1)>",
            "activescanner<xss>test",
        ]

    def _evaluate_xss_hit(self, response_text: str, payload: str) -> bool:
        """Avalia se o reflexo do payload constitui um hit de XSS real."""
        if payload not in response_text:
            return False

        # 1. Verificar se está dentro de um comentário HTML
        comment_pattern = re.compile(r"<!--.*?" + re.escape(payload) + r".*?-->", re.DOTALL)
        if comment_pattern.search(response_text):
            clean_text = comment_pattern.sub("", response_text)
            if payload not in clean_text:
                return False

        # 2. Verificar context contextual (Script, Atributo, etc)
        if re.search(r"<[a-zA-Z!/]", payload):
            return True

        return True

    def evaluate_hit(
        self, response: requests.Response, payload: Any, injection_point: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        hit = self._evaluate_xss_hit(response.text, str(payload))
        return hit, (str(payload) if hit else None)

    def build_vulnerability(
        self,
        request_node: Dict[str, Any],
        injection_point: Dict[str, Any],
        payload: Any,
        response: requests.Response,
        indicator: str,
    ) -> Vulnerability:
        param_name = injection_point.get("parameter_name")
        location = injection_point.get("location")
        return Vulnerability(
            name="Cross-Site Scripting (Reflected)",
            severity="High",
            description=(
                f"Payload XSS refletido no parametro '{param_name}' "
                f"via {request_node.get('method', 'GET')}."
            ),
            url=request_node.get("url"),
            evidence=f"Payload: {payload}\nLocation: {location}\nReflected in response.",
            cve="CWE-79",
            plugin_source=self.name,
        )
