"""
Plugin de Scanner de SSTI (Server-Side Template Injection)
Detecta injeção de templates tentando realizar cálculos matemáticos.
"""

import requests
from typing import List, Dict, Any, Optional, Tuple

from core.parameterized_vulnerability_plugin import ParameterizedVulnerabilityPlugin
from core.models import Vulnerability


class SSTIScannerPlugin(ParameterizedVulnerabilityPlugin):
    """
    Scanner de SSTI (Server-Side Template Injection).
    """

    def get_default_payloads(self) -> Dict[str, str]:
        return {
            "{{7*7}}": "49",
            "${7*7}": "49",
            "<%= 7*7 %>": "49",
            "{{7*'7'}}": "7777777",
        }

    @property
    def payload_list(self) -> List[str]:
        return list(self.get_default_payloads().keys())

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.indicators = self.get_default_payloads()
        if not self.config.get("payloads"):
            self.payloads = self.payload_list

    def evaluate_hit(
        self, response: requests.Response, payload: Any, injection_point: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        indicator = self.indicators.get(str(payload))
        if not indicator:
            return False, None
        
        hit = indicator in (response.text or "")
        return hit, (indicator if hit else None)

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
            name="Server-Side Template Injection (SSTI)",
            severity="High",
            description=f"Possivel SSTI no parametro '{param_name}'.",
            url=request_node.get("url"),
            evidence=f"Payload: {payload}\nIndicator: {indicator}",
            cve="CWE-1336",
            plugin_source=self.name,
        )
