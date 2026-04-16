"""
Plugin de Scanner de Open Redirect
Detecta redirecionamentos abertos injetando URLs externas em parâmetros.
"""

import requests
from typing import List, Dict, Any, Optional, Tuple

from core.parameterized_vulnerability_plugin import ParameterizedVulnerabilityPlugin
from core.models import Vulnerability


class OpenRedirectScannerPlugin(ParameterizedVulnerabilityPlugin):
    """
    Scanner de Open Redirect.
    """

    def get_default_payloads(self) -> List[str]:
        return [
            "https://example.com",
            "//example.com",
            "/\example.com",
            "/%09/example.com",
        ]

    def _perform_injection(
        self, session: requests.Session, request_node: Dict[str, Any], injection_point: Dict[str, Any], payload: Any
    ) -> Tuple[bool, Optional[str], Optional[requests.Response]]:
        # Sobrescrevemos para desabilitar allow_redirects
        from utils.request_utils import rebuild_attack_request
        self.rate_limiter.wait()
        prepared = rebuild_attack_request(request_node, injection_point, payload)
        response = session.send(prepared, timeout=self.timeout, allow_redirects=False)
        self.rate_limiter.record_request()
        
        if self.rate_limiter.handle_rate_limit(response.status_code):
            self.rate_limiter.wait()
            response = session.send(prepared, timeout=self.timeout, allow_redirects=False)
            self.rate_limiter.record_request()

        hit, indicator = self.evaluate_hit(response, payload, injection_point)
        return hit, indicator, response

    def evaluate_hit(
        self, response: requests.Response, payload: Any, injection_point: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        location_header = response.headers.get('Location') or response.headers.get('Refresh', '')
        if location_header and "example.com" in location_header:
            return True, f"Location: {location_header}"
        return False, None

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
            name="Open Redirect",
            severity="Medium",
            description=f"Possivel Open Redirect no parametro '{param_name}'.",
            url=request_node.get("url"),
            evidence=f"Payload: {payload}\n{indicator}",
            cve="CWE-601",
            plugin_source=self.name,
        )
