"""
Plugin de Scanner de SSRF (Server-Side Request Forgery)
Detecta vulnerabilidades de SSRF tentando acessar localhost e redes internas.
"""

import requests
from typing import List, Dict, Any, Optional, Tuple

from core.parameterized_vulnerability_plugin import ParameterizedVulnerabilityPlugin
from core.models import Vulnerability


class SSRFScannerPlugin(ParameterizedVulnerabilityPlugin):
    """
    Scanner de SSRF (Server-Side Request Forgery).
    """

    SSRF_INDICATORS = [
        ("169.254.169.254", ["ami-id", "instance-id", "latest/meta-data/"]),           # AWS
        ("metadata.google.internal", ["computeEngine", "Metadata-Flavor"]),            # GCP
        ("169.254.169.254/metadata/instance", ["computeEngine", "Microsoft.Compute"]), # Azure
        ("127.0.0.1:6379", ["redis", "PONG", "-ERR unknown command"]),                # Redis
        ("127.0.0.1:27017", ["MongoDB", "It looks like you are trying to access"]),    # MongoDB
        ("127.0.0.1:9200", ["cluster_uuid", "name", "tagline"]),                       # Elasticsearch
        ("127.0.0.1:11211", ["STAT", "version", "uptime"]),                            # Memcached
    ]

    def get_default_payloads(self) -> List[str]:
        return [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:27017",
            "http://127.0.0.1:9200",
            "http://127.0.0.1:11211",
            "http://127.0.0.1",
            "http://localhost",
        ]

    def evaluate_hit(
        self, response: requests.Response, payload: Any, injection_point: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        hit = False
        found_indicator = None

        for target_host, indicators in self.SSRF_INDICATORS:
            if target_host in str(payload):
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        hit = True
                        found_indicator = indicator
                        break
            if hit: break

        if not hit and ("127.0.0.1" in str(payload) or "localhost" in str(payload)):
            if response.status_code == 200 and len(response.text) > 0:
                hit = True
                found_indicator = "Status 200 from Localhost"

        return hit, found_indicator

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
            name="SSRF (Server-Side Request Forgery)",
            severity="High" if "Localhost" in str(indicator) else "Critical",
            description=f"Possível SSRF no parâmetro '{param_name}'.",
            url=request_node.get("url"),
            evidence=f"Payload: {payload}\nIndicator: {indicator}",
            cve="CWE-918",
            plugin_source=self.name,
        )
