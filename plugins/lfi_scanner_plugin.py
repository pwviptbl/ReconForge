"""
Plugin de Scanner de LFI (Local File Inclusion)
Detecta inclusão de arquivos locais tentando ler /etc/passwd ou arquivos de sistema Windows.
"""

import requests
from typing import List, Dict, Any, Optional, Tuple

from core.parameterized_vulnerability_plugin import ParameterizedVulnerabilityPlugin
from core.models import Vulnerability


class LFIScannerPlugin(ParameterizedVulnerabilityPlugin):
    """
    Scanner de LFI (Local File Inclusion).
    """

    def get_default_payloads(self) -> Dict[str, str]:
        # Usamos dict para mapear payload -> indicador
        return {
            "/etc/passwd": "root:x:0:0:",
            "../../../../../../../../etc/passwd": "root:x:0:0:",
            "C:\\Windows\\win.ini": "[extensions]",
            "..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini": "[extensions]",
        }

    @property
    def payload_list(self) -> List[str]:
        return list(self.get_default_payloads().keys())

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        # Se payloads vierem da config, podem ser uma lista simples. 
        # Aqui garantimos que temos acesso aos indicadores.
        self.indicators = self.get_default_payloads()
        # Sobrescrevemos self.payloads para ser a lista de chaves
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
            name="Local File Inclusion (LFI)",
            severity="High",
            description=f"Possivel LFI no parametro '{param_name}'.",
            url=request_node.get("url"),
            evidence=f"Payload: {payload}\nIndicator: {indicator}",
            cve="CWE-22",
            plugin_source=self.name,
        )
