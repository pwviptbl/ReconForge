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
        # Mapeamento padrão payload -> indicador
        return {
            "/etc/passwd": "root:x:0:0:",
            "../../../../../../../../etc/passwd": "root:x:0:0:",
            "C:\\Windows\\win.ini": "[extensions]",
            "..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini": "[extensions]",
        }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        # Se os payloads vierem de um YAML como lista, não teremos indicadores.
        # Mas para LFI, os arquivos YAML devem seguir o formato de dicionário
        # ou a subclasse deve prover o mapeamento.
        self.indicators = self.payloads if isinstance(self.payloads, dict) else self.get_default_payloads()
        # Se for um dicionário, extraímos as chaves para a lista de payloads a testar
        if isinstance(self.payloads, dict):
            self.payloads = list(self.payloads.keys())

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
