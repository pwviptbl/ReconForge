"""
Plugin de Scanner de IDOR (Insecure Direct Object Reference)
Detecta vulnerabilidades de IDOR alterando identificadores numéricos em parâmetros e URLs.
"""

import re
import requests
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

from core.parameterized_vulnerability_plugin import ParameterizedVulnerabilityPlugin
from core.models import Vulnerability
from utils.request_utils import rebuild_attack_request


class IDORScannerPlugin(ParameterizedVulnerabilityPlugin):
    """
    Scanner de IDOR (Insecure Direct Object Reference).
    """

    def get_default_payloads(self) -> List[Any]:
        # IDOR não usa payloads fixos, ele transmuta o valor original.
        return ["+1"] 

    def should_test_injection_point(self, injection_point: Dict[str, Any]) -> bool:
        original_val = injection_point.get('original_value')
        return str(original_val).isdigit()

    def _perform_injection(
        self, session: requests.Session, request_node: Dict[str, Any], injection_point: Dict[str, Any], payload: Any
    ) -> Tuple[bool, Optional[str], Optional[requests.Response]]:
        original_val = injection_point.get('original_value')
        new_val = str(int(original_val) + 1)
        
        # 1. Request Original para Baseline
        self.rate_limiter.wait()
        req_orig = rebuild_attack_request(request_node, injection_point, original_val)
        resp_orig = session.send(req_orig, timeout=self.timeout)
        self.rate_limiter.record_request()
        
        # 2. Request Modificada
        self.rate_limiter.wait()
        req_mod = rebuild_attack_request(request_node, injection_point, new_val)
        resp_mod = session.send(req_mod, timeout=self.timeout)
        self.rate_limiter.record_request()
        
        hit, indicator = self._evaluate_idor_hit(resp_orig, resp_mod)
        return hit, indicator, resp_mod

    def _evaluate_idor_hit(self, resp_orig: requests.Response, resp_mod: requests.Response) -> Tuple[bool, Optional[str]]:
        """Avalia se houve IDOR comparando as respostas."""
        if resp_orig.status_code != resp_mod.status_code:
            return False, None

        # Tentar diff semântico JSON
        try:
            data_orig = resp_orig.json()
            data_mod = resp_mod.json()
            if isinstance(data_orig, dict) and isinstance(data_mod, dict):
                if set(data_orig.keys()) == set(data_mod.keys()):
                    sensitive_keys = {'email', 'cpf', 'phone', 'name', 'address', 'id', 'user_id', 'username'}
                    for key in sensitive_keys:
                        if key in data_orig and data_orig[key] != data_mod.get(key):
                            return True, f"JSON diff: '{key}'"
        except:
            pass

        # Fallback: diff de tamanho com threshold dinâmico
        orig_len = len(resp_orig.content)
        mod_len = len(resp_mod.content)
        diff = abs(mod_len - orig_len)
        threshold = max(100, orig_len * 0.1)
        if diff > threshold:
            return True, f"Size diff: {diff} (thr {int(threshold)})"

        return False, None

    def evaluate_hit(self, response: requests.Response, payload: Any, injection_point: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        # Implementado via _perform_injection para IDOR
        return False, None

    def _test_request_node(self, session: requests.Session, request_node: Dict[str, Any], probe_logger: Any) -> List[Vulnerability]:
        # Estendemos para testar Path também
        vulns = super()._test_request_node(session, request_node, probe_logger)
        
        # Testar segmentos de PATH se for GET
        if str(request_node.get('method', 'GET')).upper() == 'GET':
            parsed = urlparse(request_node.get('url', ''))
            for match in re.finditer(r'/(\d+)(?=/|$)', parsed.path):
                original_id = match.group(1)
                vuln = self._test_idor_path(session, request_node.get('url', ''), original_id, probe_logger)
                if vuln:
                    vulns.append(vuln)
        return vulns

    def _test_idor_path(self, session: requests.Session, url: str, original_id: str, probe_logger: Any) -> Optional[Vulnerability]:
        request_node = {'method': 'GET', 'url': url, 'headers': dict(session.headers)}
        injection_point = {'location': 'PATH', 'parameter_name': 'path_segment', 'original_value': original_id}
        
        try:
            new_id = str(int(original_id) + 1)
            self.rate_limiter.wait()
            req_mod = rebuild_attack_request(request_node, injection_point, new_id)
            resp_mod = session.send(req_mod, timeout=self.timeout)
            self.rate_limiter.record_request()

            self.rate_limiter.wait()
            resp_orig = session.get(url, headers=session.headers, timeout=self.timeout)
            self.rate_limiter.record_request()

            hit, indicator = self._evaluate_idor_hit(resp_orig, resp_mod)
            if hit:
                return self.build_vulnerability(request_node, injection_point, new_id, resp_mod, indicator or "")
        except:
            pass
        return None

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
        original_val = injection_point.get("original_value")
        
        vuln_name = "Insecure Direct Object Reference (IDOR)"
        if location == "PATH":
            vuln_name += " in Path"

        return Vulnerability(
            name=vuln_name,
            severity="High",
            description=(
                f"Alteracao de ID '{original_val}' no parametro '{param_name}' "
                f"retornou resposta diferente com mesmo status."
            ),
            url=request_node.get("url"),
            evidence=f"Indicator: {indicator}\nLocation: {location}",
            cve="CWE-639",
            plugin_source=self.name,
        )
