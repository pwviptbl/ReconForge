import re
from typing import List, Any, Dict

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class XssModule(IScanModule):
    """Detecta XSS refletido via reflexao de payload no response."""

    PAYLOADS = [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><svg/onload=alert(1)>",
        "activescanner<xss>test"
    ]

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        relevant_locations = {'QUERY', 'BODY_FORM', 'BODY_JSON', 'HEADER', 'COOKIE'}
        if injection_point['location'] not in relevant_locations:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        for payload in self.PAYLOADS:
            try:
                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                response = session.send(request_to_send, timeout=session.timeout)
                if payload in (response.text or ""):
                    return [
                        Vulnerability(
                            name="Cross-Site Scripting (Reflected)",
                            severity="High",
                            description=(
                                f"Payload refletido em '{injection_point['parameter_name']}'."
                            ),
                            evidence=payload,
                            request_node_id=request_node['id'],
                            injection_point_id=injection_point['id']
                        )
                    ]
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        return []
