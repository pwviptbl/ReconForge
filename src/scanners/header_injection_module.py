from typing import List, Any, Dict

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class HeaderInjectionModule(IScanModule):
    """Detecta CRLF/Header Injection via reflexao em headers."""

    PAYLOADS = [
        "test%0d%0aX-Injected-Header: injected",
        "test%0D%0AX-Injected-Header: injected"
    ]

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        relevant_locations = {'QUERY', 'BODY_FORM'}
        if injection_point['location'] not in relevant_locations:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        for payload in self.PAYLOADS:
            try:
                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                response = session.send(request_to_send, timeout=session.timeout)
                if 'X-Injected-Header' in response.headers:
                    return [
                        Vulnerability(
                            name="HTTP Header Injection (CRLF)",
                            severity="High",
                            description=f"Injecao de header detectada em '{injection_point['parameter_name']}'.",
                            evidence=dict(response.headers),
                            request_node_id=request_node['id'],
                            injection_point_id=injection_point['id']
                        )
                    ]
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        return []
