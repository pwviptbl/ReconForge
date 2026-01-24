from typing import List, Any, Dict
from urllib.parse import urlparse

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class OpenRedirectModule(IScanModule):
    """Detecta open redirect via Location/Refresh headers."""

    PAYLOADS = [
        "https://example.com",
        "//example.com",
        "/\\example.com"
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
                response = session.send(request_to_send, timeout=session.timeout, allow_redirects=False)
                location = response.headers.get('Location') or response.headers.get('Refresh', '')
                if location and "example.com" in location:
                    return [
                        Vulnerability(
                            name="Open Redirect",
                            severity="Medium",
                            description=f"Redirecionamento aberto no parametro '{injection_point['parameter_name']}'.",
                            evidence=location,
                            request_node_id=request_node['id'],
                            injection_point_id=injection_point['id']
                        )
                    ]
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        return []
