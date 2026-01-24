import re
from typing import List, Any, Dict

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class SstiModule(IScanModule):
    """Detecta SSTI com payloads de template engines comuns."""

    PAYLOADS = {
        "{{7*7}}": "49",
        "${7*7}": "49",
        "<%= 7*7 %>": "49",
        "${{7*7}}": "49"
    }

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

        for payload, indicator in self.PAYLOADS.items():
            try:
                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                response = session.send(request_to_send, timeout=session.timeout)
                if indicator in (response.text or ""):
                    return [
                        Vulnerability(
                            name="Server-Side Template Injection (SSTI)",
                            severity="High",
                            description=(
                                f"Possivel SSTI em '{injection_point['parameter_name']}' com payload '{payload}'."
                            ),
                            evidence=indicator,
                            request_node_id=request_node['id'],
                            injection_point_id=injection_point['id']
                        )
                    ]
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        return []
