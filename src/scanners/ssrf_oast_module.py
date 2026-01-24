import time
from typing import List, Any, Dict

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class SsrfOastModule(IScanModule):
    """Detecta SSRF usando callbacks OAST."""

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        relevant_locations = {'QUERY', 'BODY_FORM', 'BODY_JSON', 'HEADER'}
        if injection_point['location'] not in relevant_locations:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        payload_interactions = []
        for payload_template in [
            "http://{domain}",
            "https://{domain}",
            "http://{domain}/ssrf",
        ]:
            try:
                interaction_id, domain = oast_client.generate_interaction_id(type_prefix="ssrf")
                payload = payload_template.format(domain=domain)
                payload_interactions.append({'payload': payload, 'id': interaction_id})

                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                session.send(request_to_send, timeout=session.timeout)
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        time.sleep(2)

        for interaction in payload_interactions:
            result = oast_client.check_hit(interaction['id'])
            if result and result.get('hit'):
                vulnerability = Vulnerability(
                    name="Server-Side Request Forgery (OAST)",
                    severity="High",
                    description=(
                        f"SSRF detectada via callback OAST. Payload '{interaction['payload']}' "
                        f"em '{injection_point['parameter_name']}' ({injection_point['location']})."
                    ),
                    evidence=result.get('data', {}),
                    request_node_id=request_node['id'],
                    injection_point_id=injection_point['id']
                )
                return [vulnerability]

        return []
