from typing import List, Any, Dict
import re

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class IdorModule(IScanModule):
    """Detecta possiveis IDOR alterando IDs numericos."""

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        relevant_locations = {'QUERY', 'BODY_FORM', 'PATH'}
        if injection_point['location'] not in relevant_locations:
            return []

        original_value = injection_point.get('original_value', '')
        if not str(original_value).isdigit():
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        try:
            original_request = rebuild_attack_request(request_node, injection_point, original_value)
            original_response = session.send(original_request, timeout=session.timeout)
        except Exception:
            return []

        try:
            new_value = str(int(original_value) + 1)
        except Exception:
            return []

        try:
            modified_request = rebuild_attack_request(request_node, injection_point, new_value)
            modified_response = session.send(modified_request, timeout=session.timeout)
        except Exception:
            return []

        if modified_response.status_code == original_response.status_code:
            if len(modified_response.text or "") and modified_response.text != original_response.text:
                return [
                    Vulnerability(
                        name="Insecure Direct Object Reference (IDOR)",
                        severity="Medium",
                        description=(
                            f"Alteracao de ID '{original_value}' -> '{new_value}' retornou resposta diferente "
                            "com mesmo status, possivel IDOR."
                        ),
                        evidence={
                            "original_len": len(original_response.text or ""),
                            "modified_len": len(modified_response.text or "")
                        },
                        request_node_id=request_node['id'],
                        injection_point_id=injection_point['id']
                    )
                ]

        return []
