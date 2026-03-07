"""
Plugin de Scanner de Open Redirect
Detecta vulnerabilidades de redirecionamento aberto em parâmetros GET.
Migrado do módulo legado src/scanners/open_redirect_module.py
"""

from typing import List, Dict, Any, Optional
import requests
import time
from urllib.parse import urlparse, parse_qs

from core.plugin_base import VulnerabilityPlugin, PluginResult
from core.models import Vulnerability
from utils.logger import get_logger
from utils.request_utils import rebuild_attack_request
from utils.http_session import build_request_node_headers, create_requests_session
from utils.web_discovery import build_request_nodes, iter_request_node_parameters

class OpenRedirectScannerPlugin(VulnerabilityPlugin):
    """
    Scanner de Open Redirect.
    Injeta URLs externas em parâmetros e verifica se a resposta redireciona para elas.
    """
    
    DEFAULT_PAYLOADS = [
        "https://example.com",
        "//example.com",
        "/\\example.com",
        "http://example.com"
    ]

    def __init__(self, config: Dict[str, Any] = None):
        config = config or {}
        super().__init__(config)
        self.config = config or {}
        self.logger = get_logger("OpenRedirectScanner")
        self.payloads = config.get('payloads', self.DEFAULT_PAYLOADS)
        self.timeout = config.get('timeout', 10)
        self.verify_ssl = config.get('verify_ssl', False)
        
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()
        vulns = []
        tested_count = 0
        
        # Preferir alvo original com porta/protocolo se disponível
        actual_target = context.get('original_target', target)
        self.logger.info(f"🚀 Iniciando varredura Open Redirect em: {actual_target}")
        
        discoveries = context.get('discoveries', {})
        session = create_requests_session(
            plugin_config=self.config,
            session_file=context.get("auth_session_file"),
        )
        session.verify = self.verify_ssl
        session.headers.update({
            'User-Agent': 'ReconForge/OpenRedirectScanner'
        })
        request_nodes = build_request_nodes(
            discoveries,
            actual_target,
            default_headers=build_request_node_headers(session),
        )

        self.logger.info(f"🔍 Testando {len(request_nodes)} requests para Open Redirect...")
        for request_node in request_nodes:
            try:
                candidates = self._test_request_node(session, request_node)
                if candidates:
                    vulns.extend(candidates)
                tested_count += len(iter_request_node_parameters(request_node))
            except Exception as e:
                self.logger.debug(f"Erro ao testar request {request_node.get('url')}: {e}")

        execution_time = time.time() - start_time
        
        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=execution_time,
            data={
                'vulnerabilities': [v.to_dict() for v in vulns],
                'tested_count': tested_count
            }
        )

    def _test_request_node(self, session: requests.Session, request_node: Dict[str, Any]) -> List[Vulnerability]:
        found_vulns = []
        for injection_point in iter_request_node_parameters(request_node):
            location = injection_point.get('location')
            if location not in {'QUERY', 'BODY_FORM', 'BODY_JSON', 'BODY_MULTIPART'}:
                continue
            param_name = injection_point.get('parameter_name')
            if not param_name:
                continue

            for payload in self.payloads:
                try:
                    prepared = rebuild_attack_request(request_node, injection_point, payload)
                    response = session.send(prepared, timeout=self.timeout, allow_redirects=False)
                    location_header = response.headers.get('Location') or response.headers.get('Refresh', '')
                    if location_header and "example.com" in location_header:
                        found_vulns.append(
                            Vulnerability(
                                name="Open Redirect",
                                severity="Medium",
                                description=f"Redirecionamento aberto detectado no parametro '{param_name}'.",
                                url=request_node.get('url'),
                                evidence=(
                                    f"Payload: {payload}\nLocation: {location}\n"
                                    f"Location Header: {location_header}"
                                ),
                                cve="CWE-601",
                                plugin_source="OpenRedirectScannerPlugin"
                            )
                        )
                        break
                except Exception:
                    pass
        return found_vulns

    def _test_get_param(self, session: requests.Session, url: str, param_name: str) -> Optional[Vulnerability]:
        request_node = {
            'method': 'GET',
            'url': url,
            'headers': dict(session.headers),
            'params': {}
        }
        
        injection_point = {
            'location': 'QUERY',
            'parameter_name': param_name,
            'original_value': ''
        }

        for payload in self.payloads:
            try:
                prepared = rebuild_attack_request(request_node, injection_point, payload)
                response = session.send(prepared, timeout=self.timeout, allow_redirects=False)
                
                # Checar Location ou Refresh header
                location = response.headers.get('Location') or response.headers.get('Refresh', '')
                
                if location and ("example.com" in location):
                    return Vulnerability(
                        name="Open Redirect",
                        severity="Medium",
                        description=f"Redirecionamento aberto detectado no parâmetro '{param_name}'.",
                        url=url,
                        evidence=f"Payload: {payload}\nLocation Header: {location}",
                        cve="CWE-601",
                        plugin_source="OpenRedirectScannerPlugin"
                    )
            except Exception:
                pass
        return None

    def _test_form(self, session: requests.Session, form: Dict[str, Any]) -> List[Vulnerability]:
        found_vulns = []
        target_url = form.get('action')
        method = form.get('method', 'get').upper()
        inputs = form.get('inputs', [])

        if not target_url:
            return []

        base_data = {}
        for inp in inputs:
            name = inp.get('name')
            if name:
                base_data[name] = inp.get('value', 'test')

        request_node = {
            'method': method,
            'url': target_url,
            'headers': dict(session.headers),
        }
        
        if method == 'POST':
            request_node['data'] = base_data
        else:
            request_node['params'] = base_data

        for inp in inputs:
            param_name = inp.get('name')
            if not param_name:
                continue
            
            injection_point = {
                'location': 'BODY_FORM' if method == 'POST' else 'QUERY',
                'parameter_name': param_name,
                'original_value': inp.get('value', '')
            }

            for payload in self.payloads:
                try:
                    prepared = rebuild_attack_request(request_node, injection_point, payload)
                    response = session.send(prepared, timeout=self.timeout, allow_redirects=False)

                    location = response.headers.get('Location') or response.headers.get('Refresh', '')
                    if location and ("example.com" in location):
                        vuln = Vulnerability(
                            name="Open Redirect in Form",
                            severity="Medium",
                            description=f"Redirecionamento aberto detectado no campo '{param_name}' do formulário.",
                            url=target_url,
                            evidence=f"Payload: {payload}\nLocation Header: {location}",
                            cve="CWE-601",
                            plugin_source="OpenRedirectScannerPlugin"
                        )
                        found_vulns.append(vuln)
                        break
                except Exception:
                    pass
        
        return found_vulns

    def get_info(self) -> Dict[str, Any]:
        info = super().get_info()
        info['category'] = 'vulnerability'
        info['requires'] = ['WebFlowMapperPlugin']
        return info
