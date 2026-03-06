"""
Plugin de Scanner de IDOR (Insecure Direct Object Reference)
Detecta vulnerabilidades de IDOR alterando identificadores numéricos em parâmetros e URLs.
Migrado do módulo legado src/scanners/idor_module.py
"""

from typing import List, Dict, Any, Optional
import requests
import time
import re
from urllib.parse import urlparse, parse_qs

from core.plugin_base import VulnerabilityPlugin, PluginResult
from core.models import Vulnerability
from utils.logger import get_logger
from utils.request_utils import rebuild_attack_request
from utils.http_session import create_requests_session
from utils.web_discovery import build_request_nodes, iter_request_node_parameters

class IDORScannerPlugin(VulnerabilityPlugin):
    """
    Scanner de IDOR (Insecure Direct Object Reference).
    Tenta acessar objetos de outros usuários incrementando/decrementando IDs numéricos.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        config = config or {}
        super().__init__(config)
        self.config = config or {}
        self.logger = get_logger("IDORScanner")
        self.timeout = config.get('timeout', 10)
        self.verify_ssl = config.get('verify_ssl', False)
        
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()
        vulns = []
        tested_count = 0
        
        # Preferir alvo original com porta/protocolo se disponível
        actual_target = context.get('original_target', target)
        self.logger.info(f"🚀 Iniciando varredura IDOR em: {actual_target}")
        
        discoveries = context.get('discoveries', {})
        session = create_requests_session(plugin_config=self.config)
        session.verify = self.verify_ssl
        session.headers.update({
            'User-Agent': 'ReconForge/IDORScanner'
        })
        request_nodes = build_request_nodes(discoveries, actual_target, default_headers=dict(session.headers))

        self.logger.info(f"🔍 Testando {len(request_nodes)} requests para IDOR...")
        for request_node in request_nodes:
            try:
                candidates = self._test_request_node(session, request_node)
                if candidates:
                    vulns.extend(candidates)
                tested_count += len(iter_request_node_parameters(request_node))
                if request_node.get('url'):
                    tested_count += len(re.findall(r'/(\d+)(?=/|$)', urlparse(request_node['url']).path))
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
            original_val = injection_point.get('original_value')
            if not str(original_val).isdigit():
                continue
            param_name = injection_point.get('parameter_name')
            if not param_name:
                continue
            vuln = self._test_idor_injection(session, request_node, injection_point, str(original_val))
            if vuln:
                found_vulns.append(vuln)

        if str(request_node.get('method', 'GET')).upper() == 'GET':
            parsed = urlparse(request_node.get('url', ''))
            for match in re.finditer(r'/(\d+)(?=/|$)', parsed.path):
                original_id = match.group(1)
                vuln = self._test_idor_path(session, request_node.get('url', ''), original_id)
                if vuln:
                    found_vulns.append(vuln)
        return found_vulns

    def _test_idor_injection(
        self,
        session: requests.Session,
        request_node: Dict[str, Any],
        injection_point: Dict[str, Any],
        original_val: str,
    ) -> Optional[Vulnerability]:
        try:
            req_orig = rebuild_attack_request(request_node, injection_point, original_val)
            resp_orig = session.send(req_orig, timeout=self.timeout)

            new_val = str(int(original_val) + 1)
            req_mod = rebuild_attack_request(request_node, injection_point, new_val)
            resp_mod = session.send(req_mod, timeout=self.timeout)

            if resp_mod.status_code == resp_orig.status_code:
                if len(resp_mod.content) != len(resp_orig.content) and abs(len(resp_mod.content) - len(resp_orig.content)) > 50:
                    return Vulnerability(
                        name="Insecure Direct Object Reference (IDOR)",
                        severity="High",
                        description=(
                            f"Alteracao de ID '{original_val}' -> '{new_val}' no parametro "
                            f"'{injection_point.get('parameter_name')}' retornou resposta diferente com mesmo status."
                        ),
                        url=request_node.get('url'),
                        evidence=(
                            f"Original Len: {len(resp_orig.content)}, Modified Len: {len(resp_mod.content)}\n"
                            f"Param: {injection_point.get('parameter_name')}\n"
                            f"Location: {injection_point.get('location')}"
                        ),
                        cve="CWE-639",
                        plugin_source="IDORScannerPlugin"
                    )
        except Exception:
            pass
        return None

    def _test_idor_param(self, session: requests.Session, url: str, param_name: str, original_val: str) -> Optional[Vulnerability]:
        """Testa IDOR em parâmetro GET numérico"""
        request_node = {
            'method': 'GET',
            'url': url,
            'headers': dict(session.headers),
            'params': {}
        }
        
        injection_point = {
            'location': 'QUERY',
            'parameter_name': param_name,
            'original_value': original_val
        }

        try:
            # Requisitar original para baseline
            req_orig = rebuild_attack_request(request_node, injection_point, original_val)
            resp_orig = session.send(req_orig, timeout=self.timeout)

            # Tentar ID + 1 (ou -1)
            new_val = str(int(original_val) + 1)
            req_mod = rebuild_attack_request(request_node, injection_point, new_val)
            resp_mod = session.send(req_mod, timeout=self.timeout)

            # Análise: mesmo status code, conteúdo diferente?
            if resp_mod.status_code == resp_orig.status_code:
                # Se o tamanho muda significativamente ou se o conteúdo original_val não está lá mas algo novo está
                if len(resp_mod.content) != len(resp_orig.content) and abs(len(resp_mod.content) - len(resp_orig.content)) > 50:
                     return Vulnerability(
                        name="Insecure Direct Object Reference (IDOR)",
                        severity="High",
                        description=f"Alteração de ID '{original_val}' -> '{new_val}' no parâmetro '{param_name}' retornou resposta diferente com mesmo status.",
                        url=url,
                        evidence=f"Original Len: {len(resp_orig.content)}, Modified Len: {len(resp_mod.content)}\nParam: {param_name}",
                        cve="CWE-639",
                        plugin_source="IDORScannerPlugin"
                    )

        except Exception:
            pass
        return None

    def _test_idor_path(self, session: requests.Session, url: str, original_id: str) -> Optional[Vulnerability]:
        """Testa IDOR em segmento de path numérico"""
        # Aqui request_utils.rebuild_attack_request suporta 'PATH' se passarmos original_value
        
        request_node = {
            'method': 'GET',
            'url': url,
            'headers': dict(session.headers),
        }
        
        injection_point = {
            'location': 'PATH',
            'parameter_name': 'path_segment', # Dummy name
            'original_value': original_id
        }
        
        try:
            # Tentar ID diferente
            new_id = str(int(original_id) + 1)
            
            # Request Modificado
            req_mod = rebuild_attack_request(request_node, injection_point, new_id)
            resp_mod = session.send(req_mod, timeout=self.timeout)
            
            # Comparar com original (precisamos fazer request original também)
            # Como rebuild_path substitui, o original é só o request normal
            resp_orig = session.get(url, headers=session.headers, timeout=self.timeout)

            if resp_mod.status_code == resp_orig.status_code:
                 if len(resp_mod.content) != len(resp_orig.content) and abs(len(resp_mod.content) - len(resp_orig.content)) > 50:
                     return Vulnerability(
                        name="Insecure Direct Object Reference (IDOR) in Path",
                        severity="High",
                        description=f"Alteração de ID '{original_id}' -> '{new_id}' na URL retornou resposta diferente com mesmo status.",
                        url=url,
                        evidence=f"Original URL: {url}\nModified URL: {req_mod.url}\nOriginal Len: {len(resp_orig.content)}, Modified Len: {len(resp_mod.content)}",
                        cve="CWE-639",
                        plugin_source="IDORScannerPlugin"
                    )

        except Exception:
            pass
        return None

    def get_info(self) -> Dict[str, Any]:
        info = super().get_info()
        info['category'] = 'vulnerability'
        info['requires'] = ['WebFlowMapperPlugin']
        return info
