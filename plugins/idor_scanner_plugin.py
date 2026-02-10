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
        endpoints = discoveries.get('endpoints', [])
        
        urls_to_test = set()
        if actual_target.startswith('http'):
            urls_to_test.add(actual_target)
        
        for endp in endpoints:
            if isinstance(endp, str):
                urls_to_test.add(endp)
            elif isinstance(endp, dict) and 'url' in endp:
                urls_to_test.add(endp['url'])

        session = create_requests_session(plugin_config=self.config)
        session.verify = self.verify_ssl
        session.headers.update({
            'User-Agent': 'ReconForge/IDORScanner'
        })

        self.logger.info(f"🔍 Testando {len(urls_to_test)} URLs para IDOR...")
        for url in urls_to_test:
            try:
                # 1. Testar Query Params
                parsed = urlparse(url)
                if parsed.query:
                    query_params = parse_qs(parsed.query)
                    for param_name, values in query_params.items():
                        for val in values:
                            if val.isdigit():
                                tested_count += 1
                                vuln = self._test_idor_param(session, url, param_name, val)
                                if vuln:
                                    vulns.append(vuln)
                
                # 2. Testar Path Params (e.g. /users/123)
                # Regex para encontrar segmentos numéricos no path
                path_segments = re.finditer(r'/(\d+)(?=/|$)', parsed.path)
                for match in path_segments:
                    original_id = match.group(1)
                    tested_count += 1
                    vuln = self._test_idor_path(session, url, original_id)
                    if vuln:
                        vulns.append(vuln)

            except Exception as e:
                self.logger.debug(f"Erro ao testar URL {url}: {e}")

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
        info['requires'] = ['WebCrawlerPlugin']
        return info
