"""
Plugin de Scanner de SSRF (Server-Side Request Forgery)
Detecta vulnerabilidades de SSRF tentando acessar localhost e redes internas.
Migrado e adaptado do módulo legado src/scanners/ssrf_oast_module.py (sem cliente OAST nativo).
"""

from typing import List, Dict, Any, Optional
import requests
import time
from urllib.parse import urlparse, parse_qs

from core.plugin_base import VulnerabilityPlugin, PluginResult
from core.models import Vulnerability
from utils.logger import get_logger
from utils.request_utils import rebuild_attack_request
from utils.http_session import create_requests_session

class SSRFScannerPlugin(VulnerabilityPlugin):
    """
    Scanner de SSRF (Server-Side Request Forgery).
    Tenta acessar serviços internos (localhost, 127.0.0.1, metadados de cloud) via injeção.
    """
    
    DEFAULT_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254/latest/meta-data/" # AWS Metadata
    ]

    def __init__(self, config: Dict[str, Any] = None):
        config = config or {}
        super().__init__(config)
        self.config = config or {}
        self.logger = get_logger("SSRFScanner")
        self.payloads = config.get('payloads', self.DEFAULT_PAYLOADS)
        self.timeout = config.get('timeout', 5)
        self.verify_ssl = config.get('verify_ssl', False)
        
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()
        vulns = []
        tested_count = 0
        
        # Preferir alvo original com porta/protocolo se disponível
        actual_target = context.get('original_target', target)
        self.logger.info(f"🚀 Iniciando varredura SSRF em: {actual_target}")
        
        discoveries = context.get('discoveries', {})
        forms = discoveries.get('forms', [])
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
            'User-Agent': 'ReconForge/SSRFScanner'
        })

        # 1. Testar URLs
        self.logger.info(f"🔍 Testando {len(urls_to_test)} URLs para SSRF...")
        for url in urls_to_test:
            try:
                parsed = urlparse(url)
                if not parsed.query:
                    continue
                
                query_params = parse_qs(parsed.query)
                for param_name in query_params:
                    tested_count += 1
                    vuln = self._test_get_param(session, url, param_name)
                    if vuln:
                        vulns.append(vuln)
            except Exception as e:
                self.logger.debug(f"Erro ao testar URL {url}: {e}")

        # 2. Testar Formulários
        self.logger.info(f"📝 Testando {len(forms)} formulários para SSRF...")
        for form in forms:
            try:
                vulns_form = self._test_form(session, form)
                if vulns_form:
                    vulns.extend(vulns_form)
                    tested_count += len(vulns_form)
            except Exception as e:
                self.logger.debug(f"Erro ao testar formulário: {e}")

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
                # Timestamp antes
                t0 = time.time()
                response = session.send(prepared, timeout=self.timeout)
                t1 = time.time()
                
                # Análise simples: se retornar 200 e tiver conteúdo diferente ou tempo diferente
                # SSRF é difícil de confirmar sem OAST. Vamos verificar se o status code muda significativamente
                # ou se o conteúdo reflete algo suspeito (como "root:x:0:0" se for file://)
                # Para localhost, verificar se string 'localhost' ou '127.0.0.1' aparece no body (reflexão de erro)
                # ou se conectou.
                
                # Heurística básica:
                if response.status_code == 200 and len(response.content) > 0:
                    # Se acessou metadados da AWS
                    if "ami-id" in response.text and "169.254.169.254" in payload:
                        return Vulnerability(
                            name="SSRF (Cloud Metadata)",
                            severity="Critical",
                            description=f"Possível SSRF acessando metadados de cloud no parâmetro '{param_name}'.",
                            url=url,
                            evidence=f"Payload: {payload}\nResponse contains 'ami-id'",
                            cve="CWE-918",
                            plugin_source="SSRFScannerPlugin"
                        )
                    
                    # Se acessou localhost e respondeu algo diferente de erro genérico
                    # Difícil validar sem baseline. Vamos assumir suspeita se status 200 e payload interno.
                    
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
                    response = session.send(prepared, timeout=self.timeout)

                    if response.status_code == 200 and "ami-id" in response.text and "169.254.169.254" in payload:
                         vuln = Vulnerability(
                            name="SSRF (Cloud Metadata) in Form",
                            severity="Critical",
                            description=f"Possível SSRF em formulário acessando metadados de cloud no campo '{param_name}'.",
                            url=target_url,
                            evidence=f"Payload: {payload}\nResponse contains 'ami-id'",
                            cve="CWE-918",
                            plugin_source="SSRFScannerPlugin"
                        )
                         found_vulns.append(vuln)
                         break
                except Exception:
                    pass
        
        return found_vulns

    def get_info(self) -> Dict[str, Any]:
        info = super().get_info()
        info['category'] = 'vulnerability'
        info['requires'] = ['WebCrawlerPlugin']
        return info
