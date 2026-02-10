"""
Plugin de Scanner de XSS Refletido
Detecta vulnerabilidades de Cross-Site Scripting (Refletido) em parâmetros GET e formulários.
Migrado do módulo legado src/scanners/xss_module.py
"""

from typing import List, Dict, Any, Optional
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode

from core.plugin_base import VulnerabilityPlugin, PluginResult
from core.models import Vulnerability
from utils.logger import get_logger
from utils.request_utils import rebuild_attack_request
from utils.http_session import create_requests_session

class XSSScannerPlugin(VulnerabilityPlugin):
    """
    Scanner de XSS Refletido.
    Analisa formulários e parâmetros de URL descobertos pelo WebCrawler.
    """
    
    DEFAULT_PAYLOADS = [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><svg/onload=alert(1)>",
        "activescanner<xss>test"
    ]

    def __init__(self, config: Dict[str, Any] = None):
        config = config or {}
        super().__init__(config)
        self.config = config or {}
        self.logger = get_logger("XSSScanner")
        self.payloads = config.get('payloads', self.DEFAULT_PAYLOADS)
        self.timeout = config.get('timeout', 10)
        self.verify_ssl = config.get('verify_ssl', False)
        
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()
        vulns = []
        tested_count = 0
        
        # Preferir alvo original com porta/protocolo se disponível
        actual_target = context.get('original_target', target)
        self.logger.info(f"🚀 Iniciando varredura XSS em: {actual_target}")
        
        # Recuperar descobertas do contexto
        discoveries = context.get('discoveries', {})
        forms = discoveries.get('forms', [])
        # endpoints podem conter URLs com query params
        endpoints = discoveries.get('endpoints', [])
        parameters = discoveries.get('parameters', {}) # {'get_params': [], ...}
        
        # Combinar URLs para teste (endpoints + target + pages_crawled se acessível)
        urls_to_test = set()
        if actual_target.startswith('http'):
            urls_to_test.add(actual_target)
        
        # Adicionar endpoints descobertos
        for endp in endpoints:
            if isinstance(endp, str):
                urls_to_test.add(endp)
            elif isinstance(endp, dict) and 'url' in endp:
                urls_to_test.add(endp['url'])

        # Sessão para requests
        session = create_requests_session(plugin_config=self.config)
        session.verify = self.verify_ssl
        session.headers.update({
            'User-Agent': 'ReconForge/XSSScanner'
        })

        # 1. Testar Parâmetros GET (Query String)
        self.logger.info(f"🔍 Testando {len(urls_to_test)} URLs para XSS em Query Params...")
        for url in urls_to_test:
            try:
                parsed = urlparse(url)
                if not parsed.query:
                    continue
                
                query_params = parse_qs(parsed.query)
                for param_name in query_params:
                    # Injetar em cada parâmetro
                    tested_count += 1
                    vuln = self._test_get_param(session, url, param_name)
                    if vuln:
                        vulns.append(vuln)
            except Exception as e:
                self.logger.debug(f"Erro ao testar URL {url}: {e}")

        # 2. Testar Formulários
        self.logger.info(f"📝 Testando {len(forms)} formulários para XSS...")
        for form in forms:
            try:
                vulns_form = self._test_form(session, form)
                if vulns_form:
                    vulns.extend(vulns_form)
                    tested_count += len(vulns_form) # Aproximação
            except Exception as e:
                self.logger.debug(f"Erro ao testar formulário {form.get('action')}: {e}")

        execution_time = time.time() - start_time
        success = True # Scanner rodou, mesmo que não ache nada

        return PluginResult(
            success=success,
            plugin_name=self.name,
            execution_time=execution_time,
            data={
                'vulnerabilities': [v.to_dict() for v in vulns], # Converter para dict
                'tested_count': tested_count
            }
        )

    def _test_get_param(self, session: requests.Session, url: str, param_name: str) -> Optional[Vulnerability]:
        """Testa XSS em parâmetro GET"""
        
        # Construir RequestNode virtual
        request_node = {
            'method': 'GET',
            'url': url,
            'headers': dict(session.headers),
            'params': {} # Params já estão na URL
        }

        injection_point = {
            'location': 'QUERY',
            'parameter_name': param_name,
            'original_value': ''
        }

        for payload in self.payloads:
            try:
                # Usar request_utils para reconstruir request com payload
                prepared = rebuild_attack_request(request_node, injection_point, payload)
                
                response = session.send(prepared, timeout=self.timeout)
                
                if payload in response.text:
                    return Vulnerability(
                        name="Cross-Site Scripting (Reflected)",
                        severity="High",
                        description=f"Payload XSS refletido no parâmetro '{param_name}' via GET.",
                        url=url,
                        evidence=f"Payload: {payload}\nReflected in response.",
                        cve="CWE-79",
                        plugin_source="XSSScannerPlugin"
                    )
            except Exception:
                pass
        return None

    def _test_form(self, session: requests.Session, form: Dict[str, Any]) -> List[Vulnerability]:
        """Testa XSS em inputs de formulário"""
        found_vulns = []
        target_url = form.get('action')
        method = form.get('method', 'get').upper()
        inputs = form.get('inputs', [])

        if not target_url:
            return []

        # Preparar dados base do formulário para o RequestNode
        base_data = {}
        for inp in inputs:
            name = inp.get('name')
            if name:
                base_data[name] = inp.get('value', 'test')

        # RequestNode base
        request_node = {
            'method': method,
            'url': target_url,
            'headers': dict(session.headers),
        }
        
        if method == 'POST':
            request_node['data'] = base_data
        else:
            request_node['params'] = base_data

        # Iterar sobre cada input para injetar
        for inp in inputs:
            param_name = inp.get('name')
            if not param_name:
                continue
            
            # Pular campos hidden de token CSRF para evitar falsos negativos (ou tentar bypass depois)
            # Mas XSS pode ocorrer neles também. Vamos testar tudo por enquanto.
            
            injection_point = {
                'location': 'BODY_FORM' if method == 'POST' else 'QUERY',
                'parameter_name': param_name,
                'original_value': inp.get('value', '')
            }

            for payload in self.payloads:
                try:
                    prepared = rebuild_attack_request(request_node, injection_point, payload)
                    response = session.send(prepared, timeout=self.timeout)

                    if payload in response.text:
                        vuln = Vulnerability(
                            name="Cross-Site Scripting (Reflected) in Form",
                            severity="High",
                            description=f"Payload XSS refletido no campo '{param_name}' do formulário em {target_url}.",
                            url=target_url,
                            evidence=f"Payload: {payload}\nForm Action: {target_url}\nMethod: {method}",
                            cve="CWE-79",
                            plugin_source="XSSScannerPlugin"
                        )
                        found_vulns.append(vuln)
                        break # Achou uma vuln neste parametro, pula para próximo param (evita spam de payloads)
                except Exception:
                    pass
        
        return found_vulns

    def get_info(self) -> Dict[str, Any]:
        info = super().get_info()
        info['category'] = 'vulnerability'
        info['requires'] = ['WebCrawlerPlugin']
        return info
