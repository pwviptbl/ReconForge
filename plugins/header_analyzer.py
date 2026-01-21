"""
Plugin de Analise de Headers HTTP
Verifica headers de seguranca e informacoes de servidor.
"""

import ssl
import time
import socket
from typing import Dict, Any, List, Optional, Tuple
import http.client

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import WebPlugin, PluginResult


class HeaderAnalyzerPlugin(WebPlugin):
    """Analisa headers HTTP/HTTPS para boas praticas de seguranca."""

    def __init__(self):
        super().__init__()
        self.name = "HeaderAnalyzerPlugin"
        self.description = "Analisa headers HTTP/HTTPS para boas praticas de seguranca."
        self.version = "1.0.0"
        self.supported_targets = ["ip", "domain", "url"]

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()

        endpoints = self._build_endpoints(target, context)
        if not endpoints:
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                summary="Nenhum endpoint HTTP/HTTPS encontrado para analisar."
            )

        analyzed = []
        findings = []

        for scheme, host, port in endpoints:
            result = self._fetch_headers(scheme, host, port)
            if not result:
                continue

            analyzed.append({
                'scheme': scheme,
                'host': host,
                'port': port,
                'status_code': result.get('status_code'),
            })

            headers = result.get('headers', {})
            missing = self._missing_security_headers(headers, scheme == 'https')
            server = headers.get('server', '')
            powered_by = headers.get('x-powered-by', '')

            if missing:
                findings.append({
                    'endpoint': f"{scheme}://{host}:{port}",
                    'missing_headers': missing,
                    'severity': 'Medium' if len(missing) >= 3 else 'Low'
                })

            if server or powered_by:
                findings.append({
                    'endpoint': f"{scheme}://{host}:{port}",
                    'disclosure': {
                        'server': server,
                        'x_powered_by': powered_by
                    },
                    'severity': 'Info'
                })

        execution_time = time.time() - start_time
        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=execution_time,
            data={
                'targets': [f"{s}://{h}:{p}" for s, h, p in endpoints],
                'analyzed': analyzed,
                'findings': findings
            },
            summary=f"Analisados {len(analyzed)} endpoints, {len(findings)} achados."
        )

    def _build_endpoints(self, target: str, context: Dict[str, Any]) -> List[Tuple[str, str, int]]:
        endpoints = []

        hostname = target
        if target.startswith(('http://', 'https://')):
            hostname = target.split('://', 1)[1].split('/', 1)[0]

        discoveries = context.get('discoveries', {})
        open_ports = discoveries.get('open_ports', [])
        services = discoveries.get('services', [])

        http_ports = set()
        https_ports = set()

        for service in services:
            if not isinstance(service, dict):
                continue
            port = service.get('port')
            name = str(service.get('service', '')).lower()
            if name in ('http', 'http-alt', 'http-proxy'):
                http_ports.add(port)
            if name in ('https', 'https-alt'):
                https_ports.add(port)

        for port in open_ports:
            if port in (80, 8080, 8000):
                http_ports.add(port)
            if port in (443, 8443):
                https_ports.add(port)

        if not http_ports and not https_ports:
            http_ports.add(80)

        if not https_ports:
            if self._can_connect(hostname, 443):
                https_ports.add(443)

        for port in sorted(http_ports):
            endpoints.append(('http', hostname, port))
        for port in sorted(https_ports):
            endpoints.append(('https', hostname, port))

        return endpoints

    def _can_connect(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            return False

    def _fetch_headers(self, scheme: str, host: str, port: int) -> Optional[Dict[str, Any]]:
        try:
            if scheme == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=10, context=context)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=10)

            conn.request("HEAD", "/")
            response = conn.getresponse()

            headers = {}
            for header, value in response.getheaders():
                headers[header.lower()] = value

            conn.close()
            return {
                'status_code': response.status,
                'headers': headers
            }
        except Exception:
            return None

    def _missing_security_headers(self, headers: Dict[str, str], is_https: bool) -> List[str]:
        required = [
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options',
            'referrer-policy',
            'permissions-policy'
        ]
        if is_https:
            required.append('strict-transport-security')

        missing = [h for h in required if h not in headers]
        return missing
