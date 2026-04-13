"""
Plugin de Analise de Headers HTTP
Verifica headers de seguranca e informacoes de servidor.
Suporta roteamento via Tor quando habilitado na config.
"""

import ssl
import time
import socket
from typing import Dict, Any, List, Optional, Tuple
import http.client
from urllib.parse import urlparse

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import WebPlugin, PluginResult
from utils.http_session import create_requests_session, resolve_use_tor
from utils.tor import ensure_tor_ready
from utils.logger import get_logger


class HeaderAnalyzerPlugin(WebPlugin):
    """Analisa headers HTTP/HTTPS para boas praticas de seguranca (com suporte a Tor)."""

    def __init__(self):
        super().__init__()
        self.name = "HeaderAnalyzerPlugin"
        self.description = "Analisa headers HTTP/HTTPS para boas praticas de seguranca."
        self.version = "1.1.0"
        self.supported_targets = ["ip", "domain", "url"]
        self.logger = get_logger("HeaderAnalyzerPlugin")

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()

        # Configurar modo Tor
        use_tor = resolve_use_tor(self.config)
        if use_tor:
            ensure_tor_ready(use_tor=True)
            self.logger.info("[HeaderAnalyzer] Modo Tor ativo — headers serão coletados via SOCKS5")

        actual_target = context.get('original_target', target)
        endpoints = self._build_endpoints(actual_target, context)
        if not endpoints:
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                summary="Nenhum endpoint HTTP/HTTPS encontrado para analisar."
            )

        # Criar sessão com proxy Tor (se habilitado)
        session = create_requests_session(plugin_config=self.config)

        analyzed = []
        findings = []

        for scheme, host, port in endpoints:
            result = self._fetch_headers_requests(session, scheme, host, port)
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
                'findings': findings,
                'tor_mode': use_tor,
            },
            summary=f"Analisados {len(analyzed)} endpoints, {len(findings)} achados."
        )

    def _build_endpoints(self, target: str, context: Dict[str, Any]) -> List[Tuple[str, str, int]]:
        endpoints = []

        hostname = target
        explicit_scheme = None
        explicit_port = None
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            hostname = parsed.hostname or hostname
            explicit_scheme = parsed.scheme
            explicit_port = parsed.port

        discoveries = context.get('discoveries', {})
        open_ports = discoveries.get('open_ports', [])
        services = discoveries.get('services', [])

        http_ports = set()
        https_ports = set()

        for service in services:
            if not isinstance(service, dict):
                continue
            port = service.get('port')
            if not isinstance(port, int):
                continue
            name = str(service.get('service', '')).lower()
            if name in ('http', 'http-alt', 'http-proxy'):
                http_ports.add(port)
            if name in ('https', 'https-alt'):
                https_ports.add(port)

        for port in open_ports:
            if not isinstance(port, int):
                continue
            if port in (80, 8080, 8000):
                http_ports.add(port)
            if port in (443, 8443):
                https_ports.add(port)

        # If the user passed an explicit URL with scheme/port, prioritize that.
        if explicit_scheme and explicit_port:
            if explicit_scheme == 'https':
                https_ports.add(explicit_port)
            else:
                http_ports.add(explicit_port)

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
        """Verifica conectividade básica (sem proxy — apenas para descoberta de endpoints)"""
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            return False

    def _fetch_headers_requests(self, session, scheme: str, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Busca headers HTTP/HTTPS via requests (suporta proxy Tor automaticamente)"""
        try:
            url = f"{scheme}://{host}:{port}/"
            resp = session.head(
                url,
                timeout=10,
                verify=False,
                allow_redirects=True,
            )
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {
                'status_code': resp.status_code,
                'headers': headers,
            }
        except Exception:
            # Fallback para GET se HEAD não funcionar
            try:
                url = f"{scheme}://{host}:{port}/"
                resp = session.get(
                    url,
                    timeout=10,
                    verify=False,
                    allow_redirects=True,
                    stream=True,           # não baixar body
                )
                resp.close()
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return {
                    'status_code': resp.status_code,
                    'headers': headers,
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
