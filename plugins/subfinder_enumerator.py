"""
Plugin Subfinder para enumeração de subdominios
Utiliza Subfinder para descoberta rapida e abrangente
"""

import subprocess
import time
import socket
from typing import Dict, Any, List

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult
from core.config import get_config
from utils.http_session import resolve_use_tor
from utils.proxy_env import build_proxy_env


class SubfinderPlugin(NetworkPlugin):
    """Plugin para enumeração de subdominios usando Subfinder"""

    def __init__(self):
        super().__init__()
        self.description = "Enumeracao de subdominios usando Subfinder"
        self.version = "1.0.0"
        self.requirements = ["subfinder"]
        self.supported_targets = ["domain"]

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa enumeração de subdominios"""
        start_time = time.time()

        try:
            domain = self._clean_domain(target)
            if not self._is_valid_domain(domain):
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error="Dominio invalido"
                )

            timeout = get_config('plugins.config.SubfinderPlugin.timeout', 120)
            resolve_ips = get_config('plugins.config.SubfinderPlugin.resolve_ips', True)
            silent = get_config('plugins.config.SubfinderPlugin.silent', True)

            cmd = ["subfinder", "-d", domain]
            if silent:
                cmd.append("-silent")

            env = build_proxy_env(use_tor=resolve_use_tor(self.config))
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout
            )

            if result.returncode != 0:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error=result.stderr.strip() or "Falha ao executar subfinder"
                )

            subdomains = self._parse_subfinder_output(result.stdout, domain)
            resolved_hosts = []
            ips = []

            if resolve_ips:
                for subdomain in subdomains:
                    ip = self._resolve_host(subdomain)
                    if ip:
                        resolved_hosts.append({
                            'subdomain': subdomain,
                            'ip': ip
                        })
                        if ip not in ips:
                            ips.append(ip)

            execution_time = time.time() - start_time

            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    'target_domain': domain,
                    'subdomains_found': len(subdomains),
                    'subdomains': subdomains,
                    'resolved_hosts': resolved_hosts,
                    'hosts': ips,
                    'raw_output': result.stdout.strip()
                }
            )

        except subprocess.TimeoutExpired:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error="Subfinder timeout"
            )
        except Exception as e:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error=str(e)
            )

    def validate_target(self, target: str) -> bool:
        """Valida se e um dominio valido"""
        domain = self._clean_domain(target)
        return self._is_valid_domain(domain)

    def _clean_domain(self, target: str) -> str:
        """Remove protocolo e path do target"""
        domain = target.lower().strip()
        if domain.startswith('http://') or domain.startswith('https://'):
            domain = domain.split('://', 1)[1]
        domain = domain.split('/')[0]
        domain = domain.split(':')[0]
        return domain

    def _is_valid_domain(self, domain: str) -> bool:
        """Verifica se e um dominio valido"""
        if not domain or '.' not in domain:
            return False
        if len(domain) < 4 or len(domain) > 253:
            return False
        return True

    def _parse_subfinder_output(self, output: str, domain: str) -> List[str]:
        """Extrai subdominios do output do Subfinder"""
        subdomains = []
        for line in output.splitlines():
            entry = line.strip().lower()
            if not entry:
                continue
            if entry.endswith(f".{domain}") and entry not in subdomains:
                subdomains.append(entry)
        return subdomains

    def _resolve_host(self, host: str) -> str:
        """Resolve host para IP"""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return ""
