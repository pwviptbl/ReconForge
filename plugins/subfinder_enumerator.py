"""
Plugin Subfinder para enumeração de subdominios
Utiliza Subfinder para descoberta rapida e abrangente
"""

import shutil
import subprocess
import time
import socket
from typing import Dict, Any, List

import requests
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult
from core.config import get_config
from utils.http_session import create_requests_session, resolve_use_tor
from utils.proxy_env import build_proxy_env


class SubfinderPlugin(NetworkPlugin):
    """Plugin para enumeração de subdominios usando Subfinder"""

    def __init__(self):
        super().__init__()
        self.description = "Enumeracao de subdominios usando Subfinder"
        self.version = "1.0.0"
        self.requirements = []  # Possui fallback nativo via crt.sh
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
            use_tor = resolve_use_tor(self.config)

            subfinder_bin = shutil.which("subfinder") or str(Path.home() / "go" / "bin" / "subfinder")
            if not shutil.which(subfinder_bin) and not Path(subfinder_bin).is_file():
                # Fallback nativo: consultar Certificate Transparency (crt.sh)
                return self._crt_sh_fallback(domain, resolve_ips, use_tor, start_time)

            cmd = [subfinder_bin, "-d", domain]
            if silent:
                cmd.append("-silent")

            executed_command = " ".join(cmd)

            env = build_proxy_env(use_tor=use_tor)
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
                    data={"command": [executed_command]},
                    error=result.stderr.strip() or "Falha ao executar subfinder"
                )

            subdomains = self._parse_subfinder_output(result.stdout, domain)
            resolved_hosts = []
            ips = []

            if resolve_ips and not use_tor:
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
                    'raw_output': result.stdout.strip(),
                    'resolution_skipped_for_tor': bool(resolve_ips and use_tor),
                    'command': [executed_command]
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

    def _crt_sh_fallback(
        self,
        domain: str,
        resolve_ips: bool,
        use_tor: bool,
        start_time: float,
    ) -> PluginResult:
        """Fallback via Certificate Transparency (crt.sh) quando subfinder não está instalado."""
        session = create_requests_session(plugin_config=self.config, use_tor=use_tor)
        subdomains = set()

        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = session.get(url, timeout=20, verify=False)
            if resp.status_code == 200:
                for item in resp.json():
                    name_value = item.get("name_value", "")
                    for entry in name_value.split("\n"):
                        clean = entry.strip().lower()
                        if clean.startswith("*."):
                            clean = clean[2:]
                        if clean.endswith(f".{domain}") or clean == domain:
                            subdomains.add(clean)
        except Exception:
            pass

        subdomains_list = sorted(list(subdomains))
        resolved_hosts = []
        ips = []

        if resolve_ips and not use_tor:
            for sub in subdomains_list:
                ip = self._resolve_host(sub)
                if ip:
                    resolved_hosts.append({"subdomain": sub, "ip": ip})
                    if ip not in ips:
                        ips.append(ip)

        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=time.time() - start_time,
            data={
                "target_domain": domain,
                "subdomains_found": len(subdomains_list),
                "subdomains": subdomains_list,
                "resolved_hosts": resolved_hosts,
                "hosts": ips,
                "raw_output": "\n".join(subdomains_list),
                "resolution_skipped_for_tor": bool(resolve_ips and use_tor),
                "engine": "crt_sh_fallback",
            },
            summary=f"Enumeração nativa via crt.sh descobriu {len(subdomains_list)} subdomínios (modo fallback).",
        )
