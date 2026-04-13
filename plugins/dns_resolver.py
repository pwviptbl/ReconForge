"""
Plugin de Resolução de DNS
Coleta informações de DNS sobre o alvo.
Suporta modo Tor para evitar DNS leak (consultas roteadas via SOCKS5).
"""

import socket
import time
from typing import Dict, Any, List, Optional
import ipaddress

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult
from utils.http_session import resolve_use_tor
from utils.tor import tor_proxy_url, ensure_tor_ready
from utils.logger import get_logger


class DNSResolverPlugin(NetworkPlugin):
    """Plugin para resolução e análise de DNS com suporte a Tor (anti-leak)"""

    def __init__(self):
        super().__init__()
        self.description = "Resolução de DNS e coleta de informações (com suporte a Tor para evitar DNS leak)"
        self.version = "1.1.0"
        self.supported_targets = ["domain", "ip"]
        self.logger = get_logger("DNSResolverPlugin")

    def _resolve_via_tor(self, domain: str) -> Dict[str, Any]:
        """Resolve domínio usando dnspython via TCP roteado pelo Tor (evita DNS leak)"""
        try:
            import dns.resolver
            import socks

            proxy_url = tor_proxy_url()
            # Extrair host:porta do proxy (ex: socks5h://127.0.0.1:9050)
            proxy_host = "127.0.0.1"
            proxy_port = 9050
            try:
                from urllib.parse import urlsplit
                parsed = urlsplit(proxy_url)
                proxy_host = parsed.hostname or proxy_host
                proxy_port = parsed.port or proxy_port
            except Exception:
                pass

            # Criar socket SOCKS5 apontando para o DNS do Tor (porta 53 via Tor)
            # Alternativa mais simples: resolver usando requests + google DoH via Tor
            import requests
            from utils.http_session import create_requests_session
            session = create_requests_session(use_tor=True)

            ips = []
            # DNS over HTTPS via Tor (Google DoH)
            try:
                resp = session.get(
                    f"https://dns.google/resolve?name={domain}&type=A",
                    timeout=15
                )
                data = resp.json()
                for answer in data.get("Answer", []):
                    if answer.get("type") == 1:  # tipo A (IPv4)
                        ips.append(answer["data"])
            except Exception as e:
                self.logger.warning(f"DoH A falhou: {e}")

            # Tentar AAAA (IPv6)
            try:
                resp = session.get(
                    f"https://dns.google/resolve?name={domain}&type=AAAA",
                    timeout=15
                )
                data = resp.json()
                for answer in data.get("Answer", []):
                    if answer.get("type") == 28:  # tipo AAAA (IPv6)
                        ips.append(answer["data"])
            except Exception as e:
                self.logger.warning(f"DoH AAAA falhou: {e}")

            return {"domain": domain, "ips": list(set(ips)), "method": "DoH-via-Tor", "error": None}

        except Exception as e:
            self.logger.error(f"Resolução via Tor falhou: {e}")
            return {"domain": domain, "ips": [], "method": "DoH-via-Tor", "error": str(e)}

    def _reverse_via_tor(self, ip: str) -> Dict[str, Any]:
        """Reverse DNS via DoH roteado pelo Tor"""
        try:
            from utils.http_session import create_requests_session
            # Construir nome PTR (ex: 1.2.3.4 -> 4.3.2.1.in-addr.arpa)
            parts = ip.split(".")
            ptr_name = ".".join(reversed(parts)) + ".in-addr.arpa"
            session = create_requests_session(use_tor=True)
            resp = session.get(
                f"https://dns.google/resolve?name={ptr_name}&type=PTR",
                timeout=15
            )
            data = resp.json()
            hostnames = []
            for answer in data.get("Answer", []):
                if answer.get("type") == 12:  # PTR
                    hostnames.append(answer["data"].rstrip("."))
            return {"ip": ip, "hostnames": hostnames, "method": "DoH-via-Tor", "error": None}
        except Exception as e:
            return {"ip": ip, "hostnames": [], "method": "DoH-via-Tor", "error": str(e)}
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa resolução de DNS (com proteção contra DNS leak via Tor)"""
        start_time = time.time()

        # Verificar se Tor está habilitado — previne DNS leak
        use_tor = resolve_use_tor(self.config)
        if use_tor:
            ensure_tor_ready(use_tor=True)
            self.logger.info("[DNS] Modo Tor ativo — usando DNS over HTTPS via Tor para evitar DNS leak")

        try:
            results = {}
            hosts = []

            # Determinar se é IP ou domínio
            is_ip = self._is_ip_address(target)

            if is_ip:
                # Reverse DNS lookup
                if use_tor:
                    results['reverse_dns'] = self._reverse_via_tor(target)
                else:
                    results['reverse_dns'] = self._reverse_dns_lookup(target)
                hosts.append(target)
            else:
                # Forward DNS lookup
                if use_tor:
                    results['forward_dns'] = self._resolve_via_tor(target)
                else:
                    results['forward_dns'] = self._forward_dns_lookup(target)

                if results['forward_dns']['ips']:
                    hosts.extend(results['forward_dns']['ips'])

                # Tentar descobrir subdomínios comuns
                results['subdomains'] = self._find_common_subdomains(target, use_tor=use_tor)
                for subdomain_info in results['subdomains']:
                    if subdomain_info['ips']:
                        hosts.extend(subdomain_info['ips'])

            # Remover duplicatas de hosts
            hosts = list(set(hosts))

            execution_time = time.time() - start_time

            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    'target': target,
                    'is_ip': is_ip,
                    'tor_mode': use_tor,
                    'dns_results': results,
                    'hosts': hosts
                }
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
        """Valida se é um domínio ou IP válido"""
        # Verificar se é IP
        if self._is_ip_address(target):
            return True
        
        # Verificar se é domínio válido (básico)
        if '.' in target and len(target) > 3:
            return True
        
        return False
    
    def _is_ip_address(self, target: str) -> bool:
        """Verifica se target é um endereço IP"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _forward_dns_lookup(self, domain: str) -> Dict[str, Any]:
        """Resolve domínio para IPs"""
        result = {
            'domain': domain,
            'ips': [],
            'error': None
        }
        
        try:
            # Resolver IPv4
            try:
                ipv4_info = socket.getaddrinfo(domain, None, socket.AF_INET)
                ipv4s = list(set([info[4][0] for info in ipv4_info]))
                result['ips'].extend(ipv4s)
            except socket.gaierror:
                pass
            
            # Tentar resolver IPv6
            try:
                ipv6_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
                ipv6s = list(set([info[4][0] for info in ipv6_info]))
                result['ips'].extend(ipv6s)
            except socket.gaierror:
                pass
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _reverse_dns_lookup(self, ip: str) -> Dict[str, Any]:
        """Resolve IP para nome de host"""
        result = {
            'ip': ip,
            'hostnames': [],
            'error': None
        }
        
        try:
            hostname_info = socket.gethostbyaddr(ip)
            result['hostnames'] = [hostname_info[0]] + list(hostname_info[1])
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _find_common_subdomains(self, domain: str, use_tor: bool = False) -> List[Dict[str, Any]]:
        """Tenta encontrar subdomínios comuns (usa Tor se habilitado)"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'app', 'portal', 'secure', 'shop', 'blog',
            'support', 'help', 'docs', 'cdn', 'static'
        ]

        found_subdomains = []

        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"

            try:
                if use_tor:
                    dns_result = self._resolve_via_tor(full_domain)
                else:
                    dns_result = self._forward_dns_lookup(full_domain)

                if dns_result['ips']:
                    found_subdomains.append({
                        'subdomain': subdomain,
                        'full_domain': full_domain,
                        'ips': dns_result['ips']
                    })
            except Exception:
                continue

        return found_subdomains
