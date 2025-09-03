"""
Plugin de Resolução de DNS
Coleta informações de DNS sobre o alvo
"""

import socket
import time
from typing import Dict, Any, List
import ipaddress

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult


class DNSResolverPlugin(NetworkPlugin):
    """Plugin para resolução e análise de DNS"""
    
    def __init__(self):
        super().__init__()
        self.description = "Resolução de DNS e coleta de informações"
        self.version = "1.0.0"
        self.supported_targets = ["domain", "ip"]
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa resolução de DNS"""
        start_time = time.time()
        
        try:
            results = {}
            hosts = []
            
            # Determinar se é IP ou domínio
            is_ip = self._is_ip_address(target)
            
            if is_ip:
                # Reverse DNS lookup
                results['reverse_dns'] = self._reverse_dns_lookup(target)
                hosts.append(target)
            else:
                # Forward DNS lookup
                results['forward_dns'] = self._forward_dns_lookup(target)
                if results['forward_dns']['ips']:
                    hosts.extend(results['forward_dns']['ips'])
                
                # Tentar descobrir subdomínios comuns
                results['subdomains'] = self._find_common_subdomains(target)
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
    
    def _find_common_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """Tenta encontrar subdomínios comuns"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'app', 'portal', 'secure', 'shop', 'blog',
            'support', 'help', 'docs', 'cdn', 'static'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            
            try:
                dns_result = self._forward_dns_lookup(full_domain)
                if dns_result['ips']:
                    found_subdomains.append({
                        'subdomain': subdomain,
                        'full_domain': full_domain,
                        'ips': dns_result['ips']
                    })
            except:
                continue
        
        return found_subdomains
