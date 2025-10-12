"""
Plugin de enumeração de subdomínios
Descobre subdomínios usando múltiplas técnicas (DNS, wordlist, APIs)
"""

import socket
import threading
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Set
import json

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult


class SubdomainEnumeratorPlugin(NetworkPlugin):
    """Plugin para enumeração de subdomínios"""
    
    def __init__(self):
        super().__init__()
        self.description = "Enumeração de subdomínios usando wordlist e APIs públicas"
        self.version = "1.0.0"
        self.supported_targets = ["domain"]
        self.timeout = 3
        self.max_workers = 30
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa enumeração de subdomínios"""
        start_time = time.time()
        
        try:
            # Limpar target (remover protocolo se existir)
            domain = self._clean_domain(target)
            
            if not self._is_valid_domain(domain):
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error="Domínio inválido"
                )
            
            # Detectar Wildcard DNS antes de enumerar
            wildcard_detected = self._detect_wildcard(domain)
            if wildcard_detected:
                self.logger.warning(
                    f"Wildcard DNS detectado. A enumeração por wordlist será pulada para evitar falsos positivos."
                )

            # Coletar subdomínios de diferentes fontes
            subdomains = set()
            
            # 1. Wordlist brute force (apenas se não houver wildcard)
            wordlist_subs = set()
            if not wildcard_detected:
                wordlist_subs = self._wordlist_enumeration(domain)
                subdomains.update(wordlist_subs)
            
            # 2. Certificate Transparency (crt.sh)
            ct_subs = self._certificate_transparency_search(domain)
            subdomains.update(ct_subs)
            
            # 3. DNS zone transfer (raramente funciona, mas vale tentar)
            zone_subs = self._dns_zone_transfer(domain)
            subdomains.update(zone_subs)
            
            # 4. Reverse DNS nos IPs conhecidos
            reverse_subs = self._reverse_dns_enumeration(domain, context)
            subdomains.update(reverse_subs)
            
            # Validar subdomínios encontrados
            valid_subdomains = self._validate_subdomains(list(subdomains))
            
            # Resolver IPs dos subdomínios válidos
            subdomain_info = self._resolve_subdomains(valid_subdomains)
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    'target_domain': domain,
                    'wildcard_detected': wildcard_detected,
                    'subdomains_found': len(valid_subdomains),
                    'subdomains': subdomain_info,
                    'enumeration_methods': {
                        'wordlist': len(wordlist_subs),
                        'certificate_transparency': len(ct_subs),
                        'zone_transfer': len(zone_subs),
                        'reverse_dns': len(reverse_subs)
                    },
                    'hosts': [info['ip'] for info in subdomain_info if info.get('ip')],
                    'valid_subdomains': valid_subdomains
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
        """Valida se é um domínio válido"""
        domain = self._clean_domain(target)
        return self._is_valid_domain(domain)
    
    def _clean_domain(self, target: str) -> str:
        """Remove protocolo e path do target"""
        domain = target.lower()
        if domain.startswith('http://') or domain.startswith('https://'):
            domain = domain.split('://', 1)[1]
        domain = domain.split('/')[0]
        domain = domain.split(':')[0]
        return domain
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Verifica se é um domínio válido"""
        if not domain or '.' not in domain:
            return False
        if len(domain) < 4 or len(domain) > 253:
            return False
        return True
    
    def _wordlist_enumeration(self, domain: str) -> Set[str]:
        """Enumeração usando wordlist de subdomínios comuns"""
        wordlist = [
            'www', 'mail', 'email', 'webmail', 'ftp', 'sftp', 'ssh', 'admin',
            'administrator', 'test', 'testing', 'dev', 'development', 'staging',
            'stage', 'prod', 'production', 'api', 'app', 'application', 'blog',
            'shop', 'store', 'ecommerce', 'news', 'portal', 'support', 'help',
            'docs', 'documentation', 'wiki', 'forum', 'community', 'social',
            'cdn', 'static', 'assets', 'images', 'img', 'media', 'files',
            'download', 'downloads', 'upload', 'uploads', 'backup', 'backups',
            'old', 'new', 'legacy', 'archive', 'temp', 'tmp', 'cache',
            'beta', 'alpha', 'demo', 'sandbox', 'preview', 'mobile', 'm',
            'wap', 'vpn', 'remote', 'secure', 'ssl', 'login', 'auth',
            'authentication', 'account', 'accounts', 'profile', 'user',
            'users', 'member', 'members', 'client', 'clients', 'customer',
            'customers', 'dashboard', 'panel', 'control', 'manage', 'manager',
            'monitoring', 'monitor', 'stats', 'statistics', 'analytics',
            'logs', 'log', 'status', 'health', 'check', 'ping', 'search',
            'find', 'lookup', 'directory', 'listing', 'index', 'home',
            'main', 'root', 'base', 'core', 'system', 'sys', 'server',
            'srv', 'service', 'services', 'db', 'database', 'data',
            'sql', 'mysql', 'postgres', 'mongo', 'redis', 'elastic',
            'ldap', 'ad', 'dc', 'dns', 'ns', 'ns1', 'ns2', 'ns3',
            'smtp', 'pop', 'pop3', 'imap', 'exchange', 'owa', 'calendar',
            'cal', 'meet', 'meeting', 'conference', 'video', 'voice',
            'chat', 'message', 'msg', 'notification', 'alert', 'events',
            'git', 'svn', 'repo', 'repository', 'code', 'ci', 'cd',
            'jenkins', 'build', 'deploy', 'deployment', 'release'
        ]
        
        # Adicionar variações numéricas
        for i in range(1, 11):
            wordlist.extend([f'server{i}', f'srv{i}', f'host{i}', f'web{i}'])
        
        found_subdomains = set()
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            
            for future in as_completed(futures, timeout=60):
                try:
                    result = future.result(timeout=self.timeout)
                    if result:
                        found_subdomains.add(result)
                except:
                    continue
        
        return found_subdomains
    
    def _certificate_transparency_search(self, domain: str) -> Set[str]:
        """Busca subdomínios usando Certificate Transparency logs"""
        found_subdomains = set()
        
        try:
            # API do crt.sh
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        if 'name_value' in entry:
                            names = entry['name_value'].split('\n')
                            for name in names:
                                name = name.strip().lower()
                                if name.endswith(f'.{domain}') and '*' not in name:
                                    found_subdomains.add(name)
                except json.JSONDecodeError:
                    pass
        except:
            pass
        
        return found_subdomains
    
    def _dns_zone_transfer(self, domain: str) -> Set[str]:
        """Tenta DNS zone transfer (raramente funciona)"""
        found_subdomains = set()
        
        try:
            # Descobrir servidores DNS autoritativos
            import dns.resolver
            import dns.zone
            import dns.query
            
            ns_records = dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    for name in zone.nodes.keys():
                        if name != '@':
                            subdomain = f"{name}.{domain}"
                            found_subdomains.add(subdomain)
                except:
                    continue
        except:
            pass
        
        return found_subdomains
    
    def _reverse_dns_enumeration(self, domain: str, context: Dict[str, Any]) -> Set[str]:
        """Enumeração usando reverse DNS nos IPs conhecidos"""
        found_subdomains = set()
        
        # Obter IPs do contexto
        hosts = context.get('discoveries', {}).get('hosts', [])
        
        for host_ip in hosts:
            try:
                hostname = socket.gethostbyaddr(host_ip)[0]
                if hostname.endswith(f'.{domain}'):
                    found_subdomains.add(hostname)
            except:
                continue
        
        return found_subdomains
    
    def _detect_wildcard(self, domain: str) -> bool:
        """Detecta a presença de um DNS wildcard."""
        import uuid
        # Gera um subdomínio aleatório que é improvável de existir
        random_subdomain = f"{uuid.uuid4().hex[:12]}.{domain}"
        try:
            socket.gethostbyname(random_subdomain)
            self.logger.info(f"Wildcard DNS detectado para o domínio: {domain}")
            return True
        except socket.gaierror:
            # Isso é o esperado se não houver wildcard
            return False
        except Exception as e:
            self.logger.warning(f"Ocorreu um erro inesperado durante a detecção de wildcard: {e}")
            return False

    def _validate_subdomains(self, subdomains: List[str]) -> List[str]:
        """Valida se os subdomínios realmente resolvem"""
        valid_subdomains = []
        
        def validate_subdomain(subdomain):
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except socket.gaierror:
                return None
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(validate_subdomain, sub): sub for sub in subdomains}
            
            for future in as_completed(futures, timeout=30):
                try:
                    result = future.result(timeout=self.timeout)
                    if result:
                        valid_subdomains.append(result)
                except:
                    continue
        
        return valid_subdomains
    
    def _resolve_subdomains(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Resolve IPs dos subdomínios válidos"""
        subdomain_info = []
        
        def resolve_subdomain(subdomain):
            try:
                ip = socket.gethostbyname(subdomain)
                return {
                    'subdomain': subdomain,
                    'ip': ip,
                    'resolved': True
                }
            except socket.gaierror:
                return {
                    'subdomain': subdomain,
                    'ip': None,
                    'resolved': False
                }
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(resolve_subdomain, sub): sub for sub in subdomains}
            
            for future in as_completed(futures, timeout=30):
                try:
                    result = future.result(timeout=self.timeout)
                    if result:
                        subdomain_info.append(result)
                except:
                    continue
        
        return subdomain_info
