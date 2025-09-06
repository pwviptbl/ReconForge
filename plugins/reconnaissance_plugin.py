"""
Plugin de Reconhecimento Avançado e OSINT
Coleta informações completas sobre domínios e IPs incluindo:
- Resolução DNS (Domínio ↔ IP)
- Informações ASN e ranges de rede
- Enumeração de subdomínios
- Busca avançada de emails
- Localização geográfica (GeoIP)
- Informações WHOIS
- OSINT: Social Media Intelligence
- OSINT: Data Breach Checking
- OSINT: Threat Intelligence Feeds
- OSINT: Advanced Email Harvesting
"""

import socket
import re
import time
import json
import requests
import concurrent.futures
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
import itertools
import random

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

from core.plugin_base import NetworkPlugin, PluginResult


class ReconnaissancePlugin(NetworkPlugin):
    """Plugin avançado de reconhecimento e OSINT"""
    
    def __init__(self):
        super().__init__()
        self.description = "Reconhecimento avançado e OSINT: DNS, ASN, subdomínios, emails, social media, threat intel"
        self.version = "2.0.0"
        self.supported_targets = ["domain", "ip", "url"]
        
        # Configurações padrão
        self.config = {
            'dns_servers': ['8.8.8.8', '8.8.4.4', '1.1.1.1'],
            'subdomain_wordlist': 'wordlists/subdomains.txt',
            'max_subdomains': 100,
            'max_threads': 50,
            'timeout': 10,
            'use_apis': True,
            'api_delay': 1.0,
            'brute_force_subdomains': True,
            'check_email_patterns': True,
            'geoip_enabled': True,
            'whois_enabled': True,
            'asn_lookup': True,
            'crt_sh_api': True,
            'securitytrails_api': False,  # Requer API key
            'virustotal_api': False,      # Requer API key
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ]
        }
        
        # Wordlists comuns para subdomínios
        self.common_subdomains = [
            'www', 'mail', 'email', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'ns3',
            'ftp', 'sftp', 'ssh', 'vpn', 'admin', 'administrator', 'root', 'login',
            'api', 'app', 'mobile', 'm', 'secure', 'ssl', 'tls', 'dev', 'development',
            'test', 'testing', 'stage', 'staging', 'prod', 'production', 'www1', 'www2',
            'blog', 'news', 'forum', 'forums', 'shop', 'store', 'ecommerce', 'portal',
            'support', 'help', 'helpdesk', 'docs', 'documentation', 'wiki', 'kb',
            'cdn', 'static', 'assets', 'img', 'images', 'media', 'upload', 'download',
            'files', 'file', 'backup', 'old', 'legacy', 'archive', 'db', 'database',
            'mysql', 'postgres', 'oracle', 'mssql', 'mongo', 'redis', 'elasticsearch',
            'search', 'solr', 'ldap', 'ad', 'directory', 'dns', 'ntp', 'time',
            'monitor', 'monitoring', 'metrics', 'stats', 'analytics', 'logs', 'log',
            'git', 'svn', 'jenkins', 'ci', 'build', 'deploy', 'docker', 'k8s',
            'kubernetes', 'aws', 'azure', 'gcp', 'cloud', 'office', 'exchange',
            'sharepoint', 'teams', 'skype', 'zoom', 'meet', 'conference', 'demo',
            'sandbox', 'lab', 'research', 'beta', 'alpha', 'preview', 'canary'
        ]
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa reconhecimento completo"""
        start_time = time.time()
        
        try:
            # Processar target
            domain, ip = self._parse_target(target)
            
            results = {
                'target': target,
                'domain': domain,
                'ip': ip,
                'timestamp': time.time(),
                'dns_info': {},
                'asn_info': {},
                'subdomains': [],
                'emails': [],
                'geo_info': {},
                'whois_info': {},
                'network_ranges': [],
                'technologies': [],
                'certificates': [],
                'errors': []
            }
            
            # 1. Resolução DNS básica
            if domain:
                results['dns_info'] = self._dns_reconnaissance(domain)
            elif ip:
                results['dns_info'] = self._reverse_dns_lookup(ip)
            
            # 2. Coletar todos os IPs encontrados
            all_ips = set()
            if ip:
                all_ips.add(ip)
            if results['dns_info'].get('ips'):
                all_ips.update(results['dns_info']['ips'])
            
            # 3. ASN e informações de rede para cada IP
            if self.config.get('asn_lookup', True) and all_ips:
                results['asn_info'] = self._asn_reconnaissance(list(all_ips))
            
            # 4. Enumeração de subdomínios
            if domain and self.config.get('brute_force_subdomains', True):
                results['subdomains'] = self._subdomain_enumeration(domain)
            
            # 5. Busca de emails
            if domain and self.config.get('check_email_patterns', True):
                results['emails'] = self._email_reconnaissance(domain)
            
            # 6. Informações geográficas
            if self.config.get('geoip_enabled', True) and all_ips:
                results['geo_info'] = self._geoip_lookup(list(all_ips))
            
            # 7. Informações WHOIS
            if self.config.get('whois_enabled', True):
                if domain:
                    results['whois_info'] = self._whois_lookup(domain)
                elif ip:
                    results['whois_info'] = self._whois_lookup(ip)
            
            # 8. Coletar informações adicionais de subdomínios descobertos
            if results['subdomains']:
                additional_ips = self._resolve_subdomains(results['subdomains'])
                all_ips.update(additional_ips)
            
            # 9. OSINT Intelligence - Funcionalidades Expandidas
            osint_results = {}
            
            if self.config.get("social_media_scan", False) and domain:
                self.logger.info("Executando reconhecimento de mídias sociais...")
                osint_results["social_media"] = self._social_media_reconnaissance(domain)
            
            if self.config.get("check_data_breaches", False) and domain:
                self.logger.info("Verificando vazamentos de dados...")
                osint_results["data_breaches"] = self._check_data_breaches(domain)
            
            if self.config.get("threat_intelligence", False):
                self.logger.info("Coletando threat intelligence...")
                osint_results["threat_intel"] = self._threat_intelligence_lookup(domain, ip)
            
            if self.config.get("advanced_email_harvesting", False) and domain:
                self.logger.info("Executando coleta avançada de emails...")
                osint_results["advanced_emails"] = self._advanced_email_harvesting(domain)
            
            if osint_results:
                results["osint_intelligence"] = osint_results
            
            # Estatísticas finais
            results['statistics'] = {
                'total_ips': len(all_ips),
                'total_subdomains': len(results['subdomains']),
                'total_emails': len(results['emails']),
                'unique_asns': len(set(asn['asn'] for asn in results['asn_info'].values() if 'asn' in asn)),
                'countries': len(set(geo['country'] for geo in results['geo_info'].values() if 'country' in geo))
            }
            
            # Preparar dados finais para o contexto
            hosts = list(all_ips)
            discovered_domains = [domain] if domain else []
            discovered_domains.extend([sub['domain'] for sub in results['subdomains'] if sub.get('resolved')])
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    'reconnaissance': results,
                    'hosts': hosts,
                    'domains': discovered_domains,
                    'services': self._extract_services(results),
                    'technologies': results['technologies']
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
        """Valida se é um domínio, IP ou URL válida"""
        # Verificar se é IP
        try:
            socket.inet_aton(target.split('/')[0])
            return True
        except socket.error:
            pass
        
        # Verificar se é domínio/URL
        if '.' in target and len(target) > 3:
            return True
        
        return False
    
    def _parse_target(self, target: str) -> tuple:
        """Extrai domínio e IP do target"""
        domain = None
        ip = None
        
        # Remover protocolo se presente
        if '://' in target:
            target = target.split('://', 1)[1]
        
        # Remover path se presente
        target = target.split('/')[0]
        
        # Verificar se é IP
        try:
            socket.inet_aton(target)
            ip = target
        except socket.error:
            domain = target
        
        return domain, ip
    
    def _dns_reconnaissance(self, domain: str) -> Dict[str, Any]:
        """Reconhecimento DNS completo"""
        results = {
            'domain': domain,
            'ips': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'aaaa_records': [],
            'errors': []
        }
        
        if not DNS_AVAILABLE:
            # Fallback para socket básico
            try:
                ip = socket.gethostbyname(domain)
                results['ips'] = [ip]
            except Exception as e:
                results['errors'].append(f"DNS resolution failed: {e}")
            return results
        
        # Usar dnspython para consultas avançadas
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.config.get('dns_servers', ['8.8.8.8'])
        resolver.timeout = self.config.get('timeout', 10)
        
        # Diferentes tipos de registros DNS
        record_types = {
            'A': 'ips',
            'AAAA': 'aaaa_records',
            'MX': 'mx_records',
            'NS': 'ns_records',
            'TXT': 'txt_records',
            'CNAME': 'cname_records'
        }
        
        for record_type, result_key in record_types.items():
            try:
                answers = resolver.resolve(domain, record_type)
                records = []
                
                for answer in answers:
                    if record_type == 'A':
                        records.append(str(answer))
                    elif record_type == 'AAAA':
                        records.append(str(answer))
                    elif record_type == 'MX':
                        records.append({'preference': answer.preference, 'exchange': str(answer.exchange)})
                    elif record_type == 'NS':
                        records.append(str(answer))
                    elif record_type == 'TXT':
                        records.append(str(answer))
                    elif record_type == 'CNAME':
                        records.append(str(answer))
                
                results[result_key] = records
                
            except Exception as e:
                results['errors'].append(f"{record_type} lookup failed: {e}")
        
        return results
    
    def _reverse_dns_lookup(self, ip: str) -> Dict[str, Any]:
        """Lookup reverso de DNS"""
        results = {
            'ip': ip,
            'hostnames': [],
            'ptr_records': [],
            'errors': []
        }
        
        # Lookup básico com socket
        try:
            hostname_info = socket.gethostbyaddr(ip)
            results['hostnames'] = [hostname_info[0]] + list(hostname_info[1])
        except Exception as e:
            results['errors'].append(f"Reverse DNS lookup failed: {e}")
        
        # Lookup avançado com dnspython
        if DNS_AVAILABLE:
            try:
                reverse_name = dns.reversename.from_address(ip)
                resolver = dns.resolver.Resolver()
                resolver.nameservers = self.config.get('dns_servers', ['8.8.8.8'])
                
                answers = resolver.resolve(reverse_name, 'PTR')
                results['ptr_records'] = [str(answer) for answer in answers]
                
            except Exception as e:
                results['errors'].append(f"PTR lookup failed: {e}")
        
        return results
    
    def _asn_reconnaissance(self, ips: List[str]) -> Dict[str, Any]:
        """Reconhecimento de ASN e informações de rede"""
        results = {}
        
        for ip in ips:
            try:
                ip_info = {
                    'ip': ip,
                    'asn': None,
                    'asn_description': None,
                    'network': None,
                    'country': None,
                    'registry': None,
                    'allocation_date': None,
                    'nets': [],
                    'errors': []
                }
                
                if IPWHOIS_AVAILABLE:
                    # Usar ipwhois para informações detalhadas
                    try:
                        whois_obj = IPWhois(ip)
                        whois_result = whois_obj.lookup_rdap(depth=1)
                        
                        ip_info['asn'] = whois_result.get('asn')
                        ip_info['asn_description'] = whois_result.get('asn_description')
                        ip_info['network'] = whois_result.get('network', {}).get('cidr')
                        ip_info['country'] = whois_result.get('network', {}).get('country')
                        ip_info['registry'] = whois_result.get('asn_registry')
                        ip_info['allocation_date'] = whois_result.get('asn_date')
                        
                        # Informações de redes
                        if 'nets' in whois_result:
                            ip_info['nets'] = whois_result['nets']
                        
                    except Exception as e:
                        ip_info['errors'].append(f"IPWhois lookup failed: {e}")
                
                # Fallback: API ip-api.com (grátis)
                if not ip_info['asn'] and self.config.get('use_apis', True):
                    try:
                        response = requests.get(
                            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
                            timeout=self.config.get('timeout', 10)
                        )
                        
                        if response.status_code == 200:
                            api_data = response.json()
                            if api_data.get('status') == 'success':
                                ip_info['asn'] = api_data.get('as', '').split()[0] if api_data.get('as') else None
                                ip_info['asn_description'] = api_data.get('asname')
                                ip_info['country'] = api_data.get('country')
                                ip_info['isp'] = api_data.get('isp')
                                ip_info['org'] = api_data.get('org')
                        
                        # Delay para respeitar rate limit
                        time.sleep(self.config.get('api_delay', 1.0))
                        
                    except Exception as e:
                        ip_info['errors'].append(f"IP-API lookup failed: {e}")
                
                results[ip] = ip_info
                
            except Exception as e:
                results[ip] = {'ip': ip, 'errors': [f"ASN lookup failed: {e}"]}
        
        return results
    
    def _subdomain_enumeration(self, domain: str) -> List[Dict[str, Any]]:
        """Enumeração de subdomínios usando múltiplas técnicas"""
        found_subdomains = set()
        results = []
        
        # 1. Brute force com wordlist comum
        if self.config.get('brute_force_subdomains', True):
            brute_force_results = self._brute_force_subdomains(domain)
            found_subdomains.update(sub['subdomain'] for sub in brute_force_results)
            results.extend(brute_force_results)
        
        # 2. Certificate Transparency (crt.sh)
        if self.config.get('crt_sh_api', True):
            crt_results = self._crt_sh_lookup(domain)
            for subdomain in crt_results:
                if subdomain not in found_subdomains:
                    found_subdomains.add(subdomain)
                    results.append({
                        'subdomain': subdomain,
                        'domain': f"{subdomain}.{domain}" if subdomain else domain,
                        'method': 'certificate_transparency',
                        'resolved': False,
                        'ips': []
                    })
        
        # 3. Resolver todos os subdomínios encontrados
        if results:
            self._resolve_subdomains_batch(results)
        
        # Filtrar apenas os que resolveram
        resolved_results = [sub for sub in results if sub.get('resolved', False)]
        
        # Limitar resultados
        max_subdomains = self.config.get('max_subdomains', 100)
        return resolved_results[:max_subdomains]
    
    def _brute_force_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """Brute force de subdomínios usando wordlist"""
        results = []
        subdomains_to_test = self.common_subdomains.copy()
        
        # Carregar wordlist personalizada se existir
        wordlist_path = Path(self.config.get('subdomain_wordlist', ''))
        if wordlist_path.exists():
            try:
                with open(wordlist_path, 'r') as f:
                    custom_subdomains = [line.strip() for line in f if line.strip()]
                subdomains_to_test.extend(custom_subdomains)
            except Exception:
                pass  # Continuar com wordlist padrão
        
        # Remover duplicatas e limitar
        subdomains_to_test = list(set(subdomains_to_test))[:self.config.get('max_subdomains', 100)]
        
        # Threading para acelerar
        max_threads = self.config.get('max_threads', 50)
        
        def test_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                ips = []
                try:
                    ip = socket.gethostbyname(full_domain)
                    ips.append(ip)
                    resolved = True
                except socket.gaierror:
                    resolved = False
                
                return {
                    'subdomain': subdomain,
                    'domain': full_domain,
                    'method': 'brute_force',
                    'resolved': resolved,
                    'ips': ips
                }
            except Exception:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_subdomain = {
                executor.submit(test_subdomain, sub): sub 
                for sub in subdomains_to_test
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain, timeout=60):
                try:
                    result = future.result()
                    if result and result['resolved']:
                        results.append(result)
                except Exception:
                    continue
        
        return results
    
    def _crt_sh_lookup(self, domain: str) -> List[str]:
        """Busca subdomínios via Certificate Transparency (crt.sh)"""
        subdomains = set()
        
        try:
            # Usar API crt.sh
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=self.config.get('timeout', 10))
            
            if response.status_code == 200:
                certificates = response.json()
                
                for cert in certificates:
                    name = cert.get('name_value', '')
                    if name:
                        # Processar múltiplos nomes no certificado
                        names = name.split('\n')
                        for cert_name in names:
                            cert_name = cert_name.strip()
                            if cert_name.endswith(f'.{domain}'):
                                subdomain = cert_name[:-len(f'.{domain}')]
                                if subdomain and '.' not in subdomain:  # Apenas subdomínios diretos
                                    subdomains.add(subdomain)
            
            time.sleep(self.config.get('api_delay', 1.0))
            
        except Exception:
            pass  # Ignorar erros da API
        
        return list(subdomains)
    
    def _resolve_subdomains_batch(self, subdomains: List[Dict[str, Any]]):
        """Resolve subdomínios em lote para otimizar performance"""
        max_threads = self.config.get('max_threads', 50)
        
        def resolve_subdomain(sub_dict):
            try:
                domain = sub_dict['domain']
                ips = []
                
                # Tentar resolver
                try:
                    ip = socket.gethostbyname(domain)
                    ips.append(ip)
                    sub_dict['resolved'] = True
                    sub_dict['ips'] = ips
                except socket.gaierror:
                    sub_dict['resolved'] = False
                    sub_dict['ips'] = []
                
            except Exception:
                sub_dict['resolved'] = False
                sub_dict['ips'] = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(resolve_subdomain, sub) for sub in subdomains]
            concurrent.futures.wait(futures, timeout=60)
    
    def _resolve_subdomains(self, subdomains: List[Dict[str, Any]]) -> Set[str]:
        """Resolve subdomínios e retorna IPs únicos encontrados"""
        ips = set()
        for sub in subdomains:
            if sub.get('ips'):
                ips.update(sub['ips'])
        return ips
    
    def _email_reconnaissance(self, domain: str) -> List[Dict[str, Any]]:
        """Busca de emails relacionados ao domínio"""
        emails = []
        
        # Padrões comuns de email
        common_patterns = [
            'admin', 'administrator', 'info', 'contact', 'support', 'help',
            'sales', 'marketing', 'hr', 'jobs', 'careers', 'security',
            'webmaster', 'postmaster', 'hostmaster', 'abuse', 'noc',
            'mail', 'email', 'newsletter', 'news', 'press', 'media'
        ]
        
        for pattern in common_patterns:
            email = f"{pattern}@{domain}"
            emails.append({
                'email': email,
                'type': 'common_pattern',
                'verified': False,  # Não verificamos se existe realmente
                'source': 'pattern_generation'
            })
        
        # TODO: Integrar com APIs como Hunter.io, HaveIBeenPwned quando disponível
        # TODO: Buscar em motores de busca (respeitando robots.txt)
        # TODO: Verificar registros DNS MX para padrões
        
        return emails[:20]  # Limitar resultados
    
    def _geoip_lookup(self, ips: List[str]) -> Dict[str, Any]:
        """Lookup de localização geográfica para IPs"""
        results = {}
        
        for ip in ips:
            try:
                # Usar API ip-api.com (grátis, sem necessidade de key)
                response = requests.get(
                    f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,reverse,mobile,proxy,hosting",
                    timeout=self.config.get('timeout', 10)
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        results[ip] = {
                            'ip': ip,
                            'country': data.get('country'),
                            'country_code': data.get('countryCode'),
                            'region': data.get('region'),
                            'region_name': data.get('regionName'),
                            'city': data.get('city'),
                            'zip': data.get('zip'),
                            'latitude': data.get('lat'),
                            'longitude': data.get('lon'),
                            'timezone': data.get('timezone'),
                            'isp': data.get('isp'),
                            'org': data.get('org'),
                            'reverse': data.get('reverse'),
                            'mobile': data.get('mobile'),
                            'proxy': data.get('proxy'),
                            'hosting': data.get('hosting')
                        }
                    else:
                        results[ip] = {'ip': ip, 'error': data.get('message', 'Unknown error')}
                else:
                    results[ip] = {'ip': ip, 'error': f'API returned {response.status_code}'}
                
                # Rate limiting
                time.sleep(self.config.get('api_delay', 1.0))
                
            except Exception as e:
                results[ip] = {'ip': ip, 'error': str(e)}
        
        return results
    
    def _whois_lookup(self, target: str) -> Dict[str, Any]:
        """Lookup WHOIS para domínio ou IP"""
        results = {
            'target': target,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': [],
            'contacts': {},
            'raw_whois': '',
            'errors': []
        }
        
        try:
            # Determinar se é IP ou domínio
            is_ip = False
            try:
                socket.inet_aton(target)
                is_ip = True
            except socket.error:
                pass
            
            if WHOIS_AVAILABLE and not is_ip:
                # Usar python-whois para domínios
                try:
                    whois_info = python_whois.whois(target)
                    
                    results['registrar'] = whois_info.registrar
                    results['creation_date'] = str(whois_info.creation_date) if whois_info.creation_date else None
                    results['expiration_date'] = str(whois_info.expiration_date) if whois_info.expiration_date else None
                    results['name_servers'] = whois_info.name_servers or []
                    results['registrant'] = whois_info.registrant
                    results['admin'] = whois_info.admin
                    results['tech'] = whois_info.tech
                    results['raw_whois'] = whois_info.text
                    
                except Exception as e:
                    results['errors'].append(f"Python-whois lookup failed: {e}")
            
            elif IPWHOIS_AVAILABLE and is_ip:
                # Usar ipwhois para IPs
                try:
                    whois_obj = IPWhois(target)
                    whois_result = whois_obj.lookup_whois()
                    
                    results['nets'] = whois_result.get('nets', [])
                    results['asn'] = whois_result.get('asn')
                    results['asn_description'] = whois_result.get('asn_description')
                    results['registry'] = whois_result.get('asn_registry')
                    results['raw_whois'] = whois_result.get('raw')
                    
                except Exception as e:
                    results['errors'].append(f"IPWhois lookup failed: {e}")
            
        except Exception as e:
            results['errors'].append(f"WHOIS lookup failed: {e}")
        
        return results
    
    def _extract_services(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrai informações de serviços dos resultados do reconhecimento"""
        services = []
        
        # Serviços de DNS descobertos
        dns_info = results.get('dns_info', {})
        
        # Servidores de email (MX records)
        for mx in dns_info.get('mx_records', []):
            if isinstance(mx, dict):
                services.append({
                    'service': 'SMTP',
                    'host': mx.get('exchange'),
                    'port': 25,
                    'protocol': 'tcp',
                    'priority': mx.get('preference'),
                    'source': 'dns_mx'
                })
        
        # Servidores DNS (NS records)
        for ns in dns_info.get('ns_records', []):
            services.append({
                'service': 'DNS',
                'host': ns,
                'port': 53,
                'protocol': 'udp',
                'source': 'dns_ns'
            })
        
        return services
    
    def _social_media_reconnaissance(self, domain: str) -> Dict[str, Any]:
        """Reconhecimento de presença em mídias sociais"""
        social_results = {
            'linkedin': None,
            'twitter': None,
            'github': None,
            'facebook': None,
            'error': None
        }
        
        try:
            import requests
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            # Extrair nome da empresa do domínio
            company_name = domain.split('.')[0].replace('-', ' ').replace('_', ' ')
            
            # LinkedIn - verificar existência de página da empresa
            try:
                linkedin_url = f"https://www.linkedin.com/company/{company_name}"
                response = session.head(linkedin_url, timeout=10)
                social_results['linkedin'] = {
                    'url': linkedin_url,
                    'exists': response.status_code == 200,
                    'status_code': response.status_code
                }
            except Exception as e:
                social_results['linkedin'] = {'error': str(e)}
            
            # Twitter/X - verificar handle da empresa
            try:
                twitter_url = f"https://twitter.com/{company_name}"
                response = session.head(twitter_url, timeout=10)
                social_results['twitter'] = {
                    'url': twitter_url,
                    'exists': response.status_code == 200,
                    'status_code': response.status_code
                }
            except Exception as e:
                social_results['twitter'] = {'error': str(e)}
            
            # GitHub - verificar organização
            try:
                github_url = f"https://github.com/{company_name}"
                response = session.head(github_url, timeout=10)
                social_results['github'] = {
                    'url': github_url,
                    'exists': response.status_code == 200,
                    'status_code': response.status_code
                }
            except Exception as e:
                social_results['github'] = {'error': str(e)}
            
            # Facebook - verificar página da empresa
            try:
                facebook_url = f"https://www.facebook.com/{company_name}"
                response = session.head(facebook_url, timeout=10)
                social_results['facebook'] = {
                    'url': facebook_url,
                    'exists': response.status_code == 200,
                    'status_code': response.status_code
                }
            except Exception as e:
                social_results['facebook'] = {'error': str(e)}
                
        except ImportError:
            social_results['error'] = "requests library not available"
        except Exception as e:
            social_results['error'] = str(e)
        
        return social_results
    
    def _check_data_breaches(self, domain: str) -> Dict[str, Any]:
        """Verificação de vazamentos de dados"""
        breach_results = {
            'haveibeenpwned': None,
            'leaklookup': None,
            'breaches_found': [],
            'error': None
        }
        
        try:
            import requests
            session = requests.Session()
            
            # HaveIBeenPwned API (versão pública limitada)
            try:
                hibp_url = f"https://haveibeenpwned.com/api/v3/breaches"
                response = session.get(hibp_url, timeout=15)
                if response.status_code == 200:
                    breaches = response.json()
                    domain_breaches = [
                        breach for breach in breaches 
                        if domain.lower() in breach.get('Domain', '').lower()
                    ]
                    breach_results['haveibeenpwned'] = {
                        'total_breaches': len(breaches),
                        'domain_breaches': len(domain_breaches),
                        'breaches': domain_breaches[:5]  # Limitado a 5 resultados
                    }
            except Exception as e:
                breach_results['haveibeenpwned'] = {'error': str(e)}
            
            # Verificação simples de padrões de email do domínio
            try:
                common_emails = [
                    f"admin@{domain}",
                    f"info@{domain}",
                    f"contact@{domain}",
                    f"support@{domain}",
                    f"sales@{domain}"
                ]
                breach_results['common_emails_to_check'] = common_emails
            except Exception as e:
                breach_results['error'] = str(e)
                
        except ImportError:
            breach_results['error'] = "requests library not available"
        except Exception as e:
            breach_results['error'] = str(e)
        
        return breach_results
    
    def _threat_intelligence_lookup(self, domain: str, ip: str) -> Dict[str, Any]:
        """Lookup de threat intelligence"""
        threat_results = {
            'virustotal': None,
            'abuseipdb': None,
            'reputation_score': 0,
            'threats_found': [],
            'error': None
        }
        
        try:
            import requests
            session = requests.Session()
            
            # VirusTotal API (versão pública limitada)
            if domain:
                try:
                    # Verificação básica sem API key
                    vt_url = f"https://www.virustotal.com/gui/domain/{domain}"
                    threat_results['virustotal'] = {
                        'domain': domain,
                        'url': vt_url,
                        'note': 'Manual verification recommended'
                    }
                except Exception as e:
                    threat_results['virustotal'] = {'error': str(e)}
            
            # AbuseIPDB verificação básica
            if ip:
                try:
                    abuse_url = f"https://www.abuseipdb.com/check/{ip}"
                    threat_results['abuseipdb'] = {
                        'ip': ip,
                        'url': abuse_url,
                        'note': 'Manual verification recommended'
                    }
                except Exception as e:
                    threat_results['abuseipdb'] = {'error': str(e)}
            
            # Verificações básicas de reputação
            try:
                threat_indicators = []
                
                if domain:
                    # Verificar domínios suspeitos
                    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
                    if any(domain.endswith(tld) for tld in suspicious_tlds):
                        threat_indicators.append("Suspicious TLD detected")
                    
                    # Verificar caracteres suspeitos
                    if '-' in domain and domain.count('-') > 3:
                        threat_indicators.append("Excessive hyphens in domain")
                
                threat_results['basic_checks'] = threat_indicators
                threat_results['reputation_score'] = max(0, 100 - len(threat_indicators) * 25)
                
            except Exception as e:
                threat_results['error'] = str(e)
                
        except ImportError:
            threat_results['error'] = "requests library not available"
        except Exception as e:
            threat_results['error'] = str(e)
        
        return threat_results
    
    def _advanced_email_harvesting(self, domain: str) -> Dict[str, Any]:
        """Coleta avançada de emails usando múltiplas técnicas"""
        email_results = {
            'google_dorking': [],
            'github_search': [],
            'linkedin_patterns': [],
            'total_emails': 0,
            'unique_emails': set(),
            'error': None
        }
        
        try:
            import requests
            import re
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@' + re.escape(domain) + r'\b')
            
            # Google Dorking (simulado - busca por padrões)
            try:
                google_queries = [
                    f'site:{domain} "email"',
                    f'site:{domain} "@{domain}"',
                    f'"{domain}" contact',
                    f'site:linkedin.com "{domain}"'
                ]
                email_results['google_dorking'] = {
                    'queries': google_queries,
                    'note': 'Manual Google search recommended with these queries'
                }
            except Exception as e:
                email_results['google_dorking'] = {'error': str(e)}
            
            # GitHub search (API pública limitada)
            try:
                github_url = f"https://api.github.com/search/code?q={domain}+in:file"
                response = session.get(github_url, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    email_results['github_search'] = {
                        'total_results': data.get('total_count', 0),
                        'note': 'Check GitHub manually for email addresses in code'
                    }
            except Exception as e:
                email_results['github_search'] = {'error': str(e)}
            
            # Padrões comuns de email
            try:
                common_patterns = [
                    f"admin@{domain}",
                    f"contact@{domain}",
                    f"info@{domain}",
                    f"support@{domain}",
                    f"sales@{domain}",
                    f"marketing@{domain}",
                    f"hr@{domain}",
                    f"security@{domain}",
                    f"webmaster@{domain}",
                    f"noreply@{domain}"
                ]
                email_results['common_patterns'] = common_patterns
                email_results['unique_emails'].update(common_patterns)
            except Exception as e:
                email_results['error'] = str(e)
            
            # Converter set para list para serialização
            email_results['unique_emails'] = list(email_results['unique_emails'])
            email_results['total_emails'] = len(email_results['unique_emails'])
            
        except ImportError:
            email_results['error'] = "requests library not available"
        except Exception as e:
            email_results['error'] = str(e)
        
        return email_results
    
    def get_info(self) -> Dict[str, Any]:
        """Informações detalhadas sobre o plugin"""
        info = super().get_info()
        
        # Verificar dependências disponíveis
        dependencies = {
            'dnspython': DNS_AVAILABLE,
            'ipwhois': IPWHOIS_AVAILABLE,
            'tldextract': TLDEXTRACT_AVAILABLE,
            'python-whois': WHOIS_AVAILABLE
        }
        
        info['dependencies'] = dependencies
        info['features'] = [
            'DNS Resolution (A, AAAA, MX, NS, TXT, CNAME)',
            'Reverse DNS Lookup',
            'ASN and Network Information',
            'Subdomain Enumeration (Brute-force + Certificate Transparency)',
            'Email Pattern Discovery',
            'Geographic IP Location',
            'WHOIS Information',
            'Social Media Intelligence (LinkedIn, Twitter, GitHub, Facebook)',
            'Data Breach Checking (HaveIBeenPwned integration)',
            'Threat Intelligence Lookup (VirusTotal, AbuseIPDB)',
            'Advanced Email Harvesting (Google Dorking, GitHub, patterns)',
            'Multi-threaded Operations',
            'Rate Limited API Calls'
        ]
        
        return info
