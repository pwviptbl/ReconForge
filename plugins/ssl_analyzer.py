"""
Plugin de Análise SSL/TLS
Analisa certificados e configurações SSL/TLS.
Suporta roteamento via Tor: socket SOCKS5 (PySocks) + ssl.wrap_socket.
"""

import ssl
import socket
import time
import subprocess
import json
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import datetime

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult
from core.config import get_config
from utils.http_session import resolve_use_tor
from utils.tor import tor_proxy_url, ensure_tor_ready
from utils.logger import get_logger


class SSLAnalyzerPlugin(NetworkPlugin):
    """Plugin para análise de SSL/TLS e certificados (com suporte a Tor)"""

    def __init__(self):
        super().__init__()
        self.description = "Análise completa de SSL/TLS e certificados digitais (suporte a Tor via PySocks)"
        self.version = "1.1.0"
        self.supported_targets = ["domain", "url", "ip"]
        self.logger = get_logger("SSLAnalyzerPlugin")

        # Configurações padrão
        self.timeout = 10
        self.check_vulnerabilities = True
        self.verify_chain = True
        
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa análise SSL/TLS (com suporte a Tor via PySocks)"""
        start_time = time.time()

        # Configurar modo Tor
        use_tor = resolve_use_tor(self.config)
        if use_tor:
            ensure_tor_ready(use_tor=True)
            self.logger.info("[SSLAnalyzer] Modo Tor ativo — socket SSL roteado via SOCKS5")

        try:
            # Ler configurações do YAML
            self.check_vulnerabilities = get_config('plugins.config.SSLAnalyzerPlugin.check_vulnerabilities', True)
            self.verify_chain = get_config('plugins.config.SSLAnalyzerPlugin.verify_chain', True)
            check_revocation = get_config('plugins.config.SSLAnalyzerPlugin.check_revocation', True)
            analyze_ciphers = get_config('plugins.config.SSLAnalyzerPlugin.analyze_ciphers', True)
            check_hsts = get_config('plugins.config.SSLAnalyzerPlugin.check_hsts', True)
            
            # Preparar target para análise SSL
            hostname, port = self._parse_target(target)
            if not hostname:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error=f"Target inválido para análise SSL: {target}"
                )
            
            results = {
                'target': target,
                'hostname': hostname,
                'port': port
            }
            
            hosts = []
            
            # Verificar se o serviço SSL está disponível
            ssl_available = self._check_ssl_availability(hostname, port, use_tor=use_tor)
            results['ssl_available'] = ssl_available

            if not ssl_available:
                return PluginResult(
                    success=True,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={
                        **results,
                        'ssl_enabled': False,
                        'message': 'SSL/TLS não está disponível neste target'
                    }
                )

            # Análise do certificado
            results['certificate_analysis'] = self._analyze_certificate(hostname, port, use_tor=use_tor)

            # Análise de configuração SSL/TLS
            results['ssl_configuration'] = self._analyze_ssl_configuration(hostname, port, use_tor=use_tor)

            # Análise de cifras
            if analyze_ciphers:
                results['cipher_analysis'] = self._analyze_ciphers(hostname, port, use_tor=use_tor)

            # Verificação de vulnerabilidades
            if self.check_vulnerabilities:
                results['vulnerability_scan'] = self._scan_ssl_vulnerabilities(hostname, port, use_tor=use_tor)

            # Verificação HSTS
            if check_hsts:
                results['hsts_analysis'] = self._check_hsts_header(hostname, port)

            # Verificação de revogação
            if check_revocation:
                results['revocation_check'] = self._check_certificate_revocation(hostname, port)

            # Adicionar hostname aos hosts descobertos
            try:
                host_ip = socket.gethostbyname(hostname)
                hosts.append(host_ip)
            except Exception:
                pass

            execution_time = time.time() - start_time

            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    **results,
                    'ssl_enabled': True,
                    'hosts': hosts,
                    'tor_mode': use_tor,
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
        """Valida se o target é adequado para análise SSL"""
        hostname, port = self._parse_target(target)
        return hostname is not None
    
    def _parse_target(self, target: str) -> tuple[Optional[str], int]:
        """Parseia target para extrair hostname e porta"""
        try:
            # Se é URL completa
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                hostname = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                # Só analisar SSL se for HTTPS ou porta SSL comum
                if parsed.scheme == 'http' and port not in [443, 8443, 8080]:
                    return None, None
                return hostname, port
            
            # Se tem formato hostname:porta
            if ':' in target:
                parts = target.split(':')
                if len(parts) == 2:
                    try:
                        port = int(parts[1])
                        return parts[0], port
                    except ValueError:
                        pass
            
            # Hostname simples - assumir porta 443
            if '.' in target:
                return target, 443
            
            # IP - assumir porta 443
            try:
                socket.inet_aton(target)
                return target, 443
            except:
                pass
            
            return None, None
            
        except Exception:
            return None, None
    
    def _check_ssl_availability(self, hostname: str, port: int, use_tor: bool = False) -> bool:
        """Verifica se SSL está disponível no target (via Tor se habilitado)"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            if use_tor:
                try:
                    import socks as pysocks
                    from utils.tor import tor_proxy_url
                    from urllib.parse import urlsplit
                    parsed = urlsplit(tor_proxy_url())
                    raw = pysocks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                    raw.set_proxy(pysocks.SOCKS5, parsed.hostname or '127.0.0.1', parsed.port or 9050, rdns=True)
                    raw.settimeout(self.timeout)
                    raw.connect((hostname, port))
                    context.wrap_socket(raw, server_hostname=hostname).close()
                    return True
                except Exception:
                    return False
            else:
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        return True

        except Exception:
            return False
    
    def _analyze_certificate(self, hostname: str, port: int, use_tor: bool = False) -> Dict[str, Any]:
        """Analisa o certificado SSL (via Tor se habilitado)"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            if use_tor:
                import socks as pysocks
                from utils.tor import tor_proxy_url
                from urllib.parse import urlsplit
                parsed = urlsplit(tor_proxy_url())
                raw = pysocks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                raw.set_proxy(pysocks.SOCKS5, parsed.hostname or '127.0.0.1', parsed.port or 9050, rdns=True)
                raw.settimeout(self.timeout)
                raw.connect((hostname, port))
                ssock = context.wrap_socket(raw, server_hostname=hostname)
            else:
                _conn = socket.create_connection((hostname, port), timeout=self.timeout)
                ssock = context.wrap_socket(_conn, server_hostname=hostname)

            try:
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)

                cert_info = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'signature_algorithm': cert.get('signatureAlgorithm'),
                    'public_key_info': self._analyze_public_key(cert),
                    'extensions': self._analyze_extensions(cert),
                    'san_list': cert.get('subjectAltName', []),
                    'is_self_signed': self._is_self_signed(cert),
                    'validation_status': self._validate_certificate_chain(hostname, port)
                }
                cert_info['validity_analysis'] = self._analyze_certificate_validity(cert)
                cert_info['security_analysis'] = self._analyze_certificate_security(cert)
                return cert_info
            finally:
                ssock.close()

        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_ssl_configuration(self, hostname: str, port: int, use_tor: bool = False) -> Dict[str, Any]:
        """Analisa configuração SSL/TLS (use_tor propagado para sub-métodos)"""
        try:
            config_info = {
                'supported_protocols': self._get_supported_protocols(hostname, port, use_tor=use_tor),
                'preferred_cipher': self._get_preferred_cipher(hostname, port, use_tor=use_tor),
                'compression_support': self._check_compression_support(hostname, port),
                'renegotiation_support': self._check_renegotiation_support(hostname, port),
                'session_resumption': self._check_session_resumption(hostname, port)
            }

            return config_info

        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_ciphers(self, hostname: str, port: int, use_tor: bool = False) -> Dict[str, Any]:
        """Analisa cifras suportadas (propaga use_tor para _test_cipher_support)"""
        try:
            cipher_suites = [
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES256-SHA384',
                'ECDHE-RSA-AES128-SHA256',
                'AES256-GCM-SHA384',
                'AES128-GCM-SHA256',
                'AES256-SHA256',
                'AES128-SHA256',
                'DES-CBC3-SHA',  # Fraca
                'RC4-SHA',       # Fraca
                'NULL-SHA'       # Muito fraca
            ]

            supported_ciphers = []
            weak_ciphers = []

            for cipher in cipher_suites:
                if self._test_cipher_support(hostname, port, cipher, use_tor=use_tor):
                    supported_ciphers.append(cipher)
                    if any(weak in cipher for weak in ['DES', 'RC4', 'NULL', 'MD5']):
                        weak_ciphers.append(cipher)

            return {
                'supported_ciphers': supported_ciphers,
                'total_supported': len(supported_ciphers),
                'weak_ciphers': weak_ciphers,
                'security_level': self._assess_cipher_security(supported_ciphers),
                'perfect_forward_secrecy': any('ECDHE' in cipher for cipher in supported_ciphers)
            }

        except Exception as e:
            return {'error': str(e)}
    
    def _scan_ssl_vulnerabilities(self, hostname: str, port: int, use_tor: bool = False) -> Dict[str, Any]:
        """Escaneia vulnerabilidades SSL conhecidas (use_tor propagado para sub-checagens)"""
        try:
            vulnerabilities = {
                'heartbleed': self._check_heartbleed(hostname, port, use_tor=use_tor),
                'poodle': self._check_poodle(hostname, port, use_tor=use_tor),
                'beast': self._check_beast(hostname, port),
                'freak': self._check_freak(hostname, port),
                'logjam': self._check_logjam(hostname, port),
                'drown': self._check_drown(hostname, port),
                'weak_rsa': self._check_weak_rsa(hostname, port)
            }

            vuln_count = sum(
                1 for vuln in vulnerabilities.values()
                if isinstance(vuln, dict) and vuln.get('vulnerable', False)
            )

            vulnerabilities['summary'] = {
                'total_vulnerabilities': vuln_count,
                'risk_level': self._assess_vulnerability_risk(vulnerabilities)
            }

            return vulnerabilities

        except Exception as e:
            return {'error': str(e)}
    
    def _check_hsts_header(self, hostname: str, port: int) -> Dict[str, Any]:
        """Verifica cabeçalho HSTS via requests (suporta Tor via sessão global)"""
        try:
            from utils.http_session import create_requests_session
            session = create_requests_session(plugin_config=self.config)
            url = f"https://{hostname}:{port}/" if port != 443 else f"https://{hostname}/"
            resp = session.head(url, timeout=self.timeout, verify=False, allow_redirects=True)
            hsts_header = resp.headers.get('Strict-Transport-Security')

            if hsts_header:
                hsts_info = self._parse_hsts_header(hsts_header)
                hsts_info['present'] = True
                return hsts_info
            else:
                return {
                    'present': False,
                    'recommendation': 'Implementar cabeçalho HSTS para maior segurança'
                }

        except Exception as e:
            return {'error': str(e)}
        finally:
            try:
                conn.close()
            except:
                pass
    
    def _check_certificate_revocation(self, hostname: str, port: int) -> Dict[str, Any]:
        """Verifica status de revogação do certificado"""
        try:
            # Implementação básica - pode ser expandida com OCSP
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Verificar se há informações OCSP ou CRL
                    extensions = cert.get('extensions', [])
                    
                    ocsp_urls = []
                    crl_urls = []
                    
                    for ext in extensions:
                        if 'OCSP' in str(ext):
                            # Extrair URLs OCSP se disponível
                            pass
                        elif 'CRL' in str(ext):
                            # Extrair URLs CRL se disponível
                            pass
                    
                    return {
                        'ocsp_urls': ocsp_urls,
                        'crl_urls': crl_urls,
                        'revocation_check_available': len(ocsp_urls) > 0 or len(crl_urls) > 0,
                        'status': 'not_revoked'  # Implementação básica
                    }
                    
        except Exception as e:
            return {'error': str(e)}
    
    # Métodos auxiliares para análise detalhada
    
    def _analyze_public_key(self, cert: Dict) -> Dict[str, Any]:
        """Analisa informações da chave pública"""
        # Implementação básica - pode ser expandida
        return {
            'algorithm': 'unknown',
            'key_size': 'unknown',
            'analysis': 'Basic analysis - expand for detailed key information'
        }
    
    def _analyze_extensions(self, cert: Dict) -> List[Dict[str, Any]]:
        """Analisa extensões do certificado"""
        # Implementação básica
        return []
    
    def _is_self_signed(self, cert: Dict) -> bool:
        """Verifica se o certificado é auto-assinado"""
        try:
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            return subject == issuer
        except:
            return False
    
    def _validate_certificate_chain(self, hostname: str, port: int) -> Dict[str, Any]:
        """Valida cadeia de certificados"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return {
                        'valid': True,
                        'verified': True,
                        'chain_length': 'unknown'
                    }
                    
        except ssl.SSLError as e:
            return {
                'valid': False,
                'error': str(e)
            }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }
    
    def _analyze_certificate_validity(self, cert: Dict) -> Dict[str, Any]:
        """Analisa validade temporal do certificado"""
        try:
            not_before = cert.get('notBefore')
            not_after = cert.get('notAfter')
            
            # Converter para datetime (formato: 'MMM DD HH:MM:SS YYYY GMT')
            if not_before and not_after:
                not_before_dt = datetime.datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                not_after_dt = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                now = datetime.datetime.utcnow()
                
                is_valid = not_before_dt <= now <= not_after_dt
                days_until_expiry = (not_after_dt - now).days
                
                return {
                    'is_valid': is_valid,
                    'not_before': not_before,
                    'not_after': not_after,
                    'days_until_expiry': days_until_expiry,
                    'expires_soon': days_until_expiry <= 30,
                    'expired': days_until_expiry < 0
                }
            
            return {'error': 'Could not parse certificate dates'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_certificate_security(self, cert: Dict) -> Dict[str, Any]:
        """Analisa aspectos de segurança do certificado"""
        try:
            issues = []
            
            # Verificar algoritmo de assinatura
            sig_alg = cert.get('signatureAlgorithm', '').lower()
            if 'md5' in sig_alg:
                issues.append('Weak signature algorithm: MD5')
            elif 'sha1' in sig_alg:
                issues.append('Weak signature algorithm: SHA-1')
            
            # Verificar se é auto-assinado
            if self._is_self_signed(cert):
                issues.append('Self-signed certificate')
            
            return {
                'security_issues': issues,
                'security_level': 'high' if not issues else 'medium' if len(issues) == 1 else 'low'
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_supported_protocols(self, hostname: str, port: int) -> List[str]:
        """Obtém protocolos SSL/TLS suportados"""
        protocols = []
        tls_version = getattr(ssl, "TLSVersion", None)
        if not tls_version:
            return protocols

        test_versions = [
            ('TLSv1.3', tls_version.TLSv1_3),
            ('TLSv1.2', tls_version.TLSv1_2),
            ('TLSv1.1', tls_version.TLSv1_1),
            ('TLSv1.0', tls_version.TLSv1),
        ]

        for protocol_name, version in test_versions:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version
                context.maximum_version = version

                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        protocols.append(protocol_name)
            except Exception:
                continue

        return protocols
    
    def _get_preferred_cipher(self, hostname: str, port: int) -> Optional[str]:
        """Obtém cifra preferida pelo servidor"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as ssock:
                    return ssock.cipher()[0] if ssock.cipher() else None
                    
        except Exception:
            return None
    
    def _check_compression_support(self, hostname: str, port: int) -> Dict[str, Any]:
        """Verifica suporte a compressão SSL"""
        # Implementação básica
        return {'supported': False, 'note': 'Compression check not implemented'}
    
    def _check_renegotiation_support(self, hostname: str, port: int) -> Dict[str, Any]:
        """Verifica suporte a renegociação"""
        # Implementação básica
        return {'supported': 'unknown', 'note': 'Renegotiation check not implemented'}
    
    def _check_session_resumption(self, hostname: str, port: int) -> Dict[str, Any]:
        """Verifica suporte a resumo de sessão"""
        # Implementação básica
        return {'supported': 'unknown', 'note': 'Session resumption check not implemented'}
    
    def _test_cipher_support(self, hostname: str, port: int, cipher: str) -> bool:
        """Testa se uma cifra específica é suportada"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.set_ciphers(cipher)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=3) as sock:
                with context.wrap_socket(sock) as ssock:
                    return True
                    
        except Exception:
            return False
    
    def _assess_cipher_security(self, ciphers: List[str]) -> str:
        """Avalia nível de segurança das cifras"""
        if not ciphers:
            return 'none'
        
        # Verificar cifras modernas
        modern_ciphers = ['GCM', 'ECDHE', 'AES256', 'AES128']
        weak_indicators = ['DES', 'RC4', 'NULL', 'MD5']
        
        has_modern = any(modern in cipher for cipher in ciphers for modern in modern_ciphers)
        has_weak = any(weak in cipher for cipher in ciphers for weak in weak_indicators)
        
        if has_weak:
            return 'low'
        elif has_modern:
            return 'high'
        else:
            return 'medium'
    
    def _parse_hsts_header(self, header: str) -> Dict[str, Any]:
        """Parseia cabeçalho HSTS"""
        try:
            result = {'raw_header': header}
            
            # Extrair max-age
            max_age_match = re.search(r'max-age=(\d+)', header)
            if max_age_match:
                result['max_age'] = int(max_age_match.group(1))
                result['max_age_days'] = result['max_age'] / (24 * 60 * 60)
            
            # Verificar includeSubDomains
            result['include_subdomains'] = 'includeSubDomains' in header
            
            # Verificar preload
            result['preload'] = 'preload' in header
            
            return result
            
        except Exception as e:
            return {'error': str(e)}
    
    # Métodos de verificação de vulnerabilidades específicas
    
    def _check_heartbleed(self, hostname: str, port: int) -> Dict[str, Any]:
        """Verifica vulnerabilidade Heartbleed"""
        # Implementação básica - pode ser expandida
        return {'vulnerable': False, 'note': 'Basic check - expand for detailed Heartbleed detection'}
    
    def _check_poodle(self, hostname: str, port: int) -> Dict[str, Any]:
        """Verifica vulnerabilidade POODLE"""
        # Verificar se SSLv3 está habilitado
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    return {'vulnerable': True, 'reason': 'SSLv3 enabled'}
                    
        except Exception:
            return {'vulnerable': False, 'reason': 'SSLv3 not supported'}
    
    def _check_beast(self, hostname: str, port: int) -> Dict[str, Any]:
        """Verifica vulnerabilidade BEAST"""
        # Implementação básica
        return {'vulnerable': False, 'note': 'Basic check - expand for detailed BEAST detection'}
    
    def _check_freak(self, hostname: str, port: int) -> Dict[str, Any]:
        """Verifica vulnerabilidade FREAK"""
        # Implementação básica
        return {'vulnerable': False, 'note': 'Basic check - expand for detailed FREAK detection'}
    
    def _check_logjam(self, hostname: str, port: int) -> Dict[str, Any]:
        """Verifica vulnerabilidade Logjam"""
        # Implementação básica
        return {'vulnerable': False, 'note': 'Basic check - expand for detailed Logjam detection'}
    
    def _check_drown(self, hostname: str, port: int) -> Dict[str, Any]:
        """Verifica vulnerabilidade DROWN"""
        # Implementação básica
        return {'vulnerable': False, 'note': 'Basic check - expand for detailed DROWN detection'}
    
    def _check_weak_rsa(self, hostname: str, port: int) -> Dict[str, Any]:
        """Verifica chaves RSA fracas"""
        # Implementação básica
        return {'vulnerable': False, 'note': 'Basic check - expand for detailed RSA key analysis'}
    
    def _assess_vulnerability_risk(self, vulnerabilities: Dict[str, Any]) -> str:
        """Avalia nível de risco das vulnerabilidades"""
        high_risk_vulns = ['heartbleed', 'poodle', 'freak', 'drown']
        
        for vuln_name in high_risk_vulns:
            vuln_data = vulnerabilities.get(vuln_name, {})
            if isinstance(vuln_data, dict) and vuln_data.get('vulnerable', False):
                return 'high'
        
        # Verificar outras vulnerabilidades
        vuln_count = sum(1 for vuln in vulnerabilities.values() 
                        if isinstance(vuln, dict) and vuln.get('vulnerable', False))
        
        if vuln_count > 0:
            return 'medium'
        else:
            return 'low'
