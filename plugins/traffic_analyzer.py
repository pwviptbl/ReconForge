"""
Plugin de Análise de Tráfego
Analisa padrões de tráfego de rede e detecta anomalias
"""

import time
import socket
import subprocess
import json
import re
from typing import Dict, Any, List, Optional
import threading
from collections import defaultdict, Counter
import statistics

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult
from core.config import get_config


class TrafficAnalyzerPlugin(NetworkPlugin):
    """Plugin para análise de tráfego de rede"""
    
    def __init__(self):
        super().__init__()
        self.description = "Análise de padrões de tráfego de rede e detecção de anomalias"
        self.version = "1.0.0"
        self.supported_targets = ["ip", "domain", "url"]
        
        # Configurações padrão
        self.capture_duration = 60
        self.analysis_window = 300
        self.anomaly_threshold = 2.5
        
        # Dados coletados
        self.traffic_data = []
        self.connection_stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.packet_sizes = []
        self.response_times = []
        
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa análise de tráfego"""
        start_time = time.time()
        
        try:
            # Ler configurações do YAML
            self.capture_duration = get_config('plugins.config.TrafficAnalyzerPlugin.capture_duration', 60)
            self.analysis_window = get_config('plugins.config.TrafficAnalyzerPlugin.analysis_window', 300)
            self.anomaly_threshold = get_config('plugins.config.TrafficAnalyzerPlugin.anomaly_threshold', 2.5)
            protocol_analysis = get_config('plugins.config.TrafficAnalyzerPlugin.protocol_analysis', True)
            bandwidth_measurement = get_config('plugins.config.TrafficAnalyzerPlugin.bandwidth_measurement', True)
            
            # Preparar target
            hostname, port = self._parse_target(target)
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
                'analysis_duration': self.capture_duration
            }
            
            hosts = []
            
            # Análise de conectividade básica
            results['connectivity_analysis'] = self._analyze_basic_connectivity(hostname, port)
            
            # Análise de protocolos se habilitada
            if protocol_analysis:
                results['protocol_analysis'] = self._analyze_protocols(hostname, port)
            
            # Medição de bandwidth se habilitada
            if bandwidth_measurement:
                results['bandwidth_analysis'] = self._analyze_bandwidth(hostname, port)
            
            # Análise de padrões de resposta
            results['response_patterns'] = self._analyze_response_patterns(hostname, port)
            
            # Detecção de anomalias
            results['anomaly_detection'] = self._detect_anomalies()
            
            # Análise de latência
            results['latency_analysis'] = self._analyze_latency(hostname, port)
            
            # Monitoramento de conexões
            results['connection_monitoring'] = self._monitor_connections(hostname, port)
            
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
        """Valida se o target é adequado para análise de tráfego"""
        hostname, port = self._parse_target(target)
        return hostname is not None
    
    def _parse_target(self, target: str) -> tuple[Optional[str], Optional[int]]:
        """Parseia target para extrair hostname e porta"""
        try:
            # URL completa
            if target.startswith(('http://', 'https://')):
                import urllib.parse
                parsed = urllib.parse.urlparse(target)
                hostname = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                return hostname, port
            
            # hostname:porta
            if ':' in target and not target.count(':') > 1:  # Evitar IPv6
                parts = target.split(':')
                if len(parts) == 2:
                    try:
                        port = int(parts[1])
                        return parts[0], port
                    except ValueError:
                        pass
            
            # Hostname simples - assumir porta 80
            if '.' in target:
                return target, 80
            
            # IP - assumir porta 80
            try:
                socket.inet_aton(target)
                return target, 80
            except:
                pass
            
            return None, None
            
        except Exception:
            return None, None
    
    def _analyze_basic_connectivity(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analisa conectividade básica com o target"""
        try:
            connectivity_tests = []
            
            # Teste de múltiplas conexões TCP
            for i in range(5):
                start_time = time.time()
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    
                    result = sock.connect_ex((hostname, port))
                    connect_time = time.time() - start_time
                    
                    if result == 0:
                        # Conexão bem-sucedida
                        connectivity_tests.append({
                            'test_num': i + 1,
                            'success': True,
                            'connect_time': connect_time,
                            'error': None
                        })
                    else:
                        connectivity_tests.append({
                            'test_num': i + 1,
                            'success': False,
                            'connect_time': connect_time,
                            'error': f'Connection failed with code {result}'
                        })
                    
                    sock.close()
                    
                except Exception as e:
                    connectivity_tests.append({
                        'test_num': i + 1,
                        'success': False,
                        'connect_time': time.time() - start_time,
                        'error': str(e)
                    })
                
                # Pequeno delay entre testes
                time.sleep(1)
            
            # Calcular estatísticas
            successful_tests = [t for t in connectivity_tests if t['success']]
            success_rate = len(successful_tests) / len(connectivity_tests)
            
            if successful_tests:
                connect_times = [t['connect_time'] for t in successful_tests]
                avg_connect_time = statistics.mean(connect_times)
                min_connect_time = min(connect_times)
                max_connect_time = max(connect_times)
            else:
                avg_connect_time = None
                min_connect_time = None
                max_connect_time = None
            
            return {
                'tests_performed': len(connectivity_tests),
                'successful_connections': len(successful_tests),
                'success_rate': success_rate,
                'average_connect_time': avg_connect_time,
                'min_connect_time': min_connect_time,
                'max_connect_time': max_connect_time,
                'detailed_tests': connectivity_tests,
                'connection_stable': success_rate >= 0.8
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_protocols(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analisa protocolos em uso"""
        try:
            protocol_detection = {
                'target_port': port,
                'detected_protocols': [],
                'service_detection': {}
            }
            
            # Detecção de protocolo baseada na porta
            common_protocols = {
                21: 'FTP',
                22: 'SSH',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                445: 'SMB',
                993: 'IMAPS',
                995: 'POP3S',
                3306: 'MySQL',
                3389: 'RDP',
                5432: 'PostgreSQL',
                6379: 'Redis'
            }
            
            expected_protocol = common_protocols.get(port, 'Unknown')
            protocol_detection['expected_protocol'] = expected_protocol
            
            # Teste de banner grabbing para identificar serviço
            banner_info = self._grab_service_banner(hostname, port)
            if banner_info:
                protocol_detection['service_detection'] = banner_info
                
                # Tentar identificar protocolo pelo banner
                banner_text = banner_info.get('banner', '').lower()
                
                if 'http' in banner_text or 'server:' in banner_text:
                    protocol_detection['detected_protocols'].append('HTTP')
                elif 'ssh' in banner_text:
                    protocol_detection['detected_protocols'].append('SSH')
                elif 'ftp' in banner_text:
                    protocol_detection['detected_protocols'].append('FTP')
                elif 'smtp' in banner_text:
                    protocol_detection['detected_protocols'].append('SMTP')
            
            # Teste específico para HTTP/HTTPS
            if port in [80, 443, 8080, 8443]:
                http_analysis = self._analyze_http_traffic(hostname, port)
                protocol_detection['http_analysis'] = http_analysis
                
                if http_analysis.get('is_http'):
                    protocol_detection['detected_protocols'].append('HTTP/HTTPS')
            
            return protocol_detection
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_bandwidth(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analisa bandwidth e throughput"""
        try:
            bandwidth_tests = []
            
            # Teste de download simples (para HTTP/HTTPS)
            if port in [80, 443, 8080, 8443]:
                download_test = self._test_download_speed(hostname, port)
                if download_test:
                    bandwidth_tests.append(download_test)
            
            # Teste de upload simples (simulado)
            upload_test = self._test_upload_speed(hostname, port)
            if upload_test:
                bandwidth_tests.append(upload_test)
            
            # Teste de throughput de conexão TCP
            tcp_throughput = self._test_tcp_throughput(hostname, port)
            
            return {
                'bandwidth_tests': bandwidth_tests,
                'tcp_throughput': tcp_throughput,
                'test_duration': 30,  # segundos
                'analysis': 'Bandwidth analysis based on connection tests'
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_response_patterns(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analisa padrões de resposta do target"""
        try:
            response_data = []
            
            # Fazer múltiplas requisições e medir tempos
            for i in range(10):
                start_time = time.time()
                
                if port in [80, 443, 8080, 8443]:
                    # Teste HTTP
                    response_info = self._make_http_request_timed(hostname, port)
                else:
                    # Teste TCP genérico
                    response_info = self._make_tcp_request_timed(hostname, port)
                
                if response_info:
                    response_data.append(response_info)
                
                # Delay entre requisições
                time.sleep(2)
            
            # Analisar padrões
            if response_data:
                response_times = [r.get('response_time', 0) for r in response_data if r.get('response_time')]
                
                if response_times:
                    pattern_analysis = {
                        'total_requests': len(response_data),
                        'successful_requests': len([r for r in response_data if r.get('success')]),
                        'average_response_time': statistics.mean(response_times),
                        'min_response_time': min(response_times),
                        'max_response_time': max(response_times),
                        'response_time_std': statistics.stdev(response_times) if len(response_times) > 1 else 0,
                        'consistent_responses': statistics.stdev(response_times) < 0.1 if len(response_times) > 1 else True
                    }
                    
                    # Detectar padrões anômalos
                    pattern_analysis['anomalies'] = self._detect_response_anomalies(response_data)
                    
                    return pattern_analysis
            
            return {'error': 'No response data collected'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _detect_anomalies(self) -> Dict[str, Any]:
        """Detecta anomalias nos dados coletados"""
        try:
            anomalies = {
                'detected_anomalies': [],
                'anomaly_score': 0,
                'risk_level': 'low'
            }
            
            # Análise baseada nos response times coletados
            if self.response_times:
                mean_time = statistics.mean(self.response_times)
                std_time = statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0
                
                # Detectar outliers usando z-score
                outliers = []
                for time_val in self.response_times:
                    if std_time > 0:
                        z_score = abs((time_val - mean_time) / std_time)
                        if z_score > self.anomaly_threshold:
                            outliers.append(time_val)
                
                if outliers:
                    anomalies['detected_anomalies'].append({
                        'type': 'response_time_outliers',
                        'count': len(outliers),
                        'values': outliers
                    })
                    anomalies['anomaly_score'] += len(outliers) * 10
            
            # Determinar nível de risco
            if anomalies['anomaly_score'] >= 50:
                anomalies['risk_level'] = 'high'
            elif anomalies['anomaly_score'] >= 20:
                anomalies['risk_level'] = 'medium'
            
            return anomalies
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_latency(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analisa latência de rede"""
        try:
            latency_measurements = []
            
            # Múltiplas medições de latência
            for i in range(10):
                start_time = time.time()
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    
                    result = sock.connect_ex((hostname, port))
                    latency = (time.time() - start_time) * 1000  # ms
                    
                    latency_measurements.append({
                        'measurement': i + 1,
                        'latency_ms': latency,
                        'success': result == 0
                    })
                    
                    sock.close()
                    
                except Exception:
                    latency_measurements.append({
                        'measurement': i + 1,
                        'latency_ms': None,
                        'success': False
                    })
                
                time.sleep(1)
            
            # Calcular estatísticas de latência
            successful_measurements = [m for m in latency_measurements if m['success'] and m['latency_ms']]
            
            if successful_measurements:
                latencies = [m['latency_ms'] for m in successful_measurements]
                
                latency_stats = {
                    'measurements': latency_measurements,
                    'successful_measurements': len(successful_measurements),
                    'average_latency_ms': statistics.mean(latencies),
                    'min_latency_ms': min(latencies),
                    'max_latency_ms': max(latencies),
                    'latency_std_ms': statistics.stdev(latencies) if len(latencies) > 1 else 0,
                    'jitter_ms': max(latencies) - min(latencies),
                    'connection_quality': self._assess_connection_quality(latencies)
                }
                
                return latency_stats
            
            return {'error': 'No successful latency measurements'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _monitor_connections(self, hostname: str, port: int) -> Dict[str, Any]:
        """Monitora estado de conexões"""
        try:
            connection_monitoring = {
                'monitoring_duration': 30,
                'connection_attempts': 0,
                'successful_connections': 0,
                'failed_connections': 0,
                'connection_timeline': []
            }
            
            start_monitoring = time.time()
            
            while time.time() - start_monitoring < 30:  # Monitor por 30 segundos
                attempt_time = time.time()
                connection_monitoring['connection_attempts'] += 1
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    
                    result = sock.connect_ex((hostname, port))
                    
                    if result == 0:
                        connection_monitoring['successful_connections'] += 1
                        status = 'success'
                    else:
                        connection_monitoring['failed_connections'] += 1
                        status = 'failed'
                    
                    sock.close()
                    
                except Exception:
                    connection_monitoring['failed_connections'] += 1
                    status = 'error'
                
                connection_monitoring['connection_timeline'].append({
                    'timestamp': attempt_time,
                    'status': status
                })
                
                time.sleep(5)  # Aguardar 5 segundos entre tentativas
            
            # Calcular estatísticas
            total_attempts = connection_monitoring['connection_attempts']
            if total_attempts > 0:
                success_rate = connection_monitoring['successful_connections'] / total_attempts
                connection_monitoring['success_rate'] = success_rate
                connection_monitoring['stability'] = 'stable' if success_rate >= 0.8 else 'unstable'
            
            return connection_monitoring
            
        except Exception as e:
            return {'error': str(e)}
    
    # Métodos auxiliares
    
    def _grab_service_banner(self, hostname: str, port: int) -> Optional[Dict[str, Any]]:
        """Captura banner do serviço"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            sock.connect((hostname, port))
            
            # Enviar requisição básica ou aguardar banner
            if port == 80:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 21:
                pass  # FTP geralmente envia banner automaticamente
            elif port == 22:
                pass  # SSH envia banner automaticamente
            
            # Receber resposta
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.close()
            
            return {
                'banner': banner.strip(),
                'banner_length': len(banner),
                'port': port
            }
            
        except Exception:
            return None
    
    def _analyze_http_traffic(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analisa tráfego HTTP específico"""
        try:
            import http.client
            
            is_https = port in [443, 8443]
            
            if is_https:
                conn = http.client.HTTPSConnection(hostname, port, timeout=10)
            else:
                conn = http.client.HTTPConnection(hostname, port, timeout=10)
            
            start_time = time.time()
            conn.request("HEAD", "/")
            response = conn.getresponse()
            response_time = time.time() - start_time
            
            # Analisar cabeçalhos
            headers = {}
            for header, value in response.getheaders():
                headers[header.lower()] = value
            
            conn.close()
            
            return {
                'is_http': True,
                'status_code': response.status,
                'response_time': response_time,
                'server': headers.get('server', 'Unknown'),
                'content_type': headers.get('content-type', 'Unknown'),
                'headers_count': len(headers),
                'uses_https': is_https
            }
            
        except Exception:
            return {'is_http': False, 'error': 'HTTP analysis failed'}
    
    def _test_download_speed(self, hostname: str, port: int) -> Optional[Dict[str, Any]]:
        """Testa velocidade de download"""
        try:
            import http.client
            
            is_https = port in [443, 8443]
            
            if is_https:
                conn = http.client.HTTPSConnection(hostname, port, timeout=30)
            else:
                conn = http.client.HTTPConnection(hostname, port, timeout=30)
            
            start_time = time.time()
            conn.request("GET", "/")
            response = conn.getresponse()
            
            # Ler dados
            data = response.read()
            download_time = time.time() - start_time
            
            conn.close()
            
            data_size = len(data)
            speed_bps = data_size / download_time if download_time > 0 else 0
            
            return {
                'test_type': 'download',
                'data_size_bytes': data_size,
                'download_time_seconds': download_time,
                'speed_bps': speed_bps,
                'speed_kbps': speed_bps / 1024
            }
            
        except Exception:
            return None
    
    def _test_upload_speed(self, hostname: str, port: int) -> Optional[Dict[str, Any]]:
        """Testa velocidade de upload (simulado)"""
        # Implementação básica - pode ser expandida
        try:
            test_data = b'A' * 1024  # 1KB de dados de teste
            
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((hostname, port))
            
            # Simular envio de dados
            sock.send(test_data)
            upload_time = time.time() - start_time
            
            sock.close()
            
            speed_bps = len(test_data) / upload_time if upload_time > 0 else 0
            
            return {
                'test_type': 'upload_simulation',
                'data_size_bytes': len(test_data),
                'upload_time_seconds': upload_time,
                'speed_bps': speed_bps,
                'speed_kbps': speed_bps / 1024
            }
            
        except Exception:
            return None
    
    def _test_tcp_throughput(self, hostname: str, port: int) -> Dict[str, Any]:
        """Testa throughput TCP"""
        try:
            throughput_tests = []
            
            for i in range(3):
                start_time = time.time()
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                
                connect_result = sock.connect_ex((hostname, port))
                connect_time = time.time() - start_time
                
                if connect_result == 0:
                    throughput_tests.append({
                        'test': i + 1,
                        'success': True,
                        'connect_time': connect_time
                    })
                else:
                    throughput_tests.append({
                        'test': i + 1,
                        'success': False,
                        'connect_time': connect_time
                    })
                
                sock.close()
                time.sleep(1)
            
            successful_tests = [t for t in throughput_tests if t['success']]
            
            if successful_tests:
                avg_connect_time = statistics.mean([t['connect_time'] for t in successful_tests])
                
                return {
                    'tests_performed': len(throughput_tests),
                    'successful_tests': len(successful_tests),
                    'average_connect_time': avg_connect_time,
                    'throughput_score': 1 / avg_connect_time if avg_connect_time > 0 else 0
                }
            
            return {'error': 'No successful throughput tests'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _make_http_request_timed(self, hostname: str, port: int) -> Optional[Dict[str, Any]]:
        """Faz requisição HTTP cronometrada"""
        try:
            import http.client
            
            is_https = port in [443, 8443]
            
            start_time = time.time()
            
            if is_https:
                conn = http.client.HTTPSConnection(hostname, port, timeout=10)
            else:
                conn = http.client.HTTPConnection(hostname, port, timeout=10)
            
            conn.request("HEAD", "/")
            response = conn.getresponse()
            response_time = time.time() - start_time
            
            # Registrar tempo de resposta
            self.response_times.append(response_time)
            
            conn.close()
            
            return {
                'success': True,
                'response_time': response_time,
                'status_code': response.status,
                'request_type': 'http'
            }
            
        except Exception as e:
            return {
                'success': False,
                'response_time': time.time() - start_time,
                'error': str(e),
                'request_type': 'http'
            }
    
    def _make_tcp_request_timed(self, hostname: str, port: int) -> Optional[Dict[str, Any]]:
        """Faz requisição TCP cronometrada"""
        try:
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            result = sock.connect_ex((hostname, port))
            response_time = time.time() - start_time
            
            # Registrar tempo de resposta
            self.response_times.append(response_time)
            
            sock.close()
            
            return {
                'success': result == 0,
                'response_time': response_time,
                'result_code': result,
                'request_type': 'tcp'
            }
            
        except Exception as e:
            return {
                'success': False,
                'response_time': time.time() - start_time,
                'error': str(e),
                'request_type': 'tcp'
            }
    
    def _detect_response_anomalies(self, response_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detecta anomalias nos padrões de resposta"""
        anomalies = []
        
        try:
            # Analisar códigos de status (para HTTP)
            status_codes = [r.get('status_code') for r in response_data if r.get('status_code')]
            if status_codes:
                status_counter = Counter(status_codes)
                
                # Detectar códigos de status anômalos
                error_codes = [code for code in status_codes if code >= 400]
                if len(error_codes) > len(status_codes) * 0.3:  # Mais de 30% de erros
                    anomalies.append({
                        'type': 'high_error_rate',
                        'error_rate': len(error_codes) / len(status_codes),
                        'details': dict(status_counter)
                    })
            
            # Analisar tempos de resposta
            response_times = [r.get('response_time') for r in response_data if r.get('response_time')]
            if len(response_times) > 1:
                mean_time = statistics.mean(response_times)
                std_time = statistics.stdev(response_times)
                
                # Detectar variação excessiva
                if std_time > mean_time * 0.5:  # Desvio padrão > 50% da média
                    anomalies.append({
                        'type': 'high_response_time_variation',
                        'mean_time': mean_time,
                        'std_deviation': std_time,
                        'coefficient_of_variation': std_time / mean_time
                    })
            
            return anomalies
            
        except Exception:
            return []
    
    def _assess_connection_quality(self, latencies: List[float]) -> str:
        """Avalia qualidade da conexão baseada nas latências"""
        if not latencies:
            return 'unknown'
        
        avg_latency = statistics.mean(latencies)
        jitter = max(latencies) - min(latencies)
        
        if avg_latency < 50 and jitter < 10:
            return 'excellent'
        elif avg_latency < 100 and jitter < 25:
            return 'good'
        elif avg_latency < 200 and jitter < 50:
            return 'fair'
        else:
            return 'poor'
