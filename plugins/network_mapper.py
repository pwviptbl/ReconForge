"""
Plugin de Mapeamento de Rede
Mapeia topologia de rede e infraestrutura de conectividade
"""

import socket
import subprocess
import time
import threading
import ipaddress
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor
import json
import re

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult
from core.config import get_config


class NetworkMapperPlugin(NetworkPlugin):
    """Plugin para mapeamento de topologia de rede"""
    
    def __init__(self):
        super().__init__()
        self.description = "Mapeamento de topologia e infraestrutura de rede"
        self.version = "1.0.0"
        self.supported_targets = ["ip", "domain", "cidr"]
        
        # Configurações padrão
        self.max_hops = 30
        self.timeout = 5
        self.parallel_threads = 10
        
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa mapeamento de rede"""
        start_time = time.time()
        
        try:
            # Ler configurações do YAML
            self.max_hops = get_config('plugins.config.NetworkMapperPlugin.max_hops', 30)
            self.timeout = get_config('plugins.config.NetworkMapperPlugin.timeout', 5)
            self.parallel_threads = get_config('plugins.config.NetworkMapperPlugin.parallel_threads', 10)
            enable_traceroute = get_config('plugins.config.NetworkMapperPlugin.enable_traceroute', True)
            enable_host_discovery = get_config('plugins.config.NetworkMapperPlugin.enable_host_discovery', True)
            enable_topology_mapping = get_config('plugins.config.NetworkMapperPlugin.enable_topology_mapping', True)
            
            results = {
                'target': target,
                'target_type': self._detect_target_type(target)
            }
            
            # Resolver target para IP se necessário
            target_ip = self._resolve_target(target)
            if not target_ip:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error=f"Não foi possível resolver: {target}"
                )
            
            results['target_ip'] = target_ip
            hosts = []
            
            # Traceroute para mapear rota
            if enable_traceroute:
                results['traceroute'] = self._perform_traceroute(target_ip)
                
            # Host discovery se for CIDR
            if enable_host_discovery and self._is_cidr(target):
                discovered_hosts = self._discover_hosts_in_network(target)
                results['host_discovery'] = discovered_hosts
                hosts.extend([h['ip'] for h in discovered_hosts if h.get('ip')])
            else:
                hosts.append(target_ip)
                
            # Mapeamento de topologia
            if enable_topology_mapping:
                results['topology'] = self._map_network_topology(target_ip)
                results['infrastructure'] = self._discover_infrastructure(target_ip)
                
            # Análise de conectividade
            results['connectivity'] = self._analyze_connectivity(target_ip)
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    **results,
                    'hosts': list(set(hosts))  # Remove duplicatas
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
        """Valida se o target é adequado para mapeamento de rede"""
        try:
            # IP válido
            socket.inet_aton(target.split('/')[0])
            return True
        except socket.error:
            try:
                # Hostname válido
                socket.gethostbyname(target)
                return True
            except socket.error:
                # CIDR válido
                try:
                    ipaddress.ip_network(target, strict=False)
                    return True
                except:
                    return False
    
    def _detect_target_type(self, target: str) -> str:
        """Detecta o tipo de target"""
        try:
            if '/' in target:
                ipaddress.ip_network(target, strict=False)
                return "cidr"
            
            ip = ipaddress.ip_address(target)
            if ip.is_private:
                return "internal_ip"
            else:
                return "external_ip"
        except:
            return "domain"
    
    def _resolve_target(self, target: str) -> Optional[str]:
        """Resolve target para IP"""
        try:
            # Se já é IP, retornar
            socket.inet_aton(target.split('/')[0])
            return target.split('/')[0]
        except socket.error:
            try:
                # Tentar resolver hostname
                return socket.gethostbyname(target)
            except socket.error:
                return None
    
    def _is_cidr(self, target: str) -> bool:
        """Verifica se é notação CIDR"""
        try:
            ipaddress.ip_network(target, strict=False)
            return '/' in target
        except:
            return False
    
    def _perform_traceroute(self, target_ip: str) -> Dict[str, Any]:
        """Executa traceroute para mapear rota"""
        try:
            # Tentar usar traceroute do sistema
            result = subprocess.run(
                ['traceroute', '-m', str(self.max_hops), '-w', str(self.timeout), target_ip],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                hops = self._parse_traceroute_output(result.stdout)
                return {
                    'success': True,
                    'hops': hops,
                    'total_hops': len(hops),
                    'target_reached': any(hop.get('ip') == target_ip for hop in hops)
                }
            else:
                # Fallback para traceroute Python
                return self._python_traceroute(target_ip)
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Traceroute timeout'}
        except FileNotFoundError:
            # traceroute não disponível, usar fallback
            return self._python_traceroute(target_ip)
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _parse_traceroute_output(self, output: str) -> List[Dict[str, Any]]:
        """Parseia output do traceroute"""
        hops = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Pular primeira linha
            if not line.strip():
                continue
                
            # Regex para parsear linha do traceroute
            hop_match = re.match(r'\s*(\d+)\s+(.+)', line)
            if hop_match:
                hop_num = int(hop_match.group(1))
                hop_data = hop_match.group(2)
                
                # Extrair IP se presente
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', hop_data)
                ip = ip_match.group(1) if ip_match else None
                
                # Extrair hostname se presente
                hostname_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', hop_data)
                hostname = hostname_match.group(1) if hostname_match else None
                
                # Extrair latência
                latency_matches = re.findall(r'(\d+(?:\.\d+)?)\s*ms', hop_data)
                latencies = [float(lat) for lat in latency_matches]
                avg_latency = sum(latencies) / len(latencies) if latencies else None
                
                hops.append({
                    'hop': hop_num,
                    'ip': ip,
                    'hostname': hostname,
                    'latency_ms': avg_latency,
                    'raw_data': hop_data.strip()
                })
        
        return hops
    
    def _python_traceroute(self, target_ip: str) -> Dict[str, Any]:
        """Implementação Python simples de traceroute"""
        try:
            hops = []
            
            for ttl in range(1, self.max_hops + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                sock.settimeout(self.timeout)
                
                try:
                    start_time = time.time()
                    sock.sendto(b'', (target_ip, 33434))
                    data, addr = sock.recvfrom(512)
                    end_time = time.time()
                    
                    latency = (end_time - start_time) * 1000  # ms
                    
                    hops.append({
                        'hop': ttl,
                        'ip': addr[0],
                        'hostname': None,
                        'latency_ms': latency
                    })
                    
                    # Se chegou ao destino
                    if addr[0] == target_ip:
                        break
                        
                except socket.timeout:
                    hops.append({
                        'hop': ttl,
                        'ip': None,
                        'hostname': None,
                        'latency_ms': None,
                        'timeout': True
                    })
                except Exception:
                    pass
                finally:
                    sock.close()
            
            return {
                'success': True,
                'hops': hops,
                'total_hops': len(hops),
                'method': 'python_fallback'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _discover_hosts_in_network(self, cidr: str) -> List[Dict[str, Any]]:
        """Descobre hosts ativos em uma rede CIDR"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            # Limitar a 254 hosts para evitar scans muito longos
            hosts_to_scan = list(network.hosts())[:254]
            
            active_hosts = []
            lock = threading.Lock()
            
            def ping_host(ip_obj):
                ip_str = str(ip_obj)
                if self._ping_host(ip_str):
                    host_info = {
                        'ip': ip_str,
                        'status': 'active',
                        'method': 'ping'
                    }
                    
                    # Tentar reverse DNS
                    try:
                        hostname = socket.gethostbyaddr(ip_str)[0]
                        host_info['hostname'] = hostname
                    except:
                        host_info['hostname'] = None
                    
                    with lock:
                        active_hosts.append(host_info)
            
            # Usar ThreadPoolExecutor para ping concorrente
            with ThreadPoolExecutor(max_workers=self.parallel_threads) as executor:
                executor.map(ping_host, hosts_to_scan)
            
            return sorted(active_hosts, key=lambda x: ipaddress.ip_address(x['ip']))
            
        except Exception as e:
            return [{'error': str(e)}]
    
    def _ping_host(self, ip: str) -> bool:
        """Verifica se host responde a ping"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(self.timeout), ip],
                capture_output=True,
                timeout=self.timeout + 2
            )
            return result.returncode == 0
        except:
            return False
    
    def _map_network_topology(self, target_ip: str) -> Dict[str, Any]:
        """Mapeia topologia básica da rede"""
        try:
            topology = {
                'default_gateway': self._get_default_gateway(),
                'local_network': self._get_local_network_info(),
                'dns_servers': self._get_dns_servers(),
                'network_interfaces': self._get_network_interfaces()
            }
            
            return topology
            
        except Exception as e:
            return {'error': str(e)}
    
    def _discover_infrastructure(self, target_ip: str) -> Dict[str, Any]:
        """Descobre infraestrutura de rede"""
        try:
            infrastructure = {
                'target_analysis': self._analyze_target_infrastructure(target_ip),
                'network_devices': self._identify_network_devices(target_ip),
                'services_detected': self._detect_network_services(target_ip)
            }
            
            return infrastructure
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_connectivity(self, target_ip: str) -> Dict[str, Any]:
        """Analisa conectividade com o target"""
        try:
            connectivity = {
                'reachability': self._test_reachability(target_ip),
                'mtu_discovery': self._discover_mtu(target_ip),
                'packet_loss': self._measure_packet_loss(target_ip)
            }
            
            return connectivity
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_default_gateway(self) -> Optional[str]:
        """Obtém gateway padrão"""
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'default via' in line:
                        parts = line.split()
                        return parts[2]  # IP do gateway
        except:
            pass
        return None
    
    def _get_local_network_info(self) -> Dict[str, Any]:
        """Obtém informações da rede local"""
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            if result.returncode == 0:
                networks = []
                for line in result.stdout.strip().split('\n'):
                    if '/' in line and 'dev' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            networks.append({
                                'network': parts[0],
                                'interface': parts[2] if 'dev' in parts[1:] else None
                            })
                return {'networks': networks}
        except:
            pass
        return {}
    
    def _get_dns_servers(self) -> List[str]:
        """Obtém servidores DNS configurados"""
        try:
            with open('/etc/resolv.conf', 'r') as f:
                dns_servers = []
                for line in f:
                    if line.startswith('nameserver'):
                        dns_servers.append(line.split()[1])
                return dns_servers
        except:
            return []
    
    def _get_network_interfaces(self) -> List[Dict[str, Any]]:
        """Obtém interfaces de rede"""
        try:
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                interfaces = []
                current_iface = None
                
                for line in result.stdout.split('\n'):
                    if ': ' in line and 'inet' not in line:
                        # Nova interface
                        parts = line.split(': ')
                        if len(parts) >= 2:
                            current_iface = {
                                'name': parts[1].split('@')[0],
                                'state': 'UP' if 'state UP' in line else 'DOWN',
                                'ips': []
                            }
                            interfaces.append(current_iface)
                    elif 'inet ' in line and current_iface:
                        # IP da interface
                        inet_match = re.search(r'inet (\S+)', line)
                        if inet_match:
                            current_iface['ips'].append(inet_match.group(1))
                
                return interfaces
        except:
            pass
        return []
    
    def _analyze_target_infrastructure(self, target_ip: str) -> Dict[str, Any]:
        """Analisa infraestrutura do target"""
        # Análise básica - pode ser expandida
        return {
            'ip_type': 'private' if ipaddress.ip_address(target_ip).is_private else 'public',
            'ip_version': ipaddress.ip_address(target_ip).version
        }
    
    def _identify_network_devices(self, target_ip: str) -> List[Dict[str, Any]]:
        """Identifica dispositivos de rede"""
        # Implementação básica - pode ser expandida com fingerprinting
        return []
    
    def _detect_network_services(self, target_ip: str) -> List[Dict[str, Any]]:
        """Detecta serviços de rede"""
        # Implementação básica - pode ser integrada com outros plugins
        return []
    
    def _test_reachability(self, target_ip: str) -> Dict[str, Any]:
        """Testa alcançabilidade do target"""
        try:
            # Teste de ping
            ping_result = self._ping_host(target_ip)
            
            # Teste de conectividade TCP básica
            tcp_ports = [80, 443, 22, 21, 25, 53]
            open_ports = []
            
            for port in tcp_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            
            return {
                'ping': ping_result,
                'tcp_connectivity': len(open_ports) > 0,
                'open_ports': open_ports
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _discover_mtu(self, target_ip: str) -> Dict[str, Any]:
        """Descobre MTU do caminho"""
        try:
            result = subprocess.run(
                ['ping', '-M', 'do', '-s', '1472', '-c', '1', target_ip],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                return {'mtu': 1500, 'method': 'ping_test'}
            else:
                return {'mtu': 'unknown', 'method': 'ping_test_failed'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _measure_packet_loss(self, target_ip: str) -> Dict[str, Any]:
        """Mede perda de pacotes"""
        try:
            result = subprocess.run(
                ['ping', '-c', '10', '-i', '0.2', target_ip],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                # Extrair estatísticas de perda
                output = result.stdout
                loss_match = re.search(r'(\d+)% packet loss', output)
                if loss_match:
                    packet_loss = int(loss_match.group(1))
                    return {
                        'packet_loss_percent': packet_loss,
                        'packets_sent': 10,
                        'method': 'ping_statistics'
                    }
            
            return {'packet_loss_percent': 'unknown'}
            
        except Exception as e:
            return {'error': str(e)}
