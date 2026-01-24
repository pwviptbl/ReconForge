"""
Plugin de Scanner de Portas
Baseado no scanner_portas_python.py do projeto original
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List
import ipaddress

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult
from core.config import get_config


class PortScannerPlugin(NetworkPlugin):
    """Plugin para scanning de portas TCP"""
    
    def __init__(self):
        super().__init__()
        self.description = "Scanner de portas TCP eficiente"
        self.version = "1.0.0"
        
        # Configurações
        self.timeout = 1.0
        self.max_workers = 100
        
        # Portas comuns para scan rápido
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
            993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 
            8000, 8080, 8096, 8443, 8085, 8090
        ]
        
        # Serviços conhecidos
        self.known_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 
            8000: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8096: 'Jellyfin/Media', 8443: 'HTTPS-Alt'
        }
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa scanning de portas"""
        start_time = time.time()
        
        try:
            # Ler configurações do YAML
            common_ports_only = get_config('plugins.config.PortScannerPlugin.common_ports_only', False)
            max_ports = get_config('plugins.config.PortScannerPlugin.max_ports', 1024)
            default_scan_type = get_config('plugins.config.PortScannerPlugin.scan_type', 'full')
            self.timeout = float(get_config('plugins.config.PortScannerPlugin.timeout', self.timeout))
            self.max_workers = int(get_config('plugins.config.PortScannerPlugin.max_threads', self.max_workers))
            
            # Determinar tipo de scan baseado na configuração
            if common_ports_only:
                scan_type = kwargs.get('scan_type', 'quick')
            else:
                scan_type = kwargs.get('scan_type', default_scan_type)
            
            # Determinar portas a escanear
            if scan_type == 'quick':
                ports = self.common_ports
            elif scan_type == 'full':
                ports = list(range(1, 1024))  # Well-known ports
            elif scan_type == 'extended':
                ports = list(range(1, max_ports + 1))  # Extended range based on config
            else:
                ports = kwargs.get('ports', self.common_ports)
            
            # Resolver target para IP(s)
            target_ips = self._resolve_targets(target)
            if not target_ips:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error=f"Não foi possível resolver: {target}"
                )
            
            # Executar scan por IP
            open_ports = []
            services = []
            hosts_with_open_ports = set()
            for ip in target_ips:
                ip_open_ports = self._scan_ports(ip, ports)
                if ip_open_ports:
                    hosts_with_open_ports.add(ip)
                open_ports.extend(ip_open_ports)
                for port in ip_open_ports:
                    service_name = self.known_services.get(port, 'unknown')
                    services.append({
                        'port': port,
                        'service': service_name,
                        'host': ip
                    })
            open_ports = sorted(set(open_ports))
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    'target': target,
                    'target_ip': target_ips[0],
                    'target_ips': target_ips,
                    'scan_type': scan_type,
                    'total_ports_scanned': len(ports),
                    'open_ports': open_ports,
                    'services': services,
                    'hosts': sorted(hosts_with_open_ports)
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
        """Valida se o target é adequado para port scanning"""
        try:
            # Tentar resolver como IP
            socket.inet_aton(target)
            return True
        except socket.error:
            try:
                # Tentar resolver como hostname
                socket.gethostbyname(target)
                return True
            except socket.error:
                # Verificar se é CIDR
                try:
                    ipaddress.ip_network(target, strict=False)
                    return True
                except:
                    return False
    
    def _resolve_targets(self, target: str) -> List[str]:
        """Resolve target para um ou mais IPs"""
        try:
            # Se já é IP, retornar
            socket.inet_aton(target)
            return [target]
        except socket.error:
            try:
                # Resolver hostname para todos os IPs
                _, _, ips = socket.gethostbyname_ex(target)
                return sorted(set(ips))
            except socket.error:
                return []
    
    def _scan_ports(self, ip: str, ports: List[int]) -> List[int]:
        """Escaneia portas usando múltiplas threads"""
        open_ports = []
        lock = threading.Lock()
        
        def scan_port(port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    with lock:
                        open_ports.append(port)
                
                sock.close()
            except:
                pass
        
        # Usar ThreadPoolExecutor para controlar concorrência
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(scan_port, ports)
        
        return sorted(open_ports)
