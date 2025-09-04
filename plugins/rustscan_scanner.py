"""
Plugin Rustscan para varredura rápida de portas
Utiliza Rustscan para descoberta eficiente de portas abertas
"""

import subprocess
import json
import time
from typing import Dict, Any, List
import re

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult
from core.config import get_config


class RustscanPlugin(NetworkPlugin):
    """Plugin para varredura rápida de portas usando Rustscan"""
    
    def __init__(self):
        super().__init__()
        self.description = "Varredura rápida de portas usando Rustscan"
        self.version = "1.0.0"
        self.requirements = ["rustscan"]
        self.supported_targets = ["ip", "domain", "cidr"]
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa varredura Rustscan"""
        start_time = time.time()
        
        try:
            # Verificar se rustscan está disponível
            if not self._check_rustscan_available():
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error="Rustscan não está instalado ou não está no PATH"
                )
            
            # Obter configurações de porta do config YAML
            port_range = get_config('plugins.config.RustscanPlugin.port_range', '1-1000')
            scan_all_ports = get_config('plugins.config.RustscanPlugin.scan_all_ports', False)
            
            # Se scan_all_ports está ativo, usar range completo
            if scan_all_ports:
                port_range = '1-65535'
            
            # Permitir override via kwargs
            port_range = kwargs.get('port_range', port_range)
            scan_all_ports = kwargs.get('scan_all_ports', scan_all_ports)
            
            # Executar varredura
            rustscan_results = self._run_rustscan(target, port_range)
            
            # Processar resultados
            processed_results = self._process_rustscan_results(rustscan_results, target)
            
            execution_time = time.time() - start_time
            
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data=processed_results
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
        """Valida se é um alvo válido para Rustscan"""
        return len(target.strip()) > 0
    
    def _check_rustscan_available(self) -> bool:
        """Verifica se Rustscan está disponível"""
        try:
            result = subprocess.run(
                ['rustscan', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _run_rustscan(self, target: str, port_range: str = '1-65535') -> Dict[str, Any]:
        """Executa varredura Rustscan"""
        try:
            # Comando Rustscan otimizado
            cmd = [
                'rustscan',
                '-a', target,
                '-r', port_range,  # Range de portas configurável
                '--ulimit', '5000',  # Limite de arquivos abertos
                '--timeout', '1000',  # Timeout em ms
                '--tries', '1',  # Número de tentativas
                '--batch-size', '10000',  # Tamanho do batch
                '-g',  # Greppable output
                '--accessible'  # Apenas portas acessíveis
            ]
            
            # Executar comando
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # Timeout de 2 minutos
            )
            
            return {
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'target': target
            }
            
        except subprocess.TimeoutExpired:
            raise Exception("Rustscan timeout após 2 minutos")
        except Exception as e:
            raise e
    
    def _process_rustscan_results(self, rustscan_results: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Processa resultados do Rustscan"""
        processed = {
            'target': target,
            'hosts': [],
            'open_ports': [],
            'services': [],
            'scan_info': {
                'total_hosts_scanned': 0,
                'total_ports_found': 0
            },
            'raw_output': rustscan_results.get('stdout', ''),
            'errors': rustscan_results.get('stderr', '')
        }
        
        stdout = rustscan_results.get('stdout', '')
        
        if rustscan_results.get('returncode') == 0 and stdout:
            # Analisar output do Rustscan
            hosts_ports = self._parse_rustscan_output(stdout)
            
            for host_ip, ports in hosts_ports.items():
                processed['hosts'].append(host_ip)
                
                for port in ports:
                    processed['open_ports'].append(port)
                    
                    # Tentar identificar serviço comum
                    service_name = self._identify_common_service(port)
                    
                    service_info = {
                        'host': host_ip,
                        'port': port,
                        'protocol': 'tcp',  # Rustscan faz TCP por padrão
                        'service': service_name,
                        'state': 'open'
                    }
                    
                    processed['services'].append(service_info)
            
            processed['scan_info']['total_hosts_scanned'] = len(processed['hosts'])
            processed['scan_info']['total_ports_found'] = len(processed['open_ports'])
        
        return processed
    
    def _parse_rustscan_output(self, output: str) -> Dict[str, List[int]]:
        """Analisa output do Rustscan para extrair hosts e portas"""
        hosts_ports = {}
        
        # Padrões comuns de output do Rustscan
        patterns = [
            r'Open\s+(\d+\.\d+\.\d+\.\d+):(\d+)',  # Open IP:PORT
            r'(\d+\.\d+\.\d+\.\d+):(\d+)',  # IP:PORT
            r'(\d+)/tcp\s+open.*?(\d+\.\d+\.\d+\.\d+)',  # PORT/tcp open IP
            r'(\d+\.\d+\.\d+\.\d+)\s*->\s*\[([0-9,]+)\]'  # IP -> [port1,port2,port3]
        ]
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Verificar primeiro o padrão mais específico (IP -> [ports])
            arrow_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s*->\s*\[([0-9,]+)\]', line)
            if arrow_match:
                host_ip = arrow_match.group(1)
                ports_str = arrow_match.group(2)
                try:
                    ports = [int(p.strip()) for p in ports_str.split(',') if p.strip()]
                    hosts_ports[host_ip] = ports
                    continue
                except ValueError:
                    pass
            
            # Tentar outros padrões
            for pattern in patterns[:-1]:  # Excluir o último padrão que já foi testado
                matches = re.finditer(pattern, line)
                for match in matches:
                    if len(match.groups()) == 2:
                        try:
                            # Dependendo do padrão, IP e porta podem estar em ordens diferentes
                            group1, group2 = match.groups()
                            
                            # Verificar qual é IP e qual é porta
                            if '.' in group1 and group1.count('.') == 3:
                                # group1 é IP, group2 é porta
                                host_ip = group1
                                port = int(group2)
                            else:
                                # group1 é porta, group2 é IP
                                port = int(group1)
                                host_ip = group2
                            
                            if host_ip not in hosts_ports:
                                hosts_ports[host_ip] = []
                            
                            if port not in hosts_ports[host_ip]:
                                hosts_ports[host_ip].append(port)
                                
                        except ValueError:
                            continue
        
        # Se não encontrou nada com padrões específicos, tentar abordagem mais simples
        if not hosts_ports:
            # Procurar por números que podem ser portas
            port_pattern = r'\b(\d{1,5})\b'
            ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
            
            ips = re.findall(ip_pattern, output)
            ports = [int(p) for p in re.findall(port_pattern, output) if 1 <= int(p) <= 65535]
            
            # Se encontrou IPs e portas, associá-los
            if ips and ports:
                for ip in set(ips):
                    hosts_ports[ip] = list(set(ports))
        
        return hosts_ports
    
    def _identify_common_service(self, port: int) -> str:
        """Identifica serviços comuns baseado na porta"""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        
        return common_ports.get(port, f'Unknown-{port}')
