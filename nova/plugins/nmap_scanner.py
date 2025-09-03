"""
Plugin de varredura Nmap
Utiliza o Nmap para varreduras completas de rede e detecção de serviços
"""

import subprocess
import json
import xml.etree.ElementTree as ET
import tempfile
import time
from typing import Dict, Any, List
from pathlib import Path

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult


class NmapScannerPlugin(NetworkPlugin):
    """Plugin para varreduras Nmap avançadas"""
    
    def __init__(self):
        super().__init__()
        self.description = "Varredura Nmap completa com detecção de serviços e scripts NSE"
        self.version = "1.0.0"
        self.requirements = ["nmap"]
        self.supported_targets = ["ip", "cidr", "domain"]
    
    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa varredura Nmap"""
        start_time = time.time()
        
        try:
            # Verificar se nmap está disponível
            if not self._check_nmap_available():
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error="Nmap não está instalado ou não está no PATH"
                )
            
            # Determinar tipo de varredura baseado no contexto
            scan_type = self._determine_scan_type(target, context)
            
            # Executar varredura
            nmap_results = self._run_nmap_scan(target, scan_type)
            
            # Processar resultados
            processed_results = self._process_nmap_results(nmap_results, target)
            
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
        """Valida se é um alvo válido para Nmap"""
        # Aceita IPs, CIDRs e domínios
        return len(target.strip()) > 0
    
    def _check_nmap_available(self) -> bool:
        """Verifica se Nmap está disponível"""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _determine_scan_type(self, target: str, context: Dict[str, Any]) -> str:
        """Determina o tipo de varredura baseado no contexto"""
        # Se já conhecemos portas abertas, fazer varredura de serviços
        if context.get('discoveries', {}).get('open_ports'):
            return 'service_detection'
        
        # Se é uma rede, fazer descoberta de hosts
        if '/' in target:
            return 'host_discovery'
        
        # Varredura padrão
        return 'standard'
    
    def _run_nmap_scan(self, target: str, scan_type: str) -> Dict[str, Any]:
        """Executa varredura Nmap específica"""
        # Definir comando baseado no tipo
        base_cmd = ['nmap']
        
        if scan_type == 'host_discovery':
            cmd = base_cmd + ['-sn', '-T4', target]
            timeout = 180
        elif scan_type == 'service_detection':
            cmd = base_cmd + ['-sV', '-sC', '-T4', '--top-ports', '1000', target]
            timeout = 300
        else:  # standard
            cmd = base_cmd + ['-sS', '-sV', '-T4', '--top-ports', '100', target]
            timeout = 120
        
        # Adicionar output XML
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            xml_file = f.name
        
        cmd.extend(['-oX', xml_file])
        
        try:
            # Executar comando
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Ler resultado XML
            if Path(xml_file).exists():
                with open(xml_file, 'r') as f:
                    xml_content = f.read()
                
                # Limpar arquivo temporário
                Path(xml_file).unlink(missing_ok=True)
                
                return {
                    'returncode': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'xml_content': xml_content,
                    'scan_type': scan_type
                }
            else:
                return {
                    'returncode': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'xml_content': None,
                    'scan_type': scan_type
                }
                
        except subprocess.TimeoutExpired:
            Path(xml_file).unlink(missing_ok=True)
            raise Exception(f"Nmap timeout após {timeout} segundos")
        except Exception as e:
            Path(xml_file).unlink(missing_ok=True)
            raise e
    
    def _process_nmap_results(self, nmap_results: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Processa resultados do Nmap"""
        processed = {
            'target': target,
            'scan_type': nmap_results.get('scan_type', 'unknown'),
            'hosts': [],
            'open_ports': [],
            'services': [],
            'scripts_output': [],
            'raw_output': nmap_results.get('stdout', ''),
            'errors': nmap_results.get('stderr', '')
        }
        
        # Processar XML se disponível
        xml_content = nmap_results.get('xml_content')
        if xml_content:
            try:
                root = ET.fromstring(xml_content)
                
                # Processar hosts
                for host in root.findall('host'):
                    host_info = self._process_host(host)
                    if host_info:
                        processed['hosts'].append(host_info)
                        
                        # Adicionar portas abertas
                        for port_info in host_info.get('ports', []):
                            if port_info.get('state') == 'open':
                                processed['open_ports'].append(port_info['port'])
                                processed['services'].append({
                                    'host': host_info['ip'],
                                    'port': port_info['port'],
                                    'protocol': port_info.get('protocol', 'tcp'),
                                    'service': port_info.get('service', 'unknown'),
                                    'version': port_info.get('version', ''),
                                    'product': port_info.get('product', '')
                                })
                
            except ET.ParseError as e:
                processed['xml_parse_error'] = str(e)
        
        return processed
    
    def _process_host(self, host_element) -> Dict[str, Any]:
        """Processa elemento host do XML"""
        host_info = {
            'ip': None,
            'hostnames': [],
            'status': 'unknown',
            'ports': []
        }
        
        # IP do host
        address = host_element.find('address[@addrtype="ipv4"]')
        if address is not None:
            host_info['ip'] = address.get('addr')
        
        # Status do host
        status = host_element.find('status')
        if status is not None:
            host_info['status'] = status.get('state', 'unknown')
        
        # Hostnames
        hostnames = host_element.find('hostnames')
        if hostnames is not None:
            for hostname in hostnames.findall('hostname'):
                host_info['hostnames'].append(hostname.get('name'))
        
        # Portas
        ports = host_element.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_info = self._process_port(port)
                if port_info:
                    host_info['ports'].append(port_info)
        
        return host_info if host_info['ip'] else None
    
    def _process_port(self, port_element) -> Dict[str, Any]:
        """Processa elemento port do XML"""
        port_info = {
            'port': int(port_element.get('portid')),
            'protocol': port_element.get('protocol'),
            'state': 'unknown',
            'service': 'unknown',
            'version': '',
            'product': '',
            'scripts': []
        }
        
        # Estado da porta
        state = port_element.find('state')
        if state is not None:
            port_info['state'] = state.get('state')
        
        # Informações do serviço
        service = port_element.find('service')
        if service is not None:
            port_info['service'] = service.get('name', 'unknown')
            port_info['version'] = service.get('version', '')
            port_info['product'] = service.get('product', '')
        
        # Scripts NSE
        for script in port_element.findall('script'):
            script_info = {
                'id': script.get('id'),
                'output': script.get('output', '')
            }
            port_info['scripts'].append(script_info)
        
        return port_info
