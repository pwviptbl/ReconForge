"""
Plugin de varredura Nmap
Utiliza o Nmap para varreduras completas de rede e detecção de serviços
"""

import subprocess
import json
import xml.etree.ElementTree as ET
import tempfile
import time
import re
from typing import Dict, Any, List, Optional
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
        self.version = "1.1.0"
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
            nmap_results = self._run_nmap_scan(target, scan_type, context)
            
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
    
    def _run_nmap_scan(self, target: str, scan_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Executa varredura Nmap específica"""
        # Definir comando baseado no tipo
        base_cmd = ['nmap', '-T4']
        
        if scan_type == 'host_discovery':
            cmd = base_cmd + ['-sn', target]
            timeout = 180
        elif scan_type == 'service_detection':
            # Scan aprofundado com detecção de SO, serviços, scripts padrão e de vulnerabilidade
            cmd = base_cmd + [
                '-sS', '-sU', '-sV', '-O',
                '--script', 'default,vuln'
            ]
            # Otimização: se já conhecemos as portas, escanear apenas elas
            open_ports = context.get('discoveries', {}).get('open_ports')
            if open_ports:
                ports_str = ','.join(map(str, open_ports))
                cmd.extend(['-p', ports_str])
            else:
                cmd.extend(['--top-ports', '1000'])

            cmd.append(target)
            timeout = 1200  # Aumentar timeout para scan aprofundado
        else:  # standard
            cmd = base_cmd + ['-sS', '-sV', '--top-ports', '100', target]
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
            'vulnerabilities': [],
            'raw_output': nmap_results.get('stdout', ''),
            'errors': nmap_results.get('stderr', '')
        }
        seen_vulns = set()
        
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
                        
                        # Adicionar portas abertas e vulnerabilidades
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

                                # Processar scripts de vulnerabilidade
                                for script in port_info.get('scripts', []):
                                    script_id = script.get('id', '')
                                    script_output = script.get('output', '')

                                    if script_id == 'vulners':
                                        for entry in self._parse_vulners_output(script_output):
                                            vuln = self._build_vuln_entry(
                                                host_info['ip'],
                                                port_info['port'],
                                                port_info.get('service', 'unknown'),
                                                entry['id'],
                                                entry.get('score'),
                                                entry.get('url'),
                                                script_id,
                                                entry.get('exploit', False)
                                            )
                                            key = self._vuln_key(vuln)
                                            if key not in seen_vulns:
                                                processed['vulnerabilities'].append(vuln)
                                                seen_vulns.add(key)
                                        continue

                                    if 'vuln' in script_id or 'CVE-' in script_output.upper():
                                        extracted_cves = self._extract_cves_from_output(script_output)
                                        if extracted_cves:
                                            for cve_id in extracted_cves:
                                                vuln = self._build_vuln_entry(
                                                    host_info['ip'],
                                                    port_info['port'],
                                                    port_info.get('service', 'unknown'),
                                                    cve_id,
                                                    None,
                                                    None,
                                                    script_id,
                                                    False
                                                )
                                                key = self._vuln_key(vuln)
                                                if key not in seen_vulns:
                                                    processed['vulnerabilities'].append(vuln)
                                                    seen_vulns.add(key)
                                        else:
                                            vuln = self._build_vuln_entry(
                                                host_info['ip'],
                                                port_info['port'],
                                                port_info.get('service', 'unknown'),
                                                script_id,
                                                None,
                                                None,
                                                script_id,
                                                False,
                                                script_output
                                            )
                                            key = self._vuln_key(vuln)
                                            if key not in seen_vulns:
                                                processed['vulnerabilities'].append(vuln)
                                                seen_vulns.add(key)
                
            except ET.ParseError as e:
                processed['xml_parse_error'] = str(e)
        
        return processed

    def _extract_cves_from_output(self, output: str) -> List[str]:
        """Extrai CVEs de uma string de output"""
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        return sorted(set(re.findall(cve_pattern, output, re.IGNORECASE)))

    def _parse_vulners_output(self, output: str) -> List[Dict[str, Any]]:
        """Extrai entradas do script vulners com score/URL"""
        entries = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith('cpe:/'):
                continue
            match = re.match(r'([A-Za-z0-9:._-]+)\s+([0-9.]+)\s+(https?://\S+)', line)
            if not match:
                continue
            vuln_id, score_str, url = match.groups()
            try:
                score = float(score_str)
            except ValueError:
                score = None
            entries.append({
                'id': vuln_id,
                'score': score,
                'url': url,
                'exploit': '*EXPLOIT*' in line
            })
        return entries

    def _score_to_severity(self, score: Optional[float]) -> str:
        """Converte score em severidade simples"""
        if score is None:
            return 'unknown'
        if score >= 9.0:
            return 'critical'
        if score >= 7.0:
            return 'high'
        if score >= 4.0:
            return 'medium'
        if score > 0:
            return 'low'
        return 'unknown'

    def _build_vuln_entry(
        self,
        host: str,
        port: int,
        service: str,
        vuln_id: str,
        score: Optional[float],
        url: Optional[str],
        source: str,
        exploit: bool,
        output: Optional[str] = None
    ) -> Dict[str, Any]:
        """Padroniza um item de vulnerabilidade"""
        entry = {
            'title': vuln_id,
            'severity': self._score_to_severity(score),
            'cvss': score,
            'url': url,
            'host': host,
            'port': port,
            'service': service,
            'source': source,
            'exploit': exploit
        }
        if vuln_id.upper().startswith('CVE-'):
            entry['cve'] = vuln_id.upper()
        if output:
            entry['description'] = output[:300]
        return entry

    def _vuln_key(self, vuln: Dict[str, Any]) -> str:
        """Gera chave para deduplicacao de vulnerabilidades"""
        return "|".join([
            str(vuln.get('title', '')),
            str(vuln.get('host', '')),
            str(vuln.get('port', ''))
        ])
    
    def _process_host(self, host_element) -> Dict[str, Any]:
        """Processa elemento host do XML"""
        host_info = {
            'ip': None,
            'hostnames': [],
            'status': 'unknown',
            'os_detection': {},
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
        
        # Detecção de SO
        os_element = host_element.find('os')
        if os_element is not None:
            for match in os_element.findall('osmatch'):
                os_class = match.find('osclass')
                if os_class is not None:
                    host_info['os_detection'] = {
                        'name': match.get('name'),
                        'accuracy': match.get('accuracy'),
                        'vendor': os_class.get('vendor'),
                        'osfamily': os_class.get('osfamily'),
                        'osgen': os_class.get('osgen'),
                        'type': os_class.get('type')
                    }
                    break # Pegar o melhor resultado

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
