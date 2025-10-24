"""
Plugin de Análise de Protocolo
Analisa serviços em portas abertas para identificar vulnerabilidades e recolher informações.
"""

import subprocess
import time
import re
from typing import Dict, Any, List

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult

class ProtocolAnalyzerPlugin(NetworkPlugin):
    """Plugin para análise aprofundada de protocolos de rede."""

    def __init__(self):
        super().__init__()
        self.name = "ProtocolAnalyzer"
        self.description = "Analisa protocolos em portas abertas (ex: SMB, SSH) para vulnerabilidades."
        self.version = "1.0.0"
        self.requirements = ["nmap"]
        self.supported_targets = ["ip", "domain"]

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa a análise de protocolos nas portas abertas fornecidas."""
        start_time = time.time()

        open_ports = context.get('discoveries', {}).get('open_ports', [])
        if not open_ports:
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={'message': 'Nenhuma porta aberta para analisar.'}
            )

        analysis_results = {
            'target': target,
            'port_details': {}
        }

        # Mapeamento de portas para scripts Nmap
        protocol_scripts = {
            21: 'ftp-*',
            22: 'ssh-*',
            25: 'smtp-*',
            53: 'dns-*',
            139: 'smb-enum-*',
            445: 'smb-enum-*',
            3306: 'mysql-*',
            5432: 'pgsql-*',
            3389: 'rdp-*'
        }

        ports_to_scan = [port for port in open_ports if port in protocol_scripts]

        if not ports_to_scan:
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={'message': 'Nenhum protocolo suportado encontrado nas portas abertas.'}
            )

        try:
            for port in ports_to_scan:
                script = protocol_scripts[port]
                nmap_output = self._run_nmap_script(target, port, script)
                analysis_results['port_details'][port] = self._parse_nmap_output(nmap_output)

            execution_time = time.time() - start_time
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data=analysis_results
            )

        except Exception as e:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error=str(e)
            )

    def _run_nmap_script(self, target: str, port: int, script: str) -> str:
        """Executa um script Nmap específico num alvo e porta."""
        cmd = ['nmap', '-sV', '-p', str(port), '--script', script, target]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return f"Erro ao executar Nmap: {str(e)}"

    def _parse_nmap_output(self, nmap_output: str) -> Dict[str, Any]:
        """Analisa o output do Nmap para extrair informações relevantes."""
        results = {
            'vulnerabilities': [],
            'service_info': [],
            'raw_output': nmap_output
        }

        # Extrair vulnerabilidades (procura por "State: VULNERABLE")
        vuln_pattern = re.compile(r'(\S+):\s*\n\s*State: VULNERABLE\n(.*?)(?=\n\s*\S+:|\Z)', re.DOTALL)
        for match in vuln_pattern.finditer(nmap_output):
            script_id = match.group(1).strip()
            details = match.group(2).strip()
            results['vulnerabilities'].append({'script': script_id, 'details': details})

        # Extrair informações de enumeração (ex: smb-enum-shares)
        info_pattern = re.compile(r'\| (\S+):\s*\n((?:\|   .*\n)*)', re.MULTILINE)
        for match in info_pattern.finditer(nmap_output):
            script_id = match.group(1).strip()
            details = match.group(2).replace('|   ', '').strip()
            results['service_info'].append({'script': script_id, 'details': details})

        return results
