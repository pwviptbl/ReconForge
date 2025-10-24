"""
Plugin para Análise de Más Configurações de Segurança
"""

import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from typing import Dict, Any, List
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult


class MisconfigurationAnalyzerPlugin(NetworkPlugin):
    """
    Plugin dedicado a encontrar vulnerabilidades de má configuração
    utilizando scripts Nmap (NSE).
    """

    def __init__(self):
        super().__init__()
        self.name = "MisconfigurationAnalyzer"
        self.description = "Analisa falhas de configuração em serviços de rede (FTP, SMB, SSL, etc.)"
        self.version = "1.0.0"
        self.requirements = ["nmap"]
        self.supported_targets = ["ip", "domain"]

        # Scripts NSE focados em más configurações
        self.misconfiguration_scripts = [
            "ftp-anon",          # Verifica login anônimo em FTP
            "smb-enum-shares",   # Enumera compartilhamentos SMB
            "nfs-ls",            # Lista compartilhamentos NFS
            "ssl-enum-ciphers",  # Enumera cifras SSL/TLS fracas
            "http-config-backup",# Procura por backups de configuração em servidores web
            "http-enum",         # Enumera diretórios e arquivos comuns
            "smtp-open-relay"    # Verifica se o servidor SMTP é um open relay
        ]

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa a análise de más configurações com Nmap"""
        start_time = time.time()

        # O plugin depende das portas abertas descobertas anteriormente
        open_ports = context.get('discoveries', {}).get('open_ports', [])
        if not open_ports:
            return PluginResult(
                success=True, # Sucesso, mas sem ação
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                summary="Nenhuma porta aberta encontrada para analisar."
            )

        try:
            ports_str = ','.join(map(str, open_ports))
            scripts_str = ','.join(self.misconfiguration_scripts)

            # Comando Nmap para rodar apenas os scripts de má configuração nas portas abertas
            cmd = [
                'nmap', '-T4', '-sV',
                '--script', scripts_str,
                '-p', ports_str,
                target
            ]

            # Adicionar output XML
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                xml_file = f.name

            cmd.extend(['-oX', xml_file])

            # Executar Nmap
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # Timeout de 10 minutos
            )

            # Ler resultado XML
            xml_content = ""
            if Path(xml_file).exists():
                with open(xml_file, 'r') as f:
                    xml_content = f.read()
                Path(xml_file).unlink(missing_ok=True)

            # Processar resultados
            findings = self._process_results(xml_content)

            execution_time = time.time() - start_time

            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={'misconfigurations': findings},
                summary=f"Encontradas {len(findings)} possíveis más configurações."
            )

        except subprocess.TimeoutExpired:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error="Timeout na execução do Nmap para análise de más configurações."
            )
        except Exception as e:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error=str(e)
            )

    def _process_results(self, xml_content: str) -> List[Dict[str, Any]]:
        """Processa o XML do Nmap para extrair resultados dos scripts"""
        findings = []
        if not xml_content:
            return findings

        try:
            root = ET.fromstring(xml_content)

            for host in root.findall('host'):
                ip_address = host.find('address').get('addr')

                for port in host.findall('.//port'):
                    port_id = port.get('portid')

                    for script in port.findall('script'):
                        script_id = script.get('id')
                        output = script.get('output', '').strip()

                        # Adicionar apenas se o script retornou uma informação relevante
                        if output and "ERROR:" not in output:
                            findings.append({
                                'host': ip_address,
                                'port': int(port_id),
                                'script': script_id,
                                'details': output,
                                'severity': self._get_severity(script_id, output)
                            })
            return findings
        except ET.ParseError:
            return [] # Retorna vazio se o XML for inválido

    def _get_severity(self, script_id: str, output: str) -> str:
        """Determina a severidade baseada no script e no resultado"""
        output_lower = output.lower()
        if script_id == 'ftp-anon' and 'anonymous ftp login allowed' in output_lower:
            return 'High'
        if script_id == 'smb-enum-shares' and 'anonymous access' in output_lower:
            return 'High'
        if script_id == 'smtp-open-relay':
            return 'Critical'
        if script_id == 'ssl-enum-ciphers' and 'least strength' in output_lower:
            # Extrair a força para ser mais preciso
            if 'f' in output_lower or 'd' in output_lower:
                 return 'High'
            if 'c' in output_lower or 'b' in output_lower:
                return 'Medium'
        if script_id == 'http-config-backup':
            return 'High'

        return 'Info'
